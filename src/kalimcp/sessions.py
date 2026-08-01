# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Aaron K. Clark
"""Interactive session manager (issue #16).

Two kinds of long-lived session, each keyed by a session id and tracked in
an in-memory registry:

* **SSH** — backed by OpenSSH ControlMaster. ``ssh_start`` opens a
  multiplexed master connection (a control socket); ``ssh_exec`` reuses it
  to run a remote command without re-authenticating. Every operation is a
  normal :func:`kalimcp.run.run` subprocess (a list argv, no shell), so it
  is audited and needs no extra dependency. Passwords go through the audit
  redactor; pulled files are the caller's to ``loot_write`` at 0600.
* **Reverse shell** — ``revshell_listen`` starts a persistent listener
  (``nc -lvnp PORT`` by default) whose output is drained by a background
  thread; ``revshell_exec`` writes a command to the connected shell's stdin
  and returns the new output. The non-blocking *payload trigger* fires the
  callback command in the background, waits N seconds, and returns listener
  status instead of blocking the server until the shell lands.

Per the no-authorization-gate rule, sessions are **audited, not
scope-gated**. The persistent-process layer is isolated behind the
module-level ``_popen`` factory so the test suite can exercise the registry
without spawning anything real.
"""

from __future__ import annotations

import shlex
import subprocess
import threading
import time
import uuid
from pathlib import Path
from typing import Any

from . import audit, run

_SESSION_DIR = Path.home() / ".kalimcp" / "sessions"

# id -> metadata dict (ssh + revshell). Revshell live processes live in
# _procs, keyed by the same id.
_sessions: dict[str, dict[str, Any]] = {}
_procs: dict[str, _PersistentProc] = {}


def _new_id(prefix: str) -> str:
    return f"{prefix}-{uuid.uuid4().hex[:8]}"


def _session_dir() -> Path:
    try:
        _SESSION_DIR.mkdir(parents=True, exist_ok=True)
    except OSError:
        pass
    return _SESSION_DIR


def _audit(action: str, **fields: Any) -> None:
    audit.log("session_invoke", action=action, **fields)


# ---------- SSH sessions (OpenSSH ControlMaster) ----------

def _ctl_path(sid: str) -> str:
    return str(_session_dir() / f"{sid}.sock")


async def ssh_start(
    *,
    host: str,
    user: str,
    password: str = "",
    key: str = "",
    port: int = 22,
    timeout_seconds: int = 30,
) -> dict[str, Any]:
    """Open a multiplexed SSH master connection; returns its session id."""
    if host.startswith("-") or user.startswith("-"):
        return run.error_result("host/user may not begin with '-'")
    if key and (err := run.validate_file(key, "key")):
        return err

    sid = _new_id("ssh")
    ctl = _ctl_path(sid)
    argv: list[str] = []
    if password:
        argv += ["sshpass", "-p", password]
    argv += [
        "ssh", "-M", "-S", ctl,
        "-o", "ControlPersist=600",
        "-o", "StrictHostKeyChecking=accept-new",
        "-o", "ConnectTimeout=10",
        "-p", str(int(port)),
    ]
    if key:
        argv += ["-i", key, "-o", "BatchMode=yes"]
    argv += ["-fN", f"{user}@{host}"]

    result = await run.run(argv, timeout=timeout_seconds)
    logged = audit.redact_argv(argv, {"-p"}, [password] if password else None)
    _audit("ssh_start", session_id=sid, host=host, user=user, port=int(port),
           argv=logged, exit_code=result.get("exit_code"))
    if result.get("exit_code") != 0:
        return {"ok": False, "error": "ssh_start_failed",
                "stderr": result.get("stderr", ""), "session_id": sid}
    _sessions[sid] = {
        "id": sid, "kind": "ssh", "host": host, "user": user, "port": int(port),
        "ctl": ctl, "started_at": _now(),
    }
    return {"ok": True, "session_id": sid, "kind": "ssh", "host": host, "user": user}


async def socks_start(
    *,
    host: str,
    user: str,
    password: str = "",
    key: str = "",
    port: int = 22,
    socks_port: int = 1080,
    timeout_seconds: int = 30,
) -> dict[str, Any]:
    """Open an SSH master with a dynamic SOCKS forward (a pivot).

    Mirrors :func:`ssh_start` but adds ``-D <socks_port>`` — a dynamic,
    application-level port forward — so other tools can reach the target's
    internal network through ``socks5://127.0.0.1:<socks_port>`` (point them
    there via proxychains or a tool-native ``--proxy`` flag). The session is
    a normal SSH ControlMaster (kind "socks") and is torn down by ``ssh_stop``.
    """
    if host.startswith("-") or user.startswith("-"):
        return run.error_result("host/user may not begin with '-'")
    if key and (err := run.validate_file(key, "key")):
        return err

    sid = _new_id("socks")
    ctl = _ctl_path(sid)
    sp = int(socks_port)
    argv: list[str] = []
    if password:
        argv += ["sshpass", "-p", password]
    argv += [
        "ssh", "-M", "-S", ctl,
        "-D", str(sp),
        "-o", "ControlPersist=600",
        "-o", "StrictHostKeyChecking=accept-new",
        "-o", "ConnectTimeout=10",
        "-p", str(int(port)),
    ]
    if key:
        argv += ["-i", key, "-o", "BatchMode=yes"]
    argv += ["-fN", f"{user}@{host}"]

    result = await run.run(argv, timeout=timeout_seconds)
    logged = audit.redact_argv(argv, {"-p"}, [password] if password else None)
    _audit("socks_start", session_id=sid, host=host, user=user, port=int(port),
           socks_port=sp, argv=logged, exit_code=result.get("exit_code"))
    if result.get("exit_code") != 0:
        return {"ok": False, "error": "socks_start_failed",
                "stderr": result.get("stderr", ""), "session_id": sid}
    _sessions[sid] = {
        "id": sid, "kind": "socks", "host": host, "user": user, "port": int(port),
        "ctl": ctl, "socks_port": sp, "started_at": _now(),
    }
    return {
        "ok": True, "session_id": sid, "kind": "socks",
        "proxy": f"socks5://127.0.0.1:{sp}",
        "note": "point other tools here via proxychains or a tool-native "
                "--proxy flag",
    }


async def ssh_exec(session_id: str, command: str, *, timeout_seconds: int = 60) -> dict[str, Any]:
    """Run ``command`` on an open SSH session (reuses the master socket)."""
    sess = _sessions.get(session_id)
    if not sess or sess.get("kind") not in ("ssh", "socks"):
        return run.error_result(f"no such ssh session: {session_id}")
    argv = [
        "ssh", "-S", sess["ctl"], "-p", str(sess["port"]),
        f"{sess['user']}@{sess['host']}", "--", command,
    ]
    result = await run.run(argv, timeout=timeout_seconds)
    _audit("ssh_exec", session_id=session_id, argv=argv,
           exit_code=result.get("exit_code"))
    return {"ok": True, "session_id": session_id, **result}


async def ssh_put(
    session_id: str, local_path: str, remote_path: str, *, timeout_seconds: int = 120
) -> dict[str, Any]:
    """Upload ``local_path`` to ``remote_path`` over an open SSH master (scp)."""
    sess = _sessions.get(session_id)
    if not sess or sess.get("kind") not in ("ssh", "socks"):
        return run.error_result(f"no such ssh session: {session_id}")
    if err := run.validate_file(local_path, "local_path"):
        return err
    ctl = sess["ctl"]
    argv = [
        "scp", "-o", f"ControlPath={ctl}", "-P", str(sess["port"]),
        "--", local_path, f"{sess['user']}@{sess['host']}:{remote_path}",
    ]
    result = await run.run(argv, timeout=timeout_seconds)
    _audit("ssh_put", session_id=session_id, argv=argv,
           remote_path=remote_path, exit_code=result.get("exit_code"))
    return {"ok": result.get("exit_code") == 0, "session_id": session_id,
            "remote_path": remote_path, **result}


async def ssh_get(
    session_id: str, remote_path: str, local_path: str, *, timeout_seconds: int = 120
) -> dict[str, Any]:
    """Download ``remote_path`` to ``local_path`` over an open SSH master (scp)."""
    sess = _sessions.get(session_id)
    if not sess or sess.get("kind") not in ("ssh", "socks"):
        return run.error_result(f"no such ssh session: {session_id}")
    ctl = sess["ctl"]
    argv = [
        "scp", "-o", f"ControlPath={ctl}", "-P", str(sess["port"]),
        "--", f"{sess['user']}@{sess['host']}:{remote_path}", local_path,
    ]
    result = await run.run(argv, timeout=timeout_seconds)
    _audit("ssh_get", session_id=session_id, argv=argv,
           remote_path=remote_path, local_path=local_path,
           exit_code=result.get("exit_code"))
    return {"ok": result.get("exit_code") == 0, "session_id": session_id,
            "local_path": local_path, **result}


async def enum_upload_run(
    session_id: str,
    local_script: str,
    remote_path: str = "/tmp/.km_enum",
    interpreter: str = "sh",
    *,
    timeout_seconds: int = 300,
) -> dict[str, Any]:
    """Upload a local-enum script (PEASS-style) and run it on the target.

    Convenience combo: ``ssh_put`` the script, then ``ssh_exec`` a single
    remote command (``chmod +x <remote_path> && <interpreter> <remote_path>``)
    that executes on the TARGET via the SSH master — this is the intended
    remote capability, not a local shell.
    """
    if err := run.validate_file(local_script, "local_script"):
        return err
    put = await ssh_put(session_id, local_script, remote_path,
                        timeout_seconds=min(timeout_seconds, 120))
    if not put.get("ok"):
        return {"ok": False, "error": "upload_failed", "session_id": session_id,
                "put": put}
    remote_cmd = f"chmod +x {remote_path} && {interpreter} {remote_path}"
    run_res = await ssh_exec(session_id, remote_cmd, timeout_seconds=timeout_seconds)
    _audit("enum_upload_run", session_id=session_id, remote_path=remote_path,
           interpreter=interpreter)
    return {"ok": run_res.get("ok", False), "session_id": session_id,
            "remote_path": remote_path, "put": put, "run": run_res}


async def ssh_stop(session_id: str, *, timeout_seconds: int = 15) -> dict[str, Any]:
    """Close an SSH or SOCKS session (tears down the master socket)."""
    sess = _sessions.pop(session_id, None)
    if not sess or sess.get("kind") not in ("ssh", "socks"):
        return {"ok": False, "error": "no_such_session", "session_id": session_id}
    argv = ["ssh", "-S", sess["ctl"], "-O", "exit",
            f"{sess['user']}@{sess['host']}"]
    result = await run.run(argv, timeout=timeout_seconds)
    _audit("ssh_stop", session_id=session_id, exit_code=result.get("exit_code"))
    return {"ok": True, "session_id": session_id, "stopped": True}


# ---------- reverse-shell listener (persistent process) ----------

def _popen(argv: list[str]) -> Any:
    """Spawn a persistent process with duplex pipes. Patched in tests."""
    return subprocess.Popen(  # noqa: S603 (list argv, no shell)
        argv,
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        bufsize=0,
        start_new_session=True,
    )


class _PersistentProc:
    """Wraps a long-lived process: a background thread drains stdout into a
    buffer; ``send`` writes to stdin; ``read_new`` returns + clears the
    buffer. Used for the reverse-shell listener."""

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


def _fire_trigger(argv: list[str]) -> Any:
    """Fire a payload-trigger command in the background (non-blocking)."""
    return _popen(argv)


async def revshell_listen(
    *,
    port: int,
    trigger: str = "",
    wait_seconds: int = 5,
    timeout_seconds: int = 0,
) -> dict[str, Any]:
    """Start a reverse-shell listener on ``port``.

    If ``trigger`` (a shell command to run *locally* to make the target
    connect back, e.g. an exploit invocation) is given, it is fired in the
    background; the call then waits ``wait_seconds`` and reports whether the
    shell landed — it never blocks the server waiting for the connection.
    """
    p = int(port)
    if not (1 <= p <= 65535):
        return run.error_result(f"invalid port: {port}")
    sid = _new_id("revshell")
    listener_argv = ["nc", "-lvnp", str(p)]
    try:
        proc = _PersistentProc(listener_argv)
    except (OSError, ValueError) as exc:
        return {"ok": False, "error": "listener_failed", "message": str(exc)}
    _procs[sid] = proc
    trigger_pid = None
    if trigger.strip():
        # Trigger is operator-supplied; split safely, run as argv (no shell).
        try:
            tproc = _fire_trigger(shlex.split(trigger))
            trigger_pid = getattr(tproc, "pid", None)
            proc._trigger = tproc  # type: ignore[attr-defined]
        except (OSError, ValueError):
            trigger_pid = None
        time.sleep(max(0, min(int(wait_seconds), 60)))
    _sessions[sid] = {
        "id": sid, "kind": "revshell", "port": p, "started_at": _now(),
        "listener_argv": listener_argv,
    }
    _audit("revshell_listen", session_id=sid, port=p, triggered=bool(trigger.strip()))
    # Drain whatever arrived during the wait. This includes nc's own
    # "listening" banner, so it's returned as raw output for the agent to
    # judge — not asserted as a confirmed shell.
    initial = proc.read_new().decode("utf-8", errors="replace") if trigger.strip() else ""
    return {
        "ok": True, "session_id": sid, "kind": "revshell", "port": p,
        "trigger_pid": trigger_pid, "initial_output": initial,
        "note": "non-blocking: poll revshell_exec to interact once the shell lands.",
    }


async def revshell_exec(session_id: str, command: str = "", *, read_wait: float = 0.5) -> dict[str, Any]:
    """Send ``command`` to a reverse shell and return its new output.

    Pass an empty ``command`` to just drain pending output.
    """
    proc = _procs.get(session_id)
    sess = _sessions.get(session_id)
    if not proc or not sess or sess.get("kind") != "revshell":
        return run.error_result(f"no such revshell session: {session_id}")
    if command:
        proc.send(command.encode("utf-8", errors="replace") + b"\n")
        time.sleep(max(0.0, min(read_wait, 10.0)))
    output = proc.read_new().decode("utf-8", errors="replace")
    _audit("revshell_exec", session_id=session_id, alive=proc.alive())
    return {"ok": True, "session_id": session_id, "alive": proc.alive(), "output": output}


async def revshell_stop(session_id: str) -> dict[str, Any]:
    proc = _procs.pop(session_id, None)
    sess = _sessions.pop(session_id, None)
    if not proc or not sess:
        return {"ok": False, "error": "no_such_session", "session_id": session_id}
    trigger = getattr(proc, "_trigger", None)
    if trigger is not None:
        try:
            trigger.terminate()
        except (ProcessLookupError, OSError, AttributeError):
            pass
    proc.stop()
    _audit("revshell_stop", session_id=session_id)
    return {"ok": True, "session_id": session_id, "stopped": True}


# ---------- shared status / list ----------

def session_status(session_id: str) -> dict[str, Any]:
    sess = _sessions.get(session_id)
    if not sess:
        return {"ok": False, "error": "no_such_session", "session_id": session_id}
    out = {"ok": True, **sess}
    if sess.get("kind") == "revshell":
        proc = _procs.get(session_id)
        out["alive"] = bool(proc and proc.alive())
    return out


def session_list() -> dict[str, Any]:
    items = []
    for sid, sess in sorted(_sessions.items()):
        # Annotate as dict[str, Any]: without it, the comprehension's literal key
        # tuple narrows the value type to dict[Literal["id","kind","started_at"], Any],
        # and the later "endpoint"/"proxy"/"port"/"alive" assignments become
        # index-type errors under mypy 2.3+.
        entry: dict[str, Any] = {k: sess[k] for k in ("id", "kind", "started_at") if k in sess}
        if sess.get("kind") in ("ssh", "socks"):
            entry["endpoint"] = f"{sess['user']}@{sess['host']}:{sess['port']}"
            if sess.get("kind") == "socks":
                entry["proxy"] = f"socks5://127.0.0.1:{sess['socks_port']}"
        else:
            entry["port"] = sess.get("port")
            proc = _procs.get(sid)
            entry["alive"] = bool(proc and proc.alive())
        items.append(entry)
    return {"sessions": items, "count": len(items)}


# ---------- helpers ----------

# Commands that block forever as a one-shot — the agent should open a
# session instead of running these through a scan wrapper.
_BLOCKING_PATTERNS = (
    "nc -l", "nc -lvnp", "ncat -l", "socat ", "/dev/tcp/",
    "msfconsole", "ssh ", "telnet ",
)


def detect_blocking_command(command: str) -> dict[str, Any]:
    """Flag a command that would block as a one-shot (use a session instead)."""
    c = (command or "").lower()
    for pat in _BLOCKING_PATTERNS:
        if pat in c:
            return {
                "blocking": True,
                "pattern": pat.strip(),
                "advice": "this command holds a connection open — use the "
                          "session tools (ssh_start / revshell_listen) instead "
                          "of a one-shot run.",
            }
    return {"blocking": False}


def system_network_info() -> dict[str, Any]:
    """Report local interface addresses so the agent picks the right LHOST
    for a reverse shell (e.g. the VPN/tun address on an engagement)."""
    import socket
    addrs: list[dict[str, str]] = []
    try:
        hostname = socket.gethostname()
        for info in socket.getaddrinfo(hostname, None):
            ip = str(info[4][0])
            family = "ipv6" if ":" in ip else "ipv4"
            addrs.append({"address": ip, "family": family})
    except OSError:
        pass
    # De-dup while preserving order.
    seen = set()
    uniq = []
    for a in addrs:
        if a["address"] not in seen:
            seen.add(a["address"])
            uniq.append(a)
    # Heuristic LHOST recommendation: prefer a VPN tun (10./172.16-31.) or
    # other non-loopback IPv4.
    recommended = ""
    for a in uniq:
        ip = a["address"]
        if a["family"] == "ipv4" and not ip.startswith("127."):
            recommended = ip
            if ip.startswith(("10.", "172.")):
                break
    return {"addresses": uniq, "recommended_lhost": recommended}


def _now() -> str:
    from datetime import UTC, datetime
    return datetime.now(UTC).isoformat(timespec="seconds")


def reset_for_test() -> None:
    _sessions.clear()
    _procs.clear()
