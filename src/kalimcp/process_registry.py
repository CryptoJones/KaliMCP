# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Aaron K. Clark
"""In-memory registry of live tool subprocesses (issue #13).

``run.run`` records every subprocess it launches here and removes it on
exit, so an operator can `process_list` what is currently running and
`process_kill` a runaway scan (a wedged nmap, a brute-force that will
take 13 hours) without tearing down the whole MCP session.

Two deliberate safety properties:

* **Kill only what we launched.** ``kill`` refuses any PID not in the
  registry, so it can never be turned into an arbitrary-process killer.
* **No secrets in the snapshot.** A tool's argv can carry a password or
  cred file (hydra ``-p``, impacket ``user:pass@host``). The snapshot
  exposes only the *binary* (``argv[0]``) and the argument *count* — never
  the argv itself — so `process_list` can't leak what the audit log works
  to redact.

The module is process-global and thread-safe (a plain lock); the registry
outlives any single event loop.
"""

from __future__ import annotations

import os
import signal
import threading
import time
from typing import Any

_lock = threading.Lock()
_procs: dict[int, dict[str, Any]] = {}


def register(pid: int, argv: list[str], *, timeout: float, engagement: str = "") -> None:
    """Record a freshly launched subprocess."""
    with _lock:
        _procs[pid] = {
            "pid": pid,
            "binary": argv[0] if argv else "",
            "argc": len(argv),
            "started": time.monotonic(),
            "timeout_s": timeout,
            "engagement": engagement,
        }


def unregister(pid: int) -> None:
    """Drop a subprocess that has exited. No-op if already gone."""
    with _lock:
        _procs.pop(pid, None)


def snapshot() -> list[dict[str, Any]]:
    """Return the live processes, secret-free, sorted by PID."""
    now = time.monotonic()
    with _lock:
        rows = [
            {
                "pid": e["pid"],
                "binary": e["binary"],
                "argc": e["argc"],
                "elapsed_s": round(now - e["started"], 1),
                "timeout_s": e["timeout_s"],
                "engagement": e["engagement"],
            }
            for e in _procs.values()
        ]
    return sorted(rows, key=lambda r: r["pid"])


def kill(pid: int, *, sig: int = signal.SIGTERM) -> dict[str, Any]:
    """Signal a registered subprocess's whole process group.

    Refuses any PID we didn't launch. Sends ``sig`` (SIGTERM by default;
    pass ``signal.SIGKILL`` to force) to the group — tools launch with
    ``start_new_session=True``, so the group reaps grandchildren too.
    """
    with _lock:
        known = pid in _procs
    if not known:
        return {"ok": False, "error": "unknown_pid", "pid": pid}
    try:
        os.killpg(os.getpgid(pid), sig)
        return {"ok": True, "pid": pid, "signal": int(sig)}
    except ProcessLookupError:
        unregister(pid)
        return {"ok": False, "error": "not_running", "pid": pid}
    except OSError as exc:
        return {"ok": False, "error": "kill_failed", "pid": pid, "message": str(exc)}


def reset_for_test() -> None:
    with _lock:
        _procs.clear()
