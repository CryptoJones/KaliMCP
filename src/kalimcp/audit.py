# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Aaron K. Clark
"""JSONL audit log for every MCP tool invocation.

Every tool call lands in /var/log/kalimcp.log (default) or whatever
``KALIMCP_LOG_FILE`` points at. If the default path isn't writable
the writer falls back to ``~/.kalimcp/kalimcp.log`` with a one-time
stderr breadcrumb.

The audit log is the operator's primary forensic record — every
``invoke`` event includes the tool name, the full argv that ran,
the target, the exit code, and the elapsed wall-clock time. A
separate ``refused`` event fires when the active-tool refuse list
short-circuits a call before any subprocess starts. Tool
stdout/stderr are NOT logged, to keep the file small and avoid
accidentally recording credentials a scan returned. Operators
who want full output should redirect tool stdout themselves.
"""

from __future__ import annotations

import hashlib
import json
import os
import sys
import time
from collections.abc import Iterable
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

DEFAULT_LOG_PATH = Path("/var/log/kalimcp.log")
FALLBACK_LOG_PATH = Path.home() / ".kalimcp" / "kalimcp.log"

_resolved_path: Path | None = None
_disabled: bool = False
_warned: bool = False


def _writable(path: Path) -> bool:
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("a", encoding="utf-8"):
            pass
        return True
    except (PermissionError, OSError):
        return False


def configure(path: str | os.PathLike | None = None, disabled: bool = False) -> Path | None:
    """Resolve the effective log path, or disable logging."""
    global _resolved_path, _disabled, _warned
    _resolved_path = None
    _disabled = False
    _warned = False

    if disabled or os.environ.get("KALIMCP_NO_LOG"):
        _disabled = True
        return None

    if path is None:
        env_path = os.environ.get("KALIMCP_LOG_FILE")
        candidate = Path(env_path) if env_path else DEFAULT_LOG_PATH
    else:
        candidate = Path(path)

    if _writable(candidate):
        _resolved_path = candidate
        return candidate

    if path is not None or os.environ.get("KALIMCP_LOG_FILE"):
        print(
            f"kalimcp: audit log path {candidate} is not writable; disabling.",
            file=sys.stderr,
        )
        _disabled = True
        return None

    if _writable(FALLBACK_LOG_PATH):
        _resolved_path = FALLBACK_LOG_PATH
        if not _warned:
            print(
                f"kalimcp: {DEFAULT_LOG_PATH} not writable; logging to "
                f"{FALLBACK_LOG_PATH} (`sudo touch {DEFAULT_LOG_PATH} && "
                f"sudo chown $USER {DEFAULT_LOG_PATH}` to use the system path).",
                file=sys.stderr,
            )
            _warned = True
        return FALLBACK_LOG_PATH

    _disabled = True
    return None


def get_path() -> Path | None:
    if _resolved_path is None and not _disabled:
        configure()
    return _resolved_path


def log(event: str, **fields: Any) -> None:
    """Append a JSONL line. Side-channel — never raises."""
    path = get_path()
    if path is None:
        return
    entry = {
        "ts": datetime.now(UTC).isoformat(timespec="seconds"),
        "event": event,
    }
    for k, v in fields.items():
        if k in ("ts", "event"):
            continue
        entry[k] = v
    try:
        line = json.dumps(entry, sort_keys=True, default=str) + "\n"
        with path.open("a", encoding="utf-8") as fh:
            fh.write(line)
    except (OSError, TypeError, ValueError):
        return


def time_block():
    """Context manager that yields a function returning elapsed ms.

    Usage:
        with time_block() as elapsed:
            ...
        log("done", elapsed_ms=elapsed())
    """
    class _T:
        def __enter__(self):
            self._start = time.monotonic()
            return lambda: round((time.monotonic() - self._start) * 1000, 2)

        def __exit__(self, *_):
            return False

    return _T()


def redact_argv(argv: list[str], secret_flags: Iterable[str] | None) -> list[str]:
    """Return a copy of ``argv`` with values following secret-bearing
    flags replaced by ``sha256:<8hex>``.

    Credential tools (hydra, medusa, netexec, ...) pass passwords or
    cred-bearing file paths on the command line. Logging argv
    verbatim would write those literals into the audit file, which
    defeats the file-mode-0600 discipline applied to a real loot
    store. This helper rewrites just the secret values; the flag
    itself stays so operators can still see *that* a credential was
    used, just not its content.

    The replacement is the first 8 hex chars of the SHA-256 hash of
    the value, prefixed with ``sha256:``. That lets an operator who
    has the suspected plaintext verify a match, without exposing
    anything if the audit log leaks.

    No-op (returns ``argv`` unchanged) when ``secret_flags`` is
    falsy.
    """
    if not secret_flags:
        return list(argv)
    flags = set(secret_flags)
    out: list[str] = []
    skip_next = False
    for tok in argv:
        if skip_next:
            digest = hashlib.sha256(tok.encode("utf-8", errors="replace")).hexdigest()[:8]
            out.append(f"sha256:{digest}")
            skip_next = False
            continue
        out.append(tok)
        if tok in flags:
            skip_next = True
    return out


def reset_for_test() -> None:
    global _resolved_path, _disabled, _warned
    _resolved_path = None
    _disabled = False
    _warned = False
