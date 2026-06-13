# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Aaron K. Clark
"""JSONL audit log for every MCP tool invocation.

Every tool call lands in /var/log/kalimcp.log (default) or whatever
``KALIMCP_LOG_FILE`` points at. If the default path isn't writable
the writer falls back to ``~/.kalimcp/kalimcp.log`` with a one-time
stderr breadcrumb.

The audit log is the operator's primary forensic record — every
``tool_invoke`` event includes the tool name, the full argv that
ran, the target, the exit code, and the elapsed wall-clock time. A
separate ``out_of_scope_warning`` event fires when a target falls
outside the active engagement's declared scope. Tool stdout/stderr
are NOT logged, to keep the file small and avoid accidentally
recording credentials a scan returned. Operators who want full
output should redirect tool stdout themselves.
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

# The audit log holds recon metadata and credential-flag usage — more
# sensitive than the engagement loot store, which is already 0600. Open
# (and create) it owner-only so a default umask of 022 can't leave it
# world-readable.
_LOG_MODE = 0o600


def _open_append(path: Path):
    """Open ``path`` for append, creating it 0600 if absent.

    ``os.open`` applies the mode only on creation, so a pre-existing
    file keeps its own mode (``configure`` tightens those separately).
    Returns a text file object; the caller closes it.
    """
    fd = os.open(path, os.O_WRONLY | os.O_APPEND | os.O_CREAT, _LOG_MODE)
    return os.fdopen(fd, "a", encoding="utf-8")


def _tighten_mode(path: Path) -> None:
    """Best-effort chmod to 0600 for a log file created before this
    discipline (or by another tool with a looser umask)."""
    try:
        if path.exists():
            path.chmod(_LOG_MODE)
    except OSError:
        pass


def _writable(path: Path) -> bool:
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        with _open_append(path):
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
        _tighten_mode(candidate)
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
        _tighten_mode(FALLBACK_LOG_PATH)
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
        with _open_append(path) as fh:
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


# A secret value shorter than this is not redacted by substring match:
# a 1-2 char password would match (and corrupt) nearly every token in
# argv, including flags and the binary name. Such values are degenerate
# anyway; the flag-based path still covers them when they follow a flag.
_MIN_REDACTABLE_VALUE = 3


def _hash8(value: str) -> str:
    """``sha256:<8hex>`` digest of ``value`` — the redaction token."""
    digest = hashlib.sha256(value.encode("utf-8", errors="replace")).hexdigest()[:8]
    return f"sha256:{digest}"


def redact_argv(
    argv: list[str],
    secret_flags: Iterable[str] | None,
    secret_values: Iterable[str] | None = None,
) -> list[str]:
    """Return a copy of ``argv`` with secret material replaced by
    ``sha256:<8hex>``.

    Credential tools (hydra, medusa, netexec, impacket, ...) pass
    passwords or cred-bearing file paths on the command line. Logging
    argv verbatim would write those literals into the audit file,
    which defeats the file-mode-0600 discipline applied to the log.
    This helper rewrites just the secret values; the surrounding flag
    and structure stay so operators can still see *that* a credential
    was used, just not its content.

    Three shapes are redacted:

    1. ``-flag value`` — the standalone token after a secret flag.
    2. ``--flag=value`` — the value half of a fused token whose
       left side is a secret flag.
    3. **By value** — any ``secret_values`` substring found anywhere
       in a token (e.g. a password fused into a ``user:pass@host``
       positional). This is the fail-*closed* path: it redacts the
       secret even when a wrapper forgot to declare the right flag,
       and even when the secret never rides behind a flag at all.

    The replacement is the first 8 hex chars of the SHA-256 hash of
    the value, prefixed with ``sha256:``. That lets an operator who
    has the suspected plaintext verify a match, without exposing
    anything if the audit log leaks.

    No-op (returns ``argv`` unchanged) when both ``secret_flags`` and
    ``secret_values`` are falsy.
    """
    flags = set(secret_flags or ())
    # Longest first so a value that is a substring of another doesn't
    # get partially rewritten by the shorter one.
    values = sorted(
        {v for v in (secret_values or []) if v and len(v) >= _MIN_REDACTABLE_VALUE},
        key=len,
        reverse=True,
    )
    if not flags and not values:
        return list(argv)

    def by_value(tok: str) -> str:
        for v in values:
            if v in tok:
                tok = tok.replace(v, _hash8(v))
        return tok

    out: list[str] = []
    skip_next = False
    for tok in argv:
        if skip_next:
            # Whole token is the secret-flag's value.
            out.append(_hash8(tok))
            skip_next = False
            continue
        # `--flag=value` fused form: redact the value half only.
        name, sep, val = tok.partition("=")
        if sep and name in flags:
            out.append(f"{name}={_hash8(val)}")
            continue
        out.append(by_value(tok))
        if tok in flags:
            skip_next = True
    return out


def reset_for_test() -> None:
    global _resolved_path, _disabled, _warned
    _resolved_path = None
    _disabled = False
    _warned = False
