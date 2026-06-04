# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Aaron K. Clark
"""Subprocess helpers — every tool wrapper goes through these.

Each invocation:
  * runs with a hard per-tool timeout (default 5 minutes) so a
    runaway scan can't block the MCP server indefinitely,
  * captures stdout + stderr (combined output capped at 2 MB so
    pathologically chatty tools don't OOM the host),
  * returns a structured dict the MCP tool wrapper can serialize.

The runner never raises on tool failure (non-zero exit). It returns
the structured failure to the caller so the LLM agent can read +
react. Only subprocess-launching errors (e.g. binary not found)
bubble up as exceptions.
"""

from __future__ import annotations

import asyncio
import os
import shlex
import signal
from typing import Any

DEFAULT_TIMEOUT_SECONDS = 300
MAX_OUTPUT_BYTES = 2 * 1024 * 1024  # 2 MB combined


class ToolNotInstalled(RuntimeError):
    """The wrapped binary isn't on PATH."""


def _kill_group(proc: asyncio.subprocess.Process) -> None:
    """SIGKILL the tool and everything it spawned (its whole process group).

    Tools launch with ``start_new_session=True`` so the child is its own
    process-group leader; killing the group reaps grandchildren too (e.g. a
    wrapper that forks the real scanner). No-op if it already exited.
    """
    if proc.returncode is not None:
        return
    try:
        os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
    except ProcessLookupError:
        pass
    except OSError:
        try:
            proc.kill()
        except ProcessLookupError:
            pass


async def run(
    argv: list[str],
    *,
    timeout: float | None = None,
    stdin: bytes | None = None,
) -> dict[str, Any]:
    """Run a command and return a structured result.

    Returns:
      {
        "argv":      [...],         # what we actually ran
        "exit_code": int,
        "elapsed_s": float,
        "stdout":    str,           # truncated to MAX_OUTPUT_BYTES
        "stderr":    str,
        "truncated": bool,
        "timed_out": bool,
      }
    """
    if not argv:
        raise ValueError("empty argv")

    t = timeout if timeout is not None else DEFAULT_TIMEOUT_SECONDS

    try:
        proc = await asyncio.create_subprocess_exec(
            *argv,
            stdin=asyncio.subprocess.PIPE if stdin is not None else asyncio.subprocess.DEVNULL,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            start_new_session=True,
        )
    except FileNotFoundError as exc:
        raise ToolNotInstalled(
            f"binary not found: {argv[0]} — install it or run KaliMCP inside the "
            "Dockerfile-provided Kali image"
        ) from exc

    loop = asyncio.get_running_loop()
    start = loop.time()
    timed_out = False
    try:
        try:
            stdout_b, stderr_b = await asyncio.wait_for(proc.communicate(input=stdin), timeout=t)
        except TimeoutError:
            timed_out = True
            _kill_group(proc)
            try:
                stdout_b, stderr_b = await proc.communicate()
            except Exception:
                stdout_b, stderr_b = b"", b""
    finally:
        # If the tool is still running as we leave — the surrounding task was
        # cancelled because the MCP server is shutting down or the client
        # disconnected — kill the whole group so a scan can't outlive the
        # session as an orphan.
        _kill_group(proc)

    elapsed = loop.time() - start

    truncated = False
    if len(stdout_b) > MAX_OUTPUT_BYTES:
        stdout_b = stdout_b[:MAX_OUTPUT_BYTES]
        truncated = True
    if len(stderr_b) > MAX_OUTPUT_BYTES:
        stderr_b = stderr_b[:MAX_OUTPUT_BYTES]
        truncated = True

    return {
        "argv": argv,
        "exit_code": proc.returncode if proc.returncode is not None else -1,
        "elapsed_s": round(elapsed, 3),
        "stdout": stdout_b.decode("utf-8", errors="replace"),
        "stderr": stderr_b.decode("utf-8", errors="replace"),
        "truncated": truncated,
        "timed_out": timed_out,
    }


def quote_argv(argv: list[str]) -> str:
    """Return a shell-safe single-line representation for the audit log."""
    return " ".join(shlex.quote(a) for a in argv)


def error_result(stderr: str, *, parsed: Any = None, **extra: Any) -> dict[str, Any]:
    """Structured failure for an error caught *before* the subprocess launches.

    Wrappers validate their inputs (known profile, wordlist exists, secret
    supplied, …) and early-return one of these on a bad call. It mirrors the
    shape of a real :func:`run` result — exit_code -1, empty output, nothing
    timed out or truncated, empty argv — so the audit/record path downstream
    treats a rejected call exactly like a tool that ran and failed.

    ``parsed`` is attached only when given (wrappers pass their empty-parsed
    skeleton so the result shape stays stable). ``**extra`` merges in
    wrapper-specific keys such as ``profile=...``.
    """
    result: dict[str, Any] = {
        "exit_code": -1,
        "elapsed_s": 0,
        "stdout": "",
        "stderr": stderr,
        "truncated": False,
        "timed_out": False,
        "argv": [],
    }
    if parsed is not None:
        result["parsed"] = parsed
    result.update(extra)
    return result
