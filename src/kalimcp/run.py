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
import shlex
from typing import Any

DEFAULT_TIMEOUT_SECONDS = 300
MAX_OUTPUT_BYTES = 2 * 1024 * 1024  # 2 MB combined


class ToolNotInstalled(RuntimeError):
    """The wrapped binary isn't on PATH."""


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
        stdout_b, stderr_b = await asyncio.wait_for(proc.communicate(input=stdin), timeout=t)
    except asyncio.TimeoutError:
        timed_out = True
        proc.kill()
        try:
            stdout_b, stderr_b = await proc.communicate()
        except Exception:
            stdout_b, stderr_b = b"", b""

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
