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
from pathlib import Path
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

    # Drain stdout/stderr incrementally into capped buffers. Reading as the
    # tool runs (rather than a single communicate() at the end) means a
    # timeout still yields the partial output captured so far instead of
    # discarding it (issue #19). Each buffer stops growing at
    # MAX_OUTPUT_BYTES, but the reader keeps draining so a full pipe can't
    # deadlock the child.
    stdout_buf = bytearray()
    stderr_buf = bytearray()
    truncated = False

    async def _drain(stream: asyncio.StreamReader | None, buf: bytearray) -> None:
        nonlocal truncated
        if stream is None:
            return
        while True:
            chunk = await stream.read(65536)
            if not chunk:
                break
            room = MAX_OUTPUT_BYTES - len(buf)
            if room > 0:
                buf += chunk[:room]
            if len(chunk) > room:
                truncated = True

    async def _feed() -> None:
        if stdin is None or proc.stdin is None:
            return
        try:
            proc.stdin.write(stdin)
            await proc.stdin.drain()
        except (BrokenPipeError, ConnectionResetError):
            pass
        finally:
            try:
                proc.stdin.close()
            except Exception:
                pass

    drain_tasks = [
        asyncio.ensure_future(_drain(proc.stdout, stdout_buf)),
        asyncio.ensure_future(_drain(proc.stderr, stderr_buf)),
        asyncio.ensure_future(_feed()),
    ]
    timed_out = False
    try:
        try:
            await asyncio.wait_for(proc.wait(), timeout=t)
        except TimeoutError:
            timed_out = True
            _kill_group(proc)
        # Now the process has exited or been killed (kill EOFs the pipes,
        # so the drains finish): collect whatever they hold/can still read.
        try:
            await asyncio.wait_for(
                asyncio.gather(*drain_tasks, return_exceptions=True), timeout=5.0
            )
        except TimeoutError:
            for tk in drain_tasks:
                tk.cancel()
    finally:
        # Cancellation (server shutdown / client disconnect) or any exit:
        # never let the scan or its readers outlive this call.
        _kill_group(proc)
        for tk in drain_tasks:
            if not tk.done():
                tk.cancel()

    elapsed = loop.time() - start
    stdout_b = bytes(stdout_buf)
    stderr_b = bytes(stderr_buf)

    return {
        "argv": argv,
        "exit_code": proc.returncode if proc.returncode is not None else -1,
        "elapsed_s": round(elapsed, 3),
        "stdout": stdout_b.decode("utf-8", errors="replace"),
        "stderr": stderr_b.decode("utf-8", errors="replace"),
        "truncated": truncated,
        "timed_out": timed_out,
        # Output captured before a timeout is real but incomplete — flag it
        # so a caller never mistakes a timed-out scan for a finished one.
        "partial": bool(timed_out and (stdout_b or stderr_b)),
    }


def validate_file(
    path: str, label: str = "file", *, parsed: Any = None
) -> dict[str, Any] | None:
    """Shared input-path check for wrappers that take a file argument.

    Returns ``None`` when ``path`` names an existing regular file, or an
    :func:`error_result` describing the problem otherwise. This is the
    single choke point the issue-#9 review asked for: ffuf and gobuster
    used to hand-roll ``Path(wl).is_file()`` while the credential/cracking
    wrappers (hydra, john, hashcat) silently passed any agent-supplied
    path straight to the tool. Routing them all through here means a new
    wrapper can't omit the check, and a bad path yields a clean structured
    error instead of a confusing tool-level failure.

    This is existence/type validation, not a path allowlist — consistent
    with the project's no-authorization-gate design rule. It does not
    restrict *which* files an operator-trusted agent may point a tool at.
    """
    if not path:
        return error_result(f"no {label} provided", parsed=parsed)
    try:
        if not Path(path).is_file():
            return error_result(f"{label} not found: {path}", parsed=parsed)
    except OSError as exc:
        return error_result(f"{label} not accessible: {path} ({exc})", parsed=parsed)
    return None


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
