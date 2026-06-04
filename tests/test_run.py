# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Aaron K. Clark
"""Subprocess runner tests."""

from __future__ import annotations

import asyncio
import os

import pytest

from kalimcp import run


def _alive(pid: int) -> bool:
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    return True


async def _wait_pidfile(pidfile, timeout: float = 5.0) -> int:
    loop = asyncio.get_running_loop()
    deadline = loop.time() + timeout
    while loop.time() < deadline:
        if pidfile.exists():
            text = pidfile.read_text().strip()
            if text:
                return int(text)
        await asyncio.sleep(0.02)
    raise AssertionError("subprocess never recorded its pid")


async def _wait_dead(pid: int, timeout: float = 3.0) -> None:
    loop = asyncio.get_running_loop()
    deadline = loop.time() + timeout
    while loop.time() < deadline:
        if not _alive(pid):
            return
        await asyncio.sleep(0.02)


@pytest.mark.asyncio
async def test_run_echo_returns_clean_result():
    result = await run.run(["sh", "-c", "echo hello; echo world >&2; exit 0"])
    assert result["exit_code"] == 0
    assert "hello" in result["stdout"]
    assert "world" in result["stderr"]
    assert result["timed_out"] is False
    assert result["truncated"] is False
    assert result["argv"] == ["sh", "-c", "echo hello; echo world >&2; exit 0"]


@pytest.mark.asyncio
async def test_run_nonzero_exit_returned_not_raised():
    result = await run.run(["sh", "-c", "exit 7"])
    assert result["exit_code"] == 7
    assert result["timed_out"] is False


@pytest.mark.asyncio
async def test_run_timeout_marks_timed_out():
    result = await run.run(["sh", "-c", "sleep 5"], timeout=0.5)
    assert result["timed_out"] is True


@pytest.mark.asyncio
async def test_timeout_kills_grandchild(tmp_path):
    # The backgrounded `sleep` shares the shell's process group; a timeout must
    # reap the whole group, not just the immediate child.
    pidfile = tmp_path / "child.pid"
    cmd = ["sh", "-c", f"sleep 30 & echo $! > {pidfile}; wait"]
    result = await run.run(cmd, timeout=0.5)
    assert result["timed_out"] is True
    child = int(pidfile.read_text().strip())
    await _wait_dead(child)
    assert not _alive(child), "grandchild scan survived the timeout"


@pytest.mark.asyncio
async def test_cancellation_kills_process_group(tmp_path):
    # When the MCP server shuts down (stdin EOF) or the client disconnects, the
    # in-flight tool's task is cancelled — the subprocess must not orphan.
    pidfile = tmp_path / "child.pid"
    cmd = ["sh", "-c", f"sleep 30 & echo $! > {pidfile}; wait"]
    task = asyncio.create_task(run.run(cmd))
    child = await _wait_pidfile(pidfile)
    assert _alive(child)
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task
    await _wait_dead(child)
    assert not _alive(child), "tool subprocess survived task cancellation"


@pytest.mark.asyncio
async def test_run_missing_binary_raises_ToolNotInstalled():
    with pytest.raises(run.ToolNotInstalled):
        await run.run(["definitely-does-not-exist-binary-name-12345"])


@pytest.mark.asyncio
async def test_run_truncates_large_output():
    # Generate >2MB of stdout
    cmd = ["sh", "-c", "head -c 3000000 /dev/zero | tr '\\0' 'x'"]
    result = await run.run(cmd, timeout=10)
    assert result["truncated"] is True
    assert len(result["stdout"]) <= run.MAX_OUTPUT_BYTES


def test_quote_argv_handles_spaces_and_specials():
    s = run.quote_argv(["echo", "hello world", "$INJECT"])
    assert "'hello world'" in s
    assert "'$INJECT'" in s


@pytest.mark.asyncio
async def test_empty_argv_rejected():
    with pytest.raises(ValueError):
        await run.run([])
