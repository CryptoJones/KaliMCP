# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Aaron K. Clark
"""Subprocess runner tests."""

from __future__ import annotations

import pytest

from kalimcp import run


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
