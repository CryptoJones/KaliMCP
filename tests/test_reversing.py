# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Aaron K. Clark
"""Tests for the reverse-engineering loot-triage wrappers (gdb, radare2).

These verify the argv each wrapper hands to ``run.run`` — given these
args, the right CLI invocation comes out. No real subprocess runs;
``run.run`` is patched, and the file-existence check is patched the same
way ``test_tools.py`` does it.
"""

from __future__ import annotations

from unittest.mock import AsyncMock, patch

import pytest

from kalimcp.tools import reversing


@pytest.fixture(autouse=True)
def _files_exist():
    """Wrappers route the file-path arg through ``run.validate_file``;
    these synthetic paths don't exist on disk, so make the existence check
    pass by default. The "missing file" test patches it to ``False``."""
    with patch("kalimcp.run.Path.is_file", return_value=True):
        yield


def _fake_result(stdout: str = "ok") -> dict:
    return {
        "exit_code": 0,
        "elapsed_s": 0.01,
        "stdout": stdout,
        "stderr": "",
        "truncated": False,
        "timed_out": False,
        "argv": [],
    }


# ---------- gdb_inspect ----------


@pytest.mark.asyncio
async def test_gdb_default_argv():
    with patch("kalimcp.tools.reversing.run.run", new=AsyncMock(return_value=_fake_result())) as m:
        await reversing.gdb_inspect(path="/loot/bin")
    assert m.call_args.args[0] == [
        "gdb", "-batch", "-nx", "-ex", "info functions", "--", "/loot/bin",
    ]


@pytest.mark.asyncio
async def test_gdb_custom_command_is_one_argv_item():
    with patch("kalimcp.tools.reversing.run.run", new=AsyncMock(return_value=_fake_result())) as m:
        await reversing.gdb_inspect(path="/loot/bin", command="disassemble main")
    argv = m.call_args.args[0]
    # The whole operator command is a single -ex argument (no shell split).
    assert argv == ["gdb", "-batch", "-nx", "-ex", "disassemble main", "--", "/loot/bin"]


@pytest.mark.asyncio
async def test_gdb_timeout_passed_through():
    with patch("kalimcp.tools.reversing.run.run", new=AsyncMock(return_value=_fake_result())) as m:
        await reversing.gdb_inspect(path="/loot/bin", timeout_seconds=42)
    assert m.call_args.kwargs.get("timeout") == 42


@pytest.mark.asyncio
async def test_gdb_missing_file_errors_without_running():
    with patch("kalimcp.run.Path.is_file", return_value=False), \
            patch("kalimcp.tools.reversing.run.run", new=AsyncMock()) as m:
        result = await reversing.gdb_inspect(path="/nope")
    m.assert_not_called()
    assert result["exit_code"] == -1
    assert "not found" in result["stderr"]


# ---------- r2_analyze ----------


@pytest.mark.asyncio
async def test_r2_default_argv():
    with patch("kalimcp.tools.reversing.run.run", new=AsyncMock(return_value=_fake_result())) as m:
        await reversing.r2_analyze(path="/loot/bin")
    # radare2 has no `--` separator (it means "open no file"); the path is
    # the final positional.
    assert m.call_args.args[0] == [
        "r2", "-q", "-e", "scr.color=0", "-c", "aaa;afl", "/loot/bin",
    ]


@pytest.mark.asyncio
async def test_r2_custom_commands_is_one_argv_item():
    with patch("kalimcp.tools.reversing.run.run", new=AsyncMock(return_value=_fake_result())) as m:
        await reversing.r2_analyze(path="/loot/bin", commands="aa;pdf @ main")
    argv = m.call_args.args[0]
    # The whole command string is a single -c argument.
    assert argv == ["r2", "-q", "-e", "scr.color=0", "-c", "aa;pdf @ main", "/loot/bin"]


@pytest.mark.asyncio
async def test_r2_relative_path_gets_dot_slash_guard():
    """A relative path is normalized to ./<path> so r2 can't read a
    leading-dash filename as a flag (r2 has no `--` separator)."""
    with patch("kalimcp.tools.reversing.run.run", new=AsyncMock(return_value=_fake_result())) as m:
        await reversing.r2_analyze(path="weird-name")
    assert m.call_args.args[0][-1] == "./weird-name"


@pytest.mark.asyncio
async def test_r2_timeout_passed_through():
    with patch("kalimcp.tools.reversing.run.run", new=AsyncMock(return_value=_fake_result())) as m:
        await reversing.r2_analyze(path="/loot/bin", timeout_seconds=77)
    assert m.call_args.kwargs.get("timeout") == 77


@pytest.mark.asyncio
async def test_r2_missing_file_errors_without_running():
    with patch("kalimcp.run.Path.is_file", return_value=False), \
            patch("kalimcp.tools.reversing.run.run", new=AsyncMock()) as m:
        result = await reversing.r2_analyze(path="/nope")
    m.assert_not_called()
    assert result["exit_code"] == -1
    assert "not found" in result["stderr"]
