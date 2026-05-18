# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Aaron K. Clark
"""Tests for the active-tool decorator (refuse-list + audit-log path).

Exercises the decorator's branching without invoking real subprocesses
or hitting the network. The wrapped coroutine is a stub that records
its calls so we can assert when it was/wasn't reached.
"""

from __future__ import annotations

import os
from unittest.mock import patch

import pytest

from kalimcp.tools._active import active_tool


@active_tool("test-tool")
async def _stub(target: str, **kwargs):
    """Stub wrapped scan — returns a deterministic success payload."""
    return {"exit_code": 0, "stdout": f"scanned {target}", "stderr": ""}


@active_tool("test-tool-raises")
async def _stub_raises(target: str, **kwargs):
    raise RuntimeError("simulated tool failure")


@pytest.mark.asyncio
async def test_refused_target_short_circuits_before_running():
    """A .gov target is refused; the stub coroutine never runs."""
    # KALIMCP_ALLOW_REFUSED must be unset (or != "1") for this path.
    with patch.dict(os.environ, {}, clear=False):
        os.environ.pop("KALIMCP_ALLOW_REFUSED", None)
        result = await _stub(target="example.gov")
    assert result["ok"] is False
    assert result["error"] == "refused"
    assert "gov" in result["message"].lower()


@pytest.mark.asyncio
async def test_refused_target_allowed_by_env_override():
    """KALIMCP_ALLOW_REFUSED=1 lets the scan through."""
    with patch.dict(os.environ, {"KALIMCP_ALLOW_REFUSED": "1"}):
        result = await _stub(target="example.gov")
    assert result["ok"] is True
    assert result["stdout"] == "scanned example.gov"


@pytest.mark.asyncio
async def test_cloud_metadata_ip_refused():
    """169.254.169.254 is the cloud-metadata endpoint — refused."""
    os.environ.pop("KALIMCP_ALLOW_REFUSED", None)
    result = await _stub(target="169.254.169.254")
    assert result["ok"] is False
    assert result["error"] == "refused"
    assert "metadata" in result["message"].lower()


@pytest.mark.asyncio
async def test_financial_domain_refused():
    """Hard-coded financial-services hosts are refused."""
    os.environ.pop("KALIMCP_ALLOW_REFUSED", None)
    result = await _stub(target="chase.com")
    assert result["ok"] is False
    assert result["error"] == "refused"
    assert "financial" in result["message"].lower()


@pytest.mark.asyncio
async def test_allowed_target_runs_and_returns_success():
    """A non-refused target reaches the wrapped function."""
    result = await _stub(target="127.0.0.1")
    assert result["ok"] is True
    assert result["stdout"] == "scanned 127.0.0.1"
    assert result["exit_code"] == 0


@pytest.mark.asyncio
async def test_wrapped_exception_returned_as_structured_error():
    """If the wrapped tool raises, the decorator returns a structured error."""
    result = await _stub_raises(target="127.0.0.1")
    assert result["ok"] is False
    assert result["error"] == "tool_exception"
    assert "simulated tool failure" in result["message"]


@pytest.mark.asyncio
async def test_audit_log_includes_argv_on_invoke(tmp_path, monkeypatch):
    """tool_invoke events should carry the argv from the wrapped run() result."""
    from kalimcp import audit

    log_path = tmp_path / "audit.log"
    monkeypatch.setenv("KALIMCP_LOG_FILE", str(log_path))
    audit.configure()

    @active_tool("test-argv")
    async def stub(target: str, **kwargs):
        return {
            "exit_code": 0,
            "argv": ["fake-cli", "--flag", target],
            "stdout": "",
        }

    result = await stub(target="127.0.0.1")
    assert result["ok"] is True

    # Read the appended audit log line back.
    import json
    lines = log_path.read_text().strip().splitlines()
    invoke = [json.loads(line) for line in lines if json.loads(line).get("event") == "tool_invoke"]
    assert invoke, "no tool_invoke event written"
    assert invoke[-1]["argv"] == ["fake-cli", "--flag", "127.0.0.1"]
