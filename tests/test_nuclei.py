# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Aaron K. Clark
"""Tests for the nuclei wrapper.

Verifies the argv handed to ``run.run`` and the JSONL parser. No real
subprocess runs — ``run.run`` is patched.
"""

from __future__ import annotations

from unittest.mock import AsyncMock, patch

import pytest

from kalimcp.tools import nuclei


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


# ---------- argv shape ----------


@pytest.mark.asyncio
async def test_nuclei_basic_argv():
    with patch("kalimcp.tools.nuclei.run.run", new=AsyncMock(return_value=_fake_result())) as m:
        await nuclei.scan(target="https://example.com/")
    argv = m.call_args.args[0]
    assert argv == [
        "nuclei", "-u", "https://example.com/",
        "-jsonl", "-silent", "-rl", "150",
    ]


@pytest.mark.asyncio
async def test_nuclei_severity_and_tags_appended():
    with patch("kalimcp.tools.nuclei.run.run", new=AsyncMock(return_value=_fake_result())) as m:
        await nuclei.scan(
            target="https://example.com/",
            severity="critical,high",
            tags="cve,rce",
            rate_limit=50,
        )
    argv = m.call_args.args[0]
    assert "-severity" in argv and argv[argv.index("-severity") + 1] == "critical,high"
    assert "-tags" in argv and argv[argv.index("-tags") + 1] == "cve,rce"
    assert argv[argv.index("-rl") + 1] == "50"


@pytest.mark.asyncio
async def test_nuclei_custom_templates_validated_and_appended():
    with patch("kalimcp.run.Path.is_file", return_value=True), \
         patch("kalimcp.tools.nuclei.run.run", new=AsyncMock(return_value=_fake_result())) as m:
        await nuclei.scan(target="https://example.com/", templates="/tmp/custom.yaml")
    argv = m.call_args.args[0]
    assert "-t" in argv and argv[argv.index("-t") + 1] == "/tmp/custom.yaml"


@pytest.mark.asyncio
async def test_nuclei_missing_templates_returns_error_without_running():
    with patch("kalimcp.run.Path.is_file", return_value=False), \
         patch("kalimcp.tools.nuclei.run.run", new=AsyncMock()) as m:
        result = await nuclei.scan(target="https://example.com/", templates="/nope")
    m.assert_not_called()
    assert result["exit_code"] == -1
    assert "templates not found" in result["stderr"]
    assert result["parsed"] == {"findings": [], "count": 0}


@pytest.mark.asyncio
async def test_nuclei_dash_target_rejected_without_running():
    with patch("kalimcp.tools.nuclei.run.run", new=AsyncMock()) as m:
        result = await nuclei.scan(target="-config evil.yaml")
    m.assert_not_called()
    assert result["exit_code"] == -1
    assert "target" in result["stderr"]


@pytest.mark.asyncio
async def test_nuclei_timeout_passed_through():
    with patch("kalimcp.tools.nuclei.run.run", new=AsyncMock(return_value=_fake_result())) as m:
        await nuclei.scan(target="https://example.com/", timeout_seconds=42)
    assert m.call_args.kwargs.get("timeout") == 42


# ---------- JSONL parser ----------

_NUCLEI_JSONL_SAMPLE = (
    '{"template-id":"tech-detect","info":{"name":"Technology Detection","severity":"info"},'
    '"type":"http","host":"https://example.com","matched-at":"https://example.com"}\n'
    '{"template-id":"CVE-2021-44228","info":{"name":"Apache Log4j RCE","severity":"critical"},'
    '"type":"http","host":"https://example.com","matched-at":"https://example.com/api"}\n'
)


@pytest.mark.asyncio
async def test_nuclei_parsed_field_populated_on_success():
    fake = _fake_result(stdout=_NUCLEI_JSONL_SAMPLE)
    with patch("kalimcp.tools.nuclei.run.run", new=AsyncMock(return_value=fake)):
        result = await nuclei.scan(target="https://example.com/")
    parsed = result["parsed"]
    assert parsed["count"] == 2
    by_id = {f["template_id"]: f for f in parsed["findings"]}
    log4j = by_id["CVE-2021-44228"]
    assert log4j["name"] == "Apache Log4j RCE"
    assert log4j["severity"] == "critical"
    assert log4j["host"] == "https://example.com"
    assert log4j["matched_at"] == "https://example.com/api"
    assert log4j["type"] == "http"
    assert by_id["tech-detect"]["severity"] == "info"


@pytest.mark.asyncio
async def test_nuclei_parsed_field_empty_when_stdout_blank():
    fake = _fake_result(stdout="")
    with patch("kalimcp.tools.nuclei.run.run", new=AsyncMock(return_value=fake)):
        result = await nuclei.scan(target="https://example.com/")
    assert result["parsed"] == {"findings": [], "count": 0}
