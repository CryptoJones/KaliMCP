# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Aaron K. Clark
"""Tests for the OWASP ZAP wrapper.

The argv-contract test patches ``run.run`` (no subprocess spawns).
``_parse_report`` is driven directly against a temp report file —
the only on-disk I/O here is the pytest ``tmp_path`` fixture.
"""

from __future__ import annotations

import json
from unittest.mock import AsyncMock, patch

import pytest

from kalimcp.tools import zap


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


# ---------- argv contract ----------


@pytest.mark.asyncio
async def test_zap_default_argv():
    with patch("kalimcp.tools.zap.run.run", new=AsyncMock(return_value=_fake_result())) as m:
        await zap.baseline_scan(target="https://example.com/")
    argv = m.call_args.args[0]
    assert argv == [
        "zaproxy",
        "-cmd",
        "-quickurl",
        "https://example.com/",
        "-quickout",
        "/tmp/kalimcp_zap_report.json",
        "-quickprogress",
    ]


@pytest.mark.asyncio
async def test_zap_custom_report_path_in_argv():
    with patch("kalimcp.tools.zap.run.run", new=AsyncMock(return_value=_fake_result())) as m:
        await zap.baseline_scan(target="https://example.com/", report_path="/tmp/r.json")
    argv = m.call_args.args[0]
    assert "-quickurl" in argv and argv[argv.index("-quickurl") + 1] == "https://example.com/"
    assert "-quickout" in argv and argv[argv.index("-quickout") + 1] == "/tmp/r.json"


@pytest.mark.asyncio
async def test_zap_timeout_passed_through():
    with patch("kalimcp.tools.zap.run.run", new=AsyncMock(return_value=_fake_result())) as m:
        await zap.baseline_scan(target="https://example.com/", timeout_seconds=42)
    assert m.call_args.kwargs.get("timeout") == 42


@pytest.mark.asyncio
async def test_zap_dash_target_rejected_without_running():
    with patch("kalimcp.tools.zap.run.run", new=AsyncMock()) as m:
        result = await zap.baseline_scan(target="-config/api.key=x")
    m.assert_not_called()
    assert result["exit_code"] == -1
    assert "target" in result["stderr"]
    assert result["parsed"]["alerts"] == []


# ---------- _parse_report ----------

_ZAP_REPORT_SAMPLE = {
    "site": [
        {
            "@name": "https://example.com",
            "alerts": [
                {
                    "name": "Missing Anti-clickjacking Header",
                    "riskdesc": "Medium (Medium)",
                    "confidence": "Medium",
                    "instances": [{"uri": "https://example.com/login"}],
                },
                {
                    "alert": "X-Content-Type-Options Header Missing",
                    "risk": "Low",
                    "confidence": "High",
                    "instances": [],
                },
            ],
        }
    ]
}


def test_parse_report_parses_alerts(tmp_path):
    report = tmp_path / "zap.json"
    report.write_text(json.dumps(_ZAP_REPORT_SAMPLE))
    parsed = zap._parse_report(str(report))
    assert parsed["report_path"] == str(report)
    assert parsed["alert_count"] == 2
    by_name = {a["name"]: a for a in parsed["alerts"]}
    clickjack = by_name["Missing Anti-clickjacking Header"]
    assert clickjack["risk"] == "Medium (Medium)"
    assert clickjack["confidence"] == "Medium"
    assert clickjack["url"] == "https://example.com/login"
    # alert with no instances falls back to the site @name; "alert"/"risk" keys.
    xcto = by_name["X-Content-Type-Options Header Missing"]
    assert xcto["risk"] == "Low"
    assert xcto["url"] == "https://example.com"


def test_parse_report_missing_file_yields_empty_skeleton(tmp_path):
    missing = tmp_path / "nope.json"
    parsed = zap._parse_report(str(missing))
    assert parsed == {"alerts": [], "alert_count": 0, "report_path": str(missing)}


def test_parse_report_unparseable_file_yields_empty_skeleton(tmp_path):
    bad = tmp_path / "bad.json"
    bad.write_text("not actually json")
    parsed = zap._parse_report(str(bad))
    assert parsed == {"alerts": [], "alert_count": 0, "report_path": str(bad)}
