# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Aaron K. Clark
"""Report-export tests (issue #18)."""

from __future__ import annotations

import json
from pathlib import Path
from xml.etree import ElementTree as ET

import pytest


@pytest.fixture
def workspace(tmp_path, monkeypatch):
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.delenv("KALIMCP_ENGAGEMENT", raising=False)
    from kalimcp import engagement
    engagement.ROOT_DIR = Path.home() / ".kalimcp"
    engagement.ENGAGEMENTS_DIR = engagement.ROOT_DIR / "engagements"
    engagement.ACTIVE_STATE_FILE = engagement.ROOT_DIR / "active_engagement"
    return engagement


def _seed(ws):
    ws.create("op", scope=["10.0.0.0/24"], operator="alice")
    ws.use("op")
    ws.record_finding("sqli", "10.0.0.5", {"severity": "high", "evidence": "id=1' -> error"},
                      source_tool="sqlmap")
    ws.record_finding("host", "10.0.0.6", {"ports": [22, 80]}, source_tool="nmap")
    ws.record_cred("10.0.0.5", "ssh", "alice", "hunter2", source_tool="hydra")


def test_unknown_format_errors(workspace):
    from kalimcp import report
    res = report.generate("pdf")
    assert res["ok"] is False
    assert res["error"] == "unknown_format"


def test_markdown_report(workspace):
    from kalimcp import report
    _seed(workspace)
    res = report.generate("markdown")
    assert res["ok"] is True
    content = res["content"]
    assert "# Engagement report" in content
    assert "10.0.0.5" in content and "sqli" in content
    # Secret is masked, never printed.
    assert "hunter2" not in content
    assert "********" in content


def test_sarif_report_valid_and_dedups_rules(workspace):
    from kalimcp import report
    _seed(workspace)
    doc = json.loads(report.generate("sarif")["content"])
    assert doc["version"] == "2.1.0"
    run = doc["runs"][0]
    assert run["tool"]["driver"]["name"] == "KaliMCP"
    rule_ids = [r["id"] for r in run["tool"]["driver"]["rules"]]
    assert "sqli" in rule_ids and "host" in rule_ids
    assert len(rule_ids) == len(set(rule_ids))  # deduped
    # The high-severity sqli finding is an error-level result.
    sqli = next(r for r in run["results"] if r["ruleId"] == "sqli")
    assert sqli["level"] == "error"
    assert "hunter2" not in report.generate("sarif")["content"]


def test_sarif_attaches_web_evidence(workspace):
    from kalimcp import report
    workspace.create("op")
    workspace.use("op")
    workspace.record_finding(
        "xss", "site.example",
        {"request": "GET /?q=<script> HTTP/1.1", "response": "200 reflected"},
        source_tool="manual",
    )
    run = json.loads(report.generate("sarif")["content"])["runs"][0]
    result = run["results"][0]
    assert result["webRequest"]["body"]["text"].startswith("GET")
    assert "reflected" in result["webResponse"]["body"]["text"]


def test_junit_report_marks_failures(workspace):
    from kalimcp import report
    _seed(workspace)
    xml = report.generate("junit")["content"]
    root = ET.fromstring(xml)
    assert root.tag == "testsuites"
    # 2 findings, 1 error-level (sqli high) -> 1 failure.
    assert root.attrib["tests"] == "2"
    assert root.attrib["failures"] == "1"
    failures = root.findall(".//failure")
    assert len(failures) == 1


def test_empty_engagement_reports_cleanly(workspace):
    from kalimcp import report
    workspace.create("empty")
    workspace.use("empty")
    md = report.generate("markdown")["content"]
    assert "No findings recorded" in md
    junit = ET.fromstring(report.generate("junit")["content"])
    assert junit.attrib["tests"] == "0"
