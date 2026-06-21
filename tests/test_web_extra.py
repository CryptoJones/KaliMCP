# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Aaron K. Clark
"""Tests for the extra web wrappers: wpscan and gowitness.

argv-contract + parse + redaction checks. ``run.run`` is patched in
every test, so no real subprocess spawns and no network is hit. The
gowitness wrapper does a best-effort ``mkdir`` of its output dir; the
tests point it at a tmp dir so the only filesystem side effect is
contained.
"""

from __future__ import annotations

import json
from unittest.mock import AsyncMock, patch

import pytest

from kalimcp.tools import gowitness, wpscan


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


# ---------- wpscan ----------


@pytest.mark.asyncio
async def test_wpscan_argv_without_token():
    with patch(
        "kalimcp.tools.wpscan.run.run", new=AsyncMock(return_value=_fake_result("{}"))
    ) as m:
        result = await wpscan.scan(target="https://blog.example.com/")
    assert result["ok"] is True
    argv = m.call_args.args[0]
    assert argv == [
        "wpscan",
        "--url",
        "https://blog.example.com/",
        "--format",
        "json",
        "--no-banner",
        "--enumerate",
        "vp,u",
    ]
    assert "--api-token" not in argv


@pytest.mark.asyncio
async def test_wpscan_argv_with_token_and_enumerate():
    with patch(
        "kalimcp.tools.wpscan.run.run", new=AsyncMock(return_value=_fake_result("{}"))
    ) as m:
        await wpscan.scan(
            target="https://blog.example.com/",
            enumerate="ap,t,u",
            api_token="TOKENSECRET123",
        )
    argv = m.call_args.args[0]
    assert argv[:8] == [
        "wpscan",
        "--url",
        "https://blog.example.com/",
        "--format",
        "json",
        "--no-banner",
        "--enumerate",
        "ap,t,u",
    ]
    assert argv[-2:] == ["--api-token", "TOKENSECRET123"]


@pytest.mark.asyncio
async def test_wpscan_redacts_api_token_in_audit_log(tmp_path, monkeypatch):
    """The WPScan API token is a secret; it must not land in the audit argv."""
    from kalimcp import audit, run

    log_path = tmp_path / "audit.log"
    monkeypatch.setenv("KALIMCP_LOG_FILE", str(log_path))
    audit.configure()

    async def fake_run(argv, **_kwargs):
        return {"exit_code": 0, "argv": list(argv), "stdout": "{}", "stderr": ""}

    monkeypatch.setattr(run, "run", fake_run)
    await wpscan.scan(
        target="https://blog.example.com/", api_token="SUPERSECRETTOKEN"
    )

    lines = log_path.read_text().strip().splitlines()
    invoke = [
        json.loads(line)
        for line in lines
        if json.loads(line).get("event") == "tool_invoke"
    ]
    assert invoke, "no tool_invoke event written"
    argv = invoke[-1]["argv"]
    assert "SUPERSECRETTOKEN" not in argv
    assert invoke[-1]["secrets_redacted"] is True
    redacted = [t for t in argv if t.startswith("sha256:")]
    assert len(redacted) == 1
    assert len(redacted[0]) == len("sha256:") + 8


@pytest.mark.asyncio
async def test_wpscan_parses_json():
    sample = json.dumps(
        {
            "version": {
                "number": "6.4.2",
                "vulnerabilities": [
                    {"title": "Core RCE", "fixed_in": "6.4.3"},
                ],
            },
            "plugins": {
                "contact-form-7": {
                    "vulnerabilities": [
                        {"title": "CF7 XSS", "fixed_in": "5.8.1"},
                    ],
                },
            },
            "users": {"admin": {}, "editor": {}},
            "interesting_findings": [
                {"url": "https://blog.example.com/readme.html", "type": "readme"},
            ],
        }
    )
    with patch(
        "kalimcp.tools.wpscan.run.run", new=AsyncMock(return_value=_fake_result(sample))
    ):
        result = await wpscan.scan(target="https://blog.example.com/")
    parsed = result["parsed"]
    assert parsed["version"] == "6.4.2"
    titles = {v["title"] for v in parsed["vulnerabilities"]}
    assert titles == {"Core RCE", "CF7 XSS"}
    assert set(parsed["users"]) == {"admin", "editor"}
    assert parsed["interesting_findings"][0]["type"] == "readme"


@pytest.mark.asyncio
async def test_wpscan_empty_parsed_on_no_output():
    with patch(
        "kalimcp.tools.wpscan.run.run", new=AsyncMock(return_value=_fake_result(""))
    ):
        result = await wpscan.scan(target="https://blog.example.com/")
    assert result["parsed"] == {
        "version": None,
        "vulnerabilities": [],
        "users": [],
        "interesting_findings": [],
    }


# ---------- gowitness ----------


@pytest.mark.asyncio
async def test_gowitness_default_output_dir(tmp_path, monkeypatch):
    # Redirect ~ so the default ~/.kalimcp/screenshots lands in a tmp dir.
    monkeypatch.setattr(gowitness.Path, "home", lambda: tmp_path)
    with patch(
        "kalimcp.tools.gowitness.run.run",
        new=AsyncMock(return_value=_fake_result("")),
    ) as m:
        result = await gowitness.capture(target="https://example.com/")
    assert result["ok"] is True
    argv = m.call_args.args[0]
    expected_dir = str(tmp_path / ".kalimcp" / "screenshots")
    assert argv == [
        "gowitness",
        "scan",
        "single",
        "--url",
        "https://example.com/",
        "--screenshot-path",
        expected_dir,
    ]
    assert result["parsed"]["output_dir"] == expected_dir
    assert (tmp_path / ".kalimcp" / "screenshots").is_dir()


@pytest.mark.asyncio
async def test_gowitness_custom_output_dir(tmp_path):
    out = tmp_path / "shots"
    with patch(
        "kalimcp.tools.gowitness.run.run",
        new=AsyncMock(return_value=_fake_result("")),
    ) as m:
        result = await gowitness.capture(
            target="https://example.com/", output_dir=str(out)
        )
    argv = m.call_args.args[0]
    assert argv == [
        "gowitness",
        "scan",
        "single",
        "--url",
        "https://example.com/",
        "--screenshot-path",
        str(out),
    ]
    assert result["parsed"]["output_dir"] == str(out)


@pytest.mark.asyncio
async def test_gowitness_lists_screenshot_files(tmp_path):
    out = tmp_path / "shots"
    out.mkdir()
    shot = out / "https-example-com.png"
    shot.write_bytes(b"\x89PNG")
    with patch(
        "kalimcp.tools.gowitness.run.run",
        new=AsyncMock(return_value=_fake_result("")),
    ):
        result = await gowitness.capture(
            target="https://example.com/", output_dir=str(out)
        )
    assert result["parsed"]["screenshots"] == [str(shot)]


@pytest.mark.asyncio
async def test_gowitness_rejects_leading_dash_output_dir():
    with patch(
        "kalimcp.tools.gowitness.run.run",
        new=AsyncMock(return_value=_fake_result("")),
    ) as m:
        result = await gowitness.capture(
            target="https://example.com/", output_dir="-/tmp/evil"
        )
    # Rejected before the subprocess launches.
    m.assert_not_called()
    assert result["ok"] is True  # decorator wraps the error_result
    assert result["parsed"]["screenshots"] == []
