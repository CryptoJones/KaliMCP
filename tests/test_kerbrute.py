# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Aaron K. Clark
"""Tests for the kerbrute wrappers (AD username enum + password spray).

Verify the argv each wrapper hands to ``run.run``, the best-effort
stdout parsers, the missing-file guard, and — critically — that the
active-tool decorator redacts the sprayed password out of the audit
log argv (it rides in as a trailing positional, redacted by value).
No real subprocess runs; ``run.run`` is patched.
"""

from __future__ import annotations

import json
from unittest.mock import AsyncMock, patch

import pytest

from kalimcp.tools import kerbrute


@pytest.fixture(autouse=True)
def _files_exist():
    """Wrappers route file args through ``run.validate_file``; the argv
    tests use synthetic paths, so make existence checks pass by default.
    The missing-file test patches it to ``False`` to override."""
    with patch("kalimcp.run.Path.is_file", return_value=True):
        yield


def _fake_result(stdout: str = "ok", argv: list[str] | None = None) -> dict:
    return {
        "exit_code": 0,
        "elapsed_s": 0.01,
        "stdout": stdout,
        "stderr": "",
        "truncated": False,
        "timed_out": False,
        "argv": argv if argv is not None else [],
    }


# ---------- userenum: argv ----------


@pytest.mark.asyncio
async def test_userenum_argv():
    with patch("kalimcp.tools.kerbrute.run.run", new=AsyncMock(return_value=_fake_result())) as m:
        result = await kerbrute.userenum(
            target="corp.local", dc_ip="10.0.0.1", user_list="/tmp/users.txt",
        )
    assert result["ok"] is True
    argv = m.call_args.args[0]
    assert argv == [
        "kerbrute", "userenum", "--dc", "10.0.0.1", "-d", "corp.local", "/tmp/users.txt",
    ]


@pytest.mark.asyncio
async def test_userenum_timeout_passed_through():
    with patch("kalimcp.tools.kerbrute.run.run", new=AsyncMock(return_value=_fake_result())) as m:
        await kerbrute.userenum(
            target="corp.local", dc_ip="10.0.0.1", user_list="/tmp/u.txt", timeout_seconds=42,
        )
    assert m.call_args.kwargs.get("timeout") == 42


@pytest.mark.asyncio
async def test_userenum_missing_file_returns_error_without_running():
    with patch("kalimcp.run.Path.is_file", return_value=False), \
         patch("kalimcp.tools.kerbrute.run.run", new=AsyncMock()) as m:
        result = await kerbrute.userenum(
            target="corp.local", dc_ip="10.0.0.1", user_list="/nope.txt",
        )
    m.assert_not_called()
    assert result["exit_code"] == -1
    assert "user_list not found" in result["stderr"]
    assert result["parsed"] == {"valid_users": []}


# ---------- userenum: parser ----------

_USERENUM_OUTPUT_SAMPLE = """
    __             __               __
   / /_____  _____/ /_  _______  __/ /____

2026/06/21 12:00:00 >  Using KDC(s):
2026/06/21 12:00:00 >  	10.0.0.1:88

2026/06/21 12:00:01 >  [+] VALID USERNAME:	 alice@corp.local
2026/06/21 12:00:01 >  [+] VALID USERNAME:	 bob@corp.local
2026/06/21 12:00:02 >  Done! Tested 100 usernames (2 valid) in 1.234 seconds
"""


@pytest.mark.asyncio
async def test_userenum_parses_valid_usernames():
    fake = _fake_result(stdout=_USERENUM_OUTPUT_SAMPLE)
    with patch("kalimcp.tools.kerbrute.run.run", new=AsyncMock(return_value=fake)):
        result = await kerbrute.userenum(
            target="corp.local", dc_ip="10.0.0.1", user_list="/u.txt",
        )
    assert result["parsed"]["valid_users"] == ["alice@corp.local", "bob@corp.local"]


@pytest.mark.asyncio
async def test_userenum_parsed_empty_when_stdout_blank():
    fake = _fake_result(stdout="")
    with patch("kalimcp.tools.kerbrute.run.run", new=AsyncMock(return_value=fake)):
        result = await kerbrute.userenum(
            target="corp.local", dc_ip="10.0.0.1", user_list="/u.txt",
        )
    assert result["parsed"] == {"valid_users": []}


# ---------- passwordspray: argv ----------


@pytest.mark.asyncio
async def test_passwordspray_argv():
    with patch("kalimcp.tools.kerbrute.run.run", new=AsyncMock(return_value=_fake_result())) as m:
        await kerbrute.passwordspray(
            target="corp.local", dc_ip="10.0.0.1",
            user_list="/tmp/users.txt", password="Spring2025!",
        )
    argv = m.call_args.args[0]
    assert argv == [
        "kerbrute", "passwordspray", "--dc", "10.0.0.1", "-d", "corp.local",
        "/tmp/users.txt", "Spring2025!",
    ]


@pytest.mark.asyncio
async def test_passwordspray_missing_file_returns_error_without_running():
    with patch("kalimcp.run.Path.is_file", return_value=False), \
         patch("kalimcp.tools.kerbrute.run.run", new=AsyncMock()) as m:
        result = await kerbrute.passwordspray(
            target="corp.local", dc_ip="10.0.0.1",
            user_list="/nope.txt", password="x",
        )
    m.assert_not_called()
    assert result["exit_code"] == -1
    assert result["parsed"] == {"valid_logins": []}


# ---------- passwordspray: parser ----------

_SPRAY_OUTPUT_SAMPLE = """
2026/06/21 12:00:00 >  Using KDC(s):
2026/06/21 12:00:00 >  	10.0.0.1:88

2026/06/21 12:00:01 >  [+] VALID LOGIN:	 alice@corp.local:Spring2025!
2026/06/21 12:00:02 >  Done! Tested 100 logins (1 successes) in 1.234 seconds
"""


@pytest.mark.asyncio
async def test_passwordspray_parses_valid_login():
    fake = _fake_result(stdout=_SPRAY_OUTPUT_SAMPLE)
    with patch("kalimcp.tools.kerbrute.run.run", new=AsyncMock(return_value=fake)):
        result = await kerbrute.passwordspray(
            target="corp.local", dc_ip="10.0.0.1",
            user_list="/u.txt", password="Spring2025!",
        )
    assert result["parsed"]["valid_logins"] == [
        {"user": "alice@corp.local", "password": "Spring2025!"},
    ]


@pytest.mark.asyncio
async def test_passwordspray_parsed_empty_when_stdout_blank():
    fake = _fake_result(stdout="")
    with patch("kalimcp.tools.kerbrute.run.run", new=AsyncMock(return_value=fake)):
        result = await kerbrute.passwordspray(
            target="corp.local", dc_ip="10.0.0.1",
            user_list="/u.txt", password="x",
        )
    assert result["parsed"] == {"valid_logins": []}


# ---------- CRITICAL: audit log redaction ----------


@pytest.mark.asyncio
async def test_passwordspray_audit_log_redacts_password(tmp_path, monkeypatch):
    """The sprayed password rides in as a trailing positional; the
    active-tool decorator must hash it out of the audit argv by value
    (``password`` is in _DEFAULT_SECRET_KWARGS)."""
    from kalimcp import audit, run

    log_path = tmp_path / "audit.log"
    monkeypatch.setenv("KALIMCP_LOG_FILE", str(log_path))
    audit.configure()

    async def fake_run(argv, **_kwargs):
        # run.run echoes back the real argv it would have launched.
        return {"exit_code": 0, "argv": list(argv), "stdout": "", "stderr": ""}

    monkeypatch.setattr(run, "run", fake_run)
    await kerbrute.passwordspray(
        target="corp.local", dc_ip="10.0.0.1",
        user_list="/u.txt", password="Spring2025!",
    )

    lines = log_path.read_text().strip().splitlines()
    invoke = [json.loads(line) for line in lines if json.loads(line).get("event") == "tool_invoke"]
    assert invoke, "no tool_invoke event written"
    logged = invoke[-1]
    argv = logged["argv"]
    assert "Spring2025!" not in " ".join(argv)
    assert any(tok.startswith("sha256:") for tok in argv)
    assert logged["secrets_redacted"] is True
