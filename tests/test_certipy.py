# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Aaron K. Clark
"""Tests for the Certipy (AD CS, ESC1-16) wrappers.

Verify the argv each wrapper hands to ``run.run`` (password path AND
nthash path), the best-effort stdout parsers, and — critically — that
the active-tool decorator redacts the password / NT hash out of the
audit log argv. No real subprocess runs; ``run.run`` is patched.
"""

from __future__ import annotations

import json
from unittest.mock import AsyncMock, patch

import pytest

from kalimcp.tools import certipy


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


# ---------- find: argv shapes ----------


@pytest.mark.asyncio
async def test_find_password_argv():
    with patch("kalimcp.tools.certipy.run.run", new=AsyncMock(return_value=_fake_result())) as m:
        result = await certipy.find(
            target="corp.local", username="alice", password="hunter2", dc_ip="10.0.0.1",
        )
    assert result["ok"] is True
    argv = m.call_args.args[0]
    assert argv == [
        "certipy", "find",
        "-u", "alice@corp.local",
        "-stdout", "-vulnerable",
        "-p", "hunter2",
        "-dc-ip", "10.0.0.1",
    ]


@pytest.mark.asyncio
async def test_find_nthash_argv():
    with patch("kalimcp.tools.certipy.run.run", new=AsyncMock(return_value=_fake_result())) as m:
        await certipy.find(
            target="corp.local", username="alice",
            nthash="aad3b435b51404eeaad3b435b51404ee",
        )
    argv = m.call_args.args[0]
    # NT-hash path: -hashes :<nt>, no -p, no -dc-ip (dc_ip empty).
    assert "-p" not in argv
    assert "-hashes" in argv
    assert argv[argv.index("-hashes") + 1] == ":aad3b435b51404eeaad3b435b51404ee"
    assert "-dc-ip" not in argv


@pytest.mark.asyncio
async def test_find_timeout_passed_through():
    with patch("kalimcp.tools.certipy.run.run", new=AsyncMock(return_value=_fake_result())) as m:
        await certipy.find(target="corp.local", username="alice", password="x", timeout_seconds=42)
    assert m.call_args.kwargs.get("timeout") == 42


# ---------- find: parser ----------

_FIND_OUTPUT_SAMPLE = """Certipy v4.8.2 - by Oliver Lyak (ly4k)

[*] Finding certificate templates
[*] Found 33 certificate templates
[*] Finding certificate authorities
Certificate Authorities
  0
    CA Name                             : CORP-CA
    DNS Name                            : ca.corp.local
Certificate Templates
  0
    Template Name                       : VulnTemplate
    [!] Vulnerabilities
      ESC1                              : Enrollee supplies subject and client auth EKU
"""


@pytest.mark.asyncio
async def test_find_parses_esc1_vulnerable_template():
    fake = _fake_result(stdout=_FIND_OUTPUT_SAMPLE)
    with patch("kalimcp.tools.certipy.run.run", new=AsyncMock(return_value=fake)):
        result = await certipy.find(target="corp.local", username="alice", password="x")
    parsed = result["parsed"]
    assert "ESC1" in parsed["esc_findings"]
    assert "VulnTemplate" in parsed["vulnerable_templates"]
    assert "CORP-CA" in parsed["cas"]


@pytest.mark.asyncio
async def test_find_parsed_empty_when_stdout_blank():
    fake = _fake_result(stdout="")
    with patch("kalimcp.tools.certipy.run.run", new=AsyncMock(return_value=fake)):
        result = await certipy.find(target="corp.local", username="alice", password="x")
    assert result["parsed"] == {
        "vulnerable_templates": [],
        "cas": [],
        "esc_findings": [],
    }


# ---------- request: argv shapes ----------


@pytest.mark.asyncio
async def test_request_password_argv():
    with patch("kalimcp.tools.certipy.run.run", new=AsyncMock(return_value=_fake_result())) as m:
        await certipy.request(
            target="corp.local", username="alice", password="hunter2",
            ca="CORP-CA", template="VulnTemplate", upn="administrator@corp.local",
            dc_ip="10.0.0.1",
        )
    argv = m.call_args.args[0]
    assert argv == [
        "certipy", "req",
        "-u", "alice@corp.local",
        "-ca", "CORP-CA",
        "-template", "VulnTemplate",
        "-upn", "administrator@corp.local",
        "-p", "hunter2",
        "-dc-ip", "10.0.0.1",
    ]


@pytest.mark.asyncio
async def test_request_nthash_argv_omits_upn_when_unset():
    with patch("kalimcp.tools.certipy.run.run", new=AsyncMock(return_value=_fake_result())) as m:
        await certipy.request(
            target="corp.local", username="alice",
            nthash="aad3b435b51404eeaad3b435b51404ee",
            ca="CORP-CA", template="VulnTemplate",
        )
    argv = m.call_args.args[0]
    assert "-upn" not in argv
    assert "-p" not in argv
    assert argv[argv.index("-hashes") + 1] == ":aad3b435b51404eeaad3b435b51404ee"


# ---------- request: parser ----------

_REQ_OUTPUT_SAMPLE = """Certipy v4.8.2 - by Oliver Lyak (ly4k)

[*] Requesting certificate via RPC
[*] Successfully requested certificate
[*] Got certificate with UPN 'administrator@corp.local'
[*] Saved certificate and private key to 'administrator.pfx'
"""


@pytest.mark.asyncio
async def test_request_parses_pfx_path():
    fake = _fake_result(stdout=_REQ_OUTPUT_SAMPLE)
    with patch("kalimcp.tools.certipy.run.run", new=AsyncMock(return_value=fake)):
        result = await certipy.request(
            target="corp.local", username="alice", password="x",
            ca="CORP-CA", template="VulnTemplate",
        )
    assert result["parsed"] == {"pfx_path": "administrator.pfx", "ok": True}


@pytest.mark.asyncio
async def test_request_parsed_not_ok_when_no_pfx():
    fake = _fake_result(stdout="[-] Got error: access denied")
    with patch("kalimcp.tools.certipy.run.run", new=AsyncMock(return_value=fake)):
        result = await certipy.request(
            target="corp.local", username="alice", password="x",
            ca="CORP-CA", template="VulnTemplate",
        )
    assert result["parsed"] == {"pfx_path": "", "ok": False}


# ---------- CRITICAL: audit log redaction ----------


@pytest.mark.asyncio
async def test_find_audit_log_redacts_password(tmp_path, monkeypatch):
    """The `-p <password>` value must be sha256:<hex> in the audit argv,
    never the cleartext literal (active_tool secret_flags path)."""
    from kalimcp import audit, run

    log_path = tmp_path / "audit.log"
    monkeypatch.setenv("KALIMCP_LOG_FILE", str(log_path))
    audit.configure()

    async def fake_run(argv, **_kwargs):
        # run.run echoes back the real argv it would have launched.
        return {"exit_code": 0, "argv": list(argv), "stdout": "", "stderr": ""}

    monkeypatch.setattr(run, "run", fake_run)
    await certipy.find(target="corp.local", username="alice", password="hunter2")

    lines = log_path.read_text().strip().splitlines()
    invoke = [json.loads(line) for line in lines if json.loads(line).get("event") == "tool_invoke"]
    assert invoke, "no tool_invoke event written"
    logged = invoke[-1]
    argv = logged["argv"]
    # The flag stays visible; the secret is hashed out.
    assert "-p" in argv
    assert "hunter2" not in argv
    assert any(tok.startswith("sha256:") for tok in argv)
    assert logged["secrets_redacted"] is True


@pytest.mark.asyncio
async def test_request_audit_log_redacts_nthash(tmp_path, monkeypatch):
    """The NT hash passed via `-hashes :<nt>` must not land in the audit argv."""
    from kalimcp import audit, run

    log_path = tmp_path / "audit.log"
    monkeypatch.setenv("KALIMCP_LOG_FILE", str(log_path))
    audit.configure()

    async def fake_run(argv, **_kwargs):
        return {"exit_code": 0, "argv": list(argv), "stdout": "", "stderr": ""}

    monkeypatch.setattr(run, "run", fake_run)
    await certipy.request(
        target="corp.local", username="alice",
        nthash="aad3b435b51404eeaad3b435b51404ee",
        ca="CORP-CA", template="VulnTemplate",
    )

    lines = log_path.read_text().strip().splitlines()
    invoke = [json.loads(line) for line in lines if json.loads(line).get("event") == "tool_invoke"]
    assert invoke, "no tool_invoke event written"
    logged = invoke[-1]
    argv = logged["argv"]
    assert "-hashes" in argv
    assert "aad3b435b51404eeaad3b435b51404ee" not in " ".join(argv)
    assert logged["secrets_redacted"] is True
