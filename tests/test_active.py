# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Aaron K. Clark
"""Tests for the active-tool decorator (audit-log + scope-warning path).

Exercises the decorator's branching without invoking real subprocesses
or hitting the network. The wrapped coroutine is a stub that records
its calls so we can assert when it was/wasn't reached.
"""

from __future__ import annotations

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
async def test_target_runs_and_returns_success():
    """A target reaches the wrapped function and gets a success envelope."""
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
    # No secret_flags declared → secrets_redacted is False.
    assert invoke[-1]["secrets_redacted"] is False


@pytest.mark.asyncio
async def test_audit_log_redacts_secret_flag_values(tmp_path, monkeypatch):
    """Values following secret-bearing flags should be sha256:<hex> in the audit log."""
    from kalimcp import audit

    log_path = tmp_path / "audit.log"
    monkeypatch.setenv("KALIMCP_LOG_FILE", str(log_path))
    audit.configure()

    @active_tool("test-redact", secret_flags={"-p", "--password"})
    async def stub(target: str, **kwargs):
        return {
            "exit_code": 0,
            "argv": [
                "fake-cli", "-u", "alice", "-p", "hunter2",
                "--password", "s3cret!", "--target", target,
            ],
            "stdout": "",
        }

    await stub(target="192.168.1.10")

    import json
    lines = log_path.read_text().strip().splitlines()
    invoke = [json.loads(line) for line in lines if json.loads(line).get("event") == "tool_invoke"]
    assert invoke, "no tool_invoke event written"
    argv = invoke[-1]["argv"]
    # Username is not a secret — left in plain.
    assert "alice" in argv
    # Both password literals are replaced.
    assert "hunter2" not in argv
    assert "s3cret!" not in argv
    # Replacement format: sha256:<8hex>.
    redacted = [t for t in argv if t.startswith("sha256:")]
    assert len(redacted) == 2
    for r in redacted:
        assert len(r) == len("sha256:") + 8
    assert invoke[-1]["secrets_redacted"] is True


@pytest.mark.asyncio
async def test_audit_log_redacts_password_fused_in_positional(tmp_path, monkeypatch):
    """A password embedded in a positional (impacket `user:pass@host`)
    is redacted by value even though no secret flag points at it."""
    from kalimcp import audit

    log_path = tmp_path / "audit.log"
    monkeypatch.setenv("KALIMCP_LOG_FILE", str(log_path))
    audit.configure()

    @active_tool("test-impacket", secret_flags={"-password", "-hashes"})
    async def stub(target: str, *, username: str, password: str = "", **kwargs):
        return {
            "exit_code": 0,
            "argv": ["impacket-secretsdump", f"{username}:{password}@{target}"],
            "stdout": "",
        }

    await stub(target="dc.corp.local", username="admin", password="hunter2")

    import json
    lines = log_path.read_text().strip().splitlines()
    invoke = [json.loads(line) for line in lines if json.loads(line).get("event") == "tool_invoke"]
    argv = invoke[-1]["argv"]
    assert "hunter2" not in " ".join(argv)
    assert "hunter2@dc.corp.local" not in " ".join(argv)
    assert invoke[-1]["secrets_redacted"] is True


@pytest.mark.asyncio
async def test_audit_log_redacts_fused_flag_equals_value(tmp_path, monkeypatch):
    """`--wordlist=path` (john's shape) is redacted via the secret flag."""
    from kalimcp import audit

    log_path = tmp_path / "audit.log"
    monkeypatch.setenv("KALIMCP_LOG_FILE", str(log_path))
    audit.configure()

    @active_tool("test-john", secret_flags={"--wordlist", "-w"})
    async def stub(target: str, **kwargs):
        return {
            "exit_code": 0,
            "argv": ["john", "--wordlist=/loot/creds.txt", target],
            "stdout": "",
        }

    await stub(target="/loot/hashes.txt")
    import json
    lines = log_path.read_text().strip().splitlines()
    invoke = [json.loads(line) for line in lines if json.loads(line).get("event") == "tool_invoke"]
    argv = invoke[-1]["argv"]
    assert "/loot/creds.txt" not in " ".join(argv)
    assert any(t.startswith("--wordlist=sha256:") for t in argv)
    assert invoke[-1]["secrets_redacted"] is True


@pytest.mark.asyncio
async def test_audit_log_no_redaction_when_no_secret_flag_present(tmp_path, monkeypatch):
    """If a wrapper sets secret_flags but the argv has none, secrets_redacted=False."""
    from kalimcp import audit

    log_path = tmp_path / "audit.log"
    monkeypatch.setenv("KALIMCP_LOG_FILE", str(log_path))
    audit.configure()

    @active_tool("test-no-redact", secret_flags={"--password"})
    async def stub(target: str, **kwargs):
        return {
            "exit_code": 0,
            "argv": ["fake-cli", "-u", "alice", "--host", target],
            "stdout": "",
        }

    await stub(target="192.168.1.10")
    import json
    lines = log_path.read_text().strip().splitlines()
    invoke = [json.loads(line) for line in lines if json.loads(line).get("event") == "tool_invoke"]
    assert invoke[-1]["secrets_redacted"] is False


# ---------- engagement workspace integration ----------


@pytest.fixture
def engagement_workspace(tmp_path, monkeypatch):
    """Point HOME at tmp_path so workspace state lands there."""
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.delenv("KALIMCP_ENGAGEMENT", raising=False)
    from pathlib import Path

    from kalimcp import engagement
    engagement.ROOT_DIR = Path.home() / ".kalimcp"
    engagement.ENGAGEMENTS_DIR = engagement.ROOT_DIR / "engagements"
    engagement.ACTIVE_STATE_FILE = engagement.ROOT_DIR / "active_engagement"
    return engagement


@pytest.mark.asyncio
async def test_autorecord_off_by_default(engagement_workspace, monkeypatch):
    """No KALIMCP_AUTORECORD=1 → tool calls do NOT mirror into the workspace."""
    monkeypatch.delenv("KALIMCP_AUTORECORD", raising=False)
    engagement_workspace.create("op_default", scope=[])
    engagement_workspace.use("op_default")

    @active_tool("test-recorder")
    async def stub(target: str, **kwargs):
        return {
            "exit_code": 0,
            "argv": ["fake", target],
            "parsed": {
                "credentials_found": [
                    {"host": target, "service": "ssh",
                     "username": "alice", "password": "hunter2"},
                ],
            },
        }

    await stub(target="10.0.0.5")
    creds = engagement_workspace.query_creds()
    assert creds == [], "auto-record should be OFF by default"


@pytest.mark.asyncio
async def test_autorecord_writes_findings_when_enabled(engagement_workspace, monkeypatch):
    monkeypatch.setenv("KALIMCP_AUTORECORD", "1")
    engagement_workspace.create("op_record", scope=[])
    engagement_workspace.use("op_record")

    @active_tool("test-nmap")
    async def stub(target: str, **kwargs):
        return {
            "exit_code": 0,
            "argv": ["nmap", target],
            "parsed": {
                "hosts": [
                    {"addr": target, "state": "up",
                     "ports": [{"portid": 22, "service": "ssh"}]},
                ],
            },
        }

    await stub(target="10.0.0.5")
    findings = engagement_workspace.query_findings(category="host")
    assert len(findings) == 1
    assert findings[0]["host"] == "10.0.0.5"
    assert findings[0]["source_tool"] == "test-nmap"


@pytest.mark.asyncio
async def test_autorecord_writes_creds_when_enabled(engagement_workspace, monkeypatch):
    monkeypatch.setenv("KALIMCP_AUTORECORD", "1")
    engagement_workspace.create("op_creds", scope=[])
    engagement_workspace.use("op_creds")

    @active_tool("test-hydra")
    async def stub(target: str, **kwargs):
        return {
            "exit_code": 0,
            "argv": ["hydra", target, "ssh"],
            "parsed": {
                "credentials_found": [
                    {"host": target, "service": "ssh",
                     "username": "alice", "password": "hunter2"},
                ],
            },
        }

    await stub(target="10.0.0.5")
    creds = engagement_workspace.query_creds()
    assert len(creds) == 1
    cred = creds[0]
    assert cred["user"] == "alice"
    assert cred["secret"] == "hunter2"
    assert cred["proto"] == "ssh"
    assert cred["host"] == "10.0.0.5"
    assert cred["source_tool"] == "test-hydra"


@pytest.mark.asyncio
async def test_autorecord_handles_netexec_successes_shape(engagement_workspace, monkeypatch):
    monkeypatch.setenv("KALIMCP_AUTORECORD", "1")
    engagement_workspace.create("op_ne", scope=[])
    engagement_workspace.use("op_ne")

    @active_tool("test-netexec")
    async def stub(target: str, **kwargs):
        return {
            "exit_code": 0,
            "argv": ["netexec", "smb", target],
            "parsed": {
                "successes": [
                    {"host": "10.0.0.10", "proto": "smb",
                     "user": "admin", "secret": "Password123"},
                ],
            },
        }

    await stub(target="10.0.0.0/24")
    creds = engagement_workspace.query_creds()
    assert len(creds) == 1
    assert creds[0]["host"] == "10.0.0.10"
    assert creds[0]["proto"] == "smb"


@pytest.mark.asyncio
async def test_out_of_scope_warning_added_to_result(engagement_workspace, monkeypatch):
    monkeypatch.delenv("KALIMCP_AUTORECORD", raising=False)
    engagement_workspace.create("op_scope", scope=["10.0.0.0/24"])
    engagement_workspace.use("op_scope")

    @active_tool("test-scope")
    async def stub(target: str, **kwargs):
        return {"exit_code": 0, "argv": ["fake", target]}

    # Target inside scope → no warning.
    in_scope = await stub(target="10.0.0.5")
    assert in_scope.get("warning") is None
    # Target outside scope → warning annotated, BUT call still completes.
    out_of_scope = await stub(target="8.8.8.8")
    assert out_of_scope["warning"] == "out_of_scope"
    assert out_of_scope["exit_code"] == 0


@pytest.mark.asyncio
async def test_out_of_scope_warning_logged_to_audit(
    engagement_workspace, tmp_path, monkeypatch
):
    from kalimcp import audit

    monkeypatch.delenv("KALIMCP_AUTORECORD", raising=False)
    log_path = tmp_path / "audit.log"
    monkeypatch.setenv("KALIMCP_LOG_FILE", str(log_path))
    audit.configure()
    engagement_workspace.create("op_audit", scope=["10.0.0.0/24"])
    engagement_workspace.use("op_audit")

    @active_tool("test-scope-audit")
    async def stub(target: str, **kwargs):
        return {"exit_code": 0, "argv": ["fake", target]}

    await stub(target="8.8.8.8")
    import json
    events = [
        json.loads(line)
        for line in log_path.read_text().splitlines()
        if line.strip()
    ]
    warnings = [e for e in events if e.get("event") == "out_of_scope_warning"]
    assert warnings, "out_of_scope_warning should be in the audit log"
    assert warnings[-1]["target"] == "8.8.8.8"
    assert warnings[-1]["engagement"] == "op_audit"


@pytest.mark.asyncio
async def test_empty_scope_does_not_warn(engagement_workspace, monkeypatch):
    monkeypatch.delenv("KALIMCP_AUTORECORD", raising=False)
    engagement_workspace.create("op_open", scope=[])
    engagement_workspace.use("op_open")

    @active_tool("test-open")
    async def stub(target: str, **kwargs):
        return {"exit_code": 0, "argv": ["fake", target]}

    # No scope declared → no gate, no warning regardless of target.
    result = await stub(target="8.8.8.8")
    assert result.get("warning") is None
