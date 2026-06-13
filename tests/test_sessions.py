# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Aaron K. Clark
"""Interactive-session manager tests (issue #16).

SSH sessions go through run.run (patched). The reverse-shell listener's
persistent process is replaced by a fake duplex object via the patched
sessions._popen factory, so nothing real is spawned.
"""

from __future__ import annotations

import queue
from unittest.mock import AsyncMock, patch

import pytest

from kalimcp import sessions

_SENTINEL = object()


@pytest.fixture(autouse=True)
def _reset():
    sessions.reset_for_test()
    yield
    sessions.reset_for_test()


def _ok(stdout="", code=0):
    return {"exit_code": code, "stdout": stdout, "stderr": "", "argv": ["ssh"],
            "truncated": False, "timed_out": False}


# ---------- SSH (ControlMaster) ----------


@pytest.mark.asyncio
async def test_ssh_start_builds_controlmaster_argv_and_registers():
    with patch("kalimcp.sessions.run.run", new=AsyncMock(return_value=_ok())) as m:
        res = await sessions.ssh_start(host="10.0.0.5", user="root", password="hunter2")
    assert res["ok"] is True
    sid = res["session_id"]
    argv = m.call_args.args[0]
    assert argv[:3] == ["sshpass", "-p", "hunter2"]
    assert "-M" in argv and "-S" in argv and "-fN" in argv
    assert argv[-1] == "root@10.0.0.5"
    # Registered and listable.
    assert sessions.session_status(sid)["kind"] == "ssh"
    assert sessions.session_list()["count"] == 1


@pytest.mark.asyncio
async def test_ssh_start_redacts_password_in_audit(tmp_path, monkeypatch):
    from kalimcp import audit
    log = tmp_path / "audit.log"
    monkeypatch.setenv("KALIMCP_LOG_FILE", str(log))
    audit.configure()
    with patch("kalimcp.sessions.run.run", new=AsyncMock(return_value=_ok())):
        await sessions.ssh_start(host="h", user="u", password="hunter2")
    audit.reset_for_test()
    assert "hunter2" not in log.read_text()


@pytest.mark.asyncio
async def test_ssh_start_failure_not_registered():
    with patch("kalimcp.sessions.run.run", new=AsyncMock(return_value=_ok(code=255))):
        res = await sessions.ssh_start(host="h", user="u", key="/no/key")
    # key path doesn't exist -> validate_file rejects before run even.
    assert res["exit_code"] == -1 or res["ok"] is False


@pytest.mark.asyncio
async def test_ssh_exec_reuses_socket():
    with patch("kalimcp.sessions.run.run", new=AsyncMock(return_value=_ok())):
        start = await sessions.ssh_start(host="h", user="u", key=__file__)
    sid = start["session_id"]
    with patch("kalimcp.sessions.run.run", new=AsyncMock(return_value=_ok(stdout="uid=0"))) as m:
        res = await sessions.ssh_exec(sid, "id")
    assert res["ok"] is True
    argv = m.call_args.args[0]
    assert argv[0] == "ssh" and "-S" in argv and argv[-2:] == ["--", "id"]


@pytest.mark.asyncio
async def test_ssh_exec_unknown_session():
    res = await sessions.ssh_exec("ssh-nope", "id")
    assert res["exit_code"] == -1


@pytest.mark.asyncio
async def test_ssh_stop_deregisters():
    with patch("kalimcp.sessions.run.run", new=AsyncMock(return_value=_ok())):
        start = await sessions.ssh_start(host="h", user="u", key=__file__)
        sid = start["session_id"]
        stop = await sessions.ssh_stop(sid)
    assert stop["ok"] is True
    assert sessions.session_status(sid)["ok"] is False


# ---------- reverse shell (fake persistent proc) ----------


class _FakeProc:
    """A fake duplex process: stdin.write echoes to stdout."""

    def __init__(self, argv):
        self.argv = argv
        self.pid = 4242
        self._rc = None
        self._q: queue.Queue = queue.Queue()
        self.stdin = self
        self.stdout = self
        self._q.put(b"Listening on 0.0.0.0\n")

    # stdout side
    def read(self, _n):
        data = self._q.get()
        return b"" if data is _SENTINEL else data

    # stdin side
    def write(self, data):
        self._q.put(b"$ " + data)

    def flush(self):
        pass

    def poll(self):
        return self._rc

    def terminate(self):
        self._rc = -15
        self._q.put(_SENTINEL)


@pytest.mark.asyncio
async def test_revshell_listen_registers_and_lists():
    with patch("kalimcp.sessions._popen", side_effect=lambda argv: _FakeProc(argv)):
        res = await sessions.revshell_listen(port=4444)
    assert res["ok"] is True
    sid = res["session_id"]
    lst = sessions.session_list()
    assert lst["count"] == 1
    assert lst["sessions"][0]["kind"] == "revshell"
    assert sessions.session_status(sid)["alive"] is True


@pytest.mark.asyncio
async def test_revshell_invalid_port():
    res = await sessions.revshell_listen(port=99999)
    assert res["exit_code"] == -1


@pytest.mark.asyncio
async def test_revshell_exec_sends_and_reads():
    with patch("kalimcp.sessions._popen", side_effect=lambda argv: _FakeProc(argv)):
        res = await sessions.revshell_listen(port=4444)
        sid = res["session_id"]
        out = await sessions.revshell_exec(sid, "whoami", read_wait=0.3)
    assert out["ok"] is True
    # The fake echoes "$ whoami" back; the listener banner may precede it.
    assert "whoami" in out["output"]


@pytest.mark.asyncio
async def test_revshell_trigger_is_fired_and_reaped():
    fired = {}

    def fake_popen(argv):
        p = _FakeProc(argv)
        if argv and argv[0] != "nc":
            fired["trigger"] = argv
        return p

    with patch("kalimcp.sessions._popen", side_effect=fake_popen):
        res = await sessions.revshell_listen(
            port=4444, trigger="curl http://10.0.0.1/x", wait_seconds=0,
        )
        sid = res["session_id"]
        stop = await sessions.revshell_stop(sid)
    assert fired["trigger"][0] == "curl"
    assert stop["ok"] is True
    assert sessions.session_status(sid)["ok"] is False


# ---------- helpers ----------


def test_detect_blocking_command():
    assert sessions.detect_blocking_command("nc -lvnp 4444")["blocking"] is True
    assert sessions.detect_blocking_command("ssh root@host")["blocking"] is True
    assert sessions.detect_blocking_command("ls -la")["blocking"] is False


def test_system_network_info_shape():
    info = sessions.system_network_info()
    assert "addresses" in info
    assert "recommended_lhost" in info
