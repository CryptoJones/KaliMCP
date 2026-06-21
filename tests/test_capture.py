# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Aaron K. Clark
"""Credential-capture listener tests (Responder / mitm6 / ntlmrelayx).

The persistent listener process is replaced by a fake duplex object via
the patched capture._popen factory, so nothing real is spawned — mirrors
how tests/test_sessions.py fakes sessions._popen.
"""

from __future__ import annotations

import queue
import time
from unittest.mock import patch

import pytest

from kalimcp.tools import capture

_SENTINEL = object()


@pytest.fixture(autouse=True)
def _reset():
    capture.reset_for_test()
    yield
    capture.reset_for_test()


class _FakeProc:
    """A fake listener process: yields a canned banner, then EOF."""

    def __init__(self, argv, banner=b"[+] Listening...\n"):
        self.argv = argv
        self.pid = 4242
        self._rc = None
        self._q: queue.Queue = queue.Queue()
        self.stdin = self
        self.stdout = self
        if banner:
            self._q.put(banner)

    def read(self, _n):
        data = self._q.get()
        self._q.task_done()
        return b"" if data is _SENTINEL else data

    def write(self, data):
        pass

    def flush(self):
        pass

    def poll(self):
        return self._rc

    def terminate(self):
        self._rc = -15
        self._q.put(_SENTINEL)

    def feed(self, data: bytes):
        self._q.put(data)


def _fake_popen(captured):
    def _factory(argv):
        p = _FakeProc(argv)
        captured.append(p)
        return p
    return _factory


def _wait_for_buffer(cid, *, timeout=2.0):
    """Spin until the drain thread has buffered the fed chunk (deterministic,
    no fixed sleep): reads the proc's private buffer directly."""
    proc = capture._captures[cid]["proc"]
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        with proc._lock:
            if proc._buf:
                return
        time.sleep(0.005)


# ---------- argv construction ----------


@pytest.mark.asyncio
async def test_responder_argv():
    procs: list = []
    with patch("kalimcp.tools.capture._popen", side_effect=_fake_popen(procs)):
        res = await capture.capture_start(tool="responder", interface="eth1", wait_seconds=0)
    assert res["ok"] is True
    assert procs[0].argv == ["responder", "-I", "eth1", "-wd"]


@pytest.mark.asyncio
async def test_mitm6_argv_with_domain():
    procs: list = []
    with patch("kalimcp.tools.capture._popen", side_effect=_fake_popen(procs)):
        res = await capture.capture_start(
            tool="mitm6", interface="eth0", domain="corp.local", wait_seconds=0,
        )
    assert res["ok"] is True
    assert procs[0].argv == ["mitm6", "-d", "corp.local", "-i", "eth0"]


@pytest.mark.asyncio
async def test_mitm6_argv_without_domain():
    procs: list = []
    with patch("kalimcp.tools.capture._popen", side_effect=_fake_popen(procs)):
        await capture.capture_start(tool="mitm6", interface="eth0", wait_seconds=0)
    assert procs[0].argv == ["mitm6", "-i", "eth0"]


@pytest.mark.asyncio
async def test_ntlmrelayx_argv():
    procs: list = []
    with patch("kalimcp.tools.capture._popen", side_effect=_fake_popen(procs)):
        res = await capture.capture_start(
            tool="ntlmrelayx", relay_target="smb://10.0.0.5", wait_seconds=0,
        )
    assert res["ok"] is True
    assert procs[0].argv == ["impacket-ntlmrelayx", "-t", "smb://10.0.0.5", "-smb2support"]


@pytest.mark.asyncio
async def test_ntlmrelayx_requires_relay_target():
    with patch("kalimcp.tools.capture._popen", side_effect=_fake_popen([])):
        res = await capture.capture_start(tool="ntlmrelayx", wait_seconds=0)
    assert res.get("exit_code") == -1
    assert "relay_target" in res["stderr"]


@pytest.mark.asyncio
async def test_extra_args_appended():
    procs: list = []
    with patch("kalimcp.tools.capture._popen", side_effect=_fake_popen(procs)):
        await capture.capture_start(
            tool="responder", interface="eth0", extra="-A -v", wait_seconds=0,
        )
    assert procs[0].argv == ["responder", "-I", "eth0", "-wd", "-A", "-v"]


@pytest.mark.asyncio
async def test_invalid_tool_rejected():
    res = await capture.capture_start(tool="bogus", wait_seconds=0)
    assert res.get("exit_code") == -1
    assert "tool must be one of" in res["stderr"]


# ---------- registry lifecycle ----------


@pytest.mark.asyncio
async def test_start_registers_and_lists():
    procs: list = []
    with patch("kalimcp.tools.capture._popen", side_effect=_fake_popen(procs)):
        res = await capture.capture_start(tool="responder", wait_seconds=0)
    cid = res["capture_id"]
    lst = capture.capture_list()
    assert lst["count"] == 1
    assert lst["captures"][0]["id"] == cid
    assert lst["captures"][0]["tool"] == "responder"
    assert lst["captures"][0]["alive"] is True


@pytest.mark.asyncio
async def test_stop_deregisters():
    procs: list = []
    with patch("kalimcp.tools.capture._popen", side_effect=_fake_popen(procs)):
        res = await capture.capture_start(tool="responder", wait_seconds=0)
    cid = res["capture_id"]
    stop = capture.capture_stop(cid)
    assert stop["ok"] is True
    assert capture.capture_list()["count"] == 0


def test_poll_unknown_capture():
    res = capture.capture_poll("cap-nope")
    assert res.get("exit_code") == -1


def test_stop_unknown_capture():
    res = capture.capture_stop("cap-nope")
    assert res["ok"] is False


# ---------- hash parsing ----------


@pytest.mark.asyncio
async def test_poll_parses_netntlmv2_hash():
    procs: list = []
    with patch("kalimcp.tools.capture._popen", side_effect=_fake_popen(procs)):
        res = await capture.capture_start(tool="responder", wait_seconds=0)
    cid = res["capture_id"]
    # Representative Responder NetNTLMv2 line.
    line = (
        "alice::CORP:1122334455667788:"
        "ABCDEF0123456789ABCDEF0123456789:"
        "0101000000000000C0653150DE09D201000000000000000000"
        "1A2B3C4D5E6F7A8B9C0D1E2F3A4B5C6D0000000000000000"
    )
    procs[0].feed((line + "\n").encode())
    _wait_for_buffer(cid)
    poll = capture.capture_poll(cid)
    assert poll["ok"] is True
    hashes = poll["captured_hashes"]
    assert len(hashes) == 1
    h = hashes[0]
    assert h["user"] == "alice"
    assert h["domain"] == "CORP"
    assert h["type"] == "NetNTLMv2"
    assert h["hash"] == line


@pytest.mark.asyncio
async def test_poll_no_hashes():
    procs: list = []
    with patch("kalimcp.tools.capture._popen", side_effect=_fake_popen(procs)):
        res = await capture.capture_start(tool="responder", wait_seconds=0)
    cid = res["capture_id"]
    procs[0].feed(b"[*] Skipping previously captured hash for bob\n")
    _wait_for_buffer(cid)
    poll = capture.capture_poll(cid)
    assert poll["captured_hashes"] == []
    assert poll["alive"] is True


def test_parse_netntlmv1():
    line = "bob::WORKGROUP:1122334455667788:AABBCCDD"
    hashes = capture._parse_hashes(line)
    assert len(hashes) == 1
    assert hashes[0]["type"] == "NetNTLMv1"
    assert hashes[0]["user"] == "bob"
