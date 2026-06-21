# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Aaron K. Clark
"""Reverse-tunnel pivot tests (Chisel / Ligolo-ng).

The persistent server process is replaced by a fake duplex object via the
patched pivot._popen factory, so nothing real is spawned — mirrors how
tests/test_capture.py fakes capture._popen.
"""

from __future__ import annotations

import queue
import time
from unittest.mock import patch

import pytest

from kalimcp.tools import pivot

_SENTINEL = object()


@pytest.fixture(autouse=True)
def _reset():
    pivot.reset_for_test()
    yield
    pivot.reset_for_test()


class _FakeProc:
    """A fake pivot server: yields a canned banner, then EOF on terminate."""

    def __init__(self, argv, banner=b"[*] Listening...\n"):
        self.argv = argv
        self.pid = 4242
        self._rc = None
        self._q: queue.Queue = queue.Queue()
        self.stdin = self
        self.stdout = self
        self.written: list[bytes] = []
        if banner:
            self._q.put(banner)

    def read(self, _n):
        data = self._q.get()
        self._q.task_done()
        return b"" if data is _SENTINEL else data

    def write(self, data):
        self.written.append(data)

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


def _wait_for_buffer(pid, *, timeout=2.0):
    proc = pivot._pivots[pid]["proc"]
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        with proc._lock:
            if proc._buf:
                return
        time.sleep(0.005)


# ---------- argv construction ----------


@pytest.mark.asyncio
async def test_chisel_default_port():
    procs: list = []
    with patch("kalimcp.tools.pivot._popen", side_effect=_fake_popen(procs)):
        res = await pivot.pivot_start(tool="chisel", wait_seconds=0)
    assert res["ok"] is True
    assert res["port"] == 8080
    assert procs[0].argv == ["chisel", "server", "-p", "8080", "--reverse"]


@pytest.mark.asyncio
async def test_chisel_custom_port():
    procs: list = []
    with patch("kalimcp.tools.pivot._popen", side_effect=_fake_popen(procs)):
        res = await pivot.pivot_start(tool="chisel", port=9999, wait_seconds=0)
    assert res["port"] == 9999
    assert procs[0].argv == ["chisel", "server", "-p", "9999", "--reverse"]


@pytest.mark.asyncio
async def test_ligolo_default_port():
    procs: list = []
    with patch("kalimcp.tools.pivot._popen", side_effect=_fake_popen(procs)):
        res = await pivot.pivot_start(tool="ligolo", wait_seconds=0)
    assert res["ok"] is True
    assert res["port"] == 11601
    assert procs[0].argv == ["ligolo-proxy", "-selfcert", "-laddr", "0.0.0.0:11601"]


@pytest.mark.asyncio
async def test_extra_args_appended():
    procs: list = []
    with patch("kalimcp.tools.pivot._popen", side_effect=_fake_popen(procs)):
        await pivot.pivot_start(tool="chisel", extra="--socks5 -v", wait_seconds=0)
    assert procs[0].argv == [
        "chisel", "server", "-p", "8080", "--reverse", "--socks5", "-v",
    ]


@pytest.mark.asyncio
async def test_invalid_tool_rejected():
    res = await pivot.pivot_start(tool="bogus", wait_seconds=0)
    assert res.get("exit_code") == -1
    assert "tool must be one of" in res["stderr"]


# ---------- operator hints ----------


@pytest.mark.asyncio
async def test_chisel_operator_hint():
    with patch("kalimcp.tools.pivot._popen", side_effect=_fake_popen([])):
        res = await pivot.pivot_start(tool="chisel", port=8080, wait_seconds=0)
    assert res["operator_hint"] == "chisel client <LHOST>:8080 R:socks"


@pytest.mark.asyncio
async def test_ligolo_operator_hint():
    with patch("kalimcp.tools.pivot._popen", side_effect=_fake_popen([])):
        res = await pivot.pivot_start(tool="ligolo", wait_seconds=0)
    assert res["operator_hint"] == "ligolo-agent -connect <LHOST>:11601 -ignore-cert"


# ---------- send / poll ----------


@pytest.mark.asyncio
async def test_send_writes_command_and_drains():
    procs: list = []
    with patch("kalimcp.tools.pivot._popen", side_effect=_fake_popen(procs)):
        res = await pivot.pivot_start(tool="ligolo", wait_seconds=0)
    pid = res["pivot_id"]
    procs[0].feed(b"[Agent] selected\n")
    _wait_for_buffer(pid)
    out = pivot.pivot_send(pid, "start")
    assert out["ok"] is True
    assert procs[0].written == [b"start\n"]
    assert "[Agent] selected" in out["output"]
    assert out["alive"] is True


@pytest.mark.asyncio
async def test_poll_drains_new_output():
    procs: list = []
    with patch("kalimcp.tools.pivot._popen", side_effect=_fake_popen(procs)):
        res = await pivot.pivot_start(tool="chisel", wait_seconds=0)
    pid = res["pivot_id"]
    procs[0].feed(b"session#1 opened\n")
    _wait_for_buffer(pid)
    poll = pivot.pivot_poll(pid)
    assert poll["ok"] is True
    assert "session#1 opened" in poll["output"]
    assert poll["alive"] is True


def test_send_unknown_pivot():
    res = pivot.pivot_send("piv-nope", "start")
    assert res.get("exit_code") == -1


def test_poll_unknown_pivot():
    res = pivot.pivot_poll("piv-nope")
    assert res.get("exit_code") == -1


# ---------- registry lifecycle ----------


@pytest.mark.asyncio
async def test_start_registers_and_lists():
    procs: list = []
    with patch("kalimcp.tools.pivot._popen", side_effect=_fake_popen(procs)):
        res = await pivot.pivot_start(tool="chisel", wait_seconds=0)
    pid = res["pivot_id"]
    lst = pivot.pivot_list()
    assert lst["count"] == 1
    assert lst["pivots"][0]["id"] == pid
    assert lst["pivots"][0]["tool"] == "chisel"
    assert lst["pivots"][0]["port"] == 8080
    assert lst["pivots"][0]["alive"] is True


@pytest.mark.asyncio
async def test_stop_deregisters():
    procs: list = []
    with patch("kalimcp.tools.pivot._popen", side_effect=_fake_popen(procs)):
        res = await pivot.pivot_start(tool="ligolo", wait_seconds=0)
    pid = res["pivot_id"]
    stop = pivot.pivot_stop(pid)
    assert stop["ok"] is True
    assert pivot.pivot_list()["count"] == 0


def test_stop_unknown_pivot():
    res = pivot.pivot_stop("piv-nope")
    assert res["ok"] is False
