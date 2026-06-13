# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Aaron K. Clark
"""Process-registry + concurrency-cap tests (issue #13)."""

from __future__ import annotations

import asyncio
import os
import signal

import pytest

from kalimcp import process_registry, run


@pytest.fixture(autouse=True)
def _reset():
    process_registry.reset_for_test()
    run.reset_concurrency_for_test()
    yield
    process_registry.reset_for_test()
    run.reset_concurrency_for_test()


# ---------- registry unit behavior ----------


def test_register_snapshot_unregister():
    process_registry.register(4242, ["nmap", "-sV", "10.0.0.1"], timeout=300, engagement="acme")
    snap = process_registry.snapshot()
    assert len(snap) == 1
    row = snap[0]
    assert row["pid"] == 4242
    assert row["binary"] == "nmap"
    assert row["argc"] == 3
    assert row["engagement"] == "acme"
    assert "elapsed_s" in row
    process_registry.unregister(4242)
    assert process_registry.snapshot() == []


def test_snapshot_never_exposes_argv_values():
    """The snapshot must not leak secret-bearing argv tokens."""
    process_registry.register(7, ["hydra", "-p", "hunter2", "ssh://h"], timeout=60)
    row = process_registry.snapshot()[0]
    assert "hunter2" not in str(row)
    assert "argv" not in row
    assert row["argc"] == 4  # count only


def test_kill_refuses_unknown_pid():
    res = process_registry.kill(999999)
    assert res["ok"] is False
    assert res["error"] == "unknown_pid"


def test_kill_dead_pid_reports_not_running_and_cleans_up():
    # A registered PID that no longer exists.
    process_registry.register(999998, ["nmap"], timeout=1)
    res = process_registry.kill(999998)
    assert res["ok"] is False
    assert res["error"] in ("not_running", "kill_failed")
    # Either way it should no longer be listed if it was not running.
    if res["error"] == "not_running":
        assert process_registry.snapshot() == []


# ---------- integration with run.run ----------


@pytest.mark.asyncio
async def test_running_process_appears_then_is_killable():
    proc_done = asyncio.create_task(run.run(["sh", "-c", "sleep 30"], timeout=30))
    # Wait for it to register.
    for _ in range(200):
        snap = process_registry.snapshot()
        if snap:
            break
        await asyncio.sleep(0.02)
    assert snap, "subprocess never registered"
    pid = snap[0]["pid"]
    assert os.path.basename(snap[0]["binary"]) == "sh"

    res = process_registry.kill(pid, sig=signal.SIGKILL)
    assert res["ok"] is True

    result = await proc_done
    # After completion the registry is clean again.
    assert process_registry.snapshot() == []
    assert result["exit_code"] != 0  # killed, not a clean exit


@pytest.mark.asyncio
async def test_concurrency_cap_serializes_excess(monkeypatch):
    monkeypatch.setenv("KALIMCP_MAX_CONCURRENCY", "2")
    run.reset_concurrency_for_test()

    # Launch 3 short sleeps with a cap of 2 — at no point should the
    # registry show more than 2 running at once.
    peak = 0
    tasks = [asyncio.create_task(run.run(["sh", "-c", "sleep 0.4"], timeout=5)) for _ in range(3)]
    for _ in range(100):
        peak = max(peak, len(process_registry.snapshot()))
        if all(t.done() for t in tasks):
            break
        await asyncio.sleep(0.02)
    await asyncio.gather(*tasks)
    assert peak <= 2, f"concurrency cap exceeded: saw {peak} running"
