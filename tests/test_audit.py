# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Aaron K. Clark
"""Audit log writer tests."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from kalimcp import audit


@pytest.fixture(autouse=True)
def _reset(monkeypatch):
    audit.reset_for_test()
    monkeypatch.delenv("KALIMCP_LOG_FILE", raising=False)
    monkeypatch.delenv("KALIMCP_NO_LOG", raising=False)
    yield
    audit.reset_for_test()


def _read_lines(path: Path):
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line]


def test_explicit_path_used(tmp_path):
    target = tmp_path / "audit.log"
    audit.configure(path=target)
    audit.log("test", foo="bar")
    rows = _read_lines(target)
    assert rows[0]["event"] == "test"
    assert rows[0]["foo"] == "bar"


def test_env_path_used(tmp_path, monkeypatch):
    target = tmp_path / "envlog.log"
    monkeypatch.setenv("KALIMCP_LOG_FILE", str(target))
    audit.configure()
    audit.log("test")
    assert target.exists()


def test_disabled_no_op(tmp_path):
    target = tmp_path / "audit.log"
    audit.configure(path=target, disabled=True)
    audit.log("test")
    assert not target.exists()


def test_KALIMCP_NO_LOG_disables(tmp_path, monkeypatch):
    monkeypatch.setenv("KALIMCP_NO_LOG", "1")
    audit.configure(path=tmp_path / "x.log")
    audit.log("test")
    assert not (tmp_path / "x.log").exists()


def test_one_line_per_event(tmp_path):
    target = tmp_path / "audit.log"
    audit.configure(path=target)
    for i in range(20):
        audit.log("burst", n=i)
    rows = _read_lines(target)
    assert len(rows) == 20
    assert [r["n"] for r in rows] == list(range(20))


def test_ts_and_event_cannot_be_overwritten(tmp_path):
    target = tmp_path / "audit.log"
    audit.configure(path=target)
    audit.log("real", ts="fake")
    rows = _read_lines(target)
    assert rows[0]["event"] == "real"
    assert rows[0]["ts"] != "fake"


def test_unwritable_explicit_path_warns_and_disables(monkeypatch, capsys):
    bad = Path("/proc/kalimcp-bad.log")
    resolved = audit.configure(path=bad)
    assert resolved is None
    assert "not writable" in capsys.readouterr().err


def test_silent_swallow_on_write_failure(tmp_path):
    target = tmp_path / "audit.log"
    audit.configure(path=target)
    target.unlink()
    target.mkdir()  # opening for append against a directory will fail
    audit.log("should_not_raise")  # must not raise


def test_time_block_returns_elapsed_ms():
    import time as _time
    with audit.time_block() as elapsed:
        _time.sleep(0.01)
    e = elapsed()
    assert isinstance(e, float)
    assert e >= 10
    assert e < 1000  # sanity bound
