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


# ---------- redact_argv ----------


def test_redact_space_separated_flag_value():
    """The classic `-p value` shape is hashed (and the flag kept)."""
    out = audit.redact_argv(["hydra", "-p", "hunter2", "host"], {"-p"})
    assert out[1] == "-p"
    assert out[2].startswith("sha256:")
    assert "hunter2" not in out


def test_redact_fused_flag_equals_value():
    """`--wordlist=value` (john's shape) redacts the value half only."""
    out = audit.redact_argv(
        ["john", "--wordlist=/loot/creds.txt", "hashes"], {"--wordlist", "-w"}
    )
    assert out[1].startswith("--wordlist=sha256:")
    assert "/loot/creds.txt" not in " ".join(out)


def test_redact_by_value_embedded_in_positional():
    """A password fused into a `user:pass@host` positional is redacted
    even though no flag points at it (fail-closed path)."""
    out = audit.redact_argv(
        ["impacket-secretsdump", "admin:hunter2@dc.corp.local"],
        secret_flags={"-password"},
        secret_values=["hunter2"],
    )
    joined = " ".join(out)
    assert "hunter2" not in joined
    # Surrounding structure is preserved so the log still shows shape.
    assert "admin:" in out[1] and "@dc.corp.local" in out[1]
    assert "sha256:" in out[1]


def test_redact_by_value_skips_too_short_secret():
    """A 1-2 char secret would corrupt every token — left alone here."""
    out = audit.redact_argv(["tool", "ab", "value"], None, secret_values=["ab"])
    assert out == ["tool", "ab", "value"]


def test_redact_noop_without_flags_or_values():
    argv = ["nmap", "-sV", "10.0.0.1"]
    assert audit.redact_argv(argv, None) == argv
    assert audit.redact_argv(argv, None, []) == argv


# ---------- file mode (#10) ----------


def test_log_file_created_0600(tmp_path):
    target = tmp_path / "audit.log"
    audit.configure(path=target)
    audit.log("test")
    assert target.stat().st_mode & 0o777 == 0o600


def test_existing_loose_log_tightened_on_configure(tmp_path):
    target = tmp_path / "audit.log"
    target.write_text("preexisting\n", encoding="utf-8")
    target.chmod(0o644)
    audit.configure(path=target)
    assert target.stat().st_mode & 0o777 == 0o600


def test_writable_probe_does_not_create_loose_file(tmp_path):
    target = tmp_path / "probe.log"
    audit.configure(path=target)  # probes via _writable, creating the file
    assert target.exists()
    assert target.stat().st_mode & 0o777 == 0o600
