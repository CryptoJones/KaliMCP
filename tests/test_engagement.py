# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Aaron K. Clark
"""Tests for the engagement workspace storage module."""

from __future__ import annotations

import json
from pathlib import Path

import pytest


@pytest.fixture
def workspace(tmp_path, monkeypatch):
    """Redirect HOME so all engagement state lands under tmp_path."""
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.delenv("KALIMCP_ENGAGEMENT", raising=False)
    # Re-import to pick up new HOME.
    from kalimcp import engagement
    # Module-level paths are computed at import; force them to refresh.
    engagement.ROOT_DIR = Path.home() / ".kalimcp"
    engagement.ENGAGEMENTS_DIR = engagement.ROOT_DIR / "engagements"
    engagement.ACTIVE_STATE_FILE = engagement.ROOT_DIR / "active_engagement"
    return engagement


# ---------- engagement lifecycle ----------

def test_create_makes_directory_and_metadata(workspace):
    result = workspace.create("op1", scope=["10.0.0.0/24", "*.example.com"], operator="alice")
    assert result["ok"] is True
    assert result["name"] == "op1"
    p = Path(result["path"])
    assert p.is_dir()
    assert (p / "loot").is_dir()
    assert (p / "screenshots").is_dir()
    meta = json.loads((p / "engagement.json").read_text())
    assert meta["scope"] == ["10.0.0.0/24", "*.example.com"]
    assert meta["operator"] == "alice"


def test_create_duplicate_returns_exists(workspace):
    workspace.create("op1")
    second = workspace.create("op1")
    assert second["ok"] is False
    assert second["error"] == "exists"


def test_create_sanitizes_unsafe_chars(workspace):
    result = workspace.create("op/1 with spaces & pipes |")
    assert result["ok"] is True
    # The on-disk name has unsafe chars replaced.
    assert "/" not in result["name"]
    assert "|" not in result["name"]
    assert " " not in result["name"]


def test_sanitize_name_rejects_dot_traversal(workspace):
    """'..' / '.' survive the charset regex (it allows '.') but must not
    escape the engagements root — they collapse to the default name."""
    assert workspace._sanitize_name("..") == workspace.DEFAULT_ENGAGEMENT
    assert workspace._sanitize_name(".") == workspace.DEFAULT_ENGAGEMENT
    assert workspace._sanitize_name("...") == workspace.DEFAULT_ENGAGEMENT
    # A legitimate dotted name is left alone.
    assert workspace._sanitize_name("op.v2") == "op.v2"


def test_engagement_dir_for_dotdot_stays_within_root(workspace):
    """engagement_dir('..') must resolve inside ENGAGEMENTS_DIR, not above it."""
    d = workspace.engagement_dir("..").resolve()
    root = workspace.ENGAGEMENTS_DIR.resolve()
    assert root == d or root in d.parents


def test_list_all_returns_engagements_sorted_recent_first(workspace):
    workspace.create("op_a")
    workspace.create("op_b")
    listings = workspace.list_all()
    names = {e["name"] for e in listings}
    assert names == {"op_a", "op_b"}
    # Both should have started_at in ISO format.
    for entry in listings:
        assert entry["started_at"]


def test_use_sets_active_engagement(workspace):
    workspace.create("op_active")
    result = workspace.use("op_active")
    assert result["ok"] is True
    assert workspace.current_engagement() == "op_active"


def test_use_unknown_engagement_returns_not_found(workspace):
    result = workspace.use("never_created")
    assert result["ok"] is False
    assert result["error"] == "not_found"


def test_current_engagement_env_overrides_state_file(workspace, monkeypatch):
    workspace.create("op_a")
    workspace.create("op_b")
    workspace.use("op_a")
    assert workspace.current_engagement() == "op_a"
    monkeypatch.setenv("KALIMCP_ENGAGEMENT", "op_b")
    assert workspace.current_engagement() == "op_b"


def test_current_engagement_defaults_to_default(workspace):
    # No state file, no env var.
    assert workspace.current_engagement() == "_default"


# ---------- findings ----------

def test_record_and_query_findings_roundtrip(workspace):
    workspace.create("op")
    workspace.use("op")
    assert workspace.record_finding("host", "10.0.0.5", {"ports": [22, 80]}, source_tool="nmap") is True
    assert workspace.record_finding("subdomain", "api.example.com", {"source": "subfinder"}) is True
    findings = workspace.query_findings()
    assert len(findings) == 2
    cats = {f["category"] for f in findings}
    assert cats == {"host", "subdomain"}


def test_evidence_advisory_fires_for_bare_claim(workspace):
    # No source_tool, empty payload -> advisory.
    msg = workspace.evidence_advisory({}, "")
    assert msg is not None
    assert "without evidence" in msg
    assert workspace.evidence_advisory(None, "") is not None


def test_evidence_advisory_silent_with_source_tool(workspace):
    assert workspace.evidence_advisory({}, "nmap") is None


def test_evidence_advisory_silent_with_evidence_field(workspace):
    assert workspace.evidence_advisory({"evidence": "GET / 200 banner=nginx"}, "") is None
    assert workspace.evidence_advisory({"loot": "ntds.txt"}, "") is None
    assert workspace.evidence_advisory({"ports": [22, 80]}, "") is None
    # An empty evidence value does not count.
    assert workspace.evidence_advisory({"evidence": ""}, "") is not None


def test_record_finding_still_writes_despite_advisory(workspace):
    """The advisory is non-blocking — the finding is recorded regardless."""
    workspace.create("op")
    workspace.use("op")
    assert workspace.record_finding("sqli", "10.0.0.5", {}) is True
    assert len(workspace.query_findings()) == 1


def test_query_findings_filters_by_category(workspace):
    workspace.create("op")
    workspace.use("op")
    workspace.record_finding("host", "10.0.0.5", {})
    workspace.record_finding("sqli", "10.0.0.5", {})
    only_hosts = workspace.query_findings(category="host")
    assert len(only_hosts) == 1
    assert only_hosts[0]["category"] == "host"


def test_query_findings_filters_by_host(workspace):
    workspace.create("op")
    workspace.use("op")
    workspace.record_finding("host", "10.0.0.5", {})
    workspace.record_finding("host", "10.0.0.6", {})
    only_5 = workspace.query_findings(host="10.0.0.5")
    assert len(only_5) == 1
    assert only_5[0]["host"] == "10.0.0.5"


def test_list_hosts_dedupes_across_findings_and_creds(workspace):
    workspace.create("op")
    workspace.use("op")
    workspace.record_finding("host", "10.0.0.5", {})
    workspace.record_finding("subdomain", "api.example.com", {})
    workspace.record_cred("10.0.0.5", "ssh", "alice", "hunter2", source_tool="hydra")
    workspace.record_cred("10.0.0.10", "smb", "admin", "Password123", source_tool="netexec")
    hosts = workspace.list_hosts()
    assert hosts == ["10.0.0.10", "10.0.0.5", "api.example.com"]


# ---------- credentials ----------

def test_record_and_query_creds_roundtrip(workspace):
    workspace.create("op")
    workspace.use("op")
    workspace.record_cred("10.0.0.5", "ssh", "alice", "hunter2", source_tool="hydra")
    workspace.record_cred("10.0.0.5", "smb", "admin", "Password123", source_tool="netexec")
    creds = workspace.query_creds(host="10.0.0.5")
    assert len(creds) == 2
    by_proto = {c["proto"]: c for c in creds}
    assert by_proto["ssh"]["secret"] == "hunter2"
    assert by_proto["smb"]["user"] == "admin"


def test_creds_file_is_mode_0600(workspace):
    workspace.create("op")
    workspace.use("op")
    workspace.record_cred("10.0.0.5", "ssh", "alice", "hunter2")
    p = workspace.engagement_dir("op") / "creds.jsonl"
    # On systems where chmod is supported, mode should be 0600.
    mode = p.stat().st_mode & 0o777
    assert mode == 0o600


# ---------- loot ----------

def test_loot_write_and_read_text_roundtrip(workspace):
    workspace.create("op")
    workspace.use("op")
    write = workspace.write_loot("ntds-pwhash-export.txt", "alice:hash:hash\nbob:hash:hash\n")
    assert write["ok"] is True
    assert write["size_bytes"] > 0
    read = workspace.read_loot("ntds-pwhash-export.txt")
    assert read["ok"] is True
    assert read["encoding"] == "utf-8"
    assert "alice" in read["text"]


def test_loot_write_and_read_binary_roundtrip(workspace):
    workspace.create("op")
    workspace.use("op")
    blob = b"\x00\x01\x02\xff" * 64
    workspace.write_loot("payload.bin", blob)
    read = workspace.read_loot("payload.bin")
    import base64
    assert read["ok"] is True
    assert read["encoding"] == "base64"
    assert base64.b64decode(read["base64"]) == blob


def test_loot_read_missing_returns_not_found(workspace):
    workspace.create("op")
    workspace.use("op")
    read = workspace.read_loot("nothing")
    assert read["ok"] is False
    assert read["error"] == "not_found"


def test_loot_list_enumerates(workspace):
    workspace.create("op")
    workspace.use("op")
    workspace.write_loot("a.txt", "A")
    workspace.write_loot("b.txt", "BB")
    items = workspace.list_loot()
    names = {i["name"] for i in items}
    assert names == {"a.txt", "b.txt"}


# ---------- notes + status ----------

def test_note_append_writes_timestamped_block(workspace):
    workspace.create("op")
    workspace.use("op")
    workspace.note_append("initial recon complete; 5 hosts up")
    workspace.note_append("escalated to DA via Kerberoast")
    notes_path = workspace.engagement_dir("op") / "notes.md"
    text = notes_path.read_text()
    assert "initial recon complete" in text
    assert "escalated to DA" in text
    # Two timestamped blocks → two "## " headings.
    assert text.count("## ") >= 2


def test_status_reflects_counts(workspace):
    workspace.create("op", scope=["10.0.0.0/24"])
    workspace.use("op")
    workspace.record_finding("host", "10.0.0.5", {})
    workspace.record_finding("host", "10.0.0.6", {})
    workspace.record_cred("10.0.0.5", "ssh", "alice", "x")
    workspace.write_loot("blob.bin", b"x" * 10)
    s = workspace.status()
    assert s["name"] == "op"
    assert s["findings_count"] == 2
    assert s["creds_count"] == 1
    assert s["loot_count"] == 1
    assert s["scope"] == ["10.0.0.0/24"]
    assert s["is_active"] is True


# ---------- scope matching ----------

def test_scope_matches_empty_scope_returns_true(workspace):
    workspace.create("op")
    workspace.use("op")
    assert workspace.scope_matches("8.8.8.8") is True


def test_scope_matches_cidr(workspace):
    workspace.create("op", scope=["10.0.0.0/24"])
    workspace.use("op")
    assert workspace.scope_matches("10.0.0.5") is True
    assert workspace.scope_matches("10.0.1.5") is False


def test_scope_matches_domain_glob(workspace):
    workspace.create("op", scope=["*.example.com"])
    workspace.use("op")
    assert workspace.scope_matches("api.example.com") is True
    assert workspace.scope_matches("test.example.org") is False


def test_scope_matches_url_pattern(workspace):
    workspace.create("op", scope=["https://example.com/api"])
    workspace.use("op")
    assert workspace.scope_matches("https://example.com/api/users") is True
    assert workspace.scope_matches("https://other.com/api/users") is False


def test_extract_host_parses_bracketed_ipv6(workspace):
    """Bracketed IPv6 (with or without a port) yields the bare address so
    ip_address() can match it — previously fell through unparsed."""
    assert workspace._extract_host("[::1]:8080") == "::1"
    assert workspace._extract_host("[2001:db8::1]") == "2001:db8::1"
    # A bare (unbracketed) literal is left intact for ip_address().
    assert workspace._extract_host("::1") == "::1"


def test_scope_matches_ipv6_target(workspace):
    """An out-of-scope IPv6 target must actually report out-of-scope
    (the bug: it silently matched because the host never parsed)."""
    workspace.create("op", scope=["2001:db8::/32"])
    workspace.use("op")
    assert workspace.scope_matches("[2001:db8::5]:443") is True
    assert workspace.scope_matches("[2001:dead::5]:443") is False


def test_scope_matches_no_engagement_returns_true(workspace):
    # No engagement created -> _default has no scope -> matches.
    assert workspace.scope_matches("8.8.8.8") is True


# ---------- wordlists ----------

def test_list_wordlists_handles_missing_dirs(workspace, monkeypatch):
    """If /usr/share/wordlists doesn't exist, return empty list (not error)."""
    monkeypatch.setattr(workspace, "_WORDLIST_DIRS", ["/no/such/path"])
    assert workspace.list_wordlists() == []


def test_list_wordlists_finds_seeded_files(workspace, tmp_path, monkeypatch):
    wl_dir = tmp_path / "wordlists"
    wl_dir.mkdir()
    (wl_dir / "common.txt").write_text("admin\nroot\n")
    (wl_dir / "rockyou.txt").write_text("password\n" * 1000)
    monkeypatch.setattr(workspace, "_WORDLIST_DIRS", [str(wl_dir)])
    result = workspace.list_wordlists()
    names = {item["name"] for item in result}
    assert "common.txt" in names
    assert "rockyou.txt" in names
