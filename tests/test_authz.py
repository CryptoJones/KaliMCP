# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Aaron K. Clark
"""Authorization model tests — the core safety invariant."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest

from kalimcp.authz import (
    Authorization,
    AuthzError,
    _is_refused,
    _scope_matches,
    check,
)


def _auth(scope, *, name="t", token="tok-secret", expires=None, explicit_unsafe=False):
    return Authorization(
        name=name, token=token, scope=tuple(scope),
        expires=expires, explicit_unsafe=explicit_unsafe,
    )


# ---------------- _scope_matches ----------------

def test_scope_matches_cidr_v4():
    assert _scope_matches("203.0.113.42", "203.0.113.0/24") is True
    assert _scope_matches("203.0.114.42", "203.0.113.0/24") is False


def test_scope_matches_cidr_v6():
    assert _scope_matches("2001:db8::42", "2001:db8::/32") is True
    assert _scope_matches("2001:db9::42", "2001:db8::/32") is False


def test_scope_matches_exact_domain():
    assert _scope_matches("example.com", "example.com") is True
    assert _scope_matches("EXAMPLE.com", "example.com") is True


def test_scope_matches_wildcard_domain():
    assert _scope_matches("api.example.com", "*.example.com") is True
    assert _scope_matches("example.com", "*.example.com") is False  # bare host doesn't match *.foo


def test_scope_matches_url_target_against_domain_pattern():
    assert _scope_matches("https://api.example.com/v1", "*.example.com") is True


def test_scope_matches_returns_false_on_empty_target():
    assert _scope_matches("", "example.com") is False


# ---------------- _is_refused ----------------

def test_refuse_gov_domain():
    assert "gov" in _is_refused("https://www.whitehouse.gov/") or ""
    assert _is_refused("https://www.whitehouse.gov/") is not None


def test_refuse_mil_domain():
    assert _is_refused("https://www.defense.mil/") is not None


def test_refuse_cloud_metadata_ipv4():
    assert _is_refused("169.254.169.254") is not None


def test_refuse_financial_hint():
    assert _is_refused("chase.com") is not None
    assert _is_refused("api.chase.com") is not None


def test_allow_refused_when_flag_set():
    assert _is_refused("https://www.example.gov/", allow_refused=True) is None
    assert _is_refused("169.254.169.254", allow_refused=True) is None


def test_normal_target_not_refused():
    assert _is_refused("203.0.113.10") is None
    assert _is_refused("example.com") is None


# ---------------- check() ----------------

def test_check_rejects_missing_target():
    with pytest.raises(AuthzError, match="missing target"):
        check(target="", token="x", authzs=[])


def test_check_rejects_missing_token():
    with pytest.raises(AuthzError, match="missing authorization_token"):
        check(target="example.com", token="", authzs=[])


def test_check_rejects_unknown_token():
    with pytest.raises(AuthzError, match="does not match any known token"):
        check(target="example.com", token="bogus", authzs=[_auth(["example.com"])])


def test_check_rejects_expired_token():
    past = (datetime.now(UTC) - timedelta(hours=1)).isoformat()
    with pytest.raises(AuthzError, match="expired"):
        check(target="example.com", token="tok-secret",
              authzs=[_auth(["example.com"], expires=past)])


def test_check_rejects_out_of_scope():
    with pytest.raises(AuthzError, match="not within the scope"):
        check(target="example.org", token="tok-secret",
              authzs=[_auth(["example.com"])])


def test_check_rejects_refused_target_without_unsafe():
    with pytest.raises(AuthzError, match="gov"):
        check(target="https://example.gov/", token="tok-secret",
              authzs=[_auth(["*.gov", "example.gov"])])


def test_check_accepts_in_scope_target():
    auth = check(target="203.0.113.42", token="tok-secret",
                 authzs=[_auth(["203.0.113.0/24"])])
    assert auth.name == "t"


def test_check_accepts_wildcard_domain():
    auth = check(target="https://api.example.com/", token="tok-secret",
                 authzs=[_auth(["*.example.com"])])
    assert auth.token_id() == auth.token_id()  # smoke


def test_token_id_is_sha256_prefix():
    a = _auth(["example.com"], token="my-secret")
    tid = a.token_id()
    assert len(tid) == 8
    assert all(c in "0123456789abcdef" for c in tid)


# ---------------- load / save round-trip ----------------

def test_load_save_round_trip(tmp_path, monkeypatch):
    monkeypatch.setenv("KALIMCP_AUTHZ_FILE", str(tmp_path / "auth.json"))
    from kalimcp import authz as az
    az.save_authorizations([
        _auth(["10.0.0.0/24"], name="lab-1", token="tok-lab-1"),
        _auth(["*.client.example.com"], name="client-eng", token="tok-client"),
    ])
    loaded = az.load_authorizations()
    assert len(loaded) == 2
    assert {a.name for a in loaded} == {"lab-1", "client-eng"}


def test_save_sets_mode_0600(tmp_path, monkeypatch):
    target = tmp_path / "auth.json"
    monkeypatch.setenv("KALIMCP_AUTHZ_FILE", str(target))
    from kalimcp import authz as az
    az.save_authorizations([_auth(["10.0.0.0/24"])])
    mode = target.stat().st_mode & 0o777
    assert mode == 0o600
