# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Aaron K. Clark
"""Tests for the untrusted-output bounding helper (issue #11)."""

from __future__ import annotations

from kalimcp import untrusted


def test_bound_short_text_unchanged():
    text = "small banner: nginx/1.25"
    out, truncated = untrusted.bound(text, limit=1000)
    assert out == text
    assert truncated is False


def test_bound_empty_text():
    assert untrusted.bound("", limit=10) == ("", False)


def test_bound_long_text_truncated_with_marker():
    text = "A" * 5000
    out, truncated = untrusted.bound(text, limit=1000)
    assert truncated is True
    assert out.startswith("A" * 1000)
    assert "truncated 4000 chars" in out
    # The kept slice plus a short marker — never the full original.
    assert len(out) < len(text)


def test_bound_at_exact_limit_not_truncated():
    text = "B" * 1000
    out, truncated = untrusted.bound(text, limit=1000)
    assert out == text
    assert truncated is False


def test_env_override_limit(monkeypatch):
    monkeypatch.setenv("KALIMCP_MODEL_OUTPUT_LIMIT", "5")
    out, truncated = untrusted.bound("123456789")
    assert truncated is True
    assert out.startswith("12345")


def test_env_override_ignored_when_invalid(monkeypatch):
    monkeypatch.setenv("KALIMCP_MODEL_OUTPUT_LIMIT", "not-a-number")
    # Falls back to the module default — a short string isn't truncated.
    out, truncated = untrusted.bound("hello")
    assert (out, truncated) == ("hello", False)
