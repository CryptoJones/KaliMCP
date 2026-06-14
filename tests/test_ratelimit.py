# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Aaron K. Clark
"""Tests for the opt-in active-tool rate limiter."""

from __future__ import annotations

import pytest

from kalimcp import ratelimit
from kalimcp.tools._active import active_tool


def test_token_bucket_burst_then_block_then_refill():
    bucket = ratelimit.TokenBucket(rate_per_minute=60, burst=3)
    for _ in range(3):
        bucket.acquire()
    with pytest.raises(ratelimit.RateLimitError):
        bucket.acquire()
    # Refill ~1 token/sec at 60/min; force the clock forward.
    bucket._updated -= 2.0
    bucket.acquire()  # should not raise


def test_acquire_is_noop_when_disabled(monkeypatch):
    monkeypatch.setattr(ratelimit, "_BUCKET", None)
    # No exception, no matter how many times.
    for _ in range(100):
        ratelimit.acquire()


def test_acquire_enforces_when_enabled(monkeypatch):
    monkeypatch.setattr(ratelimit, "_BUCKET", ratelimit.TokenBucket(60, 1))
    ratelimit.acquire()
    with pytest.raises(ratelimit.RateLimitError):
        ratelimit.acquire()


def test_bucket_from_env(monkeypatch):
    monkeypatch.delenv("KALIMCP_RATE_PER_MINUTE", raising=False)
    assert ratelimit._bucket_from_env() is None  # disabled by default
    monkeypatch.setenv("KALIMCP_RATE_PER_MINUTE", "30")
    monkeypatch.setenv("KALIMCP_RATE_BURST", "5")
    bucket = ratelimit._bucket_from_env()
    assert bucket is not None and bucket.burst == 5
    # Invalid values disable rather than crash the server.
    monkeypatch.setenv("KALIMCP_RATE_PER_MINUTE", "not-a-number")
    assert ratelimit._bucket_from_env() is None


async def test_active_tool_rate_limited(monkeypatch):
    """A configured limit short-circuits an active tool with a clean error."""
    monkeypatch.setattr(ratelimit, "_BUCKET", ratelimit.TokenBucket(60, 1))

    @active_tool("dummy")
    async def dummy(target: str) -> dict[str, object]:
        return {"argv": [], "exit_code": 0}

    first = await dummy(target="example.com")
    blocked = await dummy(target="example.com")
    assert first["ok"] is True
    assert blocked["ok"] is False
    assert blocked["error"] == "rate_limited"
