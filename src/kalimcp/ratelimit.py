# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Aaron K. Clark
"""Opt-in token-bucket rate limiting for active (network-hitting) tools.

KaliMCP is operator-driven: by default there is **no** rate limit, consistent
with "declaring scope is the operator's job" (see ``tools/_active.py``). Set
``KALIMCP_RATE_PER_MINUTE`` (and optionally ``KALIMCP_RATE_BURST``, default 10)
to bound how fast an agent can launch active scans. A runaway agent or a
prompt-injected loop then can't flood a target — or the operator's own box —
with back-to-back scans. Passive / read-only tools are never limited.

The bucket is a per-process singleton built from the environment at import. It's
accessed only from the asyncio event loop thread, so no lock is needed.
"""

from __future__ import annotations

import os
import time
from dataclasses import dataclass, field


class RateLimitError(RuntimeError):
    """Raised when the active-tool rate limit is exceeded."""


@dataclass
class TokenBucket:
    """Monotonic token-bucket limiter (DoS / fatigue resistance)."""

    rate_per_minute: float
    burst: int
    _tokens: float = field(init=False)
    _updated: float = field(init=False)

    def __post_init__(self) -> None:
        self._tokens = float(self.burst)
        self._updated = time.monotonic()

    def acquire(self, cost: float = 1.0) -> None:
        now = time.monotonic()
        self._tokens = min(
            self.burst, self._tokens + (now - self._updated) * (self.rate_per_minute / 60.0)
        )
        self._updated = now
        if self._tokens < cost:
            raise RateLimitError(
                f"Active-tool rate limit exceeded "
                f"(~{self.rate_per_minute:.0f}/min, burst {self.burst})."
            )
        self._tokens -= cost


def _bucket_from_env() -> TokenBucket | None:
    """Build a bucket from KALIMCP_RATE_* env vars, or None if disabled/invalid."""
    raw = os.environ.get("KALIMCP_RATE_PER_MINUTE")
    if not raw:
        return None
    try:
        rate = float(raw)
        burst = int(os.environ.get("KALIMCP_RATE_BURST", "10"))
    except ValueError:
        return None
    if rate <= 0 or burst <= 0:
        return None
    return TokenBucket(rate, burst)


_BUCKET: TokenBucket | None = _bucket_from_env()


def acquire(cost: float = 1.0) -> None:
    """Acquire one token if rate limiting is enabled; a no-op otherwise.

    Raises ``RateLimitError`` when the limit is configured and exhausted.
    """
    if _BUCKET is not None:
        _BUCKET.acquire(cost)
