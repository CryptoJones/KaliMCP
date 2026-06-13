# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Aaron K. Clark
"""traceroute wrapper — network path discovery to a target.

Unlike the loot-triage tools in ``passive.py``, traceroute actively
sends probes toward the target, so it goes through ``active_tool`` (scope
warning + audit + untrusted-output handling apply).
"""

from __future__ import annotations

from typing import Any

from .. import run
from ._active import active_tool


@active_tool(tool_name="traceroute")
async def trace(
    *,
    target: str,
    max_hops: int = 30,
    wait_seconds: int = 2,
    timeout_seconds: int = 120,
) -> dict[str, Any]:
    """Trace the network path to ``target`` (``traceroute -n``).

    Args:
      target: host or IP to trace toward.
      max_hops: TTL ceiling (``-m``, clamped 1..64).
      wait_seconds: per-hop response wait (``-w``, clamped 1..10).
      timeout_seconds: hard wallclock cap (default 120).

    ``-n`` skips reverse DNS so a hop's PTR record can't inject text into
    the output. Returns the raw traceroute result.
    """
    # target is the trailing positional — a leading dash would be read as
    # a traceroute flag (no validate_arg helper on this branch yet).
    if target.startswith("-") or any(c in target for c in ("\r", "\n", "\x00")):
        return run.error_result(f"invalid target: {target!r}")
    hops = max(1, min(int(max_hops), 64))
    wait = max(1, min(int(wait_seconds), 10))
    argv = ["traceroute", "-n", "-m", str(hops), "-w", str(wait), target]
    return await run.run(argv, timeout=timeout_seconds)
