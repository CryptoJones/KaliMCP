# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Aaron K. Clark
"""nmap wrapper — port + service scan with safety rails."""

from __future__ import annotations

from typing import Any

from .. import run
from ._active import active_tool

# Profiles intentionally limit what nmap can do. Operators who want
# fancier scans should add a profile here and submit a PR — not
# extend an arbitrary --extra-args parameter.
_PROFILES = {
    "tcp-fast":     ["-Pn", "-T4", "--top-ports", "100"],
    "tcp-full":     ["-Pn", "-T4", "-p-", "--max-retries", "1"],
    "service-scan": ["-Pn", "-sV", "-T4", "--top-ports", "100"],
    "udp-top-50":   ["-Pn", "-sU", "-T4", "--top-ports", "50"],
    "ping-sweep":   ["-sn", "-PE", "-T4"],
}


@active_tool(tool_name="nmap")
async def scan(
    *,
    target: str,
    profile: str = "tcp-fast",
    timeout_seconds: int = 300,
) -> dict[str, Any]:
    """Run an nmap scan against `target` using a named profile.

    Args:
      target: hostname, IP, or CIDR block.
      profile: one of {tcp-fast, tcp-full, service-scan, udp-top-50, ping-sweep}.
      timeout_seconds: hard wallclock cap (default 300).

    Returns the structured `kalimcp.run.run` result dict augmented
    with the profile name + nmap argv used.
    """
    if profile not in _PROFILES:
        return {
            "exit_code": -1,
            "elapsed_s": 0,
            "stdout": "",
            "stderr": f"unknown profile: {profile!r}. Known: {sorted(_PROFILES)}",
            "truncated": False,
            "timed_out": False,
            "profile": profile,
            "argv": [],
        }
    argv = ["nmap", *_PROFILES[profile], target]
    result = await run.run(argv, timeout=timeout_seconds)
    result["profile"] = profile
    return result
