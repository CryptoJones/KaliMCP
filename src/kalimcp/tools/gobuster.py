# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Aaron K. Clark
"""gobuster wrapper — directory + DNS enumeration."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from .. import run
from ._active import active_tool

# Common wordlist paths on Kali — try each in order.
_WORDLIST_CANDIDATES = [
    "/usr/share/wordlists/dirb/common.txt",
    "/usr/share/wordlists/dirbuster/directory-list-2.3-small.txt",
    "/usr/share/seclists/Discovery/Web-Content/common.txt",
]


def _default_wordlist() -> str | None:
    for p in _WORDLIST_CANDIDATES:
        if Path(p).is_file():
            return p
    return None


@active_tool(tool_name="gobuster-dir")
async def dir_scan(
    *,
    target: str,
    wordlist: str | None = None,
    threads: int = 10,
    timeout_seconds: int = 600,
) -> dict[str, Any]:
    """Directory brute-forcing against `target` URL.

    Args:
      target: URL like `https://example.com/`.
      wordlist: path to wordlist. Defaults to a known Kali wordlist
        if one is present; returns an error otherwise.
      threads: concurrent requests (default 10; cap 50).
      timeout_seconds: hard wallclock cap (default 600).
    """
    wl = wordlist or _default_wordlist()
    if not wl:
        return {
            "exit_code": -1,
            "elapsed_s": 0,
            "stdout": "",
            "stderr": (
                "no wordlist available. Pass `wordlist=...` or install "
                "wordlists (apt install wordlists seclists)."
            ),
            "truncated": False,
            "timed_out": False,
            "argv": [],
        }
    if not Path(wl).is_file():
        return {
            "exit_code": -1,
            "elapsed_s": 0,
            "stdout": "",
            "stderr": f"wordlist not found: {wl}",
            "truncated": False,
            "timed_out": False,
            "argv": [],
        }
    threads = max(1, min(int(threads), 50))
    argv = [
        "gobuster", "dir",
        "-u", target,
        "-w", wl,
        "-t", str(threads),
        "--no-error",
    ]
    return await run.run(argv, timeout=timeout_seconds)
