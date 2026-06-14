# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Aaron K. Clark
"""gobuster wrapper — directory + DNS enumeration.

gobuster v3+ has no clean JSON output mode. Its text output is
line-oriented and stable across releases:

    /admin   (Status: 301) [Size: 234] [--> /admin/]
    /api     (Status: 200) [Size: 4596]
    /index   (Status: 200) [Size: 1024]

``_parse_output`` extracts each match into a structured dict.
Agents consume ``parsed``; operators read raw ``stdout``.
"""

from __future__ import annotations

import re
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

# Path-finding line emitted by gobuster (`dir` mode). The size and
# redirect groups are optional — gobuster omits them when the target
# server doesn't return Content-Length, or when the status code isn't
# a redirect.
_PATH_LINE = re.compile(
    r"^(?P<path>\S+)\s+"
    r"\(Status:\s+(?P<status>\d+)\)"
    r"(?:\s+\[Size:\s+(?P<size>\d+)\])?"
    r"(?:\s+\[-->\s+(?P<redirect>[^\]]+)\])?"
    r"\s*$"
)


def _default_wordlist() -> str | None:
    for p in _WORDLIST_CANDIDATES:
        if Path(p).is_file():
            return p
    return None


def _empty_parsed() -> dict[str, Any]:
    return {"paths_found": []}


def _parse_output(text: str) -> dict[str, Any]:
    """Extract gobuster `dir`-mode findings from text output."""
    parsed = _empty_parsed()
    for line in text.splitlines():
        s = line.strip()
        if not s or s.startswith(("=", "-", "Gobuster", "[", "by ")):
            continue
        m = _PATH_LINE.match(s)
        if not m:
            continue
        entry: dict[str, Any] = {
            "path": m.group("path"),
            "status": int(m.group("status")),
        }
        size = m.group("size")
        if size is not None:
            entry["size"] = int(size)
        redirect = m.group("redirect")
        if redirect is not None:
            entry["redirect"] = redirect.strip()
        parsed["paths_found"].append(entry)
    return parsed


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

    Returns the structured ``kalimcp.run.run`` result dict augmented with:
      - ``parsed``: ``{paths_found: [{path, status, size?, redirect?}]}``.
        Raw output stays in ``stdout``.
    """
    wl = wordlist or _default_wordlist()
    if not wl:
        return run.error_result(
            "no wordlist available. Pass `wordlist=...` or install "
            "wordlists (apt install wordlists seclists).",
            parsed=_empty_parsed(),
        )
    if err := run.validate_file(wl, "wordlist", parsed=_empty_parsed()):
        return err
    threads = max(1, min(int(threads), 50))
    argv = [
        "gobuster", "dir",
        "-u", target,
        "-w", wl,
        "-t", str(threads),
        "--no-error",
    ]
    result = await run.run(argv, timeout=timeout_seconds)

    return run.distill(result, _parse_output, _empty_parsed)
