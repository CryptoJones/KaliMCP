# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Aaron K. Clark
"""John the Ripper wrapper — offline hash cracking.

Two-pass invocation: first runs john against the hashfile with the
requested wordlist + format, then runs ``john --show`` to read
already-cracked hashes out of john.pot.

``target`` in the audit log is the hashfile path (offline tools
have no network target). The hashfile path itself can be sensitive
(``/loot/ntds-dump.txt``) so it goes through the redaction list.
"""

from __future__ import annotations

import re
from typing import Any

from .. import run
from ._active import active_tool


def _empty_parsed() -> dict[str, Any]:
    return {
        "cracked": [],
        "format": "",
        "remaining": None,
        "total_hashes": None,
    }


# `john --show` format:
#   alice:hunter2:1001:1001:Alice:/home/alice:/bin/bash
#   bob:s3cret:1002:1002:Bob:/home/bob:/bin/bash
#
#   2 password hashes cracked, 1 left
_SHOW_TAIL = re.compile(
    r"(?P<cracked>\d+)\s+password\s+hashes?\s+cracked,?\s*(?P<left>\d+)?\s*(?:left|remaining)?",
    re.IGNORECASE,
)


def _parse_show(text: str) -> dict[str, Any]:
    parsed = _empty_parsed()
    lines = text.splitlines()
    # Tail line carries the statistics; everything before that is a
    # cracked record.
    for line in lines:
        s = line.strip()
        if not s:
            continue
        m = _SHOW_TAIL.search(s)
        if m and "password hash" in s.lower():
            try:
                parsed["total_hashes"] = int(m.group("cracked"))
            except (TypeError, ValueError):
                pass
            left = m.group("left")
            if left is not None:
                try:
                    parsed["remaining"] = int(left)
                except (TypeError, ValueError):
                    pass
            continue
        if ":" in s:
            user, _, rest = s.partition(":")
            password, _, _ = rest.partition(":")
            parsed["cracked"].append({"user": user, "password": password})
    return parsed


@active_tool(tool_name="john", secret_flags={"--wordlist", "-w"})
async def crack(
    *,
    target: str,
    wordlist: str = "/usr/share/wordlists/rockyou.txt",
    format: str = "",
    timeout_seconds: int = 600,
) -> dict[str, Any]:
    """Crack hashes in ``target`` (a hashfile path) with john.

    Args:
      target: filesystem path to the hashfile.
      wordlist: wordlist path. Defaults to rockyou.txt.
      format: john ``--format=NAME`` (empty to let john auto-detect).
      timeout_seconds: hard wallclock cap (default 600).

    Returns the structured ``kalimcp.run.run`` result dict augmented
    with ``parsed``: ``{cracked: [{user, password}], format,
    remaining, total_hashes}``.

    Implementation: runs john --wordlist=... <hashfile>, then
    immediately runs john --show <hashfile> to scrape the pot
    file. Returns the *show* output in stdout because the run
    output is mostly progress noise that the agent doesn't want.
    """
    argv = ["john", f"--wordlist={wordlist}"]
    if format:
        argv.append(f"--format={format}")
    argv.append(target)
    crack_result = await run.run(argv, timeout=timeout_seconds)

    show_argv = ["john", "--show"]
    if format:
        show_argv.append(f"--format={format}")
    show_argv.append(target)
    # --show is fast; cap to ~30s.
    show_timeout = min(60, max(15, timeout_seconds // 10))
    show_result = await run.run(show_argv, timeout=show_timeout)

    # Surface the --show output (it carries the cracked hashes).
    stdout = show_result.get("stdout", "") or ""
    parsed = _parse_show(stdout) if stdout.strip() else _empty_parsed()
    if format:
        parsed["format"] = format

    # Combine the two runs. Keep the cracking-pass argv so the audit
    # log records it; the show-pass argv is internal plumbing.
    return {
        **crack_result,
        "argv": argv,
        "stdout": stdout,
        "stderr": (crack_result.get("stderr", "") or "")
                 + ("\n--- show ---\n" + (show_result.get("stderr", "") or "")
                    if show_result.get("stderr") else ""),
        "show_exit_code": show_result.get("exit_code"),
        "parsed": parsed,
    }
