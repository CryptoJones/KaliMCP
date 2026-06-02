# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Aaron K. Clark
"""hashcat wrapper — GPU-accelerated offline hash cracking.

Same run-then-show pattern as john: first crack pass, then
``hashcat --show`` to scrape the pot file. ``target`` in the
audit log is the hashfile path.
"""

from __future__ import annotations

from typing import Any

from .. import run
from ._active import active_tool


def _empty_parsed() -> dict[str, Any]:
    return {
        "cracked": [],
        "mode": None,
        "remaining": None,
        "total_hashes": None,
    }


def _parse_show(text: str) -> dict[str, Any]:
    """`hashcat --show` emits ``<hash>:<plaintext>`` lines, one per crack."""
    parsed = _empty_parsed()
    for line in text.splitlines():
        s = line.rstrip()
        if not s or s.startswith(("#", "hashcat", "[")):
            continue
        # Hashcat hashes commonly contain `:` themselves (e.g.
        # NTLMv2). The last colon-separated field is the plaintext.
        idx = s.rfind(":")
        if idx <= 0:
            continue
        h = s[:idx]
        plaintext = s[idx + 1:]
        parsed["cracked"].append({"hash": h, "password": plaintext})
    parsed["total_hashes"] = len(parsed["cracked"])
    return parsed


@active_tool(tool_name="hashcat", secret_flags={"-r", "--rules-file"})
async def crack(
    *,
    target: str,
    mode: int,
    wordlist: str = "/usr/share/wordlists/rockyou.txt",
    attack_mode: int = 0,
    timeout_seconds: int = 600,
) -> dict[str, Any]:
    """Crack hashes with hashcat.

    Args:
      target: hashfile path.
      mode: hashcat ``-m`` value (1000 = NTLM, 1800 = sha512crypt,
        5600 = NetNTLMv2, etc.). Required — no default because the
        wrong mode silently produces zero cracks.
      wordlist: wordlist path. Defaults to rockyou.txt.
      attack_mode: hashcat ``-a`` (0 = straight wordlist, 3 =
        brute-force mask, etc.). Default 0.
      timeout_seconds: hard wallclock cap (default 600).

    Returns the structured ``kalimcp.run.run`` result dict augmented
    with ``parsed``: ``{cracked: [{hash, password}], mode,
    remaining, total_hashes}``.
    """
    argv = [
        "hashcat",
        f"-m={int(mode)}",
        f"-a={int(attack_mode)}",
        "--quiet",
        target,
        wordlist,
    ]
    crack_result = await run.run(argv, timeout=timeout_seconds)

    show_argv = ["hashcat", f"-m={int(mode)}", "--show", target]
    show_timeout = min(60, max(15, timeout_seconds // 10))
    show_result = await run.run(show_argv, timeout=show_timeout)

    stdout = show_result.get("stdout", "") or ""
    parsed = _parse_show(stdout) if stdout.strip() else _empty_parsed()
    parsed["mode"] = int(mode)

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
