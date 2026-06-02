# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Aaron K. Clark
"""One-shot Windows command execution via WinRM.

Wraps ``netexec winrm <host> -u USER -p PASS -X "<powershell>"``.
Cleaner than spinning up evil-winrm for a single command — the
parsed result is the captured output of the command, suitable for
agents driving lateral-movement workflows.

Use the more general ``netexec_spray`` if you need to spray
credentials. This tool is exec-only: one host, one credential pair,
one command.
"""

from __future__ import annotations

import re
from typing import Any

from .. import run
from ._active import active_tool

_PROMPT_LINE = re.compile(r"^WINRM\s+\S+\s+\d+\s+\S+\s+(?:\[\*\]|\[\+\])")


def _parse_output(text: str) -> dict[str, Any]:
    """Strip netexec's banner / progress markers and keep command output.

    netexec prefixes its own lines with ``WINRM 192.168.1.10 5985 …
    [*] …``. The command's actual output appears un-prefixed; we
    keep those lines verbatim.
    """
    output: list[str] = []
    for line in text.splitlines():
        s = line.rstrip()
        if not s:
            output.append("")
            continue
        if _PROMPT_LINE.match(s):
            continue
        output.append(s)
    # Drop trailing blank lines so the parsed output looks tidy.
    while output and not output[-1]:
        output.pop()
    return {"output_lines": output}


@active_tool(
    tool_name="winrm-exec",
    secret_flags={"-p", "--password", "-H", "--hash"},
)
async def execute(
    *,
    target: str,
    username: str,
    command: str,
    password: str = "",
    nthash: str = "",
    timeout_seconds: int = 120,
) -> dict[str, Any]:
    """Run a single PowerShell command on a Windows host over WinRM.

    Args:
      target: hostname / IP.
      username: AD or local user.
      command: PowerShell command literal.
      password: cleartext password (mutually exclusive with nthash).
      nthash: NTLM hash for pass-the-hash.
      timeout_seconds: hard wallclock cap (default 120).

    Returns ``parsed``: ``{output_lines: [...]}`` — the captured
    output of the command, with netexec's prefix lines stripped.
    """
    if not (password or nthash):
        return {
            "exit_code": -1,
            "elapsed_s": 0,
            "stdout": "",
            "stderr": "winrm_exec needs `password=` or `nthash=`.",
            "truncated": False,
            "timed_out": False,
            "argv": [],
            "parsed": {"output_lines": []},
        }
    argv: list[str] = ["netexec", "winrm", target, "-u", username]
    if nthash:
        argv.extend(["-H", nthash])
    else:
        argv.extend(["-p", password])
    # -X runs a PowerShell command; -x runs cmd. Default to powershell.
    argv.extend(["-X", command])

    result = await run.run(argv, timeout=timeout_seconds)
    stdout = result.get("stdout", "") or ""
    result["parsed"] = _parse_output(stdout) if stdout.strip() else {"output_lines": []}
    return result
