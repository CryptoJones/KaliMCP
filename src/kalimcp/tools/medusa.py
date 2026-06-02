# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Aaron K. Clark
"""medusa wrapper — alternative network logon brute-forcer to hydra.

Where hydra reads stably from rockyou.txt / a wordlist, medusa
supports a different set of protocol modules (notably ``-M cvs``,
``-M afp``, and a more forgiving ``-M smbnt``). Operators carry
both in their kit; KaliMCP exposes both for symmetry.

Output is line-oriented:

  ACCOUNT CHECK: [smbnt] Host: 192.168.1.10 (1 of 1, 0 complete) User: alice (1 of 1, 0 complete) Password: hunter2 (1 of 1 complete)
  ACCOUNT FOUND: [smbnt] Host: 192.168.1.10 User: alice Password: hunter2 [SUCCESS]

We extract the ``ACCOUNT FOUND`` lines.
"""

from __future__ import annotations

import re
from typing import Any

from .. import run
from ._active import active_tool


def _empty_parsed() -> dict[str, Any]:
    return {
        "success": False,
        "credentials_found": [],
        "hosts_tested": [],
        "services_tested": [],
        "statistics": {},
    }


_FOUND_LINE = re.compile(
    r"ACCOUNT\s+FOUND:\s*\[(?P<module>[^\]]+)\]\s+"
    r"Host:\s+(?P<host>\S+)\s+"
    r"User:\s+(?P<user>\S+)\s+"
    r"Password:\s+(?P<password>\S+)\s+\[SUCCESS\]"
)


def _parse_output(text: str) -> dict[str, Any]:
    parsed = _empty_parsed()
    if "ACCOUNT CHECK" in text or "ACCOUNT FOUND" in text:
        parsed["success"] = True
    for m in _FOUND_LINE.finditer(text):
        parsed["credentials_found"].append({
            "host": m.group("host"),
            "service": m.group("module"),
            "username": m.group("user"),
            "password": m.group("password"),
        })
    if parsed["credentials_found"]:
        parsed["hosts_tested"] = list(
            dict.fromkeys(c["host"] for c in parsed["credentials_found"])
        )
        parsed["services_tested"] = list(
            dict.fromkeys(c["service"] for c in parsed["credentials_found"])
        )
    return parsed


@active_tool(tool_name="medusa", secret_flags={"-P", "-p", "-U", "-u"})
async def crack(
    *,
    target: str,
    module: str = "ssh",
    user_list: str = "",
    pass_list: str = "",
    threads: int = 4,
    timeout_seconds: int = 300,
) -> dict[str, Any]:
    """Run medusa against ``target`` using protocol module ``module``.

    Args:
      target: hostname / IP of the service.
      module: medusa module name (``ssh``, ``ftp``, ``smbnt``,
        ``http``, etc.). See ``medusa -d`` for the full list.
      user_list: path to username file. Required.
      pass_list: path to password file. Required.
      threads: concurrent attempts per host (default 4; cap 32).
      timeout_seconds: hard wallclock cap (default 300).

    Returns the structured ``kalimcp.run.run`` result dict augmented
    with ``parsed``: ``{success, credentials_found: [{host, service,
    username, password}], hosts_tested, services_tested,
    statistics}``.
    """
    if not user_list or not pass_list:
        return {
            "exit_code": -1,
            "elapsed_s": 0,
            "stdout": "",
            "stderr": "medusa needs both `user_list` and `pass_list`.",
            "truncated": False,
            "timed_out": False,
            "argv": [],
            "parsed": _empty_parsed(),
        }
    threads = max(1, min(int(threads), 32))
    argv = [
        "medusa",
        "-h", target,
        "-U", user_list,
        "-P", pass_list,
        "-M", module,
        "-t", str(threads),
        "-F",  # stop on first success per host
    ]
    result = await run.run(argv, timeout=timeout_seconds)
    stdout = result.get("stdout", "") or ""
    if stdout.strip():
        result["parsed"] = _parse_output(stdout)
    else:
        result["parsed"] = _empty_parsed()
    return result
