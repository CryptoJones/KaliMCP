# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Aaron K. Clark
"""netexec wrapper — credential spraying across SMB/WinRM/LDAP/MSSQL/SSH/FTP.

netexec (the successor to crackmapexec) tries a (user, pass) pair
against a list of hosts and reports per-host success / failure.
Output is line-oriented and stable across versions; we parse the
``[+]`` / ``[-]`` markers into a structured ``parsed`` block.

This tool wraps a credential-spraying primitive — the operator's
password / hash MUST appear on the command line. The audit log
``argv`` field is redacted via the decorator's ``secret_flags``
mechanism so the secret literal never lands in
``/var/log/kalimcp.log``.
"""

from __future__ import annotations

import re
from typing import Any

from .. import run
from ._active import active_tool

_PROTOCOLS = ("smb", "winrm", "ldap", "mssql", "ssh", "ftp", "rdp", "wmi", "vnc")


def _empty_parsed() -> dict[str, Any]:
    return {
        "protocol": "",
        "successes": [],
        "failures_count": 0,
    }


# netexec emits per-host lines like:
#   SMB         192.168.1.10    445    DC01             [*] Windows Server 2019
#   SMB         192.168.1.10    445    DC01             [+] CORP\admin:Password123 (Pwn3d!)
#   SMB         192.168.1.20    445    WS01             [-] CORP\user:wrongpass STATUS_LOGON_FAILURE
_SUCCESS_LINE = re.compile(
    r"^(?P<proto>[A-Z]+)\s+(?P<host>\S+)\s+\d+\s+\S+\s+\[\+\]\s+"
    r"(?P<userspec>\S+)"
    r"(?:\s+\((?P<flags>[^)]+)\))?"
)
_FAILURE_LINE = re.compile(r"^[A-Z]+\s+\S+\s+\d+\s+\S+\s+\[-\]")


def _split_userspec(userspec: str) -> tuple[str, str, str]:
    """Return (domain, user, secret) from ``DOMAIN\\user:password``."""
    domain = ""
    rest = userspec
    if "\\" in userspec:
        domain, rest = userspec.split("\\", 1)
    user, _, secret = rest.partition(":")
    return domain, user, secret


def _parse_output(text: str, protocol: str) -> dict[str, Any]:
    parsed = _empty_parsed()
    parsed["protocol"] = protocol
    for line in text.splitlines():
        s = line.strip()
        if not s:
            continue
        m = _SUCCESS_LINE.match(s)
        if m:
            domain, user, secret = _split_userspec(m.group("userspec"))
            flags = (m.group("flags") or "").lower()
            entry = {
                "host": m.group("host"),
                "proto": m.group("proto").lower(),
                "domain": domain,
                "user": user,
                "secret": secret,
                "pwned": "pwn3d" in flags,
            }
            parsed["successes"].append(entry)
            continue
        if _FAILURE_LINE.match(s):
            parsed["failures_count"] += 1
    return parsed


@active_tool(tool_name="netexec", secret_flags={"-p", "--password", "-H", "--hash"})
async def spray(
    *,
    target: str,
    protocol: str = "smb",
    username: str = "",
    password: str = "",
    user_list: str = "",
    pass_list: str = "",
    nthash: str = "",
    timeout_seconds: int = 600,
) -> dict[str, Any]:
    """Run netexec against `target` (host or CIDR) with one or more (user, pass) attempts.

    Args:
      target: hostname / IP / CIDR (netexec walks ranges natively).
      protocol: one of smb/winrm/ldap/mssql/ssh/ftp/rdp/wmi/vnc.
      username: single user (preferred over user_list when both
        are empty).
      password: single password literal.
      user_list: path to a username file.
      pass_list: path to a password file.
      nthash: NTLM hash for pass-the-hash (passed via -H).
      timeout_seconds: hard wallclock cap (default 600).

    Returns the structured ``kalimcp.run.run`` result dict augmented
    with ``parsed``: ``{protocol, successes: [{host, proto, domain,
    user, secret, pwned}], failures_count}``.
    """
    if protocol not in _PROTOCOLS:
        return {
            "exit_code": -1,
            "elapsed_s": 0,
            "stdout": "",
            "stderr": f"unknown protocol: {protocol!r}. Known: {list(_PROTOCOLS)}",
            "truncated": False,
            "timed_out": False,
            "argv": [],
            "parsed": _empty_parsed(),
        }
    if not any((username, user_list)):
        return {
            "exit_code": -1,
            "elapsed_s": 0,
            "stdout": "",
            "stderr": "no username material — pass `username=` or `user_list=`.",
            "truncated": False,
            "timed_out": False,
            "argv": [],
            "parsed": _empty_parsed(),
        }
    if not any((password, pass_list, nthash)):
        return {
            "exit_code": -1,
            "elapsed_s": 0,
            "stdout": "",
            "stderr": "no secret material — pass `password=`, `pass_list=`, or `nthash=`.",
            "truncated": False,
            "timed_out": False,
            "argv": [],
            "parsed": _empty_parsed(),
        }

    argv: list[str] = ["netexec", protocol, target]
    if user_list:
        argv.extend(["-u", user_list])
    elif username:
        argv.extend(["-u", username])
    if nthash:
        argv.extend(["-H", nthash])
    elif pass_list:
        argv.extend(["-p", pass_list])
    elif password:
        argv.extend(["-p", password])

    result = await run.run(argv, timeout=timeout_seconds)
    stdout = result.get("stdout", "") or ""
    if stdout.strip():
        result["parsed"] = _parse_output(stdout, protocol)
    else:
        parsed = _empty_parsed()
        parsed["protocol"] = protocol
        result["parsed"] = parsed
    return result
