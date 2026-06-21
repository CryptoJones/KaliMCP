# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Aaron K. Clark
"""kerbrute wrappers — AD Kerberos pre-auth username enumeration and
password spraying.

kerbrute talks to a domain controller's KDC (UDP/TCP 88) using
Kerberos pre-authentication, so a single AS-REQ tells you whether a
username is valid (and, when spraying, whether a password is valid)
without ever touching SMB/LDAP or tripping an account-lockout the way
an SMB spray would. Both wrappers probe the DC, so both go through
``@active_tool``.

  - kerbrute_userenum     (kerbrute userenum)     — valid usernames
  - kerbrute_passwordspray (kerbrute passwordspray) — valid user:pass

The spray's ``password`` kwarg is redacted out of the audit log by
value: ``password`` is in ``_active._DEFAULT_SECRET_KWARGS`` so the
decorator hashes the literal out of the logged argv even though it
rides in as a trailing positional with no flag pointing at it.
"""

from __future__ import annotations

import re
from typing import Any

from .. import run
from ._active import active_tool

# kerbrute prints `[+] VALID USERNAME:  user@domain` on a hit.
_VALID_USER = re.compile(r"\[\+\]\s*VALID USERNAME:\s*(\S+)")
# kerbrute prints `[+] VALID LOGIN:  user@domain:password` on a hit.
_VALID_LOGIN = re.compile(r"\[\+\]\s*VALID LOGIN:\s*(\S+?):(.*)$")


@active_tool(tool_name="kerbrute-userenum")
async def userenum(
    *,
    target: str,
    dc_ip: str,
    user_list: str,
    timeout_seconds: int = 300,
) -> dict[str, Any]:
    """Enumerate valid AD usernames via Kerberos pre-auth.

    Args:
      target: AD domain (e.g. ``corp.local``).
      dc_ip: domain controller IP / hostname (the KDC).
      user_list: path to a newline-delimited username file.
      timeout_seconds: hard wallclock cap (default 300).

    Returns ``parsed``: ``{valid_users: ["user@domain", ...]}``.
    """
    empty: dict[str, Any] = {"valid_users": []}

    err = run.validate_arg(target, "target", parsed=empty)
    if err:
        return err
    err = run.validate_arg(dc_ip, "dc_ip", parsed=empty)
    if err:
        return err
    err = run.validate_file(user_list, "user_list", parsed=empty)
    if err:
        return err

    argv: list[str] = [
        "kerbrute", "userenum", "--dc", dc_ip, "-d", target, user_list,
    ]
    result = await run.run(argv, timeout=timeout_seconds)
    stdout = result.get("stdout", "") or ""
    parsed: dict[str, Any] = {"valid_users": []}
    for line in stdout.splitlines():
        m = _VALID_USER.search(line)
        if m:
            parsed["valid_users"].append(m.group(1))
    result["parsed"] = parsed
    return result


@active_tool(tool_name="kerbrute-spray")
async def passwordspray(
    *,
    target: str,
    dc_ip: str,
    user_list: str,
    password: str,
    timeout_seconds: int = 300,
) -> dict[str, Any]:
    """Spray a single password across an AD username list.

    ``password`` is a dedicated keyword so the active-tool decorator
    redacts its literal value out of the audit log (it rides in as a
    trailing positional with no flag pointing at it).

    Args:
      target: AD domain (e.g. ``corp.local``).
      dc_ip: domain controller IP / hostname (the KDC).
      user_list: path to a newline-delimited username file.
      password: the single password to try for every user.
      timeout_seconds: hard wallclock cap (default 300).

    Returns ``parsed``:
    ``{valid_logins: [{user: "user@domain", password: "..."}]}``.
    """
    empty: dict[str, Any] = {"valid_logins": []}

    err = run.validate_arg(target, "target", parsed=empty)
    if err:
        return err
    err = run.validate_arg(dc_ip, "dc_ip", parsed=empty)
    if err:
        return err
    err = run.validate_file(user_list, "user_list", parsed=empty)
    if err:
        return err

    argv: list[str] = [
        "kerbrute", "passwordspray", "--dc", dc_ip, "-d", target,
        user_list, password,
    ]
    result = await run.run(argv, timeout=timeout_seconds)
    stdout = result.get("stdout", "") or ""
    parsed: dict[str, Any] = {"valid_logins": []}
    for line in stdout.splitlines():
        m = _VALID_LOGIN.search(line)
        if m:
            parsed["valid_logins"].append({
                "user": m.group(1),
                "password": m.group(2).strip(),
            })
    result["parsed"] = parsed
    return result
