# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Aaron K. Clark
"""Passive lookups: whois, dig, searchsploit, openssl cert dump.

These do NOT actively probe the target's services. Whois and dig
hit registry / DNS infrastructure (not the target itself);
searchsploit is a local Exploit-DB grep; the openssl cert dump
opens a TLS handshake which is technically a network touch but
returns immediately after the cert exchange and is a normal
pre-engagement information-gathering step.

The refuse-list guard from `tools/_active.py` doesn't apply here —
a whois lookup for chase.com is harmless, an nmap scan of it
isn't. Passive calls still get audited so operators have a record
of what was looked up.
"""

from __future__ import annotations

from typing import Any

from .. import audit, run


async def _audited_run(tool: str, argv: list[str], timeout: int) -> dict[str, Any]:
    with audit.time_block() as elapsed:
        result = await run.run(argv, timeout=timeout)
    audit.log(
        "passive_invoke",
        tool=tool,
        argv=argv,
        elapsed_ms=elapsed(),
        exit_code=result.get("exit_code"),
    )
    return result


async def whois_lookup(*, query: str, timeout_seconds: int = 30) -> dict[str, Any]:
    """Whois registration lookup for a domain or IP."""
    return await _audited_run("whois", ["whois", "--", query], timeout_seconds)


async def dig_record(
    *,
    domain: str,
    record_type: str = "A",
    timeout_seconds: int = 30,
) -> dict[str, Any]:
    """DNS query via dig. record_type is A / AAAA / MX / TXT / NS / etc."""
    rtype = (record_type or "A").upper()
    if not rtype.isalpha() or len(rtype) > 16:
        return {
            "exit_code": -1, "elapsed_s": 0, "stdout": "",
            "stderr": f"invalid record_type: {record_type!r}",
            "truncated": False, "timed_out": False, "argv": [],
        }
    return await _audited_run("dig", ["dig", "+short", "+timeout=5", domain, rtype], timeout_seconds)


async def searchsploit_search(*, keyword: str, timeout_seconds: int = 30) -> dict[str, Any]:
    """Local Exploit-DB search via the `searchsploit` CLI."""
    return await _audited_run("searchsploit", ["searchsploit", "--no-colour", "--", keyword], timeout_seconds)


async def cert_dump(
    *,
    host: str,
    port: int = 443,
    timeout_seconds: int = 30,
) -> dict[str, Any]:
    """Dump the TLS certificate chain via `openssl s_client`."""
    argv = [
        "openssl", "s_client",
        "-connect", f"{host}:{int(port)}",
        "-servername", host,
        "-showcerts",
    ]
    # openssl s_client expects stdin EOF to finish; send empty stdin.
    with audit.time_block() as elapsed:
        result = await run.run(argv, timeout=timeout_seconds, stdin=b"")
    audit.log(
        "passive_invoke",
        tool="openssl-cert",
        argv=argv,
        elapsed_ms=elapsed(),
        exit_code=result.get("exit_code"),
    )
    return result
