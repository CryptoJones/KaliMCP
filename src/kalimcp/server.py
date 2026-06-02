# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Aaron K. Clark
"""MCP server entry point. Exposes Kali tools as MCP tools.

Transport: stdio (default). The MCP client launches this process
and talks JSON-RPC over stdin/stdout.

To use with Claude Code, add this to ~/.claude/mcp.json:

    {
      "mcpServers": {
        "kalimcp": {
          "command": "kalimcp"
        }
      }
    }

Or, if running through Docker:

    {
      "mcpServers": {
        "kalimcp": {
          "command": "docker",
          "args": ["run", "-i", "--rm",
                   "-v", "~/.kalimcp:/root/.kalimcp",
                   "ghcr.io/cryptojones/kalimcp:latest"]
        }
      }
    }
"""

from __future__ import annotations

import sys

from mcp.server.fastmcp import FastMCP

from . import audit
from .tools import (
    ffuf,
    gobuster,
    hydra,
    ldap,
    nikto,
    nmap,
    passive,
    smb,
    snmp,
    sqlmap,
    sslscan,
    whatweb,
)

mcp = FastMCP("kalimcp")


# ---------- active-scan tools ----------

@mcp.tool()
async def nmap_scan(
    target: str,
    profile: str = "tcp-fast",
    timeout_seconds: int = 300,
) -> dict:
    """Run nmap against `target` using a named profile.

    Profiles: tcp-fast, tcp-full, service-scan,
    udp-top-50, ping-sweep.
    """
    return await nmap.scan(
        target=target,
        profile=profile,
        timeout_seconds=timeout_seconds,
    )


@mcp.tool()
async def nikto_scan(
    target: str,
    ssl: bool = False,
    timeout_seconds: int = 600,
) -> dict:
    """Run nikto web-vulnerability scanner against `target` URL.
    """
    return await nikto.scan(
        target=target,
        ssl=ssl,
        timeout_seconds=timeout_seconds,
    )


@mcp.tool()
async def gobuster_dir(
    target: str,
    wordlist: str | None = None,
    threads: int = 10,
    timeout_seconds: int = 600,
) -> dict:
    """Directory brute-forcing on `target` URL via gobuster.
    Wordlist defaults to a known Kali path (dirb common.txt etc.).
    """
    return await gobuster.dir_scan(
        target=target,
        wordlist=wordlist,
        threads=threads,
        timeout_seconds=timeout_seconds,
    )


@mcp.tool()
async def sslscan_scan(
    target: str,
    port: int = 443,
    timeout_seconds: int = 120,
) -> dict:
    """Enumerate TLS protocols, ciphers, cert for `target:port` via sslscan.
    """
    return await sslscan.scan(
        target=target,
        port=port,
        timeout_seconds=timeout_seconds,
    )


@mcp.tool()
async def hydra_crack(
    target: str,
    service: str,
    username_list: str = "",
    password_list: str = "",
    profile: str = "standard",
    timeout_seconds: int = 300,
) -> dict:
    """Network logon brute-force against `target`'s `service` via hydra.

    Profiles: quick (fasttrack list), standard (rockyou),
    comprehensive (rockyou + 16 tasks), bruteforce (charset walk).
    Pass `username_list` / `password_list` to override profile defaults.
    `service` is a hydra service spec: ssh, ftp, smb, http-post-form, etc.
    """
    return await hydra.crack(
        target=target,
        service=service,
        username_list=username_list,
        password_list=password_list,
        profile=profile,
        timeout_seconds=timeout_seconds,
    )


@mcp.tool()
async def sqlmap_scan(
    target: str,
    profile: str = "standard",
    timeout_seconds: int = 600,
) -> dict:
    """Automated SQL injection probe against a URL via sqlmap.

    Profiles: quick (level 1, risk 1), standard (level 2, risk 2),
    comprehensive (level 3, risk 3), exploit (level 5, risk 3,
    all techniques). `target` should be a full URL including the
    parameter to test, e.g. http://host/page.php?id=1.
    """
    return await sqlmap.scan(
        target=target,
        profile=profile,
        timeout_seconds=timeout_seconds,
    )


@mcp.tool()
async def ffuf_fuzz(
    target: str,
    mode: str = "dir",
    wordlist: str | None = None,
    vhost_template: str | None = None,
    threads: int = 40,
    timeout_seconds: int = 600,
) -> dict:
    """Fast web fuzzer (ffuf). Substitutes wordlist entries into FUZZ.

    Modes: `dir` (URL path; pass `https://host/FUZZ`), `vhost`
    (Host header; pass base URL + `vhost_template` like
    `"FUZZ.example.com"`), `param` (pass `https://host/?FUZZ=test`),
    `ext` (file extension fuzzing). More flexible than gobuster.
    """
    return await ffuf.fuzz(
        target=target,
        mode=mode,
        wordlist=wordlist,
        vhost_template=vhost_template,
        threads=threads,
        timeout_seconds=timeout_seconds,
    )


@mcp.tool()
async def whatweb_fingerprint(
    target: str,
    aggression: int = 1,
    timeout_seconds: int = 120,
) -> dict:
    """HTTP / web-app fingerprint of a URL via whatweb.

    Identifies the server, CMS (WordPress / Drupal / Joomla / …),
    JS frameworks, analytics trackers. `aggression` 1 (passive) to
    4 (heavy intrusive probes).
    """
    return await whatweb.fingerprint(
        target=target,
        aggression=aggression,
        timeout_seconds=timeout_seconds,
    )


@mcp.tool()
async def smb_enum(target: str, timeout_seconds: int = 300) -> dict:
    """SMB enumeration via enum4linux-ng.

    Pulls shares, users, groups, OS info, signing status, and
    null-session ability from a Windows / Samba target.
    """
    return await smb.enumerate(target=target, timeout_seconds=timeout_seconds)


@mcp.tool()
async def snmp_enum(
    target: str,
    community: str = "public",
    timeout_seconds: int = 180,
) -> dict:
    """SNMP enumeration via snmp-check. Default community is `public`."""
    return await snmp.enumerate(
        target=target,
        community=community,
        timeout_seconds=timeout_seconds,
    )


@mcp.tool()
async def ldap_enum(
    target: str,
    port: int = 389,
    timeout_seconds: int = 60,
) -> dict:
    """Anonymous LDAP / AD rootDSE query via ldapsearch. Port 636 for LDAPS."""
    return await ldap.enumerate(
        target=target,
        port=port,
        timeout_seconds=timeout_seconds,
    )


# ---------- passive tools ----------
# These hit registry / DNS / local search, not the target itself.
# The refuse-list guard on active-scan tools doesn't apply here —
# a whois lookup for chase.com is harmless; an nmap scan of it isn't.

@mcp.tool()
async def whois_lookup(query: str, timeout_seconds: int = 30) -> dict:
    """Whois registration lookup for a domain or IP."""
    return await passive.whois_lookup(query=query, timeout_seconds=timeout_seconds)


@mcp.tool()
async def dig_record(domain: str, record_type: str = "A", timeout_seconds: int = 30) -> dict:
    """DNS lookup for `domain`. record_type: A/AAAA/MX/TXT/NS/CNAME/SOA/etc.

    Hits the resolver, not the target.
    """
    return await passive.dig_record(
        domain=domain, record_type=record_type, timeout_seconds=timeout_seconds,
    )


@mcp.tool()
async def searchsploit_search(keyword: str, timeout_seconds: int = 30) -> dict:
    """Local Exploit-DB search via `searchsploit` — entirely local."""
    return await passive.searchsploit_search(keyword=keyword, timeout_seconds=timeout_seconds)


@mcp.tool()
async def cert_dump(host: str, port: int = 443, timeout_seconds: int = 30) -> dict:
    """Dump TLS cert chain for `host:port` via openssl s_client.

    Single TLS handshake, equivalent to a browser visiting the site.
    Useful for pre-engagement cert / CN / SAN review.
    """
    return await passive.cert_dump(host=host, port=port, timeout_seconds=timeout_seconds)


def main() -> int:
    """Console entry: launch the stdio MCP server."""
    # Resolve the audit log path eagerly so the operator gets the
    # fallback breadcrumb (if any) before the first tool fires.
    audit.configure()
    try:
        mcp.run()
    except KeyboardInterrupt:
        return 0
    return 0


if __name__ == "__main__":
    sys.exit(main())
