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

import asyncio
import sys

from mcp.server.fastmcp import FastMCP

from . import audit
from .tools import gobuster, nikto, nmap, passive, sslscan

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


# ---------- passive tools (no authorization required) ----------

@mcp.tool()
async def whois_lookup(query: str, timeout_seconds: int = 30) -> dict:
    """Whois registration lookup for a domain or IP. No auth required."""
    return await passive.whois_lookup(query=query, timeout_seconds=timeout_seconds)


@mcp.tool()
async def dig_record(domain: str, record_type: str = "A", timeout_seconds: int = 30) -> dict:
    """DNS lookup for `domain`. record_type: A/AAAA/MX/TXT/NS/CNAME/SOA/etc.

    No auth required — dig hits the resolver, not the target.
    """
    return await passive.dig_record(
        domain=domain, record_type=record_type, timeout_seconds=timeout_seconds,
    )


@mcp.tool()
async def searchsploit_search(keyword: str, timeout_seconds: int = 30) -> dict:
    """Local Exploit-DB search via `searchsploit`. No auth — local-only."""
    return await passive.searchsploit_search(keyword=keyword, timeout_seconds=timeout_seconds)


@mcp.tool()
async def cert_dump(host: str, port: int = 443, timeout_seconds: int = 30) -> dict:
    """Dump TLS cert chain for `host:port` via openssl s_client.

    No auth required — single TLS handshake, equivalent to a browser
    visiting the site. Useful for pre-engagement cert/CN/SAN review.
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
