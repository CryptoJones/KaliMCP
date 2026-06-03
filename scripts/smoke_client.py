#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Aaron K. Clark
"""Smoke-test MCP client for kalimcp.

Connects to the kalimcp MCP server over stdio, lists the exposed
tools, and runs one passive call (`dig_record`) plus one active
call (`nmap_scan` against 127.0.0.1) to verify end-to-end wiring.

No authorization token is required — the active-scan tools stopped
taking one in cc66cf8, and there is no refuse list. An active
engagement with a declared scope would emit a non-blocking
`out_of_scope` warning, but 127.0.0.1 trips nothing.

This is a manual smoke script, not a pytest test — it needs a real
`kalimcp` binary and a live nmap, so it is not collected by CI.

Usage:
    # via the venv-installed kalimcp script (preferred):
    python scripts/smoke_client.py

    # with an explicit binary path:
    KALIMCP_BIN=/path/to/.venv/bin/kalimcp python scripts/smoke_client.py
"""

from __future__ import annotations

import asyncio
import os
import shutil

from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client


def _kalimcp_bin() -> str:
    """Locate the kalimcp executable.

    Honors KALIMCP_BIN, falls back to whatever `kalimcp` resolves to
    on PATH (typically a venv with the package installed).
    """
    explicit = os.getenv("KALIMCP_BIN")
    if explicit:
        return explicit
    found = shutil.which("kalimcp")
    if found:
        return found
    raise RuntimeError(
        "Could not find a `kalimcp` binary. Set KALIMCP_BIN=/path/to/venv/bin/kalimcp "
        "or install the package into a venv on PATH."
    )


async def main() -> None:
    server_params = StdioServerParameters(
        command=_kalimcp_bin(),
        args=[],
        env=None,
    )

    print(f"Connecting to kalimcp via {server_params.command} ...")

    async with stdio_client(server_params) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()
            print("Connected.")

            tools_result = await session.list_tools()
            print("\nAvailable tools:")
            for tool in tools_result.tools:
                print(f"  - {tool.name}: {tool.description}")

            # 1. Passive call — exercises the audit-log path with no
            #    network reach into the target. dig hits a public
            #    resolver, not the queried domain itself.
            print("\n--- dig_record example.com A ---")
            try:
                dig_result = await session.call_tool(
                    "dig_record",
                    {"domain": "example.com", "record_type": "A"},
                )
                for content in dig_result.content:
                    if hasattr(content, "text"):
                        print(content.text)
            except Exception as e:
                print(f"Error calling dig_record: {e}")

            # 2. Active call — uses the loopback so no operator
            #    consent / scope question. Skip with NO_ACTIVE=1 if
            #    running somewhere nmap is disallowed.
            if os.getenv("NO_ACTIVE") == "1":
                print("\nSkipping active nmap_scan (NO_ACTIVE=1).")
                return

            print("\n--- nmap_scan 127.0.0.1 tcp-fast ---")
            try:
                nmap_result = await session.call_tool(
                    "nmap_scan",
                    {"target": "127.0.0.1", "profile": "tcp-fast"},
                )
                for content in nmap_result.content:
                    if hasattr(content, "text"):
                        print(content.text)
            except Exception as e:
                print(f"Error calling nmap_scan: {e}")


if __name__ == "__main__":
    asyncio.run(main())
