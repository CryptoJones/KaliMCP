# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Aaron K. Clark
"""Tests for the FastMCP tool registration in server.py.

Catches regressions where someone accidentally drops a tool from
the registered set, renames one in a non-backward-compatible way,
or breaks the input schema of one (FastMCP infers the schema from
the wrapped coroutine's type hints; a typo in a parameter name
silently changes the public surface).
"""

from __future__ import annotations

import pytest

from kalimcp import server

# The full set of tools the server is expected to register. If any
# of these names changes the change is breaking — bump the package
# version and update CHANGELOG accordingly.
EXPECTED_TOOLS = {
    "nmap_scan",
    "nikto_scan",
    "gobuster_dir",
    "sslscan_scan",
    "hydra_crack",
    "sqlmap_scan",
    "ffuf_fuzz",
    "whatweb_fingerprint",
    "smb_enum",
    "snmp_enum",
    "ldap_enum",
    "netexec_spray",
    "medusa_crack",
    "john_crack",
    "hashcat_crack",
    "impacket_getnpusers",
    "impacket_getuserspns",
    "impacket_secretsdump",
    "impacket_smbclient",
    "winrm_exec",
    "msfvenom_payload",
    "traceroute_path",
    "whois_lookup",
    "dig_record",
    "searchsploit_search",
    "cert_dump",
    "tshark_pcap",
    "strings_extract",
    "nm_symbols",
    "objdump_inspect",
    # Engagement workspace
    "engagement_create",
    "engagement_list",
    "engagement_use",
    "engagement_status",
    "finding_record",
    "finding_query",
    "host_list",
    "cred_record",
    "cred_query",
    "loot_write",
    "loot_list",
    "loot_read",
    "note_append",
    "wordlist_list",
    "process_list",
    "process_kill",
}


@pytest.mark.asyncio
async def test_exactly_expected_tools_registered():
    """No additions or removals to the public tool set without a CHANGELOG bump."""
    tools = await server.mcp.list_tools()
    names = {t.name for t in tools}
    assert names == EXPECTED_TOOLS, (
        f"Tool surface drift detected. "
        f"missing: {EXPECTED_TOOLS - names}; extra: {names - EXPECTED_TOOLS}"
    )


@pytest.mark.asyncio
async def test_active_tools_no_longer_take_authorization_token():
    """Verifies the v0.2 breaking change is in effect.

    Active-scan tools used to take an `authorization_token` parameter.
    The v0.2 release dropped it. A regression that re-introduced it
    would silently break clients written against the v0.2 surface.
    """
    tools = await server.mcp.list_tools()
    active = (
        "nmap_scan", "nikto_scan", "gobuster_dir", "sslscan_scan",
        "hydra_crack", "sqlmap_scan",
        "ffuf_fuzz", "whatweb_fingerprint",
        "smb_enum", "snmp_enum", "ldap_enum",
        "netexec_spray", "medusa_crack",
        "john_crack", "hashcat_crack",
        "impacket_getnpusers", "impacket_getuserspns",
        "impacket_secretsdump", "impacket_smbclient",
        "winrm_exec", "msfvenom_payload",
    )
    for tool in tools:
        if tool.name not in active:
            continue
        # tool.inputSchema is a JSON Schema dict; property names live
        # under the "properties" key.
        props = (tool.inputSchema or {}).get("properties", {})
        assert "authorization_token" not in props, (
            f"{tool.name} still has an authorization_token parameter — "
            f"v0.2 dropped that. Regression."
        )


@pytest.mark.asyncio
async def test_hydra_crack_required_inputs():
    """hydra_crack should require `target` and `service`; the rest default."""
    tools = await server.mcp.list_tools()
    tool = next(t for t in tools if t.name == "hydra_crack")
    schema = tool.inputSchema or {}
    required = set(schema.get("required", []))
    assert "target" in required
    assert "service" in required
    props = schema.get("properties", {})
    for opt in ("username_list", "password_list", "profile", "timeout_seconds"):
        assert opt in props


@pytest.mark.asyncio
async def test_sqlmap_scan_required_inputs():
    """sqlmap_scan should require `target`; `profile` and `timeout_seconds` default."""
    tools = await server.mcp.list_tools()
    tool = next(t for t in tools if t.name == "sqlmap_scan")
    schema = tool.inputSchema or {}
    required = set(schema.get("required", []))
    assert "target" in required
    props = schema.get("properties", {})
    assert "profile" in props
    assert "timeout_seconds" in props


@pytest.mark.asyncio
async def test_nmap_scan_required_inputs():
    """nmap_scan should require `target`; `profile` and `timeout_seconds` have defaults."""
    tools = await server.mcp.list_tools()
    nmap_tool = next(t for t in tools if t.name == "nmap_scan")
    schema = nmap_tool.inputSchema or {}
    required = set(schema.get("required", []))
    assert "target" in required
    # The non-required fields should still appear in properties.
    props = schema.get("properties", {})
    assert "profile" in props
    assert "timeout_seconds" in props


@pytest.mark.asyncio
async def test_passive_tools_have_no_target_param():
    """Passive tools accept domain-specific param names (query/domain/host/keyword), not `target`."""
    tools = await server.mcp.list_tools()
    by_name = {t.name: t for t in tools}
    expected_keys = {
        "whois_lookup": "query",
        "dig_record": "domain",
        "searchsploit_search": "keyword",
        "cert_dump": "host",
    }
    for name, expected_param in expected_keys.items():
        props = (by_name[name].inputSchema or {}).get("properties", {})
        assert expected_param in props, f"{name} missing expected param {expected_param!r}"
