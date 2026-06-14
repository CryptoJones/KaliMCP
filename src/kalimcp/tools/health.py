# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Aaron K. Clark
"""Capability / health probe (issue #19).

Reports which of the wrapped binaries are actually present on PATH, so an
agent can degrade gracefully ("nikto isn't installed, skip the web-vuln
step") instead of discovering a `ToolNotInstalled` mid-scan. Presence is a
pure `shutil.which` check — no subprocess — so the probe is fast and safe
to call often. Versions are opt-in (`check_versions=True`) because that
spawns one short subprocess per present binary.
"""

from __future__ import annotations

import shutil
from typing import Any

from .. import run

# Logical capability -> the binary it needs on PATH. Keyed so the agent can
# map a missing binary back to the MCP tool(s) it disables.
_BINARIES: dict[str, str] = {
    "nmap_scan": "nmap",
    "nikto_scan": "nikto",
    "gobuster_dir": "gobuster",
    "ffuf_fuzz": "ffuf",
    "whatweb_fingerprint": "whatweb",
    "sslscan_scan": "sslscan",
    "smb_enum": "enum4linux-ng",
    "snmp_enum": "snmp-check",
    "ldap_enum": "ldapsearch",
    "traceroute_path": "traceroute",
    "hydra_crack": "hydra",
    "medusa_crack": "medusa",
    "netexec_spray": "netexec",
    "john_crack": "john",
    "hashcat_crack": "hashcat",
    "sqlmap_scan": "sqlmap",
    "impacket_getnpusers": "impacket-GetNPUsers",
    "impacket_getuserspns": "impacket-GetUserSPNs",
    "impacket_secretsdump": "impacket-secretsdump",
    "impacket_smbclient": "impacket-smbclient",
    "winrm_exec": "netexec",
    "msfvenom_payload": "msfvenom",
    "whois_lookup": "whois",
    "dig_record": "dig",
    "searchsploit_search": "searchsploit",
    "cert_dump": "openssl",
    "tshark_pcap": "tshark",
    "strings_extract": "strings",
    "nm_symbols": "nm",
    "objdump_inspect": "objdump",
}

# How to ask each binary for its version (best-effort, opt-in). Most take
# --version; a few differ. Anything absent here is skipped even when
# check_versions is on.
_VERSION_FLAG: dict[str, list[str]] = {
    "nmap": ["--version"], "nikto": ["-Version"], "gobuster": ["version"],
    "ffuf": ["-V"], "sslscan": ["--version"], "hydra": ["-h"],
    "sqlmap": ["--version"], "john": ["--version"], "hashcat": ["--version"],
    "netexec": ["--version"], "medusa": ["-V"], "whois": ["--version"],
    "openssl": ["version"], "tshark": ["--version"], "traceroute": ["--version"],
    "strings": ["--version"], "nm": ["--version"], "objdump": ["--version"],
}


async def capabilities(
    *, check_versions: bool = False, timeout_seconds: int = 5
) -> dict[str, Any]:
    """Report which wrapped binaries are installed.

    Returns ``{tools: [{tool, binary, available, path?, version?}],
    available, total}``. With ``check_versions=True`` each present binary
    is probed for a one-line version string (best-effort).
    """
    tools: list[dict[str, Any]] = []
    for tool, binary in sorted(_BINARIES.items()):
        path = shutil.which(binary)
        entry: dict[str, Any] = {
            "tool": tool,
            "binary": binary,
            "available": path is not None,
        }
        if path:
            entry["path"] = path
            if check_versions and binary in _VERSION_FLAG:
                entry["version"] = await _probe_version(binary, timeout_seconds)
        tools.append(entry)

    available = sum(1 for t in tools if t["available"])
    return {"tools": tools, "available": available, "total": len(tools)}


async def _probe_version(binary: str, timeout_seconds: int) -> str:
    """Best-effort first non-empty line of the binary's version output."""
    try:
        result = await run.run([binary, *_VERSION_FLAG[binary]], timeout=timeout_seconds)
    except run.ToolNotInstalled:
        return ""
    text = (result.get("stdout") or "") + (result.get("stderr") or "")
    for line in text.splitlines():
        line = line.strip()
        if line:
            return line[:200]
    return ""
