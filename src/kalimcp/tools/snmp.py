# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Aaron K. Clark
"""SNMP enumeration wrapper — uses snmp-check.

snmp-check has no machine-readable output mode. Its text output is
section-headed (``[*] System information:`` etc.) and stable
enough to parse for the headline fields: hostname, system contact,
location, uptime, running processes, installed software, listening
services.
"""

from __future__ import annotations

import re
from typing import Any

from .. import run
from ._active import active_tool


def _empty_parsed() -> dict[str, Any]:
    return {
        "target": "",
        "community": "",
        "hostname": "",
        "contact": "",
        "location": "",
        "uptime": "",
        "description": "",
        "processes": [],
        "software": [],
        "services": [],
    }


# snmp-check section headers we care about (case-insensitive prefix
# match). The body of each section is line-oriented "key: value".
_SECTIONS = {
    "system information": "system",
    "user accounts": "users",
    "network interfaces": "interfaces",
    "processes": "processes",
    "software components": "software",
    "network services": "services",
}


def _parse_output(text: str) -> dict[str, Any]:
    parsed = _empty_parsed()
    current_section: str | None = None
    _list_sections = ("processes", "software", "services")
    for raw in text.splitlines():
        line = raw.rstrip()
        s = line.strip()
        if not s:
            continue
        # Section headers look like "[*] System information:" or
        # "System information:" depending on snmp-check version.
        header = s[3:].lstrip() if s.startswith("[*]") else s
        if header.endswith(":") and header[:-1].lower() in _SECTIONS:
            current_section = _SECTIONS[header[:-1].lower()]
            continue
        if current_section in _list_sections:
            # Every non-header line in a list section is an entry —
            # snmp-check formats them as "PID 1: init" or as plain
            # lines depending on subsection. Capture the whole line
            # verbatim so the agent can reparse if needed.
            parsed[current_section].append(s)
            continue
        m = re.match(r"^\s*([^:]+):\s*(.*)$", line)
        if not m:
            continue
        key, value = m.group(1).strip().lower(), m.group(2).strip()
        if current_section == "system":
            if key == "hostname":
                parsed["hostname"] = value
            elif key == "contact":
                parsed["contact"] = value
            elif key == "location":
                parsed["location"] = value
            elif key == "uptime":
                parsed["uptime"] = value
            elif key == "description":
                parsed["description"] = value
    return parsed


@active_tool(tool_name="snmp-enum", secret_flags={"-c"})
async def enumerate(
    *,
    target: str,
    community: str = "public",
    timeout_seconds: int = 180,
) -> dict[str, Any]:
    """Run snmp-check against ``target`` with the given community string.

    Args:
      target: hostname or IP of the SNMP-capable device.
      community: SNMP community string (default ``public``).
      timeout_seconds: hard wallclock cap (default 180).

    Returns the structured ``kalimcp.run.run`` result dict augmented
    with ``parsed``: ``{target, community, hostname, contact,
    location, uptime, description, processes, software, services}``.
    """
    argv = ["snmp-check", "-c", community, "-v", "2c", target]
    result = await run.run(argv, timeout=timeout_seconds)

    stdout = result.get("stdout", "") or ""
    if stdout.strip():
        parsed = _parse_output(stdout)
    else:
        parsed = _empty_parsed()
    parsed["target"] = target
    parsed["community"] = community
    result["parsed"] = parsed
    return result
