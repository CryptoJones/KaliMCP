# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Aaron K. Clark
"""nmap wrapper — port + service scan with safety rails.

Every profile invokes nmap with ``-oX -`` so the stdout is
machine-readable XML, then ``_parse_xml`` distills it into a
``parsed`` dict on the result: ``{"hosts": [{"addr", "state",
"ports": [{"portid", "protocol", "state", "service",
"product", "version"}]}]}``. Agents consume the `parsed` field;
operators who want the raw XML can read `stdout`.
"""

from __future__ import annotations

import xml.etree.ElementTree as ET
from typing import Any

from .. import run
from ._active import active_tool

# Profiles intentionally limit what nmap can do. Operators who want
# fancier scans should add a profile here and submit a PR — not
# extend an arbitrary --extra-args parameter.
#
# Every profile ends with `-oX -` so nmap emits structured XML to
# stdout — easier for an agent to consume than human-formatted
# text. _parse_xml() handles the conversion to a `parsed` dict.
_BASE_FLAGS = ["-oX", "-"]
_PROFILES = {
    "tcp-fast":     ["-Pn", "-T4", "--top-ports", "100", *_BASE_FLAGS],
    "tcp-full":     ["-Pn", "-T4", "-p-", "--max-retries", "1", *_BASE_FLAGS],
    "service-scan": ["-Pn", "-sV", "-T4", "--top-ports", "100", *_BASE_FLAGS],
    "udp-top-50":   ["-Pn", "-sU", "-T4", "--top-ports", "50", *_BASE_FLAGS],
    "ping-sweep":   ["-sn", "-PE", "-T4", *_BASE_FLAGS],
}


def _parse_xml(xml_text: str) -> dict[str, Any]:
    """Distill nmap's XML output into a small structured dict.

    Schema (best-effort — fields missing from sparse output are omitted):

        {
          "hosts": [
            {
              "addr": "203.0.113.5",
              "addrtype": "ipv4",
              "state": "up",
              "ports": [
                {"portid": 22, "protocol": "tcp", "state": "open",
                 "service": "ssh", "product": "OpenSSH", "version": "9.6"},
                ...
              ]
            },
            ...
          ]
        }

    Returns an empty ``{"hosts": []}`` if parsing fails; ``stdout``
    still carries the raw XML for operators who want to debug.
    """
    try:
        root = ET.fromstring(xml_text)
    except ET.ParseError:
        return {"hosts": []}

    hosts: list[dict[str, Any]] = []
    for host_el in root.findall("host"):
        host: dict[str, Any] = {}

        status_el = host_el.find("status")
        if status_el is not None and status_el.get("state"):
            host["state"] = status_el.get("state")

        addr_el = host_el.find("address")
        if addr_el is not None:
            if addr_el.get("addr"):
                host["addr"] = addr_el.get("addr")
            if addr_el.get("addrtype"):
                host["addrtype"] = addr_el.get("addrtype")

        ports: list[dict[str, Any]] = []
        ports_el = host_el.find("ports")
        if ports_el is not None:
            for port_el in ports_el.findall("port"):
                port: dict[str, Any] = {
                    "protocol": port_el.get("protocol"),
                }
                portid = port_el.get("portid")
                if portid is not None:
                    try:
                        port["portid"] = int(portid)
                    except ValueError:
                        port["portid"] = portid

                state_el = port_el.find("state")
                if state_el is not None and state_el.get("state"):
                    port["state"] = state_el.get("state")

                svc_el = port_el.find("service")
                if svc_el is not None:
                    if svc_el.get("name"):
                        port["service"] = svc_el.get("name")
                    if svc_el.get("product"):
                        port["product"] = svc_el.get("product")
                    if svc_el.get("version"):
                        port["version"] = svc_el.get("version")

                ports.append(port)
        host["ports"] = ports

        hosts.append(host)
    return {"hosts": hosts}


@active_tool(tool_name="nmap")
async def scan(
    *,
    target: str,
    profile: str = "tcp-fast",
    timeout_seconds: int = 300,
) -> dict[str, Any]:
    """Run an nmap scan against `target` using a named profile.

    Args:
      target: hostname, IP, or CIDR block.
      profile: one of {tcp-fast, tcp-full, service-scan, udp-top-50, ping-sweep}.
      timeout_seconds: hard wallclock cap (default 300).

    Returns the structured ``kalimcp.run.run`` result dict augmented with:
      - ``profile``: the profile name used
      - ``parsed``: structured host/port data extracted from nmap's
        XML output. Empty ``{"hosts": []}`` if XML parsing fails.
        Raw XML stays in ``stdout``.
    """
    if profile not in _PROFILES:
        return {
            "exit_code": -1,
            "elapsed_s": 0,
            "stdout": "",
            "stderr": f"unknown profile: {profile!r}. Known: {sorted(_PROFILES)}",
            "truncated": False,
            "timed_out": False,
            "profile": profile,
            "argv": [],
            "parsed": {"hosts": []},
        }
    argv = ["nmap", *_PROFILES[profile], target]
    result = await run.run(argv, timeout=timeout_seconds)
    result["profile"] = profile

    # Parse XML stdout into structured data. Done even on non-zero
    # exit so operators can see partial results (nmap returns 1 when
    # some targets unreachable, but the scan data for the rest is
    # still useful).
    stdout = result.get("stdout", "") or ""
    if stdout.strip():
        result["parsed"] = _parse_xml(stdout)
    else:
        result["parsed"] = {"hosts": []}

    return result
