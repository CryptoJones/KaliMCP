# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Aaron K. Clark
"""nikto wrapper — web server vulnerability scanner.

nikto emits machine-readable XML via ``-Format xml -output FILE`` but
its support for streaming to stdout is patchy across versions (some
builds reject ``-output -`` outright, others write zero-byte files).
The text output, by contrast, is line-oriented and has been stable
for a decade. ``_parse_output`` distills it into a ``parsed`` dict —
host/ip/port/server fields plus a flat list of findings. Agents
consume ``parsed``; operators read raw ``stdout``.
"""

from __future__ import annotations

from typing import Any

from .. import run
from ._active import active_tool


def _empty_parsed() -> dict[str, Any]:
    return {
        "target_host": "",
        "target_ip": "",
        "target_port": "",
        "server": "",
        "vulnerabilities": [],
    }


def _parse_output(text: str) -> dict[str, Any]:
    """Best-effort extract of nikto's text output.

    nikto emits one finding per line prefixed by ``+ ``. Header
    lines (Target Host / Target IP / Target Port / Server) appear
    once near the top; everything else is a finding. Findings of the
    form ``/uri: message`` are split into ``{uri, msg}``; everything
    else lands in ``{msg}`` only.
    """
    parsed = _empty_parsed()
    for line in text.splitlines():
        s = line.strip()
        if not s.startswith("+ "):
            continue
        body = s[2:].strip()
        if body.startswith("Target Host:"):
            parsed["target_host"] = body[len("Target Host:"):].strip()
        elif body.startswith("Target IP:"):
            parsed["target_ip"] = body[len("Target IP:"):].strip()
        elif body.startswith("Target Port:"):
            parsed["target_port"] = body[len("Target Port:"):].strip()
        elif body.startswith("Server:"):
            parsed["server"] = body[len("Server:"):].strip()
        elif body.startswith("Start Time:") or body.startswith("End Time:"):
            # Run metadata, not a finding.
            continue
        elif body.startswith("/") and ": " in body:
            uri, _, msg = body.partition(": ")
            parsed["vulnerabilities"].append({"uri": uri, "msg": msg})
        else:
            parsed["vulnerabilities"].append({"msg": body})
    return parsed


@active_tool(tool_name="nikto")
async def scan(
    *,
    target: str,
    ssl: bool = False,
    timeout_seconds: int = 600,
) -> dict[str, Any]:
    """Run nikto against `target` (URL or host).

    Args:
      target: URL like `https://example.com/` or host:port.
      ssl: force-enable SSL/TLS detection.
      timeout_seconds: hard wallclock cap (default 600 — nikto is slow).

    Returns the structured ``kalimcp.run.run`` result dict augmented with:
      - ``parsed``: ``{target_host, target_ip, target_port, server,
        vulnerabilities: [{msg} or {uri, msg}]}``. Empty fields if
        nikto produced no output.
    """
    argv = ["nikto", "-host", target, "-ask", "no"]
    if ssl:
        argv.append("-ssl")
    result = await run.run(argv, timeout=timeout_seconds)

    return run.distill(result, _parse_output, _empty_parsed)
