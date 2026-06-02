# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Aaron K. Clark
"""sqlmap wrapper — automated SQL injection and database takeover tool.

Every profile invokes sqlmap with appropriate flags for different scan intensities,
then parses output into structured JSON. Agents consume the `parsed` field;
operators who want the raw output can read `stdout`.
"""

from __future__ import annotations

import re
from typing import Any

from .. import run
from ._active import active_tool

# Profiles define different sqlmap scan intensities
# Each profile ends with batch mode and output formatting flags
_BASE_FLAGS = ["--batch", "--answers=follow=n", "--output-dir=/tmp/sqlmap-output", "--flush-session"]

_PROFILES = {
    "quick": ["--level=1", "--risk=1", *_BASE_FLAGS],
    "standard": ["--level=2", "--risk=2", *_BASE_FLAGS],
    "comprehensive": ["--level=3", "--risk=3", *_BASE_FLAGS],
    "exploit": ["--level=5", "--risk=3", "--technique=BEUSTQ", *_BASE_FLAGS],
}


def _parse_output(text: str) -> dict[str, Any]:
    """Parse sqlmap output into structured data.

    Extracts key information: vulnerable parameters, database info, tables, etc.
    Returns a structured dict with findings.
    """
    result = {
        "success": False,
        "vulnerable": False,
        "injection_points": [],
        "dbms": {},
        "hosts_tested": [],
        "statistics": {},
    }

    # Check if sqlmap ran successfully
    if "[INFO] testing connection to the target URL" in text:
        result["success"] = True

    # Extract injection points
    injection_pattern = r"\[INFO\].*?parameter '([^']*)' is vulnerable"
    injections = re.findall(injection_pattern, text, re.IGNORECASE)
    for param in injections:
        result["injection_points"].append(
            {"parameter": param, "type": "SQL Injection", "confidence": "high"}
        )

    if injections:
        result["vulnerable"] = True

    # Extract DBMS information
    dbms_pattern = r"\[INFO\] the back-end DBMS is ([^\n]+)"
    dbms_match = re.search(dbms_pattern, text)
    if dbms_match:
        result["dbms"]["name"] = dbms_match.group(1).strip()

    version_pattern = r"\[INFO\] back-end DBMS: ([^\n]+)"
    version_match = re.search(version_pattern, text)
    if version_match:
        result["dbms"]["version"] = version_match.group(1).strip()

    # Extract hosts tested - look for actual URLs in the output
    # sqlmap shows: [INFO] testing connection to http://example.com/
    # We want to capture actual URLs/IPs, not the placeholder "the target URL"
    host_pattern = r"\[INFO\] testing connection to ((?:https?://)?[^\s]+)"
    hosts = re.findall(host_pattern, text)
    # Filter out the placeholder text and add actual URLs/IPs
    for host in hosts:
        if host and host not in ["the", "target", "URL", "the target URL"]:
            # Additional validation: looks like a URL/IP or contains dots/slashes
            if '.' in host or ':' in host or host.startswith(('http://', 'https://')):
                result["hosts_tested"].append(host)

    # Extract basic statistics
    if "[INFO] fetched data logged to text files under" in text:
        result["statistics"]["data_extracted"] = True

    return result


@active_tool(tool_name="sqlmap")
async def scan(
    *,
    target: str,
    profile: str = "standard",
    timeout_seconds: int = 600,
) -> dict[str, Any]:
    """Run a sqlmap scan against `target` using a named profile.

    Args:
        target: target URL (e.g., "http://example.com/page.php?id=1")
        profile: one of {quick, standard, comprehensive, exploit}
        timeout_seconds: hard wallclock cap (default 600s for thorough scans)

    Returns the structured kalimcp.run.run result dict augmented with:
      - profile: the profile name used
      - parsed: structured findings extracted from sqlmap output
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
            "parsed": {
                "success": False,
                "vulnerable": False,
                "injection_points": [],
                "dbms": {},
                "hosts_tested": [],
                "statistics": {},
            },
        }

    argv = ["sqlmap", "-u", target, *_PROFILES[profile]]
    result = await run.run(argv, timeout=timeout_seconds)
    result["profile"] = profile

    # Parse output into structured data
    stdout = result.get("stdout", "") or ""
    stderr = result.get("stderr", "") or ""
    combined_output = stdout + "\n" + stderr

    if combined_output.strip():
        result["parsed"] = _parse_output(combined_output)
    else:
        result["parsed"] = {
            "success": False,
            "vulnerable": False,
            "injection_points": [],
            "dbms": {},
            "hosts_tested": [],
            "statistics": {},
        }

    # If we had a successful scan but didn't extract any hosts from the output,
    # add the target to hosts_tested (this handles the "the target URL" case)
    if result["parsed"]["success"] and not result["parsed"]["hosts_tested"]:
        result["parsed"]["hosts_tested"] = [target]

    return result
