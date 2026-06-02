# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Aaron K. Clark
"""hydra wrapper — network logon cracker using dictionary or brute-force attacks.

Every profile invokes hydra with appropriate flags for different attack intensities,
then parses output into structured JSON. Agents consume the `parsed` field;
operators who want the raw output can read `stdout`.
"""

from __future__ import annotations

import re
from typing import Any

from .. import run
from ._active import active_tool

# Profile → (default wordlist used for both -L and -P; None means brute-force
# mode, no wordlists, hydra walks a charset instead, tail flags appended after
# wordlists). hydra honors the last -t / -W / -w it sees, so each profile
# specifies its own full flag tail rather than mixing a shared base.
_PROFILES = {
    "quick": {
        "wordlist": "/usr/share/wordlists/fasttrack.txt",
        "flags": ["-t", "4", "-W", "3", "-w", "15", "-v"],
    },
    "standard": {
        "wordlist": "/usr/share/wordlists/rockyou.txt",
        "flags": ["-t", "4", "-W", "3", "-w", "15", "-v"],
    },
    "comprehensive": {
        "wordlist": "/usr/share/wordlists/rockyou.txt",
        "flags": ["-t", "16", "-W", "3", "-w", "15", "-v"],
    },
    "bruteforce": {
        "wordlist": None,
        "flags": ["-x", "6:8:aA1", "-t", "4", "-W", "3", "-w", "15", "-v"],
    },
}


def _parse_output(text: str) -> dict[str, Any]:
    """Parse hydra output into structured data.

    Extracts cracked credentials, tried combinations, etc.
    Returns a structured dict with findings.
    """
    result = {
        "success": False,
        "credentials_found": [],
        "tried_combinations": 0,
        "hosts_tested": [],
        "services_tested": [],
        "statistics": {},
    }

    # Check if hydra ran successfully
    if "[DATA] attacking" in text:
        result["success"] = True

    # Extract cracked credentials. Real hydra emits one line per crack:
    #   [22][ssh] host: 192.168.1.10   login: admin   password: hunter2
    # First bracket is the *port*, second is the service name, then the
    # IP/host follows "host:".
    credential_pattern = (
        r"\[(\d+)\]\[([^\]]+)\]\s+host:\s*(\S+)\s+login:\s*(\S+)\s+password:\s*(\S+)"
    )
    for _port, service, host, username, password in re.findall(credential_pattern, text):
        result["credentials_found"].append({
            "host": host,
            "service": service,
            "username": username,
            "password": password,
        })

    if result["credentials_found"]:
        # Preserve insertion order with dict.fromkeys instead of set().
        result["hosts_tested"] = list(
            dict.fromkeys(cred["host"] for cred in result["credentials_found"])
        )
        result["services_tested"] = list(
            dict.fromkeys(cred["service"] for cred in result["credentials_found"])
        )

    # Extract tried combinations
    tried_pattern = r"\[STATUS\]\s+(\d+)\.?\d*\s+guesses/min\s+0\s+childs?\s+0\s+is\s+done\s+\((.+?)\s+vs\s+(.+?)\)"
    tried_match = re.search(tried_pattern, text)
    if tried_match:
        try:
            result["tried_combinations"] = int(float(tried_match.group(1)))
        except ValueError:
            pass

    # Extract basic statistics
    if "[STATUS] attack finished" in text:
        result["statistics"]["attack_completed"] = True

    return result


@active_tool(tool_name="hydra")
async def crack(
    *,
    target: str,
    service: str,
    username_list: str = "",
    password_list: str = "",
    profile: str = "standard",
    timeout_seconds: int = 300,
) -> dict[str, Any]:
    """Run a hydra crack attack against `target` service using a named profile.

    Args:
        target: target IP or hostname (e.g., "192.168.1.1")
        service: service to attack (e.g., "ssh", "ftp", "http-post-form")
        username_list: path to username list file (optional)
        password_list: path to password list file (optional)
        profile: one of {quick, standard, comprehensive, bruteforce}
        timeout_seconds: hard wallclock cap (default 300s)

    Returns the structured kalimcp.run.run result dict augmented with:
      - profile: the profile name used
      - parsed: structured findings extracted from hydra output
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
                "credentials_found": [],
                "tried_combinations": 0,
                "hosts_tested": [],
                "services_tested": [],
                "statistics": {},
            },
        }

    profile_cfg = _PROFILES[profile]
    user_wl = username_list or profile_cfg["wordlist"]
    pass_wl = password_list or profile_cfg["wordlist"]

    argv: list[str] = ["hydra"]
    if user_wl:
        argv.extend(["-L", user_wl])
    if pass_wl:
        argv.extend(["-P", pass_wl])
    argv.extend(profile_cfg["flags"])
    argv.extend([target, service])

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
            "credentials_found": [],
            "tried_combinations": 0,
            "hosts_tested": [],
            "services_tested": [],
            "statistics": {},
        }

    # If we had a successful crack but didn't extract hosts from output,
    # add the target
    if result["parsed"]["success"] and not result["parsed"]["hosts_tested"]:
        result["parsed"]["hosts_tested"] = [target]
        if service:
            result["parsed"]["services_tested"] = [service]

    return result
