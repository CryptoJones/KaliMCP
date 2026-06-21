# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Aaron K. Clark
"""wpscan wrapper — WordPress security scanner.

wpscan enumerates a WordPress install's version, vulnerable plugins
and themes, registered users, and other interesting findings (config
backups, exposed readme, etc.). ``--format json`` writes a single
JSON document to stdout that ``_parse_output`` distills into a flat
``parsed`` dict. An optional WPScan Vulnerability Database
``--api-token`` enriches the result with CVE-backed vulnerability data;
the token is a secret, so it is redacted from the audit-log argv.
"""

from __future__ import annotations

import json
from typing import Any

from .. import run
from ._active import active_tool


def _empty_parsed() -> dict[str, Any]:
    return {
        "version": None,
        "vulnerabilities": [],
        "users": [],
        "interesting_findings": [],
    }


def _collect_vulns(node: Any, into: list[dict[str, Any]]) -> None:
    """Append any ``vulnerabilities`` list found under a wpscan node.

    wpscan hangs vulnerability lists off several places: the
    ``version`` object, and each plugin/theme entry. They share the
    same shape (``[{title, references, fixed_in, ...}]``), so we flatten
    them all into one list.
    """
    if isinstance(node, dict):
        vulns = node.get("vulnerabilities")
        if isinstance(vulns, list):
            for v in vulns:
                if isinstance(v, dict):
                    into.append(v)


def _parse_output(text: str) -> dict[str, Any]:
    """Parse wpscan's ``--format json`` document into a flat dict.

    wpscan emits one JSON object. We pull the detected core version,
    flatten every vulnerability list (core + per-plugin + per-theme)
    into one list, list usernames, and surface interesting findings.
    """
    try:
        data = json.loads(text)
    except (json.JSONDecodeError, ValueError):
        return _empty_parsed()
    if not isinstance(data, dict):
        return _empty_parsed()

    parsed = _empty_parsed()

    version = data.get("version")
    if isinstance(version, dict):
        parsed["version"] = version.get("number")
        _collect_vulns(version, parsed["vulnerabilities"])

    # Plugins/themes are dicts keyed by slug; each value may carry vulns.
    for section in ("plugins", "themes", "main_theme"):
        node = data.get(section)
        if isinstance(node, dict):
            # main_theme is a single object; plugins/themes are slug -> object.
            if section == "main_theme":
                _collect_vulns(node, parsed["vulnerabilities"])
            else:
                for entry in node.values():
                    _collect_vulns(entry, parsed["vulnerabilities"])

    users = data.get("users")
    if isinstance(users, dict):
        parsed["users"] = list(users.keys())
    elif isinstance(users, list):
        parsed["users"] = [u for u in users if isinstance(u, str)]

    findings = data.get("interesting_findings")
    if isinstance(findings, list):
        for f in findings:
            if isinstance(f, dict):
                parsed["interesting_findings"].append(
                    {
                        "url": f.get("url"),
                        "type": f.get("type"),
                        "to_s": f.get("to_s"),
                    }
                )

    return parsed


@active_tool(tool_name="wpscan", secret_flags={"--api-token"})
async def scan(
    *,
    target: str,
    enumerate: str = "vp,u",
    api_token: str = "",
    timeout_seconds: int = 600,
) -> dict[str, Any]:
    """Scan a WordPress site with wpscan.

    Args:
      target: site URL like ``https://example.com/``.
      enumerate: wpscan ``--enumerate`` spec. Default ``vp,u`` —
        vulnerable plugins + users. Other tokens: ``ap`` (all
        plugins), ``vt`` (vulnerable themes), ``cb`` (config backups).
      api_token: WPScan Vulnerability Database API token. Optional;
        enriches results with CVE data. Redacted from the audit log.
      timeout_seconds: hard wallclock cap (default 600).

    Returns the structured ``kalimcp.run.run`` result dict augmented
    with ``parsed``: ``{version, vulnerabilities: [...], users: [...],
    interesting_findings: [...]}``.
    """
    argv = [
        "wpscan",
        "--url",
        target,
        "--format",
        "json",
        "--no-banner",
        "--enumerate",
        enumerate,
    ]
    if api_token:
        argv += ["--api-token", api_token]

    result = await run.run(argv, timeout=timeout_seconds)

    return run.distill(result, _parse_output, _empty_parsed)
