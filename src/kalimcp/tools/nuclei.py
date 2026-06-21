# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Aaron K. Clark
"""nuclei wrapper — ProjectDiscovery templated vulnerability scanner.

nuclei runs a library of community templates against a target URL and
reports matches. ``-jsonl -silent`` streams one JSON object per finding
to stdout, which ``_parse_output`` distills into a flat finding list.
"""

from __future__ import annotations

import json
from typing import Any

from .. import run
from ._active import active_tool


def _empty_parsed() -> dict[str, Any]:
    return {"findings": [], "count": 0}


def _parse_output(text: str) -> dict[str, Any]:
    """Parse nuclei's ``-jsonl`` output — one JSON object per line.

    Each line is a finding record. We pull the fields an operator/agent
    cares about and skip anything that isn't a JSON object.
    """
    findings: list[dict[str, Any]] = []
    for line in text.splitlines():
        s = line.strip()
        if not s.startswith("{"):
            continue
        try:
            record = json.loads(s)
        except (json.JSONDecodeError, ValueError):
            continue
        if not isinstance(record, dict):
            continue
        info = record.get("info") or {}
        if not isinstance(info, dict):
            info = {}
        findings.append({
            "template_id": record.get("template-id", ""),
            "name": info.get("name", ""),
            "severity": info.get("severity", ""),
            "host": record.get("host", ""),
            "matched_at": record.get("matched-at", ""),
            "type": record.get("type", ""),
        })
    return {"findings": findings, "count": len(findings)}


@active_tool(tool_name="nuclei")
async def scan(
    *,
    target: str,
    severity: str = "",
    tags: str = "",
    templates: str = "",
    rate_limit: int = 150,
    timeout_seconds: int = 600,
) -> dict[str, Any]:
    """Scan a target URL with nuclei's template library.

    Args:
      target: URL like ``https://example.com/``.
      severity: comma-separated filter (``critical,high``). Empty = all.
      tags: comma-separated template tag filter (``cve,rce``). Empty = all.
      templates: path to a custom template or template directory (``-t``).
        Validated for existence before launch.
      rate_limit: max requests per second (``-rl``). Default 150.
      timeout_seconds: hard wallclock cap (default 600).

    Returns the structured ``kalimcp.run.run`` result dict augmented
    with ``parsed``: ``{findings: [{template_id, name, severity, host,
    matched_at, type}], count}``.
    """
    err = run.validate_arg(target, "target", parsed=_empty_parsed())
    if err is not None:
        return err

    argv = ["nuclei", "-u", target, "-jsonl", "-silent", "-rl", str(rate_limit)]
    if severity:
        argv += ["-severity", severity]
    if tags:
        argv += ["-tags", tags]
    if templates:
        terr = run.validate_file(templates, "templates", parsed=_empty_parsed())
        if terr is not None:
            return terr
        argv += ["-t", templates]

    result = await run.run(argv, timeout=timeout_seconds)

    return run.distill(result, _parse_output, _empty_parsed)
