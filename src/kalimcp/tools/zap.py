# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Aaron K. Clark
"""OWASP ZAP wrapper — headless baseline / quick web scan.

ZAP runs headless via the ``zaproxy`` CLI in "quick scan" mode: it
spiders the target, runs the passive + a light active scan, and writes
the alerts to a report file (NOT stdout). The CLI is version-sensitive;
the ``-cmd -quickurl … -quickout … -quickprogress`` form below is the
assumed-stable invocation across recent Kali builds.

Because the alerts land in the report *file*, ``baseline_scan`` reads
and parses that file after the run (best-effort) rather than stdout.
``_parse_report`` flattens ZAP's ``site[].alerts[]`` into a flat
``alerts`` list; agents consume ``parsed``, operators read raw stdout
plus the on-disk report.
"""

from __future__ import annotations

import json
from typing import Any

from .. import run
from ._active import active_tool


def _empty_parsed(report_path: str) -> dict[str, Any]:
    return {"alerts": [], "alert_count": 0, "report_path": report_path}


def _parse_report(path: str) -> dict[str, Any]:
    """Best-effort parse of a ZAP quick-scan JSON report file.

    ZAP's JSON report nests alerts under ``site[].alerts[]``. We flatten
    them into ``{name, risk, confidence, url}`` records. A missing or
    unparseable file yields the empty skeleton — the file read is wholly
    wrapped in a try/except so a malformed report never raises.
    """
    try:
        with open(path, encoding="utf-8") as fh:
            data = json.load(fh)
    except (OSError, ValueError):
        return _empty_parsed(path)

    alerts: list[dict[str, Any]] = []
    sites = data.get("site") if isinstance(data, dict) else None
    if isinstance(sites, list):
        for site in sites:
            if not isinstance(site, dict):
                continue
            for alert in site.get("alerts") or []:
                if not isinstance(alert, dict):
                    continue
                url = ""
                instances = alert.get("instances")
                if isinstance(instances, list) and instances:
                    first = instances[0]
                    if isinstance(first, dict):
                        url = first.get("uri", "") or ""
                if not url:
                    url = site.get("@name", "") or ""
                alerts.append(
                    {
                        "name": alert.get("name", "") or alert.get("alert", ""),
                        "risk": alert.get("riskdesc", "") or alert.get("risk", ""),
                        "confidence": alert.get("confidence", ""),
                        "url": url,
                    }
                )
    return {"alerts": alerts, "alert_count": len(alerts), "report_path": path}


@active_tool(tool_name="zap")
async def baseline_scan(
    *,
    target: str,
    report_path: str = "",
    timeout_seconds: int = 900,
) -> dict[str, Any]:
    """Run an OWASP ZAP headless baseline/quick scan against `target`.

    Args:
      target: URL like ``https://example.com/``.
      report_path: where ZAP writes its JSON report. Defaults to
        ``/tmp/kalimcp_zap_report.json``.
      timeout_seconds: hard wallclock cap (default 900 — ZAP is slow).

    Returns the structured ``kalimcp.run.run`` result dict augmented
    with ``parsed``: ``{alerts: [{name, risk, confidence, url}],
    alert_count, report_path}``. Empty skeleton if the report file is
    missing or unparseable.
    """
    out = report_path or "/tmp/kalimcp_zap_report.json"

    bad = run.validate_arg(target, "target", parsed=_empty_parsed(out))
    if bad is not None:
        return bad

    # Version-sensitive CLI: this is the assumed-stable quick-scan form.
    argv = ["zaproxy", "-cmd", "-quickurl", target, "-quickout", out, "-quickprogress"]
    result = await run.run(argv, timeout=timeout_seconds)

    # Alerts are written to the report FILE, not stdout — parse it after.
    result["parsed"] = _parse_report(out)
    return result
