# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Aaron K. Clark
"""whatweb wrapper — HTTP fingerprint / tech-stack detection.

whatweb identifies the server, CMS, JS frameworks, analytics
trackers, and ~1700 other plugins on a target URL. ``--log-json=-``
streams a JSON-lines log to stdout that ``_parse_output`` distills
into a per-target plugin list.
"""

from __future__ import annotations

import json
from typing import Any

from .. import run
from ._active import active_tool


def _empty_parsed() -> dict[str, Any]:
    return {
        "target": "",
        "http_status": None,
        "server": "",
        "detected_cms": "",
        "plugins": [],
    }


def _flatten_plugin(name: str, payload: Any) -> dict[str, Any]:
    """Distill a whatweb plugin record into ``{name, version?, string?}``.

    whatweb plugin payloads vary: most are lists of dicts where each
    dict has a single key (``version``, ``string``, ``account``,
    ``module``). We collapse to the most-useful fields.
    """
    entry: dict[str, Any] = {"name": name}
    if not isinstance(payload, list):
        return entry
    for item in payload:
        if not isinstance(item, dict):
            continue
        for key in ("version", "string", "account", "module"):
            if key in item and key not in entry:
                v = item[key]
                if isinstance(v, list) and v:
                    entry[key] = v[0]
                elif not isinstance(v, (list, dict)):
                    entry[key] = v
    return entry


def _parse_output(text: str) -> dict[str, Any]:
    """Parse whatweb's ``--log-json`` output.

    whatweb writes one JSON object per target, sometimes one per
    line, sometimes pretty-printed as a single object. We try line-
    by-line first, then fall back to a whole-text parse.
    """
    records: list[dict[str, Any]] = []
    for line in text.splitlines():
        s = line.strip()
        if not s.startswith("{"):
            continue
        try:
            records.append(json.loads(s))
        except (json.JSONDecodeError, ValueError):
            continue
    if not records:
        try:
            data = json.loads(text)
            if isinstance(data, dict):
                records = [data]
            elif isinstance(data, list):
                records = [r for r in data if isinstance(r, dict)]
        except (json.JSONDecodeError, ValueError):
            return _empty_parsed()
    if not records:
        return _empty_parsed()

    # We only model the first (or only) target. whatweb usually scans
    # one target per call.
    record = records[0]
    parsed = _empty_parsed()
    parsed["target"] = record.get("target", "")
    parsed["http_status"] = record.get("http_status")

    plugins_payload = record.get("plugins") or {}
    if isinstance(plugins_payload, dict):
        for name, payload in plugins_payload.items():
            plugin = _flatten_plugin(name, payload)
            parsed["plugins"].append(plugin)
            lname = name.lower()
            if lname == "httpserver" and "string" in plugin:
                parsed["server"] = plugin["string"]
            elif lname in ("wordpress", "drupal", "joomla", "magento", "shopify"):
                parsed["detected_cms"] = name
    return parsed


@active_tool(tool_name="whatweb")
async def fingerprint(
    *,
    target: str,
    aggression: int = 1,
    timeout_seconds: int = 120,
) -> dict[str, Any]:
    """Fingerprint a web URL with whatweb.

    Args:
      target: URL like ``https://example.com/``.
      aggression: 1 (passive), 3 (aggressive), or 4 (heavy). Default 1
        — single GET, no follow-up probes. 3 fires CMS-specific
        version checks; 4 includes intrusive ones.
      timeout_seconds: hard wallclock cap (default 120).

    Returns the structured ``kalimcp.run.run`` result dict augmented
    with ``parsed``: ``{target, http_status, server, detected_cms,
    plugins: [{name, version?, string?, ...}]}``.
    """
    aggression = max(1, min(int(aggression), 4))
    argv = [
        "whatweb",
        f"--aggression={aggression}",
        "--log-json=-",
        "--no-errors",
        target,
    ]
    result = await run.run(argv, timeout=timeout_seconds)

    return run.distill(result, _parse_output, _empty_parsed)
