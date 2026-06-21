# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Aaron K. Clark
"""ProjectDiscovery asset-discovery trio: subfinder / dnsx / httpx.

Three thin wrappers around the ProjectDiscovery Go toolkit:

- ``subfinder_enum`` — passive subdomain OSINT. It queries public
  sources (cert transparency, passive-DNS aggregators, …) and does
  **not** probe the target itself, so it follows the ``passive.py``
  pattern: no ``active_tool`` decorator, a ``passive_invoke`` audit
  event, no scope warning / auto-record.
- ``probe`` (httpx) — an active web probe: it sends HTTP(S) requests to
  the target, fingerprints the response, and is decorated with
  ``@active_tool``.
- ``resolve`` (dnsx) — active DNS resolution against the target, also
  ``@active_tool``.

``httpx`` here is the ProjectDiscovery binary (``-json -silent`` line-
delimited JSON), **not** the Python HTTP library of the same name.
"""

from __future__ import annotations

import json
from typing import Any

from .. import audit, run
from ._active import active_tool

# ---------- subfinder (passive) ----------


async def _audited_run(tool: str, argv: list[str], timeout: int) -> dict[str, Any]:
    with audit.time_block() as elapsed:
        result = await run.run(argv, timeout=timeout)
    audit.log(
        "passive_invoke",
        tool=tool,
        argv=argv,
        elapsed_ms=elapsed(),
        exit_code=result.get("exit_code"),
    )
    return result


def _parse_subfinder(text: str) -> dict[str, Any]:
    """subfinder ``-silent`` prints one hostname per line."""
    subs = [line.strip() for line in text.splitlines() if line.strip()]
    return {"subdomains": subs, "count": len(subs)}


async def subfinder_enum(*, domain: str, timeout_seconds: int = 300) -> dict[str, Any]:
    """Passive subdomain enumeration for a domain via subfinder.

    Queries public OSINT sources only — does not probe the target.
    Returns the ``run.run`` result with ``parsed``:
    ``{subdomains: [...], count: N}``.
    """
    if err := run.validate_arg(domain, "domain"):
        err["parsed"] = {"subdomains": [], "count": 0}
        return err
    argv = ["subfinder", "-d", domain, "-silent"]
    result = await _audited_run("subfinder", argv, timeout_seconds)
    text = result.get("stdout", "") or ""
    result["parsed"] = (
        _parse_subfinder(text) if text.strip() else {"subdomains": [], "count": 0}
    )
    return result


# ---------- httpx (active web probe) ----------


def _empty_httpx() -> dict[str, Any]:
    return {"results": [], "count": 0}


def _parse_httpx(text: str) -> dict[str, Any]:
    """httpx ``-json`` prints one JSON object per probed URL."""
    results: list[dict[str, Any]] = []
    for line in text.splitlines():
        s = line.strip()
        if not s.startswith("{"):
            continue
        try:
            rec = json.loads(s)
        except (json.JSONDecodeError, ValueError):
            continue
        if not isinstance(rec, dict):
            continue
        results.append(
            {
                "url": rec.get("url", ""),
                "status_code": rec.get("status_code"),
                "title": rec.get("title", ""),
                "webserver": rec.get("webserver", ""),
                "tech": rec.get("tech") or [],
            }
        )
    return {"results": results, "count": len(results)}


@active_tool(tool_name="httpx")
async def probe(*, target: str, timeout_seconds: int = 120) -> dict[str, Any]:
    """Probe a web target with httpx (ProjectDiscovery).

    Sends HTTP(S) requests and reports status code, page title, detected
    technologies, and the web-server banner. Returns the ``run.run``
    result with ``parsed``:
    ``{results: [{url, status_code, title, webserver, tech}], count: N}``.
    """
    if err := run.validate_arg(target, "target"):
        err["parsed"] = _empty_httpx()
        return err
    argv = [
        "httpx",
        "-u", target,
        "-json",
        "-silent",
        "-status-code",
        "-title",
        "-tech-detect",
        "-web-server",
    ]
    result = await run.run(argv, timeout=timeout_seconds)
    return run.distill(result, _parse_httpx, _empty_httpx)


# ---------- dnsx (active DNS resolution) ----------


def _empty_dnsx() -> dict[str, Any]:
    return {"records": [], "count": 0}


def _parse_dnsx(text: str) -> dict[str, Any]:
    """dnsx ``-json`` prints one JSON object per resolved name."""
    records: list[dict[str, Any]] = []
    for line in text.splitlines():
        s = line.strip()
        if not s.startswith("{"):
            continue
        try:
            rec = json.loads(s)
        except (json.JSONDecodeError, ValueError):
            continue
        if isinstance(rec, dict):
            records.append(rec)
    return {"records": records, "count": len(records)}


@active_tool(tool_name="dnsx")
async def resolve(
    *,
    target: str,
    record_types: str = "a",
    timeout_seconds: int = 120,
) -> dict[str, Any]:
    """Resolve a target with dnsx (ProjectDiscovery), DNS records as JSON.

    Performs an A-record resolve with the full response attached
    (``-a -resp``). Returns the ``run.run`` result with ``parsed``:
    ``{records: [...], count: N}``.
    """
    if err := run.validate_arg(target, "target"):
        err["parsed"] = _empty_dnsx()
        return err
    # record_types is a comma/space separated selector (a, aaaa, cname,
    # mx, ns, txt, …); only well-formed alpha tokens become -<rt> flags.
    rtypes = [
        rt.strip().lower()
        for rt in record_types.replace(",", " ").split()
        if rt.strip().isalpha()
    ] or ["a"]
    argv = ["dnsx", "-silent", "-json", "-resp", "-d", target]
    for rt in rtypes:
        argv.append("-" + rt)
    result = await run.run(argv, timeout=timeout_seconds)
    return run.distill(result, _parse_dnsx, _empty_dnsx)
