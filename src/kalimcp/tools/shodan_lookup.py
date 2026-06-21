# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Aaron K. Clark
"""Shodan OSINT lookups (external intel — never probes the target).

Both functions query the Shodan REST API to enrich a target with
publicly-indexed data Shodan already collected, so they do **not** touch
the target host themselves. They are passive lookups in the mould of
``enrich.cve_search``: pure ``urllib`` over HTTPS run in a thread, no
subprocess, no ``@active_tool``, no audit/record path.

The Shodan API key is a **secret**. It travels in the query string, so
nothing here logs the URL, and the error path scrubs the key from any
message before returning it — the key must never appear in a returned
dict. The private ``_sync_get_json`` helper is what tests patch, so the
suite never reaches the network.
"""

from __future__ import annotations

import asyncio
import json
import urllib.error
import urllib.parse
import urllib.request
from typing import Any

_HOST_URL = "https://api.shodan.io/shodan/host"
_SEARCH_URL = "https://api.shodan.io/shodan/host/search"
_USER_AGENT = "KaliMCP"


# ---------- HTTP (patched out in tests) ----------

def _sync_get_json(url: str, timeout: float) -> Any:
    req = urllib.request.Request(url, headers={"User-Agent": _USER_AGENT})
    with urllib.request.urlopen(req, timeout=timeout) as resp:  # noqa: S310 (https only)
        return json.loads(resp.read().decode("utf-8", errors="replace"))


async def _get_json(url: str, timeout: float) -> Any:
    return await asyncio.to_thread(_sync_get_json, url, timeout)


def _redact(message: str, api_key: str) -> str:
    """Strip the API key from a message so it can never leak in output."""
    if api_key:
        message = message.replace(api_key, "<redacted>")
    return message


# ---------- host lookup ----------

async def host_lookup(ip: str, *, api_key: str, timeout_seconds: int = 15) -> dict[str, Any]:
    """Look up a single host on Shodan by IP (passive — Shodan's index only)."""
    target = (ip or "").strip()
    if not target:
        return {"ok": False, "error": "empty_ip", "source": "shodan"}
    if not (api_key or "").strip():
        return {"ok": False, "error": "shodan api_key required", "source": "shodan"}
    url = (
        f"{_HOST_URL}/{urllib.parse.quote(target)}"
        f"?key={urllib.parse.quote(api_key)}"
    )
    try:
        doc = await _get_json(url, timeout_seconds)
    except (urllib.error.URLError, TimeoutError, ValueError, OSError) as exc:
        return {
            "ok": False,
            "error": "lookup_failed",
            "message": _redact(str(exc), api_key),
            "source": "shodan",
        }
    doc = doc or {}
    return {
        "ok": True,
        "source": "shodan",
        "ip": doc.get("ip_str", target),
        "ports": doc.get("ports", []),
        "hostnames": doc.get("hostnames", []),
        "org": doc.get("org", ""),
        "os": doc.get("os"),
        "vulns": doc.get("vulns", []),
        "isp": doc.get("isp", ""),
    }


# ---------- search ----------

async def search(
    query: str,
    *,
    api_key: str,
    limit: int = 20,
    timeout_seconds: int = 15,
) -> dict[str, Any]:
    """Run a Shodan search query (passive — Shodan's index only)."""
    q = (query or "").strip()
    if not q:
        return {"ok": False, "error": "empty_query", "source": "shodan"}
    if not (api_key or "").strip():
        return {"ok": False, "error": "shodan api_key required", "source": "shodan"}
    url = (
        f"{_SEARCH_URL}?key={urllib.parse.quote(api_key)}"
        f"&query={urllib.parse.quote(q)}"
    )
    try:
        doc = await _get_json(url, timeout_seconds)
    except (urllib.error.URLError, TimeoutError, ValueError, OSError) as exc:
        return {
            "ok": False,
            "error": "lookup_failed",
            "message": _redact(str(exc), api_key),
            "source": "shodan",
        }
    doc = doc or {}
    cap = max(1, int(limit))
    matches = [
        {
            "ip_str": m.get("ip_str", ""),
            "port": m.get("port"),
            "org": m.get("org", ""),
            "hostnames": m.get("hostnames", []),
        }
        for m in (doc.get("matches", []) or [])[:cap]
    ]
    return {
        "ok": True,
        "source": "shodan",
        "query": q,
        "total": doc.get("total", 0),
        "count": len(matches),
        "matches": matches,
    }
