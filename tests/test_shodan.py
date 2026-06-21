# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Aaron K. Clark
"""Shodan OSINT lookup tests (passive external intel).

`_sync_get_json` is patched so the suite never reaches the network. The
critical leak test confirms the secret API key never appears in any
returned dict — including the error path.
"""

from __future__ import annotations

import json
import urllib.error
from unittest.mock import patch

import pytest

from kalimcp.tools import shodan_lookup

_API_KEY = "SUPERSECRETKEY123"

_HOST_SAMPLE = {
    "ip_str": "1.2.3.4",
    "ports": [22, 80, 443],
    "hostnames": ["host.example.com"],
    "org": "Example Org",
    "os": "Linux",
    "vulns": ["CVE-2021-44228"],
    "isp": "Example ISP",
}

_SEARCH_SAMPLE = {
    "total": 2,
    "matches": [
        {"ip_str": "1.1.1.1", "port": 80, "org": "Org A", "hostnames": ["a.example"]},
        {"ip_str": "2.2.2.2", "port": 443, "org": "Org B", "hostnames": []},
    ],
}


@pytest.mark.asyncio
async def test_host_lookup_parses_fields():
    with patch("kalimcp.tools.shodan_lookup._sync_get_json", return_value=_HOST_SAMPLE) as m:
        res = await shodan_lookup.host_lookup("1.2.3.4", api_key=_API_KEY)
    assert res["ok"] is True
    assert res["ip"] == "1.2.3.4"
    assert res["ports"] == [22, 80, 443]
    assert res["hostnames"] == ["host.example.com"]
    assert res["org"] == "Example Org"
    assert res["os"] == "Linux"
    assert res["vulns"] == ["CVE-2021-44228"]
    assert res["isp"] == "Example ISP"
    # The IP went into the path; the key into the query string.
    url = m.call_args.args[0]
    assert "/shodan/host/1.2.3.4" in url
    assert f"key={_API_KEY}" in url


@pytest.mark.asyncio
async def test_search_parses_matches():
    with patch("kalimcp.tools.shodan_lookup._sync_get_json", return_value=_SEARCH_SAMPLE) as m:
        res = await shodan_lookup.search("apache", api_key=_API_KEY)
    assert res["ok"] is True
    assert res["total"] == 2
    assert res["count"] == 2
    assert res["matches"][0]["ip_str"] == "1.1.1.1"
    assert res["matches"][0]["port"] == 80
    assert res["matches"][1]["org"] == "Org B"
    url = m.call_args.args[0]
    assert "query=apache" in url


@pytest.mark.asyncio
async def test_search_respects_limit():
    with patch("kalimcp.tools.shodan_lookup._sync_get_json", return_value=_SEARCH_SAMPLE):
        res = await shodan_lookup.search("apache", api_key=_API_KEY, limit=1)
    assert res["count"] == 1
    assert len(res["matches"]) == 1


@pytest.mark.asyncio
async def test_host_lookup_missing_api_key():
    res = await shodan_lookup.host_lookup("1.2.3.4", api_key="")
    assert res["ok"] is False
    assert res["error"] == "shodan api_key required"


@pytest.mark.asyncio
async def test_search_missing_api_key():
    res = await shodan_lookup.search("apache", api_key="   ")
    assert res["ok"] is False
    assert res["error"] == "shodan api_key required"


@pytest.mark.asyncio
async def test_host_lookup_empty_ip():
    res = await shodan_lookup.host_lookup("   ", api_key=_API_KEY)
    assert res["ok"] is False
    assert res["error"] == "empty_ip"


@pytest.mark.asyncio
async def test_search_empty_query():
    res = await shodan_lookup.search("", api_key=_API_KEY)
    assert res["ok"] is False
    assert res["error"] == "empty_query"


@pytest.mark.asyncio
async def test_host_lookup_network_error_is_handled():
    with patch(
        "kalimcp.tools.shodan_lookup._sync_get_json",
        side_effect=urllib.error.URLError("boom"),
    ):
        res = await shodan_lookup.host_lookup("1.2.3.4", api_key=_API_KEY)
    assert res["ok"] is False
    assert res["error"] == "lookup_failed"


@pytest.mark.asyncio
async def test_api_key_never_leaks_into_result():
    # An error that echoes the URL (key embedded) must come back redacted.
    def _raise_with_key(url, timeout):
        raise urllib.error.URLError(f"failed fetching {url}")

    with patch("kalimcp.tools.shodan_lookup._sync_get_json", side_effect=_raise_with_key):
        host_res = await shodan_lookup.host_lookup("1.2.3.4", api_key=_API_KEY)
        search_res = await shodan_lookup.search("apache", api_key=_API_KEY)

    for res in (host_res, search_res):
        assert res["ok"] is False
        # The key must appear nowhere in the serialized result.
        assert _API_KEY not in json.dumps(res)
