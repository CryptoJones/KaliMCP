# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Aaron K. Clark
"""CVE-enrichment + hash-identification tests (issue #23).

The CVE tools reach the network; here `_sync_get_json` / `_sync_post_json`
are patched so the suite never does. The hash table is offline.
"""

from __future__ import annotations

import urllib.error
from unittest.mock import patch

import pytest

from kalimcp import enrich

_NVD_SAMPLE = {
    "vulnerabilities": [{
        "cve": {
            "id": "CVE-2021-44228",
            "descriptions": [
                {"lang": "es", "value": "ignorar"},
                {"lang": "en", "value": "Log4j JNDI RCE"},
            ],
            "metrics": {"cvssMetricV31": [{
                "cvssData": {
                    "version": "3.1", "baseScore": 10.0,
                    "baseSeverity": "CRITICAL", "vectorString": "AV:N/...",
                },
            }]},
            "published": "2021-12-10",
        },
    }],
}


@pytest.mark.asyncio
async def test_cve_search_by_id_parses_cvss():
    with patch("kalimcp.enrich._sync_get_json", return_value=_NVD_SAMPLE) as m:
        res = await enrich.cve_search("CVE-2021-44228")
    assert res["ok"] is True
    assert res["results"][0]["id"] == "CVE-2021-44228"
    assert res["results"][0]["description"] == "Log4j JNDI RCE"
    assert res["results"][0]["cvss"]["base_score"] == 10.0
    assert res["results"][0]["cvss"]["severity"] == "CRITICAL"
    # CVE-ID path uses the cveId query param.
    assert "cveId=CVE-2021-44228" in m.call_args.args[0]


@pytest.mark.asyncio
async def test_cve_search_by_keyword_uses_keyword_param():
    with patch("kalimcp.enrich._sync_get_json", return_value={"vulnerabilities": []}) as m:
        res = await enrich.cve_search("apache log4j")
    assert res["ok"] is True
    assert res["count"] == 0
    assert "keywordSearch=apache" in m.call_args.args[0]


@pytest.mark.asyncio
async def test_cve_search_empty_query():
    res = await enrich.cve_search("   ")
    assert res["ok"] is False
    assert res["error"] == "empty_query"


@pytest.mark.asyncio
async def test_cve_search_network_error_is_handled():
    with patch("kalimcp.enrich._sync_get_json", side_effect=urllib.error.URLError("boom")):
        res = await enrich.cve_search("CVE-2021-44228")
    assert res["ok"] is False
    assert res["error"] == "lookup_failed"


@pytest.mark.asyncio
async def test_cve_package_audit_parses_vulns():
    sample = {"vulns": [{"id": "GHSA-xxxx", "summary": "RCE", "aliases": ["CVE-2020-1"]}]}
    with patch("kalimcp.enrich._sync_post_json", return_value=sample) as m:
        res = await enrich.cve_package_audit("flask", version="0.12", ecosystem="PyPI")
    assert res["ok"] is True
    assert res["count"] == 1
    assert res["vulns"][0]["id"] == "GHSA-xxxx"
    # The POST body carried the package coordinates.
    payload = m.call_args.args[1]
    assert payload["package"]["name"] == "flask"
    assert payload["version"] == "0.12"


@pytest.mark.asyncio
async def test_cve_package_audit_empty_package():
    res = await enrich.cve_package_audit("")
    assert res["ok"] is False


# ---------- hash identification (offline) ----------


def test_identify_md5_and_ntlm_ambiguous():
    res = enrich.identify_hash("5f4dcc3b5aa765d61d8327deb882cf99")
    assert res["value_length"] == 32
    names = {c["name"] for c in res["candidates"]}
    assert {"MD5", "NTLM"} <= names
    md5 = next(c for c in res["candidates"] if c["name"] == "MD5")
    assert md5["hashcat_mode"] == 0
    ntlm = next(c for c in res["candidates"] if c["name"] == "NTLM")
    assert ntlm["hashcat_mode"] == 1000


def test_identify_sha256():
    res = enrich.identify_hash("a" * 64)
    names = {c["name"] for c in res["candidates"]}
    assert "SHA-256" in names


def test_identify_bcrypt():
    h = "$2b$12$" + "a" * 53
    res = enrich.identify_hash(h)
    assert res["candidates"][0]["name"] == "bcrypt"
    assert res["candidates"][0]["hashcat_mode"] == 3200


def test_identify_sha512crypt_prefix():
    res = enrich.identify_hash("$6$salt$" + "x" * 86)
    assert any(c["name"] == "sha512crypt" for c in res["candidates"])


def test_identify_kerberoast():
    res = enrich.identify_hash("$krb5tgs$23$*user$REALM$" + "a" * 64)
    c = next(c for c in res["candidates"] if "TGS-REP" in c["name"])
    assert c["hashcat_mode"] == 13100


def test_identify_unknown_returns_empty():
    res = enrich.identify_hash("not-a-hash!!")
    assert res["candidates"] == []
