# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Aaron K. Clark
"""Enrichment helpers (issue #23): CVE lookup + hash identification.

* ``cve_search`` — NIST NVD lookup by CVE-ID or keyword, to enrich a
  service/version finding with CVSS + description.
* ``cve_package_audit`` — OSV.dev lookup for a dependency
  (ecosystem/package/version), for supply-chain review.
* ``identify_hash`` — an **offline** regex table that maps a captured hash
  to candidate types with their hashcat ``-m`` mode and john ``--format``,
  pairing with the existing ``hashcat_crack`` / ``john_crack`` wrappers.

The two CVE tools reach the network. All HTTP goes through the private
``_sync_get_json`` / ``_sync_post_json`` helpers (run in a thread so the
event loop isn't blocked); unit tests patch those, so the suite never
touches the network — consistent with the rest of the project.
"""

from __future__ import annotations

import asyncio
import json
import re
import urllib.error
import urllib.parse
import urllib.request
from typing import Any

_NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
_OSV_URL = "https://api.osv.dev/v1/query"
_USER_AGENT = "KaliMCP"

_CVE_ID_RE = re.compile(r"^CVE-\d{4}-\d{4,}$", re.IGNORECASE)


# ---------- HTTP (patched out in tests) ----------

def _sync_get_json(url: str, timeout: float) -> Any:
    req = urllib.request.Request(url, headers={"User-Agent": _USER_AGENT})
    with urllib.request.urlopen(req, timeout=timeout) as resp:  # noqa: S310 (https only)
        return json.loads(resp.read().decode("utf-8", errors="replace"))


def _sync_post_json(url: str, payload: dict[str, Any], timeout: float) -> Any:
    body = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(
        url, data=body,
        headers={"User-Agent": _USER_AGENT, "Content-Type": "application/json"},
    )
    with urllib.request.urlopen(req, timeout=timeout) as resp:  # noqa: S310
        return json.loads(resp.read().decode("utf-8", errors="replace"))


async def _get_json(url: str, timeout: float) -> Any:
    return await asyncio.to_thread(_sync_get_json, url, timeout)


async def _post_json(url: str, payload: dict[str, Any], timeout: float) -> Any:
    return await asyncio.to_thread(_sync_post_json, url, payload, timeout)


# ---------- CVE: NVD ----------

def _cvss_from_metrics(metrics: dict[str, Any]) -> dict[str, Any]:
    """Pull the best-available CVSS (v3.1 > v3.0 > v2) from NVD metrics."""
    for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        entries = metrics.get(key) or []
        if entries:
            data = entries[0].get("cvssData", {})
            return {
                "version": data.get("version", ""),
                "base_score": data.get("baseScore"),
                "severity": data.get("baseSeverity") or entries[0].get("baseSeverity", ""),
                "vector": data.get("vectorString", ""),
            }
    return {}


def _parse_nvd(doc: Any) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    for item in (doc or {}).get("vulnerabilities", []):
        cve = item.get("cve", {})
        descs = cve.get("descriptions", [])
        english = next((d.get("value", "") for d in descs if d.get("lang") == "en"), "")
        out.append({
            "id": cve.get("id", ""),
            "description": english,
            "cvss": _cvss_from_metrics(cve.get("metrics", {})),
            "published": cve.get("published", ""),
        })
    return out


async def cve_search(query: str, *, limit: int = 20, timeout_seconds: int = 15) -> dict[str, Any]:
    """Look up CVEs on NIST NVD by exact CVE-ID or keyword."""
    q = (query or "").strip()
    if not q:
        return {"ok": False, "error": "empty_query"}
    if _CVE_ID_RE.match(q):
        url = f"{_NVD_URL}?cveId={urllib.parse.quote(q.upper())}"
    else:
        per_page = max(1, min(int(limit), 50))
        url = (
            f"{_NVD_URL}?keywordSearch={urllib.parse.quote(q)}"
            f"&resultsPerPage={per_page}"
        )
    try:
        doc = await _get_json(url, timeout_seconds)
    except (urllib.error.URLError, TimeoutError, ValueError, OSError) as exc:
        return {"ok": False, "error": "lookup_failed", "message": str(exc), "source": "nvd"}
    results = _parse_nvd(doc)
    return {"ok": True, "source": "nvd", "query": q, "count": len(results), "results": results}


# ---------- CVE: OSV ----------

async def cve_package_audit(
    package: str,
    version: str = "",
    ecosystem: str = "PyPI",
    *,
    timeout_seconds: int = 15,
) -> dict[str, Any]:
    """Audit a dependency against OSV.dev (supply-chain review)."""
    pkg = (package or "").strip()
    if not pkg:
        return {"ok": False, "error": "empty_package"}
    payload: dict[str, Any] = {"package": {"name": pkg, "ecosystem": ecosystem}}
    if version.strip():
        payload["version"] = version.strip()
    try:
        doc = await _post_json(_OSV_URL, payload, timeout_seconds)
    except (urllib.error.URLError, TimeoutError, ValueError, OSError) as exc:
        return {"ok": False, "error": "lookup_failed", "message": str(exc), "source": "osv"}
    vulns = [
        {
            "id": v.get("id", ""),
            "summary": v.get("summary", "") or v.get("details", "")[:200],
            "aliases": v.get("aliases", []),
        }
        for v in (doc or {}).get("vulns", [])
    ]
    return {
        "ok": True, "source": "osv", "package": pkg, "ecosystem": ecosystem,
        "version": version, "count": len(vulns), "vulns": vulns,
    }


# ---------- hash identification (offline) ----------

# Prefix/structure patterns: (compiled regex, name, hashcat mode, john format).
_PREFIX_PATTERNS: list[tuple[re.Pattern[str], str, int | None, str]] = [
    (re.compile(r"^\$2[aby]\$\d{2}\$.{53}$"), "bcrypt", 3200, "bcrypt"),
    (re.compile(r"^\$1\$"), "md5crypt", 500, "md5crypt"),
    (re.compile(r"^\$5\$"), "sha256crypt", 7400, "sha256crypt"),
    (re.compile(r"^\$6\$"), "sha512crypt", 1800, "sha512crypt"),
    (re.compile(r"^\$y\$"), "yescrypt", None, "crypt"),
    (re.compile(r"^\$argon2(id|i|d)\$"), "argon2", None, "argon2"),
    (re.compile(r"^\$krb5tgs\$"), "Kerberos 5 TGS-REP (kerberoast)", 13100, "krb5tgs"),
    (re.compile(r"^\$krb5asrep\$"), "Kerberos 5 AS-REP", 18200, "krb5asrep"),
    (re.compile(r"^\$DCC2\$"), "Domain Cached Credentials 2 (mscash2)", 2100, "mscash2"),
    (re.compile(r"^\{SSHA\}"), "LDAP {SSHA}", 111, "salted-sha1"),
    (re.compile(r"^\*[0-9A-Fa-f]{40}$"), "MySQL 4.1+ (SHA1(SHA1))", 300, "mysql-sha1"),
]

# Pure-hex hashes keyed by length: (name, hashcat mode, john format).
_HEX_LEN: dict[int, list[tuple[str, int | None, str]]] = {
    16: [("MySQL323", 200, "mysql")],
    32: [("MD5", 0, "raw-md5"), ("NTLM", 1000, "nt"), ("MD4", 900, "raw-md4"),
         ("LM", 3000, "lm")],
    40: [("SHA-1", 100, "raw-sha1"), ("RIPEMD-160", 6000, "ripemd-160")],
    56: [("SHA-224", 1300, "raw-sha224")],
    64: [("SHA-256", 1400, "raw-sha256"), ("SHA3-256", 17400, "raw-sha3")],
    96: [("SHA-384", 10800, "raw-sha384")],
    128: [("SHA-512", 1700, "raw-sha512"), ("Whirlpool", 6100, "whirlpool")],
}

_NETNTLMV2_RE = re.compile(r"^[^:]+::[^:]*:[0-9A-Fa-f]{16}:[0-9A-Fa-f]{32}:[0-9A-Fa-f]+$")
_NETNTLMV1_RE = re.compile(r"^[^:]+::[^:]*:[0-9A-Fa-f]{48}:[0-9A-Fa-f]{48}:[0-9A-Fa-f]{16}$")


def identify_hash(value: str) -> dict[str, Any]:
    """Identify candidate hash types for ``value`` (offline regex table).

    Returns ``{value_length, candidates: [{name, hashcat_mode, john_format}]}``.
    The candidates are ordered most-likely first where length is ambiguous
    (e.g. a 32-hex string is MD5 or NTLM); pick by context.
    """
    v = (value or "").strip()
    candidates: list[dict[str, Any]] = []

    def add(name: str, mode: int | None, john: str) -> None:
        candidates.append({"name": name, "hashcat_mode": mode, "john_format": john})

    for pat, name, mode, john in _PREFIX_PATTERNS:
        if pat.match(v):
            add(name, mode, john)

    if _NETNTLMV2_RE.match(v):
        add("NetNTLMv2", 5600, "netntlmv2")
    elif _NETNTLMV1_RE.match(v):
        add("NetNTLMv1", 5500, "netntlm")

    if re.fullmatch(r"[0-9a-fA-F]+", v):
        for name, mode, john in _HEX_LEN.get(len(v), []):
            add(name, mode, john)

    return {"value_length": len(v), "candidates": candidates}
