# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Aaron K. Clark
"""Export an engagement's findings store as a report (issue #18).

Three formats, all built from the standard library (no heavy template /
PDF deps):

* **markdown** — a human-readable engagement report.
* **sarif** — SARIF v2.1.0, ingestible by GitHub Code Scanning. Rules are
  deduplicated by finding category; DAST ``webRequest``/``webResponse``
  artifacts are attached when a finding's payload carries HTTP evidence.
* **junit** — JUnit XML; ``error``-severity findings become ``<failure>``
  so a CI run that imports it goes red.

Credential *secrets* are masked in every format — a report is a
shareable artifact and must not spill plaintext from ``creds.jsonl``.
"""

from __future__ import annotations

import json
from typing import Any
from xml.etree import ElementTree as ET

from . import engagement

try:
    from . import __version__ as _VERSION
except Exception:  # pragma: no cover - version is always present
    _VERSION = "0"

FORMATS = ("markdown", "sarif", "junit")

# Finding category -> SARIF level (error / warning / note). A payload
# ``severity`` overrides this when present.
_CATEGORY_LEVEL: dict[str, str] = {
    "sqli": "error", "rce": "error", "secret_dump": "error", "cred": "error",
    "ssrf": "error", "auth_bypass": "error",
    "xss": "warning", "misconfig": "warning", "disclosure": "warning",
    "host": "note", "service": "note", "subdomain": "note", "port": "note",
}


def _level(finding: dict[str, Any]) -> str:
    payload = finding.get("payload") or {}
    sev = str(payload.get("severity", "")).strip().lower()
    if sev in ("critical", "high"):
        return "error"
    if sev in ("medium", "moderate"):
        return "warning"
    if sev in ("low", "info", "informational", "none"):
        return "note"
    return _CATEGORY_LEVEL.get(finding.get("category", ""), "warning")


def _finding_message(finding: dict[str, Any]) -> str:
    cat = finding.get("category", "finding")
    host = finding.get("host", "?")
    payload = finding.get("payload") or {}
    extra = payload.get("evidence") or payload.get("title") or payload.get("detail")
    base = f"{cat} on {host}"
    return f"{base}: {extra}" if extra else base


def generate(fmt: str, *, name: str | None = None) -> dict[str, Any]:
    """Render the active (or named) engagement's findings as ``fmt``.

    Returns ``{ok, format, content, findings, ...}``. ``content`` is the
    report text the caller can print or ``loot_write``.
    """
    f = (fmt or "").strip().lower()
    if f in ("md", "markdown"):
        f = "markdown"
    if f not in FORMATS:
        return {"ok": False, "error": "unknown_format", "known": list(FORMATS)}

    st = engagement.status(name)
    findings = engagement.query_findings(name=name, limit=1_000_000)
    creds = engagement.query_creds(name=name, limit=1_000_000)

    if f == "markdown":
        content = _markdown(st, findings, creds)
    elif f == "sarif":
        content = _sarif(st, findings)
    else:
        content = _junit(st, findings)
    return {
        "ok": True,
        "format": f,
        "content": content,
        "findings": len(findings),
        "creds": len(creds),
    }


# ---------- markdown ----------

def _markdown(st: dict[str, Any], findings: list[dict], creds: list[dict]) -> str:
    lines: list[str] = []
    lines.append(f"# Engagement report — {st.get('name', '?')}")
    lines.append("")
    lines.append(f"- **Operator:** {st.get('operator') or '—'}")
    lines.append(f"- **Started:** {st.get('started_at') or '—'}")
    scope = st.get("scope") or []
    lines.append(f"- **Scope:** {', '.join(scope) if scope else '— (no scope declared)'}")
    lines.append(f"- **Findings:** {len(findings)} | **Credentials:** {len(creds)}")
    lines.append("")

    lines.append("## Findings")
    lines.append("")
    if findings:
        lines.append("| Severity | Category | Host | Source | Detail |")
        lines.append("|----------|----------|------|--------|--------|")
        for fnd in findings:
            payload = fnd.get("payload") or {}
            detail = payload.get("evidence") or payload.get("detail") or ""
            detail = str(detail).replace("|", "\\|").replace("\n", " ")[:160]
            lines.append(
                f"| {_level(fnd)} | {fnd.get('category', '')} | {fnd.get('host', '')} "
                f"| {fnd.get('source_tool', '') or '—'} | {detail} |"
            )
    else:
        lines.append("_No findings recorded._")
    lines.append("")

    lines.append("## Credentials")
    lines.append("")
    if creds:
        lines.append("| Host | Proto | User | Secret | Source |")
        lines.append("|------|-------|------|--------|--------|")
        for c in creds:
            lines.append(
                f"| {c.get('host', '')} | {c.get('proto', '')} | {c.get('user', '')} "
                f"| `********` | {c.get('source_tool', '') or '—'} |"
            )
        lines.append("")
        lines.append("_Secrets are masked in exported reports; read them from "
                     "the engagement `creds.jsonl` (mode 0600) on the host._")
    else:
        lines.append("_No credentials recorded._")
    lines.append("")
    return "\n".join(lines)


# ---------- sarif ----------

def _sarif(st: dict[str, Any], findings: list[dict]) -> str:
    rules_by_id: dict[str, dict[str, Any]] = {}
    results: list[dict[str, Any]] = []

    for fnd in findings:
        cat = fnd.get("category", "finding")
        rules_by_id.setdefault(cat, {
            "id": cat,
            "name": cat,
            "shortDescription": {"text": f"{cat} finding"},
        })
        result: dict[str, Any] = {
            "ruleId": cat,
            "level": _level(fnd),
            "message": {"text": _finding_message(fnd)},
            "locations": [{
                "logicalLocations": [{
                    "fullyQualifiedName": fnd.get("host", ""),
                    "kind": "module",
                }],
            }],
            "properties": {
                "host": fnd.get("host", ""),
                "source_tool": fnd.get("source_tool", ""),
                "ts": fnd.get("ts", ""),
            },
        }
        # DAST evidence: attach webRequest / webResponse when present.
        payload = fnd.get("payload") or {}
        web: dict[str, Any] = {}
        if payload.get("request"):
            web["request"] = {"body": {"text": str(payload["request"])}}
        if payload.get("response"):
            web["response"] = {"body": {"text": str(payload["response"])}}
        if web:
            result["webRequest"] = web.get("request", {})
            result["webResponse"] = web.get("response", {})
        results.append(result)

    doc = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {
                "name": "KaliMCP",
                "informationUri": "https://github.com/CryptoJones/KaliMCP",
                "version": str(_VERSION),
                "rules": list(rules_by_id.values()),
            }},
            "results": results,
        }],
    }
    return json.dumps(doc, indent=2, sort_keys=True)


# ---------- junit ----------

def _junit(st: dict[str, Any], findings: list[dict]) -> str:
    failures = sum(1 for f in findings if _level(f) == "error")
    suites = ET.Element("testsuites", {
        "name": "KaliMCP",
        "tests": str(len(findings)),
        "failures": str(failures),
    })
    suite = ET.SubElement(suites, "testsuite", {
        "name": str(st.get("name", "engagement")),
        "tests": str(len(findings)),
        "failures": str(failures),
    })
    for fnd in findings:
        case = ET.SubElement(suite, "testcase", {
            "classname": str(fnd.get("category", "finding")),
            "name": f"{fnd.get('category', 'finding')}: {fnd.get('host', '?')}",
        })
        if _level(fnd) == "error":
            failure = ET.SubElement(case, "failure", {
                "message": _finding_message(fnd),
                "type": str(fnd.get("category", "finding")),
            })
            failure.text = json.dumps(fnd.get("payload") or {}, sort_keys=True)
    return ET.tostring(suites, encoding="unicode")
