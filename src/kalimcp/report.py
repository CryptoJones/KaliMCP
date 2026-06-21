# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Aaron K. Clark
"""Export an engagement's findings store as a report (issue #18).

Five formats, all built from the standard library (no heavy template /
PDF deps):

* **markdown** — a human-readable engagement report.
* **sarif** — SARIF v2.1.0, ingestible by GitHub Code Scanning. Rules are
  deduplicated by finding category; DAST ``webRequest``/``webResponse``
  artifacts are attached when a finding's payload carries HTTP evidence.
* **junit** — JUnit XML; ``error``-severity findings become ``<failure>``
  so a CI run that imports it goes red.
* **client** — a deliverable-shaped report: executive summary, severity
  rollup, per-finding remediation, and CVSS where the payload carries it.
  Unlike SARIF/JUnit (CI-shaped) this is the hand-to-the-customer artifact.
* **html** — the ``client`` report wrapped in a minimal, self-contained
  HTML document (no external CSS/JS), suitable for emailing or printing.

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

FORMATS = ("markdown", "sarif", "junit", "client", "html")

# Finding category -> SARIF level (error / warning / note). A payload
# ``severity`` overrides this when present.
_CATEGORY_LEVEL: dict[str, str] = {
    "sqli": "error", "rce": "error", "secret_dump": "error", "cred": "error",
    "ssrf": "error", "auth_bypass": "error",
    "xss": "warning", "misconfig": "warning", "disclosure": "warning",
    "host": "note", "service": "note", "subdomain": "note", "port": "note",
}

# Severity buckets for the client deliverable, ordered most→least severe.
_SEVERITY_ORDER = ("Critical", "High", "Medium", "Low", "Info")

# Finding category -> default severity bucket, used when the payload does
# not carry an explicit ``severity``.
_CATEGORY_SEVERITY: dict[str, str] = {
    "sqli": "Critical", "rce": "Critical", "secret_dump": "Critical",
    "cred": "Critical", "auth_bypass": "Critical",
    "ssrf": "High", "xss": "High",
    "misconfig": "Medium", "disclosure": "Medium",
    "host": "Info", "service": "Info", "subdomain": "Info", "port": "Info",
}

# Short, generic remediation hints keyed by finding category. These are
# advisory boilerplate for the deliverable, not authoritative guidance.
_CATEGORY_REMEDIATION: dict[str, str] = {
    "sqli": "Use parameterized queries / prepared statements; validate and "
            "least-privilege the database account.",
    "rce": "Patch the affected component, drop untrusted input from command "
           "execution paths, and restrict outbound egress.",
    "secret_dump": "Rotate all exposed secrets immediately and move them into "
                   "a managed secrets store.",
    "cred": "Rotate the affected credentials and enforce MFA on the account.",
    "auth_bypass": "Enforce server-side authorization on every request; do not "
                   "trust client-supplied identity.",
    "ssrf": "Restrict outbound requests to an allow-list and block access to "
            "internal/metadata addresses.",
    "xss": "Context-encode all output and apply a strict Content-Security-Policy.",
    "misconfig": "Harden the service to a known baseline and remove default "
                 "or unnecessary configuration.",
    "disclosure": "Remove sensitive data from responses and suppress verbose "
                  "error/version banners.",
    "host": "Confirm the host is in scope and inventory its exposed services.",
    "service": "Review the exposed service; restrict access and keep it patched.",
    "subdomain": "Confirm ownership and decommission stale or forgotten hosts.",
    "port": "Close unneeded ports and firewall management interfaces.",
}

_GENERIC_REMEDIATION = (
    "Validate the finding, restrict exposure, and apply vendor-recommended "
    "hardening for the affected component."
)


def _severity(finding: dict[str, Any]) -> str:
    """Map a finding to one of ``_SEVERITY_ORDER`` for the client report.

    Order of precedence: payload ``severity`` -> category default -> Info.
    """
    payload = finding.get("payload") or {}
    sev = str(payload.get("severity", "")).strip().lower()
    aliases = {
        "critical": "Critical", "crit": "Critical",
        "high": "High",
        "medium": "Medium", "moderate": "Medium",
        "low": "Low",
        "info": "Info", "informational": "Info", "none": "Info",
    }
    if sev in aliases:
        return aliases[sev]
    return _CATEGORY_SEVERITY.get(finding.get("category", ""), "Info")


def _remediation(finding: dict[str, Any]) -> str:
    return _CATEGORY_REMEDIATION.get(finding.get("category", ""), _GENERIC_REMEDIATION)


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
    elif f == "junit":
        content = _junit(st, findings)
    elif f == "client":
        content = _client_markdown(st, findings, creds)
    else:
        content = _client_html(st, findings, creds)
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


# ---------- client deliverable ----------

def _severity_counts(findings: list[dict]) -> dict[str, int]:
    counts = {sev: 0 for sev in _SEVERITY_ORDER}
    for fnd in findings:
        counts[_severity(fnd)] += 1
    return counts


def _group_by_severity(findings: list[dict]) -> dict[str, list[dict]]:
    groups: dict[str, list[dict]] = {sev: [] for sev in _SEVERITY_ORDER}
    for fnd in findings:
        groups[_severity(fnd)].append(fnd)
    return groups


def _detail(finding: dict[str, Any]) -> str:
    payload = finding.get("payload") or {}
    detail = (
        payload.get("evidence")
        or payload.get("detail")
        or payload.get("title")
        or payload.get("summary")
        or ""
    )
    return str(detail)


def _host_count(findings: list[dict], creds: list[dict]) -> int:
    hosts = {f.get("host") for f in findings if f.get("host")}
    hosts |= {c.get("host") for c in creds if c.get("host")}
    return len(hosts)


def _client_markdown(st: dict[str, Any], findings: list[dict], creds: list[dict]) -> str:
    name = st.get("name", "?")
    started = st.get("started_at") or "—"
    counts = _severity_counts(findings)
    hosts = _host_count(findings, creds)

    lines: list[str] = []
    lines.append(f"# Security Assessment Report — {name}")
    lines.append("")
    lines.append(f"_Prepared for engagement **{name}** "
                 f"(started {started})._")
    lines.append("")

    # ----- Executive Summary -----
    lines.append("## Executive Summary")
    lines.append("")
    lines.append(f"This assessment recorded **{len(findings)}** finding(s) "
                 f"across **{hosts}** host(s), and captured "
                 f"**{len(creds)}** credential(s).")
    lines.append("")
    lines.append("| Severity | Count |")
    lines.append("|----------|-------|")
    for sev in _SEVERITY_ORDER:
        lines.append(f"| {sev} | {counts[sev]} |")
    lines.append("")

    # ----- Findings, grouped by severity -----
    lines.append("## Findings")
    lines.append("")
    if findings:
        groups = _group_by_severity(findings)
        for sev in _SEVERITY_ORDER:
            bucket = groups[sev]
            if not bucket:
                continue
            lines.append(f"### {sev} ({len(bucket)})")
            lines.append("")
            lines.append("| Host | Category | Source | CVSS | Detail |")
            lines.append("|------|----------|--------|------|--------|")
            for fnd in bucket:
                payload = fnd.get("payload") or {}
                cvss = payload.get("cvss")
                cvss_s = str(cvss) if cvss not in (None, "") else "—"
                detail = _detail(fnd).replace("|", "\\|").replace("\n", " ")[:200]
                lines.append(
                    f"| {fnd.get('host', '')} | {fnd.get('category', '')} "
                    f"| {fnd.get('source_tool', '') or '—'} | {cvss_s} | {detail} |"
                )
            lines.append("")
            for fnd in bucket:
                host = fnd.get("host", "?")
                cat = fnd.get("category", "finding")
                lines.append(f"- **Remediation** ({cat} on {host}): {_remediation(fnd)}")
            lines.append("")
    else:
        lines.append("_No findings recorded._")
        lines.append("")

    # ----- Credentials (masked) -----
    lines.append("## Credentials Captured")
    lines.append("")
    if creds:
        lines.append(f"**{len(creds)}** credential(s) were captured during the "
                     "engagement. Secrets are masked in this deliverable.")
        lines.append("")
        for c in creds:
            user = c.get("user", "") or "—"
            host = c.get("host", "") or "—"
            proto = c.get("proto", "") or "—"
            lines.append(f"- `{user}@{host}` via {proto} — secret `********`")
        lines.append("")
        lines.append("_Plaintext secrets are never included in exported reports; "
                     "read them from the engagement `creds.jsonl` (mode 0600) on "
                     "the host._")
    else:
        lines.append("_No credentials captured._")
    lines.append("")
    return "\n".join(lines)


def _client_html(st: dict[str, Any], findings: list[dict], creds: list[dict]) -> str:
    """Wrap the client markdown's content in a minimal, self-contained HTML doc.

    No markdown library is available (stdlib only), so this renders the same
    sections directly as HTML rather than converting the markdown string.
    """
    from html import escape as _esc

    name = st.get("name", "?")
    started = st.get("started_at") or "—"
    counts = _severity_counts(findings)
    hosts = _host_count(findings, creds)

    parts: list[str] = []
    parts.append("<!DOCTYPE html>")
    parts.append('<html lang="en"><head><meta charset="utf-8">')
    parts.append(f"<title>Security Assessment Report — {_esc(str(name))}</title>")
    parts.append(
        "<style>body{font-family:system-ui,Arial,sans-serif;margin:2rem;"
        "max-width:60rem}table{border-collapse:collapse;width:100%}"
        "th,td{border:1px solid #ccc;padding:.4rem;text-align:left}"
        "th{background:#f3f3f3}code{background:#f3f3f3;padding:0 .2rem}"
        "h3{margin-top:1.5rem}</style></head><body>"
    )
    parts.append(f"<h1>Security Assessment Report — {_esc(str(name))}</h1>")
    parts.append(f"<p><em>Prepared for engagement <strong>{_esc(str(name))}</strong> "
                 f"(started {_esc(str(started))}).</em></p>")

    parts.append("<h2>Executive Summary</h2>")
    parts.append(f"<p>This assessment recorded <strong>{len(findings)}</strong> "
                 f"finding(s) across <strong>{hosts}</strong> host(s), and "
                 f"captured <strong>{len(creds)}</strong> credential(s).</p>")
    parts.append("<table><thead><tr><th>Severity</th><th>Count</th></tr></thead><tbody>")
    for sev in _SEVERITY_ORDER:
        parts.append(f"<tr><td>{sev}</td><td>{counts[sev]}</td></tr>")
    parts.append("</tbody></table>")

    parts.append("<h2>Findings</h2>")
    if findings:
        groups = _group_by_severity(findings)
        for sev in _SEVERITY_ORDER:
            bucket = groups[sev]
            if not bucket:
                continue
            parts.append(f"<h3>{sev} ({len(bucket)})</h3>")
            parts.append("<table><thead><tr><th>Host</th><th>Category</th>"
                         "<th>Source</th><th>CVSS</th><th>Detail</th>"
                         "<th>Remediation</th></tr></thead><tbody>")
            for fnd in bucket:
                payload = fnd.get("payload") or {}
                cvss = payload.get("cvss")
                cvss_s = _esc(str(cvss)) if cvss not in (None, "") else "—"
                parts.append(
                    "<tr>"
                    f"<td>{_esc(str(fnd.get('host', '')))}</td>"
                    f"<td>{_esc(str(fnd.get('category', '')))}</td>"
                    f"<td>{_esc(str(fnd.get('source_tool', '') or '—'))}</td>"
                    f"<td>{cvss_s}</td>"
                    f"<td>{_esc(_detail(fnd)[:200])}</td>"
                    f"<td>{_esc(_remediation(fnd))}</td>"
                    "</tr>"
                )
            parts.append("</tbody></table>")
    else:
        parts.append("<p><em>No findings recorded.</em></p>")

    parts.append("<h2>Credentials Captured</h2>")
    if creds:
        parts.append(f"<p><strong>{len(creds)}</strong> credential(s) were "
                     "captured. Secrets are masked in this deliverable.</p><ul>")
        for c in creds:
            user = _esc(str(c.get("user", "") or "—"))
            host = _esc(str(c.get("host", "") or "—"))
            proto = _esc(str(c.get("proto", "") or "—"))
            parts.append(f"<li><code>{user}@{host}</code> via {proto} — "
                         "secret <code>********</code></li>")
        parts.append("</ul><p><em>Plaintext secrets are never included in "
                     "exported reports; read them from the engagement "
                     "<code>creds.jsonl</code> (mode 0600) on the host.</em></p>")
    else:
        parts.append("<p><em>No credentials captured.</em></p>")

    parts.append("</body></html>")
    return "\n".join(parts)


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
