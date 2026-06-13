# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Aaron K. Clark
"""sslscan wrapper — TLS / SSL cipher + cert inspection.

Every invocation passes ``--xml=-`` so sslscan emits structured XML
on stdout. ``_parse_xml`` distills it into a ``parsed`` dict —
enabled protocols, accepted ciphers, certificate metadata, and known
vulnerabilities (heartbleed, compression). Agents consume
``parsed``; operators read raw XML in ``stdout``.
"""

from __future__ import annotations

import xml.etree.ElementTree as ET
from typing import Any

from .. import run
from ._active import active_tool


def _empty_parsed() -> dict[str, Any]:
    return {
        "host": "",
        "port": "",
        "protocols": [],
        "ciphers": [],
        "cert": {},
        "vulnerabilities": {},
    }


def _parse_xml(xml_text: str) -> dict[str, Any]:
    """Distill sslscan XML output into a small structured dict.

    Returns an empty container if parsing fails. Always returns
    every top-level key so callers don't have to KeyError-guard.
    """
    parsed = _empty_parsed()
    try:
        root = ET.fromstring(xml_text)
    except ET.ParseError:
        return parsed

    ssltest = root.find("ssltest")
    if ssltest is None:
        return parsed

    parsed["host"] = ssltest.get("host", "") or ssltest.get("sniname", "")
    parsed["port"] = ssltest.get("port", "")

    for proto_el in ssltest.findall("protocol"):
        ptype = proto_el.get("type", "")
        pversion = proto_el.get("version", "")
        enabled = proto_el.get("enabled") == "1"
        name = f"{ptype.upper()}v{pversion}" if ptype and pversion else (ptype or pversion)
        parsed["protocols"].append({"name": name, "enabled": enabled})

    for c_el in ssltest.findall("cipher"):
        cipher: dict[str, Any] = {
            "name": c_el.get("cipher", ""),
            "status": c_el.get("status", ""),
            "sslversion": c_el.get("sslversion", ""),
        }
        bits = c_el.get("bits")
        if bits is not None:
            try:
                cipher["bits"] = int(bits)
            except ValueError:
                cipher["bits"] = bits
        for opt in ("strength", "curve", "ecdhebits", "dhebits"):
            v = c_el.get(opt)
            if v is not None:
                cipher[opt] = v
        parsed["ciphers"].append(cipher)

    vulns: dict[str, Any] = {}
    for vuln_tag in ("heartbleed", "compression", "fallback", "renegotiation"):
        el = ssltest.find(vuln_tag)
        if el is None:
            continue
        if vuln_tag == "heartbleed":
            vulns["heartbleed"] = el.get("vulnerable") == "1"
        elif vuln_tag == "compression":
            vulns["compression"] = el.get("supported") == "1"
        elif vuln_tag == "fallback":
            vulns["fallback_scsv"] = el.get("supported") == "1"
        elif vuln_tag == "renegotiation":
            vulns["renegotiation_secure"] = el.get("secure") == "1"
    parsed["vulnerabilities"] = vulns

    certs_el = ssltest.find("certificates")
    if certs_el is not None:
        cert_el = certs_el.find("certificate")
        if cert_el is not None:
            cert: dict[str, Any] = {}
            for tag, key in (
                ("subject", "subject"),
                ("issuer", "issuer"),
                ("not-valid-before", "not_before"),
                ("not-valid-after", "not_after"),
                ("signature-algorithm", "sigalg"),
                ("altnames", "altnames"),
            ):
                child = cert_el.find(tag)
                if child is not None and child.text:
                    cert[key] = child.text.strip()
            pk_el = cert_el.find("pk")
            if pk_el is not None:
                ktype = pk_el.get("type")
                kbits = pk_el.get("bits")
                if ktype:
                    cert["key_type"] = ktype
                if kbits:
                    try:
                        cert["key_bits"] = int(kbits)
                    except ValueError:
                        cert["key_bits"] = kbits
            parsed["cert"] = cert

    return parsed


@active_tool(tool_name="sslscan")
async def scan(
    *,
    target: str,
    port: int = 443,
    timeout_seconds: int = 120,
) -> dict[str, Any]:
    """Enumerate TLS protocol versions, ciphers, and certificate info for `target`.

    Args:
      target: hostname or IP.
      port: TCP port (default 443).
      timeout_seconds: hard wallclock cap (default 120).

    Returns the structured ``kalimcp.run.run`` result dict augmented with:
      - ``parsed``: ``{host, port, protocols: [{name, enabled}],
        ciphers: [{name, bits, status, sslversion, ...}],
        cert: {subject, issuer, not_before, not_after, sigalg,
        key_type, key_bits, altnames},
        vulnerabilities: {heartbleed, compression, fallback_scsv,
        renegotiation_secure}}``. Empty containers on parse failure;
        raw XML stays in ``stdout``.
    """
    argv = ["sslscan", "--xml=-", f"--port={int(port)}", target]
    result = await run.run(argv, timeout=timeout_seconds)

    return run.distill(result, _parse_xml, _empty_parsed)
