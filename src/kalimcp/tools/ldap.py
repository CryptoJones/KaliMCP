# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Aaron K. Clark
"""LDAP enumeration wrapper — anonymous rootDSE query via ldapsearch.

Many internal LDAP / AD servers leak forest topology over an
anonymous query of the rootDSE. ``ldapsearch -x -s base`` is the
standard probe; we parse the LDIF-style key/value output into a
small structured dict (naming contexts, supported controls,
supported SASL mechanisms, default naming context, schema DN).
"""

from __future__ import annotations

import re
from typing import Any

from .. import run
from ._active import active_tool

# LDIF lines that often span multiple physical lines via the "line
# fold" convention (continuation lines start with a space). We
# normalize first.
_KEY_LINE = re.compile(r"^([A-Za-z][\w-]*)::?\s*(.*)$")


def _empty_parsed() -> dict[str, Any]:
    return {
        "host": "",
        "port": 389,
        "naming_contexts": [],
        "default_naming_context": "",
        "schema_dn": "",
        "configuration_dn": "",
        "supported_controls": [],
        "supported_sasl_mechanisms": [],
        "supported_ldap_versions": [],
        "vendor": "",
        "domain_functionality": "",
    }


def _unfold(text: str) -> list[tuple[str, str]]:
    """Fold LDIF continuation lines and yield (key, value) tuples."""
    lines: list[str] = []
    for raw in text.splitlines():
        if raw.startswith(" ") and lines:
            lines[-1] += raw[1:]
        else:
            lines.append(raw)
    out: list[tuple[str, str]] = []
    for line in lines:
        m = _KEY_LINE.match(line)
        if m:
            out.append((m.group(1), m.group(2).strip()))
    return out


def _parse_output(text: str) -> dict[str, Any]:
    parsed = _empty_parsed()
    for key, value in _unfold(text):
        k = key.lower()
        if k == "namingcontexts":
            parsed["naming_contexts"].append(value)
        elif k == "defaultnamingcontext":
            parsed["default_naming_context"] = value
        elif k == "schemanamingcontext":
            parsed["schema_dn"] = value
        elif k == "configurationnamingcontext":
            parsed["configuration_dn"] = value
        elif k == "supportedcontrol":
            parsed["supported_controls"].append(value)
        elif k == "supportedsaslmechanisms":
            parsed["supported_sasl_mechanisms"].append(value)
        elif k == "supportedldapversion":
            parsed["supported_ldap_versions"].append(value)
        elif k == "vendorname":
            parsed["vendor"] = value
        elif k == "domainfunctionality":
            parsed["domain_functionality"] = value
    return parsed


@active_tool(tool_name="ldap-enum")
async def enumerate(
    *,
    target: str,
    port: int = 389,
    timeout_seconds: int = 60,
) -> dict[str, Any]:
    """Anonymous LDAP rootDSE query against ``target``.

    Args:
      target: hostname or IP of the LDAP / Active Directory server.
      port: TCP port (default 389; pass 636 for LDAPS).
      timeout_seconds: hard wallclock cap (default 60).

    Returns the structured ``kalimcp.run.run`` result dict augmented
    with ``parsed``: ``{host, port, naming_contexts: [...],
    default_naming_context, schema_dn, configuration_dn,
    supported_controls: [...], supported_sasl_mechanisms: [...],
    supported_ldap_versions: [...], vendor, domain_functionality}``.
    """
    scheme = "ldaps" if int(port) == 636 else "ldap"
    uri = f"{scheme}://{target}:{int(port)}"
    argv = [
        "ldapsearch",
        "-x",                       # simple bind, anonymous
        "-H", uri,
        "-s", "base",               # query the rootDSE only
        "-LLL",                     # LDIF without comments/version
        "-b", "",                   # empty base DN — the rootDSE
        "+",                        # request operational attributes
    ]
    result = await run.run(argv, timeout=timeout_seconds)

    stdout = result.get("stdout", "") or ""
    if stdout.strip():
        parsed = _parse_output(stdout)
    else:
        parsed = _empty_parsed()
    parsed["host"] = target
    parsed["port"] = int(port)
    result["parsed"] = parsed
    return result
