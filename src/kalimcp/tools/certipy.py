# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Aaron K. Clark
"""Certipy wrappers — AD Certificate Services (AD CS) attack tool.

Certipy (the ``certipy-ad`` package, binary ``certipy``) enumerates and
abuses AD CS misconfigurations (the ESC1-ESC16 family). Two MCP tools
share this module because they both probe the DC / CA with domain
credentials and share the same Kerberos-target / cred-handling
conventions used by the impacket wrappers:

  - certipy_find (certipy find)  — enumerate vulnerable templates / CAs
  - certipy_request (certipy req) — request a certificate (ESC1-style)

Both go through ``@active_tool`` with ``secret_flags`` declared so the
audit log never carries a password literal or an NT hash. Credentials
are mutually exclusive: pass ``password`` XOR ``nthash`` (mirrors
impacket).
"""

from __future__ import annotations

import re
from typing import Any

from .. import run
from ._active import active_tool

# Certipy's `find -stdout` output names vulnerable templates with an
# ``ESCx`` marker (e.g. ``[!] Vulnerabilities` ... `ESC1 : ...``). These
# parsers are deliberately best-effort line scanners — Certipy's text
# layout shifts between releases, so we extract markers rather than
# assume a fixed grammar.
_ESC_MARKER = re.compile(r"\bESC(\d{1,2})\b")
_TEMPLATE_LINE = re.compile(r"Template Name\s*:\s*(?P<name>\S.*?)\s*$", re.IGNORECASE)
_CA_LINE = re.compile(r"CA Name\s*:\s*(?P<name>\S.*?)\s*$", re.IGNORECASE)
# `certipy req` prints e.g. "[*] Saved certificate and private key to 'user.pfx'".
_PFX_LINE = re.compile(r"Saved certificate and private key to '(?P<pfx>[^']+)'", re.IGNORECASE)


def _auth_args(password: str, nthash: str) -> list[str]:
    """Build the credential argv fragment (password XOR nthash).

    Mirrors the impacket wrappers: an NT hash is passed as ``-hashes
    :<nt>`` (empty LM half); otherwise a cleartext ``-p <password>``.
    Both flags are declared ``secret_flags`` on the decorator so the
    audit log redacts the value.
    """
    if nthash:
        return ["-hashes", f":{nthash}"]
    return ["-p", password]


# ---------- find ----------

@active_tool(
    tool_name="certipy-find",
    secret_flags={"-p", "-hashes"},
)
async def find(
    *,
    target: str,
    username: str,
    password: str = "",
    nthash: str = "",
    dc_ip: str = "",
    timeout_seconds: int = 300,
) -> dict[str, Any]:
    """Enumerate AD CS templates / CAs and flag vulnerable ones.

    Args:
      target: AD domain (e.g. ``corp.local``) — the realm half of
        ``user@domain``.
      username: domain user to authenticate as.
      password: password literal. Mutually exclusive with ``nthash``.
      nthash: NT hash for pass-the-hash auth.
      dc_ip: DC IP. Required for cross-realm or air-gapped DNS.
      timeout_seconds: hard wallclock cap (default 300).

    Returns ``parsed``: ``{vulnerable_templates: [...], cas: [...],
    esc_findings: [...]}`` — best-effort scan of ``find -stdout`` for
    ``ESCx`` markers, template names, and CA names.
    """
    argv: list[str] = [
        "certipy", "find",
        "-u", f"{username}@{target}",
        "-stdout", "-vulnerable",
    ]
    argv.extend(_auth_args(password, nthash))
    if dc_ip:
        argv.extend(["-dc-ip", dc_ip])

    result = await run.run(argv, timeout=timeout_seconds)
    stdout = result.get("stdout", "") or ""
    parsed: dict[str, Any] = {
        "vulnerable_templates": [],
        "cas": [],
        "esc_findings": [],
    }
    for line in stdout.splitlines():
        s = line.strip()
        if not s:
            continue
        for n in _ESC_MARKER.findall(s):
            marker = f"ESC{n}"
            if marker not in parsed["esc_findings"]:
                parsed["esc_findings"].append(marker)
        m = _TEMPLATE_LINE.search(s)
        if m:
            name = m.group("name")
            if name not in parsed["vulnerable_templates"]:
                parsed["vulnerable_templates"].append(name)
            continue
        m = _CA_LINE.search(s)
        if m:
            name = m.group("name")
            if name not in parsed["cas"]:
                parsed["cas"].append(name)
    result["parsed"] = parsed
    return result


# ---------- request ----------

@active_tool(
    tool_name="certipy-request",
    secret_flags={"-p", "-hashes"},
)
async def request(
    *,
    target: str,
    username: str,
    password: str = "",
    nthash: str = "",
    ca: str = "",
    template: str = "",
    upn: str = "",
    dc_ip: str = "",
    timeout_seconds: int = 300,
) -> dict[str, Any]:
    """Request a certificate from a CA (ESC1-style abuse).

    Args:
      target: AD domain (e.g. ``corp.local``).
      username: domain user to authenticate as.
      password / nthash: auth method (mutually exclusive).
      ca: the issuing CA name (``-ca``).
      template: certificate template to request (``-template``).
      upn: alternate UPN to embed (``-upn``) — the ESC1 impersonation
        primitive (e.g. ``administrator@corp.local``).
      dc_ip: DC IP.
      timeout_seconds: hard wallclock cap (default 300).

    Returns ``parsed``: ``{pfx_path: "...", ok: bool}`` — the saved
    ``.pfx`` path scraped from stdout (``ok`` true when one was found).
    """
    argv: list[str] = [
        "certipy", "req",
        "-u", f"{username}@{target}",
        "-ca", ca,
        "-template", template,
    ]
    if upn:
        argv.extend(["-upn", upn])
    argv.extend(_auth_args(password, nthash))
    if dc_ip:
        argv.extend(["-dc-ip", dc_ip])

    result = await run.run(argv, timeout=timeout_seconds)
    stdout = result.get("stdout", "") or ""
    pfx_path = ""
    for line in stdout.splitlines():
        m = _PFX_LINE.search(line)
        if m:
            pfx_path = m.group("pfx")
            break
    result["parsed"] = {"pfx_path": pfx_path, "ok": bool(pfx_path)}
    return result
