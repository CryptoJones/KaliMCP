# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Aaron K. Clark
"""Authorization model: tokens map to a target scope.

Every active-scan tool (nmap, nikto, gobuster, sslscan) requires an
``authorization_token`` parameter. The token is looked up in the
on-disk authorizations file (default: ~/.kalimcp/authorizations.json,
overridable via KALIMCP_AUTHZ_FILE) and the target is validated
against that token's scope.

A scope is a list of allowed target patterns:

  * CIDR blocks: "10.0.0.0/24", "192.168.1.0/24", "203.0.113.42/32"
  * Domain globs: "example.com", "*.example.com", "*.lab.local"
  * URLs: "https://example.com/api" (the host portion is matched)

A scan whose target doesn't match ANY pattern in scope is REFUSED
with a structured error. Operators add tokens via the
``kalimcp-authz`` CLI:

    kalimcp-authz add --name "Q3 pentest engagement" \\
                     --scope 203.0.113.0/24 --scope "*.client.example.com" \\
                     --expires 2026-08-01T00:00:00Z

Authorization tokens are NEVER logged in plaintext — the audit log
records a sha256 prefix (8 chars) of the token, the auth record's
``name``, and the matched scope entry.

Refuse list (cannot be added to scope):
  * RFC 1918 ranges are ALLOWED by default for lab work, but the
    refuse list blocks .gov, .mil, well-known cloud-metadata IPs,
    and a handful of financial-services TLDs. Override only by
    setting KALIMCP_ALLOW_REFUSED=1 AND having a token with
    explicit_unsafe=true.
"""

from __future__ import annotations

import dataclasses
import fnmatch
import hashlib
import ipaddress
import json
import os
import re
import urllib.parse
from datetime import datetime, timezone
from pathlib import Path

DEFAULT_AUTHZ_FILE = Path.home() / ".kalimcp" / "authorizations.json"

# Patterns we refuse outright unless the operator opts in explicitly.
_REFUSE_DOMAIN_SUFFIXES = (
    ".gov", ".mil",
    ".gov.uk", ".gov.au", ".gov.ca",
)
_REFUSE_FINANCIAL_HINTS = (
    "bankofamerica.com", "chase.com", "wellsfargo.com", "citi.com",
    "hsbc.com", "barclays.com", "santander.com",
)
_REFUSE_METADATA_IPS = {
    "169.254.169.254",  # AWS / GCP / Azure metadata
    "fd00:ec2::254",    # AWS metadata IPv6
}


class AuthzError(Exception):
    """Raised when authorization fails (missing token, out of scope, etc.)."""


@dataclasses.dataclass(frozen=True)
class Authorization:
    name: str
    token: str
    scope: tuple[str, ...]
    expires: str | None = None
    explicit_unsafe: bool = False

    def token_id(self) -> str:
        """First 8 chars of sha256 — safe to log."""
        return hashlib.sha256(self.token.encode("utf-8")).hexdigest()[:8]

    def is_expired(self, *, now: datetime | None = None) -> bool:
        if not self.expires:
            return False
        try:
            when = datetime.fromisoformat(self.expires.replace("Z", "+00:00"))
        except ValueError:
            return False
        ref = now or datetime.now(timezone.utc)
        if when.tzinfo is None:
            when = when.replace(tzinfo=timezone.utc)
        return ref >= when


def authz_path() -> Path:
    return Path(os.environ.get("KALIMCP_AUTHZ_FILE") or DEFAULT_AUTHZ_FILE)


def load_authorizations(path: Path | None = None) -> list[Authorization]:
    p = path or authz_path()
    if not p.exists():
        return []
    try:
        raw = json.loads(p.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return []
    out: list[Authorization] = []
    for entry in raw or []:
        try:
            out.append(Authorization(
                name=str(entry["name"]),
                token=str(entry["token"]),
                scope=tuple(entry.get("scope") or ()),
                expires=entry.get("expires"),
                explicit_unsafe=bool(entry.get("explicit_unsafe", False)),
            ))
        except (KeyError, TypeError):
            continue
    return out


def save_authorizations(authzs: list[Authorization], path: Path | None = None) -> None:
    p = path or authz_path()
    p.parent.mkdir(parents=True, exist_ok=True)
    data = [
        {
            "name": a.name,
            "token": a.token,
            "scope": list(a.scope),
            "expires": a.expires,
            "explicit_unsafe": a.explicit_unsafe,
        }
        for a in authzs
    ]
    # 0600 — the file contains live authorization tokens.
    p.write_text(json.dumps(data, indent=2, sort_keys=True), encoding="utf-8")
    try:
        p.chmod(0o600)
    except OSError:
        pass


def find_authorization(token: str, authzs: list[Authorization] | None = None) -> Authorization | None:
    if not token:
        return None
    authzs = authzs if authzs is not None else load_authorizations()
    for a in authzs:
        if a.token == token:
            return a
    return None


def _is_refused(target: str, *, allow_refused: bool = False) -> str | None:
    """Return a refuse reason if target is on the refuse list, else None."""
    if allow_refused:
        return None
    host = _extract_host(target)
    if not host:
        return None
    # IP-based refuse list
    try:
        ip = ipaddress.ip_address(host)
        if str(ip) in _REFUSE_METADATA_IPS:
            return f"refused: {ip} is a cloud-metadata endpoint"
    except ValueError:
        pass
    # Domain suffix refuse list
    host_l = host.lower()
    for s in _REFUSE_DOMAIN_SUFFIXES:
        if host_l == s.lstrip(".") or host_l.endswith(s):
            return f"refused: target ends in {s} (gov/mil domains require explicit_unsafe=true)"
    for h in _REFUSE_FINANCIAL_HINTS:
        if host_l == h or host_l.endswith("." + h):
            return f"refused: target {h} is in the financial-services refuse list"
    return None


def _extract_host(target: str) -> str:
    """Pull the hostname out of a URL, ip:port, or bare hostname/ip."""
    if not target:
        return ""
    if "://" in target:
        try:
            return urllib.parse.urlparse(target).hostname or ""
        except ValueError:
            return ""
    # bare host[:port] or CIDR
    if "/" in target and not target.startswith("/"):
        return target.split("/", 1)[0]
    if ":" in target and target.count(":") == 1:
        return target.split(":", 1)[0]
    return target


def _scope_matches(target: str, pattern: str) -> bool:
    """True iff `target` is covered by `pattern`."""
    host = _extract_host(target)
    if not host:
        return False
    # CIDR?
    try:
        network = ipaddress.ip_network(pattern, strict=False)
        try:
            ip = ipaddress.ip_address(host)
            return ip in network
        except ValueError:
            return False
    except ValueError:
        # Not a CIDR — treat as a domain/glob pattern
        pass
    # URL pattern? match host portion
    if "://" in pattern:
        pat_host = urllib.parse.urlparse(pattern).hostname or pattern
    else:
        pat_host = pattern
    return fnmatch.fnmatchcase(host.lower(), pat_host.lower())


def check(target: str, token: str, *, authzs: list[Authorization] | None = None) -> Authorization:
    """Validate `target` is in scope for `token`. Raises AuthzError on failure.

    Returns the matched Authorization record on success so callers
    can log the token_id + scope entry that matched.
    """
    if not target or not isinstance(target, str):
        raise AuthzError("missing target")
    if not token or not isinstance(token, str):
        raise AuthzError("missing authorization_token")

    auth = find_authorization(token, authzs)
    if auth is None:
        raise AuthzError("authorization_token does not match any known token")
    if auth.is_expired():
        raise AuthzError(f"authorization '{auth.name}' expired at {auth.expires}")

    allow_refused = (
        auth.explicit_unsafe and os.environ.get("KALIMCP_ALLOW_REFUSED") == "1"
    )
    refusal = _is_refused(target, allow_refused=allow_refused)
    if refusal:
        raise AuthzError(refusal)

    for pattern in auth.scope:
        if _scope_matches(target, pattern):
            return auth

    raise AuthzError(
        f"target '{target}' is not within the scope of authorization '{auth.name}'. "
        f"Scope: {list(auth.scope)}"
    )
