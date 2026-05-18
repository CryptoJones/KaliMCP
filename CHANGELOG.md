# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.3.0] — 2026-05-17

### Removed (breaking)
- **`kalimcp-authz` CLI removed.** v0.2 already decoupled the
  authorization-token model from active-scan invocations; v0.3
  drops the management CLI too. The `[project.scripts]` entry-point
  is gone and `src/kalimcp/authz_cli.py` was deleted. The
  underlying `Authorization` dataclass + load/save helpers stay
  importable in `kalimcp.authz` for downstream code that wants
  them programmatically.

### Added
- **Structured `parsed` field on nmap_scan results.** Every nmap
  profile now invokes nmap with `-oX -` (XML to stdout). The
  wrapper parses the XML into:
    `{"hosts": [{"addr", "addrtype", "state",
                "ports": [{"portid", "protocol", "state",
                           "service", "product", "version"}]}]}`
  Agents consume `result["parsed"]`; raw XML stays in
  `result["stdout"]` for operators. Parser fails closed (empty
  `{"hosts": []}`) on malformed XML — no exception propagates.

### Changed
- nmap profile argv shape changed (every profile now ends with
  `-oX -` before the target). Existing tests in
  `tests/test_tools.py` updated to match. Operators who shelled
  out to nmap via the audit log's `argv` field will see the new
  flags.
- `src/kalimcp/authz.py` module docstring rewritten — the
  Authorization model is now labeled "legacy from v0.1" rather
  than as an active part of the tool path.

## [0.2.0] — 2026-05-17

### Removed (breaking)
- **`authorization_token` parameter removed from every active-scan
  tool** (nmap_scan, nikto_scan, gobuster_dir, sslscan_scan).
  Previously these tools required a token whose scope covered the
  target; that check was the central feature of v0.1. Any client
  that passed `authorization_token` in tool calls must drop it.

### Changed
- **Refuse list still enforced**, just no longer behind the
  authorization model. The active-tool decorator now checks
  `authz.is_refused(target)` at the start of every call and
  short-circuits with `{"ok": false, "error": "refused"}` if the
  target is on the list (`.gov`, `.mil`, financial-services TLDs,
  cloud-instance metadata IPs). Override remains
  `KALIMCP_ALLOW_REFUSED=1` in the environment.
- New public `authz.is_refused()` function — wraps the existing
  `_is_refused` and reads `KALIMCP_ALLOW_REFUSED` from env by
  default. `_is_refused` is retained as the internal implementation.
- Audit-log `tool_invoke` events stopped recording `authz_id` /
  `authz_name` (no token to record). A new `refused` event fires
  when the refuse-list guard short-circuits a call.

### Added
- `tests/test_active.py` — 6 cases covering the refuse-list +
  audit-log path through the `active_tool` decorator.
- `test_mcp_client.py` smoke-test client at the repo root.
  Resolves the kalimcp binary via `$KALIMCP_BIN` or `PATH`; scans
  127.0.0.1 only.

### Docs
- README rewritten end-to-end: tagline now "Kali Linux security
  tools for AI agents"; "Set up an authorization" section
  removed; "What it does" table dropped the Auth column.
- pyproject.toml description aligned with current behavior.
- audit.py / passive.py / server.py / authz.py module docstrings
  rewritten to drop stale auth-required language.

### Fixed
- Refuse list was silently inert from `cc66cf8` through `31f0a71`
  — the auth-token removal in `cc66cf8` deleted the only call site
  of `_is_refused`. `31f0a71` restored enforcement via the
  decorator.

### Security note
- Live authorization token literal landed in git history at
  `38af599` (test_mcp_client.py). The token is no longer
  load-bearing post-`cc66cf8`, but operators should still remove
  the matching record from `~/.kalimcp/authorizations.json` via
  `kalimcp-authz remove <name>` and rotate if it's referenced
  elsewhere.

## [0.1.0] — 2026-05-17 (initial commit)

### Added
- MCP server exposing eight Kali tools: nmap_scan, nikto_scan,
  gobuster_dir, sslscan_scan (active, token-scoped); whois_lookup,
  dig_record, searchsploit_search, cert_dump (passive).
- Authorization model (`Authorization` dataclass + scope-pattern
  matching: CIDR, domain glob, URL). `kalimcp-authz` CLI for
  managing tokens.
- Refuse list (`.gov`, `.mil`, financial-services TLDs, cloud
  metadata IPs) enforced via `authz.check()`. Override via
  `explicit_unsafe=true` on the auth record AND
  `KALIMCP_ALLOW_REFUSED=1` env.
- JSONL audit log at `/var/log/kalimcp.log` (fallback
  `~/.kalimcp/kalimcp.log`). Records tool, target, elapsed,
  exit code, token id (sha256 prefix), token name.
- Dockerfile on `kalilinux/kali-rolling` base. CI on Codeberg
  Woodpecker + GitHub Actions for Python 3.11 and 3.12.

---

Proudly Made in Nebraska. Go Big Red! 🌽 https://xkcd.com/2347/
