# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.5.0] — 2026-06-02

### Added
- **Structured `parsed` field on every active-scan tool.** Until
  now only `nmap_scan` returned a parsed dict; `nikto_scan`,
  `gobuster_dir`, and `sslscan_scan` dumped raw stdout that agents
  had to brittle-text-parse. Now all four follow the nmap pattern:
    * `nikto_scan.parsed` — `{target_host, target_ip, target_port,
      server, vulnerabilities: [{msg} or {uri, msg}]}` extracted
      from nikto's line-oriented text output. The text format has
      been stable across versions; XML/JSON modes are not.
    * `sslscan_scan.parsed` — `{host, port, protocols: [{name,
      enabled}], ciphers: [{name, bits, status, sslversion, ...}],
      cert: {subject, issuer, not_before, not_after, sigalg,
      key_type, key_bits, altnames}, vulnerabilities:
      {heartbleed, compression, fallback_scsv,
      renegotiation_secure}}` extracted from sslscan's XML. Argv
      now includes `--xml=-` (breaking change to argv shape;
      operators tailing the audit log will see the new flag).
    * `gobuster_dir.parsed` — `{paths_found: [{path, status,
      size?, redirect?}]}` extracted via regex from gobuster's
      stable text output. gobuster has no clean machine-readable
      mode, so a regex parser is the least-bad option.
- Each tool's early-return error paths (missing wordlist, etc.)
  now also populate `parsed` with empty containers so agents
  never have to `KeyError`-guard.
- Parser tests in `tests/test_tools.py` covering populated,
  malformed, and empty-stdout cases for all three tools.

### Changed
- `sslscan_scan` argv shape: now `["sslscan", "--xml=-",
  "--port=<n>", "<target>"]`. Existing test for the default port
  updated to match. Operators monitoring the `argv` field in the
  audit log will see the new `--xml=-` flag.

## [0.4.0] — 2026-06-02

### Added
- **`hydra_crack` MCP tool** — network logon brute-force against
  ssh/ftp/smb/http-post-form/… via hydra. Four profiles: `quick`
  (fasttrack wordlist), `standard` (rockyou), `comprehensive`
  (rockyou + 16 tasks), `bruteforce` (charset walk via `-x`).
  Operator can override profile defaults with `username_list` /
  `password_list`. Output is parsed into a structured `parsed`
  block: `{success, credentials_found: [{host, service, username,
  password}], hosts_tested, services_tested, statistics}`.
- **`sqlmap_scan` MCP tool** — automated SQL injection probe
  against a target URL. Four profiles: `quick` / `standard` /
  `comprehensive` / `exploit` (level 5, risk 3, all techniques).
  Output parsed into `{success, vulnerable, injection_points: [...],
  dbms: {name, version}, hosts_tested, statistics}`.
- New per-tool tests in `tests/test_tools.py` covering argv shape
  per profile, unknown-profile error path, custom-list override
  (hydra), and parsed-output extraction from fixed sample outputs.
- New tool surface assertions in `tests/test_server.py`
  (`hydra_crack` and `sqlmap_scan` registered; both still reject
  the legacy `authorization_token` parameter).

### Changed
- **Refuse list is removed and documented as removed.** Commit
  `2143fdd` had already stripped the list's enforcement
  (`authz._is_refused` is a no-op stub returning `None`). v0.4
  reconciles `README.md`, `CHANGELOG.md`, and the module
  docstrings in `src/kalimcp/authz.py` and
  `src/kalimcp/tools/_active.py` so the documented behavior
  matches the code. The audit log at `/var/log/kalimcp.log`
  remains the operator-accountability mechanism; operator scope is
  the operator's responsibility, not a hard-coded TLD list's.
  `KALIMCP_ALLOW_REFUSED=1` is still honored but presently
  inert.
- README "What's NOT here" section trimmed: hydra and sqlmap are
  no longer excluded. Multi-release roadmap (v0.5 → v0.9) added
  to the Status table.
- `hydra.py` argv builder rewritten: the WIP version emitted
  duplicate `-L`/`-P` flags (once from a hard-coded default in the
  wrapper, again from the profile constant) and silently ignored
  caller-supplied `username_list`/`password_list` because the
  profile flags ran later in argv. New `_PROFILES` schema is a
  dict mapping profile name → `{wordlist, flags}`; the wrapper
  resolves wordlists once and emits each `-L`/`-P` exactly once.
- `hydra.py` credential regex corrected to match real hydra
  output. The WIP pattern expected `[IP][service]` in the first
  two brackets; real hydra emits `[PORT][service] host: IP login:
  USER password: PASS`. Hosts/services lists now use
  `dict.fromkeys` to preserve insertion order.

### Fixed
- `tests/test_tools.py`: every `@pytest.mark.asyncio` had been
  rewritten to `@ pytest.mark.asyncio` (stray space) in the
  staged diff. pytest would have skipped those tests as
  syntactically valid but un-decorated. All occurrences reverted.

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
