# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Security

- **File-path arguments validated at one shared choke point (#9, Theme A).**
  Added `run.validate_file()` — an existence/type check that returns a clean
  structured error for a missing or non-regular file. The credential and
  cracking wrappers (hydra `-L`/`-P`, john hashfile + wordlist, hashcat
  hashfile + wordlist) previously passed any agent-supplied path straight to
  the tool while only ffuf/gobuster hand-rolled the check; all five now route
  through the helper, so a new wrapper can't silently omit it. This is
  existence validation, not a path allowlist — consistent with the
  no-authorization-gate design rule.
- **Engagement-name `..` path traversal closed (#9, Theme C).** The name
  sanitizer's charset allows `.`, so `_sanitize_name("..")` returned `".."`
  unchanged and `engagement_dir("..")` / `store_loot(blob_name="..")`
  resolved a directory *above* the engagements root. Names that are nothing
  but dots now collapse to the default engagement.
- **IPv6 scope matching fixed (#9, Theme C).** `_extract_host()` only
  stripped a port when the target had exactly one colon, so a bracketed
  literal like `[::1]:8080` fell through unparsed and the out-of-scope
  warning silently never fired for IPv6 targets. Bracketed IPv6 (with or
  without a port) is now parsed to the bare address.

### Fixed

- **Tool subprocesses no longer orphan when the server stops.** Wrapped
  tools (nmap, hydra, sqlmap, …) now launch in their own process group
  (`start_new_session=True`), and `run.run` kills the whole group on
  timeout *and* on task cancellation. Cancellation is what fires when the
  MCP server shuts down on stdin EOF or the client disconnects, so a
  long scan can no longer keep running as an orphan after the agent is
  gone. Killing the group (not just the immediate child) also reaps tools
  that fork a real worker.

### Changed — internal

- **Validation failures go through one `run.error_result()` helper.** The
  seventeen hand-rolled "bad input" return dicts scattered across the tool
  wrappers (unknown profile/mode/protocol, missing wordlist, missing
  credential material, …) collapsed onto a single helper that builds the
  standard structured result (`exit_code -1`, empty output, empty argv).
  Wrappers pass only what differs — the `stderr` message, their
  empty-`parsed` skeleton, and any extra key such as `profile=`. Pure
  refactor; the returned shapes are byte-for-byte identical.

### Removed — dead code

- **`_KRB5_LINE` regex dropped from `tools/impacket.py`.** It was compiled
  but never matched against anything — the kerberoast/asreproast wrappers
  return hashes straight from stdout. `__version__` in the package
  `__init__` was also synced to `0.9.0` (it had drifted to a stale `0.1.0`).
- **`src/kalimcp/authz.py` deleted.** The module was entirely legacy:
  `is_refused()` had been a no-op stub returning `None` since the
  refuse list was dropped in v0.4 (`2143fdd`), and the `Authorization`
  dataclass / `check()` / load-save helpers were unwired remnants of
  the v0.1 `authorization_token` requirement (removed in `cc66cf8`).
  The unreachable refuse-list branch and `authz` import are gone from
  `tools/_active.py`; `tests/test_authz.py` and the four obsolete
  refuse-path cases in `tests/test_active.py` are deleted. No
  observable behavior changes — the refuse list had been inert for
  five releases.

### Added — project files

- `CLAUDE.md` — architecture guide for AI agents working in the repo.
- `CONTRIBUTING.md` — dev setup, the tool-wrapper checklist, dual-mirror
  workflow, commit conventions.
- `SECURITY.md` — authorized-use responsibility + how to report a flaw
  in the server code itself.
- `.dockerignore` — keeps `.git`, `.venv`, tests, and caches out of the
  build context.

### Added — CI

- **hadolint Dockerfile lint** in both Woodpecker and GitHub Actions,
  configured via `.hadolint.yaml` (`failure-threshold: error`; the
  version-pinning rules are ignored because the base is rolling). A
  full image build stays out of CI — the Kali + metasploit image is too
  heavy to build per-push.
- **mypy type checking** in both Woodpecker and GitHub Actions. The bar is
  mypy's default (non-strict), matching this thin `@mcp.tool()` shim layer —
  strict mode would mostly flag decorator and `Any`-generics noise rather than
  real bugs. `[tool.mypy]` sets `files = ["src"]`. Two wrappers gained explicit
  `dict[str, Any]` annotations (`tools/sqlmap.py`, `tools/hydra.py`) so the
  checker passes clean.
- **pip-audit dependency CVE scan** as its own job/step in both pipelines,
  after the lint and type gates. CI upgrades `pip` first so a stale-pip
  advisory can't fail the run, and a fresh resolve picks up the patched
  `pyjwt` / `starlette` that `mcp` pulls in transitively.

### Changed

- `test_mcp_client.py` moved to `scripts/smoke_client.py` and renamed so
  pytest never tries to collect the manual smoke client; its stale
  refuse-list docstring is corrected.
- Scrubbed the unpublished `ghcr.io/cryptojones/kalimcp:latest` image
  reference from the `server.py` Docker example — it now matches the
  README's local `docker build -t kalimcp .` flow.
- Refreshed audit/passive/decorator docstrings and comments that still
  described the removed refuse list; dropped the producerless
  `subdomains` auto-record rule and the dangling `web_screenshot`
  reference in the engagement docstring.

## [0.9.0] — 2026-06-02

### Added — engagement workspace

The agent now has working memory across tool calls. Every
engagement is a directory under
``~/.kalimcp/engagements/<name>/``:

    engagement.json     metadata: name, scope, started_at, operator
    findings.jsonl      append-only structured findings
    creds.jsonl         credential cache (mode 0600)
    loot/               extracted blobs (dumped data, ticket files)
    screenshots/        PNG output (reserved for future screenshot tool)
    notes.md            operator free-form notes

Active engagement resolves via ``KALIMCP_ENGAGEMENT`` env var,
then state file at ``~/.kalimcp/active_engagement`` (set by
``engagement_use``), then ``_default``.

**New ``kalimcp.engagement`` module** with pure I/O helpers:
``create``, ``list_all``, ``use``, ``status``, ``record_finding``,
``query_findings``, ``list_hosts``, ``record_cred``,
``query_creds``, ``write_loot``, ``list_loot``, ``read_loot``,
``note_append``, ``list_wordlists``, ``scope_matches``. All
file I/O is best-effort — a write failure returns ``False`` rather
than raising; the audit log remains the forensic source of truth.

**14 new MCP tools** wired into ``server.py``:
``engagement_create / engagement_list / engagement_use /
engagement_status``, ``finding_record / finding_query /
host_list``, ``cred_record / cred_query``, ``loot_write /
loot_list / loot_read``, ``note_append``, ``wordlist_list``.

### Added — auto-record + scope-warning hooks

The ``active_tool`` decorator now has two new behaviors, both
opt-in:

- **Auto-record (`KALIMCP_AUTORECORD=1`)** — after a successful
  tool call, inspect ``result["parsed"]`` and mirror structured
  findings / credentials into the active engagement workspace.
  Currently recognized keys:
    * ``parsed.hosts`` (nmap) → ``record_finding("host", addr, ...)``
    * ``parsed.subdomains`` → ``record_finding("subdomain", name, ...)``
    * ``parsed.injection_points`` (sqlmap) → ``record_finding("sqli", ...)``
    * ``parsed.secrets`` (secretsdump) → ``record_finding("secret_dump", ...)``
    * ``parsed.credentials_found`` (hydra/medusa) → ``record_cred(...)``
    * ``parsed.successes`` (netexec) → ``record_cred(...)``
    * ``parsed.cracked`` (john/hashcat) → ``record_cred("offline-crack", ...)``
  Default is OFF so existing test suites + ad-hoc tool calls
  don't silently mutate workspace state. Failures during
  auto-record are swallowed — the workspace is a side channel.
- **Scope warning** — if the active engagement has a non-empty
  ``scope`` (CIDR / domain glob / URL patterns) and the call's
  ``target`` doesn't match any pattern, the decorator annotates
  the result with ``"warning": "out_of_scope"`` and emits a
  separate ``out_of_scope_warning`` audit event. Does NOT block
  the call — the operator declared the scope and may legitimately
  scan outside it. Empty scope or no engagement means no gate.

### Changed

- ``audit.log`` events now include ``out_of_scope_warning`` and
  ``engagement_create`` / ``engagement_use`` lifecycle events.

## [0.8.0] — 2026-06-02

### Added — Windows AD post-exploit

Six new MCP tools for Active Directory post-exploitation work.
The impacket suite + a single-shot WinRM executor + msfvenom
payload generation cover the lateral-movement / loot-collection /
payload-staging surface that operators need once a foothold is
established.

- **`impacket_getnpusers`** — AS-REP roastable user enumeration
  via `impacket-GetNPUsers`. Parses `$krb5asrep$…` hash lines into
  `{users_no_preauth: [{user, hash}]}`.
- **`impacket_getuserspns`** — Kerberoasting via
  `impacket-GetUserSPNs`. Parses `$krb5tgs$…` hash lines into
  `{spns: [{user, spn, hash}]}`. Supports pass-the-hash auth via
  `nthash` instead of `password`.
- **`impacket_secretsdump`** — SAM / LSA / NTDS dump via
  `impacket-secretsdump`. Parses `user:rid:lmhash:nthash:::`
  lines into `{secrets: [{principal, rid, lmhash, nthash}],
  kerberos_keys: [...], cleartext: [...]}`. DCSync mode via
  `just_dc=True`.
- **`impacket_smbclient`** — one-shot SMB command via
  `impacket-smbclient`. Pipes the command via stdin (the binary is
  interactive by default). Parsed output is the captured response
  lines with the smbclient prompt stripped.
- **`winrm_exec`** — single PowerShell command over WinRM via
  `netexec winrm -X`. Cleaner than spinning up evil-winrm for a
  single command. Parsed output is the captured command lines
  with netexec's banner markers stripped.
- **`msfvenom_payload`** — Metasploit payload generator (NOT the
  framework). Writes payload bytes to
  `~/.kalimcp/payloads/<sha256>.<ext>` and returns
  `{path, sha256, size_bytes, format, payload, lhost, lport}`.
  Raw bytes are NEVER returned in the MCP result — operators
  retrieve the file off the box themselves. Supports encoder /
  iterations / badchars passthrough.

All Windows-credential-bearing wrappers declare secret_flags
(`-password`, `-hashes`, `--password`, `-H`, `--hash`) so the
audit log never carries credentials verbatim.

### Changed

- Dockerfile adds `impacket-scripts` and `metasploit-framework`
  (only msfvenom is wired; msfconsole / module exec stay out of
  scope).

## [0.7.0] — 2026-06-02

### Added — credential operations

Four new MCP tools for online + offline credential work, plus
audit-log hardening so secrets never land in the log file:

- **`netexec_spray`** — credential spray via netexec across
  smb/winrm/ldap/mssql/ssh/ftp/rdp/wmi/vnc. Single-pair
  (`username` + `password`) or list-based (`user_list` +
  `pass_list`); pass-the-hash via `nthash`. Parses netexec's
  ``[+] DOMAIN\\user:secret (Pwn3d!)`` success lines into
  ``{successes: [{host, proto, domain, user, secret, pwned}],
  failures_count}``.
- **`medusa_crack`** — network logon brute-force, alternative to
  hydra with different protocol-module coverage (notably
  ``smbnt``, ``cvs``, ``afp``). Parses ``ACCOUNT FOUND`` lines
  into the same parsed shape as hydra (``credentials_found``,
  ``hosts_tested``, ``services_tested``).
- **`john_crack`** — offline hash cracking via John the Ripper.
  ``target`` is the hashfile path. Two-pass invocation: runs
  ``john --wordlist=…`` then immediately ``john --show`` to scrape
  the pot file. Parsed: ``{cracked: [{user, password}], format,
  remaining, total_hashes}``.
- **`hashcat_crack`** — offline hash cracking via hashcat. Same
  run-then-show pattern. Requires explicit ``mode`` (no default —
  the wrong mode silently produces zero cracks). Parsed:
  ``{cracked: [{hash, password}], mode, total_hashes}``.

### Added — audit-log hardening

- **`audit.redact_argv(argv, secret_flags)`** rewrites values
  following secret-bearing flags to ``sha256:<8hex>``. The first
  8 hex chars of the SHA-256 digest are enough for an operator
  who suspects the plaintext to verify a match, but offer zero
  signal if the audit log leaks.
- **`@active_tool(..., secret_flags={...})`** — the decorator now
  threads a per-tool secret-flag set. When set, the audit log's
  ``argv`` field is redacted and a new ``secrets_redacted`` bool
  records that the rewrite happened. Wrapped tools that declare
  ``secret_flags``:
    * ``hydra_crack``: ``{-L, -P, -l, -p}`` (wordlist paths can
      leak engagement loot)
    * ``netexec_spray``: ``{-p, --password, -H, --hash}``
    * ``medusa_crack``: ``{-U, -u, -P, -p}``
    * ``john_crack``: ``{--wordlist, -w}``
    * ``hashcat_crack``: ``{-r, --rules-file}``
- `tool_invoke` audit events now always include a
  ``secrets_redacted: bool`` field (false for non-credential tools
  that don't declare a flag set).

### Changed

- Dockerfile adds ``netexec medusa john hashcat`` to the apt
  install list.

## [0.6.0] — 2026-06-02

### Added — recon expansion

Five new active-scan MCP tools, each following the existing
``@active_tool`` + structured-``parsed`` pattern:

- **`ffuf_fuzz`** — fast web fuzzer (gobuster's flexible cousin).
  Modes: ``dir`` (URL path), ``vhost`` (Host header), ``param``
  (GET/POST parameter name), ``ext`` (file extension). Parsed from
  ``-of json -o /dev/stdout`` into
  ``{results: [{url, status, length, words, lines, input?,
  redirect?, content_type?}]}``. Threads capped 1..200.
- **`whatweb_fingerprint`** — HTTP / tech-stack fingerprint via
  ``whatweb --log-json=-``. Parsed into
  ``{target, http_status, server, detected_cms, plugins:
  [{name, version?, string?, ...}]}``. Aggression 1 (passive) to 4
  (heavy intrusive) — clamped to that range.
- **`smb_enum`** — SMB / Windows enumeration via ``enum4linux-ng
  -A -oJ``. Parsed into ``{target, os, signing, null_session,
  shares, users, groups, domain}``. Reads JSON output from a
  tempfile and surfaces it in ``stdout`` so operators can re-parse.
- **`snmp_enum`** — SNMP enumeration via ``snmp-check -c <community>
  -v 2c``. Default community ``public``. Parsed into
  ``{target, community, hostname, contact, location, uptime,
  description, processes, software, services}``.
- **`ldap_enum`** — Anonymous LDAP / Active Directory rootDSE query
  via ``ldapsearch -x -s base``. Port 636 → ``ldaps://`` scheme.
  Parsed into ``{host, port, naming_contexts,
  default_naming_context, schema_dn, configuration_dn,
  supported_controls, supported_sasl_mechanisms,
  supported_ldap_versions, vendor, domain_functionality}``.
- New per-tool argv + parser tests in ``tests/test_tools.py``.
  ``tests/test_server.py:EXPECTED_TOOLS`` extended; all five new
  tools verified registered + free of the legacy
  ``authorization_token`` parameter.

### Changed

- ``Dockerfile`` adds ``ffuf whatweb enum4linux-ng snmp ldap-utils``
  to the apt install list.
- ``README.md`` tool table expanded; Status table v0.6 marked
  shipped. Go-binary tools (subfinder, feroxbuster, gowitness,
  kerbrute) are deliberately out of scope for this release — they
  require curl-install layers or a Go builder stage in the
  Dockerfile and will land in a follow-up phase.

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
