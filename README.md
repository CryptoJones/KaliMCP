<div align="center">

```
╔══════════════════════════════════════════════════════════════╗
║                                                              ║
║                 K  A  L  I  M  C  P                          ║
║                                                              ║
║       Kali Linux security tools for AI agents                ║
║                                                              ║
╚══════════════════════════════════════════════════════════════╝
```

**An MCP server that exposes a curated subset of Kali Linux's security
tools to an AI agent.** Every invocation is audit-logged.

[![License](https://img.shields.io/badge/License-Apache_2.0-blue.svg?logo=apache)](LICENSE)
[![Python](https://img.shields.io/badge/Python-3.11%2B-3776AB?logo=python&logoColor=white)](https://www.python.org/)
[![Kali](https://img.shields.io/badge/Base-kali--rolling-557C94?logo=kalilinux&logoColor=white)](https://www.kali.org/)
[![MCP](https://img.shields.io/badge/MCP-server-D97757?logo=anthropic&logoColor=white)](https://modelcontextprotocol.io/)
[![Codeberg](https://img.shields.io/badge/Codeberg-CryptoJones%2FKaliMCP-2185D0?logo=codeberg&logoColor=white)](https://codeberg.org/CryptoJones/KaliMCP)
[![GitHub](https://img.shields.io/badge/GitHub-CryptoJones%2FKaliMCP-181717?logo=github&logoColor=white)](https://github.com/CryptoJones/KaliMCP)

</div>

> Mirrored on both [GitHub](https://github.com/CryptoJones/KaliMCP) and
> [Codeberg](https://codeberg.org/CryptoJones/KaliMCP). Issues filed on
> either are welcome; commits are pushed to both.

---

## Authorization & scope

KaliMCP exposes offensive security tools — port scanners, web
vuln scanners, network logon brute-force, automated SQL injection
— to an AI agent. The operator is solely responsible for using it
only against targets they are authorized to scan: pentest
engagements with written scope, CTFs you have a flag for, your
own lab, bug bounty programs whose scope covers what you're
scanning. Cracking passwords or injecting SQL against systems
without authorization is a federal-grade mistake.

Every invocation appends one JSON line to `/var/log/kalimcp.log`
(target, argv, exit code, elapsed time). That audit trail is the
operator-accountability mechanism; the project does not enforce a
hard-coded refuse list.

Credential tools (`hydra_crack`, `medusa_crack`, `netexec_spray`,
`john_crack`, `hashcat_crack`) take password / hash / wordlist
values on the command line. Those values are redacted in the
audit log — the flag stays, but the value is rewritten to
`sha256:<8hex>` so the literal never lands in the log file.

Tool output is treated as **untrusted, attacker-controlled data**:
a scanned host's banners, page titles and headers can carry a
prompt-injection payload. Every active-tool result is tagged
`untrusted_output: true` (with a note telling the agent to treat it
as inert data) and the `stdout`/`stderr` handed to the model is
bounded (default 64 KiB, `KALIMCP_MODEL_OUTPUT_LIMIT` to change); the
full output stays in the capture and, with `KALIMCP_AUTORECORD=1`, in
the engagement loot store.

---

## What it does

Exposes the following [MCP](https://modelcontextprotocol.io/) tools to
any compliant client (Claude Code, Claude Desktop, future MCP-aware
clients):

**Recon / scanning**

| Tool | Wraps | Purpose |
|------|-------|---------|
| `nmap_scan` | `nmap` | port + service scan (5 named profiles); structured `parsed` JSON |
| `nikto_scan` | `nikto` | web-server vulnerability scan; structured `parsed` JSON |
| `gobuster_dir` | `gobuster` | directory / file enumeration; structured `parsed` JSON |
| `ffuf_fuzz` | `ffuf` | flexible web fuzzing (dir / vhost / param / ext modes) |
| `whatweb_fingerprint` | `whatweb` | HTTP / CMS / framework fingerprinting |
| `sslscan_scan` | `sslscan` | TLS / SSL cipher + cert enumeration; structured `parsed` JSON |
| `smb_enum` | `enum4linux-ng` | SMB shares / users / groups / OS / signing |
| `snmp_enum` | `snmp-check` | SNMP enumeration (hostname / contact / processes / software) |
| `ldap_enum` | `ldapsearch` | anonymous LDAP rootDSE query (naming contexts / vendor) |
| `traceroute_path` | `traceroute` | network path discovery (`-n`, no DNS) |
| `nuclei_scan` | `nuclei` | templated vulnerability scanning (severity / tags / custom templates) |
| `httpx_probe` | `httpx` | web probe — status / title / tech-detect / server banner |
| `dnsx_resolve` | `dnsx` | active DNS resolution (JSON records) |
| `wpscan_scan` | `wpscan` | WordPress version / vulnerable plugins+themes / users (API token redacted) |
| `gowitness_capture` | `gowitness` | headless-Chrome screenshot → engagement `screenshots/` dir |
| `zap_baseline` | `zaproxy` | OWASP ZAP headless baseline/quick web scan; parsed alert list |

**Auth & credentials**

| Tool | Wraps | Purpose |
|------|-------|---------|
| `hydra_crack` | `hydra` | network logon brute-force (ssh/ftp/smb/http-…); 4 profiles |
| `medusa_crack` | `medusa` | alt logon brute-force (different protocol modules: cvs/afp/smbnt) |
| `netexec_spray` | `netexec` | credential spray across smb/winrm/ldap/mssql/ssh; pass-the-hash |
| `john_crack` | `john` | offline hash cracking |
| `hashcat_crack` | `hashcat` | GPU-accelerated offline hash cracking |
| `sqlmap_scan` | `sqlmap` | automated SQL injection detection + exploitation; 4 profiles |

**Windows AD post-exploit**

| Tool | Wraps | Purpose |
|------|-------|---------|
| `impacket_getnpusers` | `GetNPUsers.py` | AS-REP roastable user enumeration |
| `impacket_getuserspns` | `GetUserSPNs.py` | Kerberoasting (request SPN TGS hashes) |
| `impacket_secretsdump` | `secretsdump.py` | SAM / LSA / NTDS dump (incl. DCSync) |
| `impacket_smbclient` | `smbclient.py` | one-shot SMB shell command |
| `winrm_exec` | `netexec winrm -X` | one-shot PowerShell over WinRM |
| `msfvenom_payload` | `msfvenom` | payload generation (bytes to disk, not served inline) |
| `certipy_find` | `certipy` | AD CS enumeration — flags ESC1-16 vulnerable templates / CAs |
| `certipy_request` | `certipy` | request a cert from a CA (ESC1-style abuse) → `.pfx` |
| `bloodhound_collect` | `bloodhound-python` | collect the AD graph to a `.zip` for BloodHound ingest |
| `kerbrute_userenum` | `kerbrute` | Kerberos pre-auth AD username enumeration (no lockout, low noise) |
| `kerbrute_passwordspray` | `kerbrute` | spray one password across an AD user list via Kerberos (password redacted) |

**Exploitation / delivery** (Tier 3 — crosses from capability into delivery; audited, not gated)

| Tool | Wraps | Purpose |
|------|-------|---------|
| `msf_run_module` | `msfconsole -x` | run a Metasploit module against a target (RHOSTS); can open a session |

**Credential-capture listeners** (long-lived; start → poll for captured NetNTLM hashes)

| Tool | Wraps | Purpose |
|------|-------|---------|
| `capture_start` / `capture_poll` / `capture_stop` / `capture_list` | `responder` / `mitm6` / `ntlmrelayx` | LLMNR/NBT-NS poisoning, IPv6 DNS takeover, NTLM relay |

**Cloud audit** (Tier 3 — audit a cloud account via local creds; no single target host)

| Tool | Wraps | Purpose |
|------|-------|---------|
| `cloud_scoutsuite` | `scout` | multi-cloud config audit (aws/azure/gcp/aliyun/oci) |
| `cloud_prowler` | `prowler` | cloud-security checks (OCSF JSON) |
| `cloud_kube_hunter` | `kube-hunter` | Kubernetes weakness scan (`--remote` or in-cluster) |

**Interactive sessions** (long-lived, keyed by session id; audited, not scope-gated)

| Tool | Purpose |
|------|---------|
| `ssh_session_start` / `ssh_session_exec` / `ssh_session_stop` | persistent SSH via OpenSSH ControlMaster (reused master connection) |
| `revshell_listen` / `revshell_exec` / `revshell_stop` | reverse-shell listener with non-blocking payload trigger |
| `socks_start` | SSH pivot with a dynamic SOCKS5 forward — route other tools into an internal segment |
| `ssh_put` / `ssh_get` | file transfer to/from the target over an open SSH/SOCKS session (scp) |
| `enum_upload_run` | upload a local-enum script (e.g. linpeas) and run it on the target |
| `session_status` / `session_list` | inspect open sessions |
| `system_network_info` | local interfaces + recommended LHOST (VPN-aware) |

**Engagement workspace (agent working memory)**

| Tool | Purpose |
|------|---------|
| `engagement_create` | bootstrap a new engagement dir with scope + operator |
| `engagement_list` / `engagement_use` / `engagement_status` | switch & inspect |
| `finding_record` / `finding_query` / `host_list` | append-only structured findings |
| `cred_record` / `cred_query` | credential cache (file mode 0600) |
| `loot_write` / `loot_list` / `loot_read` / `loot_verify` | extracted blob store (0600, SHA-256-verified) |
| `note_append` | operator free-form notes.md |
| `host_correlate` | per-host rollup of findings + creds (the analysis layer) |
| `findings_dedupe` | deduplicated view of findings (read-only; JSONL stays append-only) |
| `report_export` | export as Markdown / SARIF / JUnit / `client` (deliverable) / `html` (secrets masked) |
| `oast_start` / `oast_register` / `oast_poll` / `oast_stop` | self-hosted OOB callback catcher for blind-vuln detection |
| `wordlist_list` | enumerate wordlists under `/usr/share/wordlists` + seclists |
| `process_list` | list running tool subprocesses (PID, binary, elapsed) |
| `process_kill` | stop a runaway scan by PID (SIGTERM, or SIGKILL with `force`) |
| `health_check` | report which wrapped binaries are installed (optional versions) |

Set `KALIMCP_AUTORECORD=1` to have active-scan tools mirror their
parsed findings into the active engagement automatically (nmap →
findings, hydra/netexec → creds, etc.). If the active engagement
has a `scope` list, calls to out-of-scope targets get a non-
blocking `warning: "out_of_scope"` in the result + an audit event.

At most `KALIMCP_MAX_CONCURRENCY` tool subprocesses run at once
(default 8); extra calls queue. Each call still carries its own
wall-clock timeout and a 2 MB output cap. Use `process_list` /
`process_kill` to inspect and stop long-running scans without
tearing down the session.

**Passive lookups**

| Tool | Wraps | Purpose |
|------|-------|---------|
| `whois_lookup` | `whois` | domain / IP registration info |
| `dig_record` | `dig` | DNS record lookup |
| `searchsploit_search` | `searchsploit` | local Exploit-DB grep |
| `cert_dump` | `openssl s_client` | TLS cert chain inspection |
| `cve_search` | NIST NVD | CVE lookup by ID / keyword → CVSS + description |
| `cve_package_audit` | OSV.dev | dependency / supply-chain vuln lookup |
| `hash_identify` | (offline) | hash type → hashcat `-m` mode + john `--format` |
| `subfinder_enum` | `subfinder` | passive subdomain OSINT (public sources, no target probe) |
| `shodan_host` | Shodan API | host intel by IP (ports/hostnames/org/vulns); needs an API key |
| `shodan_search` | Shodan API | query Shodan's index for matching hosts; needs an API key |

**Loot triage** (read-only analysis of a file already on disk)

| Tool | Wraps | Purpose |
|------|-------|---------|
| `tshark_pcap` | `tshark` | capture analysis (summary / http / protocol hierarchy / conversations / expert) |
| `strings_extract` | `strings` | printable strings from a binary |
| `nm_symbols` | `nm` | symbol table (optional demangle / dynamic) |
| `objdump_inspect` | `objdump` | headers / sections / symbols / disassembly |
| `gdb_inspect` | `gdb` | batch-mode inspection of an on-disk binary (one `-ex` command) |
| `r2_analyze` | `radare2` | radare2 analysis of an on-disk binary (one `-c` command string) |

---

## Install

### Docker (recommended)

```bash
git clone https://github.com/CryptoJones/KaliMCP.git
cd KaliMCP
docker build -t kalimcp .
```

The image pulls from `kalilinux/kali-rolling` and installs the full
wrapped tool set alongside the Python package:

- **recon / web**: nmap, nikto, gobuster, sslscan, ffuf, whatweb,
  enum4linux-ng, snmp, ldap-utils
- **auth / credentials**: hydra, sqlmap, netexec, medusa, john,
  hashcat
- **Windows AD post-exploit**: impacket-scripts, metasploit-framework
  (only `msfvenom` is wired — see below)
- **passive / triage**: whois, dnsutils, exploitdb, openssl, tshark,
  binutils (strings/nm/objdump), traceroute
- **wordlists**: wordlists, seclists

### Bare metal (Kali Linux only — needs the tools installed already)

```bash
git clone https://github.com/CryptoJones/KaliMCP.git
cd KaliMCP
python3 -m venv .venv
.venv/bin/pip install -e .
```

---

## Wire into Claude Code

Edit (or create) `~/.claude/mcp.json`:

```json
{
  "mcpServers": {
    "kalimcp": {
      "command": "docker",
      "args": [
        "run", "-i", "--rm",
        "-v", "/home/YOU/.kalimcp:/home/kalimcp/.kalimcp",
        "kalimcp"
      ]
    }
  }
}
```

(Replace `/home/YOU` with `$HOME`.) Or bare-metal:

```json
{
  "mcpServers": {
    "kalimcp": {
      "command": "/path/to/.venv/bin/kalimcp"
    }
  }
}
```

Restart Claude Code. The tools above will be available to the
agent. Ask it to **"scan 10.0.0.5 with nmap-fast"** and it will
issue the call.

---

## Audit log

Every tool call appends one JSON line to the audit log. The Docker image
runs as the non-root `kalimcp` user and writes to
`~/.kalimcp/kalimcp.log` (i.e. the bind-mounted state dir) by default. A
bare-metal install writes to `/var/log/kalimcp.log`, falling back to
`~/.kalimcp/kalimcp.log` if that isn't writable; override the path with
`KALIMCP_LOG_FILE`. The log records:

- `event`: `tool_invoke`, `passive_invoke`, `tool_exception`.
- `tool`: which wrapper was called.
- `target`: the scanned host / URL (full string).
- `elapsed_ms`, `exit_code`, `timed_out`, `truncated`.

To use the standard system path on a bare-metal install without sudo on
every invocation:

```bash
sudo touch /var/log/kalimcp.log
sudo chown $(id -un):$(id -gn) /var/log/kalimcp.log
```

The audit log is a strict side channel. Errors writing it never
affect tool execution. `KALIMCP_NO_LOG=1` disables it entirely
(for tests).

---

## What's NOT here

The v0.4 → v0.9 red-team overhaul plus the pentest gap-coverage
phase are shipped: recon (incl. nuclei + the ProjectDiscovery
trio), web-vuln, auth/credential, Windows AD post-exploit and
analysis (BloodHound collection, Certipy AD CS, Responder/relay
capture), traversal (SOCKS pivot + file transfer), exploitation
(Metasploit module delivery), cloud audit, and the engagement
workspace are all live (see the Status table). What's still
deliberately left out:

- **BloodHound *graph querying*** — `bloodhound_collect` gathers the
  AD graph to a `.zip`, but path analysis runs in the neo4j-backed
  BloodHound GUI the operator ingests it into; the server doesn't
  embed neo4j.
- **evil-winrm's interactive shell** — `winrm_exec` covers
  single-shot PowerShell over WinRM (`netexec winrm -X`); there's
  no persistent interactive session.
- **Pacu (AWS exploitation REPL)** — intentionally omitted: it's an
  interactive shell, not a one-shot non-interactive command, so it
  doesn't fit the wrap-a-CLI model. ScoutSuite/Prowler cover cloud
  *audit*.
- **Wireless / physical / mobile** — out of scope by nature: they
  need radio hardware or a device, which a stdio container can't
  provide.

---

## Status

| Version | Feature | Status |
|---------|---------|--------|
| v0.1 | nmap / nikto / gobuster / sslscan / whois / dig / searchsploit / cert_dump; audit log; Dockerfile on kali-rolling | shipped |
| v0.2 | `authorization_token` parameter removed from active-scan tools (breaking); `argv` recorded in `tool_invoke` audit events; ruff lint gate; full test coverage on tool wrappers | shipped |
| v0.3 | structured nmap XML output → JSON; `kalimcp-authz` CLI dropped | shipped |
| v0.4 | `hydra_crack` + `sqlmap_scan` wired in; refuse list removed (audit log remains the accountability channel) | shipped |
| v0.5 | structured `parsed` JSON for `nikto_scan`, `sslscan_scan`, `gobuster_dir` | shipped |
| v0.6 | recon expansion: ffuf, whatweb, smb/snmp/ldap enum | shipped |
| v0.7 | credential operations: netexec, medusa, john, hashcat; argv-secret redaction in audit log | shipped |
| v0.8 | Windows AD post-exploit: impacket suite (NPUsers/UserSPNs/secretsdump/smbclient), winrm_exec, msfvenom payload generation | shipped |
| v0.9 | engagement workspace (`~/.kalimcp/engagements/<name>/`) — findings/creds/loot/screenshots + scope-warning audit + auto-record hook | shipped |
| (gap-coverage) | recon baseline (nuclei, subfinder/httpx/dnsx, wpscan, gowitness); AD analysis (BloodHound collect, Certipy, Responder/mitm6/ntlmrelayx capture); traversal (SOCKS pivot, scp put/get, linpeas runner); exploitation (Metasploit module delivery); cloud audit (ScoutSuite/Prowler/kube-hunter); RE (gdb/radare2); correlation + client/HTML reports | shipped |

See [CHANGELOG.md](CHANGELOG.md) for the per-release detail.

---

## Development

```bash
python3 -m venv .venv
.venv/bin/pip install -e '.[dev]'

.venv/bin/ruff check .          # lint (E, F, W, B, I, UP)
.venv/bin/mypy                  # type check (src/)
.venv/bin/pip-audit             # dependency CVE scan
.venv/bin/python -m pytest -q   # tests (no real subprocesses spawn)
```

CI (Woodpecker + GitHub Actions) runs ruff, mypy, pip-audit, a gitleaks
secret scan, a syft CycloneDX SBOM, and pytest on Python 3.11 and 3.12,
plus a hadolint pass on the Dockerfile. The Docker base image is pinned by
digest (not the moving `kali-rolling` tag) for reproducible, tamper-evident
builds — refresh it with `skopeo inspect --format '{{.Digest}}'
docker://kalilinux/kali-rolling`. See
[CONTRIBUTING.md](CONTRIBUTING.md) for the tool-wrapper checklist.

---

## Contributing & security

- [CONTRIBUTING.md](CONTRIBUTING.md) — dev setup, the tool-wrapper
  checklist, and the dual-mirror (GitHub + Codeberg) workflow.
- [SECURITY.md](SECURITY.md) — authorized-use responsibility and how to
  report a vulnerability in the server code itself.
- [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md) — actors, trust
  boundaries, and the mitigation for each threat (prompt injection via
  tool output, secret leakage, command/flag injection, resource
  exhaustion, supply chain).

---

## License

Apache 2.0. See [LICENSE](LICENSE).

Proudly Made in Nebraska. Go Big Red! 🌽 https://xkcd.com/2347/
