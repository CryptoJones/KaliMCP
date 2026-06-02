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

---

## What it does

Exposes the following [MCP](https://modelcontextprotocol.io/) tools to
any compliant client (Claude Code, Claude Desktop, future MCP-aware
clients):

| Tool | Wraps | Purpose |
|------|-------|---------|
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

**Auth & SQLi**

| Tool | Wraps | Purpose |
|------|-------|---------|
| `hydra_crack` | `hydra` | network logon brute-force (ssh/ftp/smb/http-…); 4 profiles |
| `sqlmap_scan` | `sqlmap` | automated SQL injection detection + exploitation; 4 profiles |

**Passive lookups**

| Tool | Wraps | Purpose |
|------|-------|---------|
| `whois_lookup` | `whois` | domain / IP registration info |
| `dig_record` | `dig` | DNS record lookup |
| `searchsploit_search` | `searchsploit` | local Exploit-DB grep |
| `cert_dump` | `openssl s_client` | TLS cert chain inspection |

---

## Install

### Docker (recommended)

```bash
git clone https://github.com/CryptoJones/KaliMCP.git
cd KaliMCP
docker build -t kalimcp .
```

The image pulls from `kalilinux/kali-rolling` and installs nmap,
nikto, gobuster, whois, dnsutils, exploitdb, sslscan, openssl,
wordlists, and seclists alongside the Python package.

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
        "-v", "/home/YOU/.kalimcp:/root/.kalimcp",
        "-v", "/var/log/kalimcp.log:/var/log/kalimcp.log",
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

Every tool call appends one JSON line to `/var/log/kalimcp.log` (or
`~/.kalimcp/kalimcp.log` if the system path isn't writable). The
log records:

- `event`: `tool_invoke`, `passive_invoke`, `tool_exception`.
- `tool`: which wrapper was called.
- `target`: the scanned host / URL (full string).
- `elapsed_ms`, `exit_code`, `timed_out`, `truncated`.

To use the standard system path without sudo on every invocation:

```bash
sudo touch /var/log/kalimcp.log
sudo chown $(id -un):$(id -gn) /var/log/kalimcp.log
```

The audit log is a strict side channel. Errors writing it never
affect tool execution. `KALIMCP_NO_LOG=1` disables it entirely
(for tests).

---

## What's NOT here (yet)

KaliMCP is on a multi-release red-team kit overhaul. The current
release covers reconnaissance, web-vuln, and the first wave of
auth + SQLi tooling (hydra, sqlmap). Planned in subsequent
releases: structured JSON output for `nikto`/`gobuster`/`sslscan`,
subdomain enumeration (amass/subfinder), web fuzzing (ffuf),
HTTP fingerprinting (whatweb), credential spraying (netexec),
Kerberos pre-auth enum (kerbrute), AD post-exploit (impacket
suite, evil-winrm), and an engagement workspace so the agent has
working memory across calls. See the Status table below.

Out of scope for now: the Metasploit framework itself (modules,
msfconsole). msfvenom for payload generation only is on the
post-exploit-phase roadmap.

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
| (later) | Go-binary recon tools (subfinder, feroxbuster, gowitness, kerbrute) — need curl-install layers in Dockerfile | planned |
| v0.7 | credential operations: netexec, medusa, john, hashcat, responder; argv-secret redaction in audit log | planned |
| v0.8 | post-exploit (Windows AD): impacket suite, evil-winrm, msfvenom payload generation | planned |
| v0.9 | engagement workspace (`~/.kalimcp/engagements/<name>/`) — findings + creds + loot + screenshots + scope-warning audit | planned |

See [CHANGELOG.md](CHANGELOG.md) for the per-release detail.

---

## License

Apache 2.0. See [LICENSE](LICENSE).

Proudly Made in Nebraska. Go Big Red! 🌽 https://xkcd.com/2347/
