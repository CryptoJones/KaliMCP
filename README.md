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

## Read this first

KaliMCP exposes offensive security tools to an AI agent. The
operator is responsible for using it only against targets they are
authorized to scan — pentest engagements with written scope, CTFs
you have a flag for, your own lab, bug bounty targets where the
program's scope covers what you're scanning.

A short refuse list is hard-coded in `src/kalimcp/authz.py` —
`.gov` / `.mil` / financial-services domains and cloud-instance
metadata endpoints (`169.254.169.254`) are refused unconditionally
unless the environment sets `KALIMCP_ALLOW_REFUSED=1`. The refuse
list is a safety net, not a substitute for the operator knowing
their scope.

---

## What it does

Exposes the following [MCP](https://modelcontextprotocol.io/) tools to
any compliant client (Claude Code, Claude Desktop, future MCP-aware
clients):

| Tool | Wraps | Purpose |
|------|-------|---------|
| `nmap_scan` | `nmap` | port + service scan (5 named profiles) |
| `nikto_scan` | `nikto` | web-server vulnerability scan |
| `gobuster_dir` | `gobuster` | directory / file enumeration |
| `sslscan_scan` | `sslscan` | TLS / SSL cipher + cert enumeration |
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

Restart Claude Code. The eight tools above will be available to the
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

## Refuse list

These targets are refused unconditionally unless the environment
sets `KALIMCP_ALLOW_REFUSED=1`:

| Pattern | Why |
|---------|-----|
| `*.gov`, `*.mil`, `*.gov.uk` (etc) | scanning these without a written contract is a federal-crime-grade mistake |
| `chase.com`, `bankofamerica.com`, ... | financial services have specific safe-harbor rules |
| `169.254.169.254` | cloud-instance metadata endpoint (AWS/GCP/Azure) |

The refuse list is intentionally short. It catches the most common
"oh god I didn't mean to scan that" cases; it is not a substitute
for the operator knowing their scope.

---

## What's NOT here (and why)

KaliMCP v0.1 deliberately ships only **reconnaissance + light
vulnerability scanning**. The dual-use tools below are NOT exposed
in this release:

- **Exploitation frameworks** (Metasploit modules, msfconsole).
- **Credential brute-force** (hydra, medusa).
- **SQL injection automation** (sqlmap).
- **Password cracking** against captured hashes — local-only and
  arguably defensive, but easy to misuse.

Operators with legitimate need can fork + extend.

---

## Status

| Version | Feature | Status |
|---------|---------|--------|
| v0.1 | nmap / nikto / gobuster / sslscan / whois / dig / searchsploit / cert_dump; audit log; Dockerfile on kali-rolling | shipped |
| v0.2 | richer audit-log replay | planned |
| v0.3 | structured nmap XML output → JSON; nikto JSON normalization | planned |
| v0.4 | sqlmap | planned |

---

## License

Apache 2.0. See [LICENSE](LICENSE).

Proudly Made in Nebraska. Go Big Red! 🌽 https://xkcd.com/2347/
