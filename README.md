<div align="center">

```
╔══════════════════════════════════════════════════════════════╗
║                                                              ║
║                 K  A  L  I  M  C  P                          ║
║                                                              ║
║       authorized-use security tools for AI agents            ║
║                                                              ║
╚══════════════════════════════════════════════════════════════╝
```

**An MCP server that exposes a curated subset of Kali Linux's security
tools to an AI agent.** Every active scan is gated behind a
token-scoped target allowlist. Every invocation is audit-logged.

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

**KaliMCP is for authorized security work.** Pentest engagements with
written scope. CTFs you have a flag for. Your own lab. Bug bounty
targets where the program's scope covers what you're scanning.

It is **not** a "point at the internet and see what happens" tool.
The authorization model is the central feature, not a wrapper. If
you don't have written authorization to scan a target, KaliMCP is
designed to refuse to scan it — and you should not work around that.

A `.gov` / `.mil` / financial-services refuse list is hard-coded.
Override requires both `explicit_unsafe=True` on the authorization
record AND `KALIMCP_ALLOW_REFUSED=1` in the environment. If you find
yourself reaching for both at once, take a long pause first.

---

## What it does

Exposes the following [MCP](https://modelcontextprotocol.io/) tools to
any compliant client (Claude Code, Claude Desktop, future MCP-aware
clients):

| Tool | Auth | Wraps | Purpose |
|------|------|-------|---------|
| `nmap_scan` | required | `nmap` | port + service scan (5 named profiles) |
| `nikto_scan` | required | `nikto` | web-server vulnerability scan |
| `gobuster_dir` | required | `gobuster` | directory / file enumeration |
| `sslscan_scan` | required | `sslscan` | TLS / SSL cipher + cert enumeration |
| `whois_lookup` | none | `whois` | domain / IP registration info |
| `dig_record` | none | `dig` | DNS record lookup |
| `searchsploit_search` | none | `searchsploit` | local Exploit-DB grep |
| `cert_dump` | none | `openssl s_client` | TLS cert chain inspection |

"Auth required" tools refuse if (a) no `authorization_token` is given,
(b) the token is unknown, (c) the token is expired, or (d) the
target is outside the token's scope.

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

## Set up an authorization

Active-scan tools all require an `authorization_token`. Generate one
with the `kalimcp-authz` CLI:

```bash
kalimcp-authz add \
    --name "Q3 internal pentest" \
    --scope "10.0.0.0/24" \
    --scope "*.lab.internal" \
    --expires "2026-08-01T00:00:00Z"
```

The CLI writes the token to `~/.kalimcp/authorizations.json` (mode
`0600`) and prints it to your terminal **once**. Copy it somewhere
safe — KaliMCP won't show it again. The agent passes this token on
every active-scan call.

Scope patterns can be:

- **CIDR**: `10.0.0.0/24`, `203.0.113.42/32`, `2001:db8::/32`
- **Domain or wildcard**: `example.com`, `*.lab.internal`
- **URL**: `https://example.com/api` (only the host portion is matched)

A scan whose target doesn't match **any** pattern is refused.

Inspect / manage:

```bash
kalimcp-authz list
kalimcp-authz check --token <tok> --target 10.0.0.5
kalimcp-authz remove "Q3 internal pentest"
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
prompt for (or use a known) authorization token.

---

## Audit log

Every tool call appends one JSON line to `/var/log/kalimcp.log` (or
`~/.kalimcp/kalimcp.log` if the system path isn't writable). The
log records:

- `event`: `tool_invoke`, `authz_denied`, `passive_invoke`, `tool_exception`.
- `tool`: which wrapper was called.
- `target`: the scanned host / URL (full string).
- `authz_id`: an 8-char sha256 prefix of the token used (the raw
  token never lands in the log).
- `authz_name`: the human label from the authorization record.
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

These targets are refused unconditionally unless **both** the
authorization is flagged `explicit_unsafe=True` **and** the
environment sets `KALIMCP_ALLOW_REFUSED=1`:

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
- **SQL injection automation** (sqlmap, without much more careful
  authorization plumbing).
- **Password cracking** against captured hashes — local-only and
  arguably defensive, but easy to misuse.

Operators with legitimate need can fork + extend. Pull requests
adding any of these to upstream must come with a clear authorization
extension (e.g. per-tool scopes, distinct `explicit_unsafe` flags,
expanded refuse lists).

---

## Status

| Version | Feature | Status |
|---------|---------|--------|
| v0.1 | nmap / nikto / gobuster / sslscan / whois / dig / searchsploit / cert_dump; token-scoped authz; audit log; Dockerfile on kali-rolling | shipped |
| v0.2 | per-tool scope override; rate-limit per-token; richer audit-log replay (`kalimcp-authz replay`) | planned |
| v0.3 | structured nmap XML output → JSON; nikto JSON normalization | planned |
| v0.4 | sqlmap with stricter authz (URL-prefix scope; per-call confirmation) | planned |

---

## License

Apache 2.0. See [LICENSE](LICENSE).

Proudly Made in Nebraska. Go Big Red! 🌽 https://xkcd.com/2347/
