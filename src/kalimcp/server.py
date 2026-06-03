# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Aaron K. Clark
"""MCP server entry point. Exposes Kali tools as MCP tools.

Transport: stdio (default). The MCP client launches this process
and talks JSON-RPC over stdin/stdout.

To use with Claude Code, add this to ~/.claude/mcp.json:

    {
      "mcpServers": {
        "kalimcp": {
          "command": "kalimcp"
        }
      }
    }

Or, if running through Docker (build the image locally first with
``docker build -t kalimcp .``):

    {
      "mcpServers": {
        "kalimcp": {
          "command": "docker",
          "args": ["run", "-i", "--rm",
                   "-v", "~/.kalimcp:/root/.kalimcp",
                   "-v", "/var/log/kalimcp.log:/var/log/kalimcp.log",
                   "kalimcp"]
        }
      }
    }
"""

from __future__ import annotations

import sys

from mcp.server.fastmcp import FastMCP

from . import audit, engagement
from .tools import (
    ffuf,
    gobuster,
    hashcat,
    hydra,
    impacket,
    john,
    ldap,
    medusa,
    msfvenom,
    netexec,
    nikto,
    nmap,
    passive,
    smb,
    snmp,
    sqlmap,
    sslscan,
    whatweb,
    winrm,
)

mcp = FastMCP("kalimcp")


# ---------- active-scan tools ----------

@mcp.tool()
async def nmap_scan(
    target: str,
    profile: str = "tcp-fast",
    timeout_seconds: int = 300,
) -> dict:
    """Run nmap against `target` using a named profile.

    Profiles: tcp-fast, tcp-full, service-scan,
    udp-top-50, ping-sweep.
    """
    return await nmap.scan(
        target=target,
        profile=profile,
        timeout_seconds=timeout_seconds,
    )


@mcp.tool()
async def nikto_scan(
    target: str,
    ssl: bool = False,
    timeout_seconds: int = 600,
) -> dict:
    """Run nikto web-vulnerability scanner against `target` URL.
    """
    return await nikto.scan(
        target=target,
        ssl=ssl,
        timeout_seconds=timeout_seconds,
    )


@mcp.tool()
async def gobuster_dir(
    target: str,
    wordlist: str | None = None,
    threads: int = 10,
    timeout_seconds: int = 600,
) -> dict:
    """Directory brute-forcing on `target` URL via gobuster.
    Wordlist defaults to a known Kali path (dirb common.txt etc.).
    """
    return await gobuster.dir_scan(
        target=target,
        wordlist=wordlist,
        threads=threads,
        timeout_seconds=timeout_seconds,
    )


@mcp.tool()
async def sslscan_scan(
    target: str,
    port: int = 443,
    timeout_seconds: int = 120,
) -> dict:
    """Enumerate TLS protocols, ciphers, cert for `target:port` via sslscan.
    """
    return await sslscan.scan(
        target=target,
        port=port,
        timeout_seconds=timeout_seconds,
    )


@mcp.tool()
async def hydra_crack(
    target: str,
    service: str,
    username_list: str = "",
    password_list: str = "",
    profile: str = "standard",
    timeout_seconds: int = 300,
) -> dict:
    """Network logon brute-force against `target`'s `service` via hydra.

    Profiles: quick (fasttrack list), standard (rockyou),
    comprehensive (rockyou + 16 tasks), bruteforce (charset walk).
    Pass `username_list` / `password_list` to override profile defaults.
    `service` is a hydra service spec: ssh, ftp, smb, http-post-form, etc.
    """
    return await hydra.crack(
        target=target,
        service=service,
        username_list=username_list,
        password_list=password_list,
        profile=profile,
        timeout_seconds=timeout_seconds,
    )


@mcp.tool()
async def sqlmap_scan(
    target: str,
    profile: str = "standard",
    timeout_seconds: int = 600,
) -> dict:
    """Automated SQL injection probe against a URL via sqlmap.

    Profiles: quick (level 1, risk 1), standard (level 2, risk 2),
    comprehensive (level 3, risk 3), exploit (level 5, risk 3,
    all techniques). `target` should be a full URL including the
    parameter to test, e.g. http://host/page.php?id=1.
    """
    return await sqlmap.scan(
        target=target,
        profile=profile,
        timeout_seconds=timeout_seconds,
    )


@mcp.tool()
async def ffuf_fuzz(
    target: str,
    mode: str = "dir",
    wordlist: str | None = None,
    vhost_template: str | None = None,
    threads: int = 40,
    timeout_seconds: int = 600,
) -> dict:
    """Fast web fuzzer (ffuf). Substitutes wordlist entries into FUZZ.

    Modes: `dir` (URL path; pass `https://host/FUZZ`), `vhost`
    (Host header; pass base URL + `vhost_template` like
    `"FUZZ.example.com"`), `param` (pass `https://host/?FUZZ=test`),
    `ext` (file extension fuzzing). More flexible than gobuster.
    """
    return await ffuf.fuzz(
        target=target,
        mode=mode,
        wordlist=wordlist,
        vhost_template=vhost_template,
        threads=threads,
        timeout_seconds=timeout_seconds,
    )


@mcp.tool()
async def whatweb_fingerprint(
    target: str,
    aggression: int = 1,
    timeout_seconds: int = 120,
) -> dict:
    """HTTP / web-app fingerprint of a URL via whatweb.

    Identifies the server, CMS (WordPress / Drupal / Joomla / …),
    JS frameworks, analytics trackers. `aggression` 1 (passive) to
    4 (heavy intrusive probes).
    """
    return await whatweb.fingerprint(
        target=target,
        aggression=aggression,
        timeout_seconds=timeout_seconds,
    )


@mcp.tool()
async def smb_enum(target: str, timeout_seconds: int = 300) -> dict:
    """SMB enumeration via enum4linux-ng.

    Pulls shares, users, groups, OS info, signing status, and
    null-session ability from a Windows / Samba target.
    """
    return await smb.enumerate(target=target, timeout_seconds=timeout_seconds)


@mcp.tool()
async def snmp_enum(
    target: str,
    community: str = "public",
    timeout_seconds: int = 180,
) -> dict:
    """SNMP enumeration via snmp-check. Default community is `public`."""
    return await snmp.enumerate(
        target=target,
        community=community,
        timeout_seconds=timeout_seconds,
    )


@mcp.tool()
async def ldap_enum(
    target: str,
    port: int = 389,
    timeout_seconds: int = 60,
) -> dict:
    """Anonymous LDAP / AD rootDSE query via ldapsearch. Port 636 for LDAPS."""
    return await ldap.enumerate(
        target=target,
        port=port,
        timeout_seconds=timeout_seconds,
    )


# ---------- credential operations ----------
# These tools take password / hash literals on the command line.
# The audit log redacts secret-bearing argv values to sha256:<hex>
# so the literal never lands on disk; the active_tool decorator
# enforces that via its `secret_flags=` parameter.

@mcp.tool()
async def netexec_spray(
    target: str,
    protocol: str = "smb",
    username: str = "",
    password: str = "",
    user_list: str = "",
    pass_list: str = "",
    nthash: str = "",
    timeout_seconds: int = 600,
) -> dict:
    """Credential spray via netexec across smb/winrm/ldap/mssql/ssh/ftp/rdp/wmi/vnc.

    Pass `username` + `password` for a single-pair test, or
    `user_list` + `pass_list` (file paths) for a spray. Use
    `nthash` for pass-the-hash (NTLM) instead of `password`.
    """
    return await netexec.spray(
        target=target,
        protocol=protocol,
        username=username,
        password=password,
        user_list=user_list,
        pass_list=pass_list,
        nthash=nthash,
        timeout_seconds=timeout_seconds,
    )


@mcp.tool()
async def medusa_crack(
    target: str,
    module: str = "ssh",
    user_list: str = "",
    pass_list: str = "",
    threads: int = 4,
    timeout_seconds: int = 300,
) -> dict:
    """Network-login brute-force via medusa.

    Alternative to hydra with different protocol-module coverage
    (notably `smbnt`, `cvs`, `afp`). Both `user_list` and
    `pass_list` file paths are required.
    """
    return await medusa.crack(
        target=target,
        module=module,
        user_list=user_list,
        pass_list=pass_list,
        threads=threads,
        timeout_seconds=timeout_seconds,
    )


@mcp.tool()
async def john_crack(
    target: str,
    wordlist: str = "/usr/share/wordlists/rockyou.txt",
    format: str = "",
    timeout_seconds: int = 600,
) -> dict:
    """Offline hash cracking via John the Ripper.

    `target` is the hashfile path. Runs john --wordlist=... then
    --show to extract cracked records. Pass `format` if john's
    auto-detect picks the wrong one (e.g. `format="nt"`).
    """
    return await john.crack(
        target=target,
        wordlist=wordlist,
        format=format,
        timeout_seconds=timeout_seconds,
    )


@mcp.tool()
async def hashcat_crack(
    target: str,
    mode: int,
    wordlist: str = "/usr/share/wordlists/rockyou.txt",
    attack_mode: int = 0,
    timeout_seconds: int = 600,
) -> dict:
    """Offline hash cracking via hashcat.

    `target` is the hashfile. `mode` is hashcat's `-m` value (no
    default; the wrong mode silently produces zero cracks). 1000 =
    NTLM, 1800 = sha512crypt, 5600 = NetNTLMv2. `attack_mode` is
    `-a` (0 = wordlist, 3 = brute-force mask).
    """
    return await hashcat.crack(
        target=target,
        mode=mode,
        wordlist=wordlist,
        attack_mode=attack_mode,
        timeout_seconds=timeout_seconds,
    )


# ---------- Windows AD post-exploit ----------

@mcp.tool()
async def impacket_getnpusers(
    target: str,
    dc_ip: str = "",
    user_list: str = "",
    timeout_seconds: int = 120,
) -> dict:
    """Enumerate AS-REP-roastable users in an AD domain.

    `target` is the AD domain (e.g. `corp.local`). `user_list` is a
    file of usernames to test; if empty, an authenticated bind is
    required (passed via `<domain>/<user>:<password>` in target —
    not yet supported here, use `user_list` for the unauth path).
    """
    return await impacket.getnpusers(
        target=target,
        dc_ip=dc_ip,
        user_list=user_list,
        timeout_seconds=timeout_seconds,
    )


@mcp.tool()
async def impacket_getuserspns(
    target: str,
    username: str,
    password: str = "",
    nthash: str = "",
    dc_ip: str = "",
    timeout_seconds: int = 180,
) -> dict:
    """Kerberoast — enumerate SPN-mapped users and request their TGS hashes."""
    return await impacket.getuserspns(
        target=target,
        username=username,
        password=password,
        nthash=nthash,
        dc_ip=dc_ip,
        timeout_seconds=timeout_seconds,
    )


@mcp.tool()
async def impacket_secretsdump(
    target: str,
    username: str = "",
    password: str = "",
    nthash: str = "",
    just_dc: bool = False,
    timeout_seconds: int = 600,
) -> dict:
    """Dump SAM / LSA / NTDS secrets from a Windows target.

    For DCSync against a DC pass `just_dc=True` plus credentials
    with Replicate-Directory-Changes rights.
    """
    return await impacket.secretsdump(
        target=target,
        username=username,
        password=password,
        nthash=nthash,
        just_dc=just_dc,
        timeout_seconds=timeout_seconds,
    )


@mcp.tool()
async def impacket_smbclient(
    target: str,
    username: str,
    password: str = "",
    nthash: str = "",
    command: str = "shares",
    timeout_seconds: int = 120,
) -> dict:
    """One-shot SMB command via impacket smbclient.py."""
    return await impacket.smbclient(
        target=target,
        username=username,
        password=password,
        nthash=nthash,
        command=command,
        timeout_seconds=timeout_seconds,
    )


@mcp.tool()
async def winrm_exec(
    target: str,
    username: str,
    command: str,
    password: str = "",
    nthash: str = "",
    timeout_seconds: int = 120,
) -> dict:
    """Run a single PowerShell command on a Windows host over WinRM."""
    return await winrm.execute(
        target=target,
        username=username,
        command=command,
        password=password,
        nthash=nthash,
        timeout_seconds=timeout_seconds,
    )


@mcp.tool()
async def msfvenom_payload(
    target: str,
    payload: str,
    lhost: str,
    lport: int = 4444,
    format: str = "exe",
    encoder: str = "",
    iterations: int = 1,
    badchars: str = "",
    timeout_seconds: int = 120,
) -> dict:
    """Generate a payload with msfvenom.

    `target` is a free-form descriptor logged in the audit trail
    (e.g. "win10-corp-laptop") — it does NOT reach msfvenom.
    `payload` is the msfvenom payload spec (e.g.
    `windows/x64/meterpreter/reverse_tcp`). Payload bytes are
    written to `~/.kalimcp/payloads/<sha256>.<ext>`; the MCP result
    returns path + sha256 + size, never raw bytes.
    """
    return await msfvenom.generate(
        target=target,
        payload=payload,
        lhost=lhost,
        lport=lport,
        format=format,
        encoder=encoder,
        iterations=iterations,
        badchars=badchars,
        timeout_seconds=timeout_seconds,
    )


# ---------- passive tools ----------
# These hit registry / DNS / local search, not the target itself.
# They skip the active_tool decorator's scope warning —
# a whois lookup for chase.com is harmless; an nmap scan of it isn't.

@mcp.tool()
async def whois_lookup(query: str, timeout_seconds: int = 30) -> dict:
    """Whois registration lookup for a domain or IP."""
    return await passive.whois_lookup(query=query, timeout_seconds=timeout_seconds)


@mcp.tool()
async def dig_record(domain: str, record_type: str = "A", timeout_seconds: int = 30) -> dict:
    """DNS lookup for `domain`. record_type: A/AAAA/MX/TXT/NS/CNAME/SOA/etc.

    Hits the resolver, not the target.
    """
    return await passive.dig_record(
        domain=domain, record_type=record_type, timeout_seconds=timeout_seconds,
    )


@mcp.tool()
async def searchsploit_search(keyword: str, timeout_seconds: int = 30) -> dict:
    """Local Exploit-DB search via `searchsploit` — entirely local."""
    return await passive.searchsploit_search(keyword=keyword, timeout_seconds=timeout_seconds)


@mcp.tool()
async def cert_dump(host: str, port: int = 443, timeout_seconds: int = 30) -> dict:
    """Dump TLS cert chain for `host:port` via openssl s_client.

    Single TLS handshake, equivalent to a browser visiting the site.
    Useful for pre-engagement cert / CN / SAN review.
    """
    return await passive.cert_dump(host=host, port=port, timeout_seconds=timeout_seconds)


# ---------- engagement workspace ----------
# Persistent per-engagement state — findings, creds, loot, notes.
# Lets the agent query "what hosts have we found?" / "what creds
# do we have for host X?" across tool calls. Auto-record (toggled
# by KALIMCP_AUTORECORD=1) mirrors structured `parsed` blocks from
# the active-scan tools into the workspace.

@mcp.tool()
async def engagement_create(
    name: str,
    scope: list[str] | None = None,
    operator: str = "",
) -> dict:
    """Bootstrap a new engagement.

    `scope` is a list of CIDR / domain-glob / URL patterns. Active-
    scan tools that hit a target outside scope emit a non-blocking
    `out_of_scope_warning`. Empty scope = no gate.
    """
    result = engagement.create(name=name, scope=scope, operator=operator)
    audit.log(
        "engagement_create",
        name=result.get("name"),
        ok=result.get("ok", False),
    )
    return result


@mcp.tool()
async def engagement_list() -> dict:
    """List engagements on disk, most-recent first."""
    return {"engagements": engagement.list_all(), "active": engagement.current_engagement()}


@mcp.tool()
async def engagement_use(name: str) -> dict:
    """Set the active engagement (persists across MCP-server restarts)."""
    result = engagement.use(name=name)
    audit.log("engagement_use", name=name, ok=result.get("ok", False))
    return result


@mcp.tool()
async def engagement_status(name: str = "") -> dict:
    """Show metadata + counts for the named (or active) engagement."""
    return engagement.status(name=name or None)


@mcp.tool()
async def finding_record(
    category: str,
    host: str,
    payload: dict | None = None,
    source_tool: str = "",
) -> dict:
    """Append a structured finding to the active engagement.

    `category` is a free-form tag (`host`, `service`, `sqli`,
    `subdomain`, ...). Auto-record uses the same machinery for
    `parsed` extractions from active-scan tools.
    """
    ok = engagement.record_finding(category, host, payload, source_tool=source_tool)
    return {"ok": ok}


@mcp.tool()
async def finding_query(
    category: str = "",
    host: str = "",
    since: str = "",
    limit: int = 200,
) -> dict:
    """Read findings. Empty filters return everything (capped by `limit`)."""
    return {
        "findings": engagement.query_findings(
            category=category or None,
            host=host or None,
            since=since or None,
            limit=limit,
        ),
    }


@mcp.tool()
async def host_list() -> dict:
    """Derive a unique sorted host list from findings + creds."""
    return {"hosts": engagement.list_hosts()}


@mcp.tool()
async def cred_record(
    host: str,
    proto: str,
    user: str,
    secret: str,
    source_tool: str = "",
) -> dict:
    """Append a credential to the active engagement's loot cache.

    `secret` is stored verbatim in `creds.jsonl` (mode 0600). The
    engagement directory is the operator's loot store — put it on
    encrypted storage if you need at-rest secrecy.
    """
    ok = engagement.record_cred(host, proto, user, secret, source_tool=source_tool)
    return {"ok": ok}


@mcp.tool()
async def cred_query(
    host: str = "",
    user: str = "",
    proto: str = "",
    limit: int = 200,
) -> dict:
    """Read credentials. Empty filters return everything (capped by `limit`)."""
    return {
        "credentials": engagement.query_creds(
            host=host or None,
            user=user or None,
            proto=proto or None,
            limit=limit,
        ),
    }


@mcp.tool()
async def loot_write(blob_name: str, data: str) -> dict:
    """Write a text blob into the engagement's `loot/` directory."""
    return engagement.write_loot(blob_name, data)


@mcp.tool()
async def loot_list() -> dict:
    """Enumerate files in the engagement's `loot/` directory."""
    return {"loot": engagement.list_loot()}


@mcp.tool()
async def loot_read(blob_name: str) -> dict:
    """Read a loot file. Returns text or base64-encoded bytes."""
    return engagement.read_loot(blob_name)


@mcp.tool()
async def note_append(text: str) -> dict:
    """Append a timestamped block to the engagement's notes.md."""
    ok = engagement.note_append(text)
    return {"ok": ok}


@mcp.tool()
async def wordlist_list() -> dict:
    """Enumerate wordlists under /usr/share/wordlists + /usr/share/seclists."""
    return {"wordlists": engagement.list_wordlists()}


def main() -> int:
    """Console entry: launch the stdio MCP server."""
    # Resolve the audit log path eagerly so the operator gets the
    # fallback breadcrumb (if any) before the first tool fires.
    audit.configure()
    try:
        mcp.run()
    except KeyboardInterrupt:
        return 0
    return 0


if __name__ == "__main__":
    sys.exit(main())
