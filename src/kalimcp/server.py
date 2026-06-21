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

from . import audit, engagement, enrich, oast, process_registry, report, sessions
from .tools import (
    bloodhound,
    capture,
    certipy,
    cloud,
    discovery,
    ffuf,
    gobuster,
    gowitness,
    hashcat,
    health,
    hydra,
    impacket,
    john,
    kerbrute,
    ldap,
    medusa,
    metasploit,
    msfvenom,
    netexec,
    nikto,
    nmap,
    nuclei,
    passive,
    pivot,
    reversing,
    shodan_lookup,
    smb,
    snmp,
    sqlmap,
    sslscan,
    traceroute,
    whatweb,
    winrm,
    wpscan,
    zap,
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


@mcp.tool()
async def traceroute_path(
    target: str,
    max_hops: int = 30,
    wait_seconds: int = 2,
    timeout_seconds: int = 120,
) -> dict:
    """Discover the network path to `target` via traceroute (`-n`, no DNS)."""
    return await traceroute.trace(
        target=target,
        max_hops=max_hops,
        wait_seconds=wait_seconds,
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
async def cve_search(query: str, limit: int = 20, timeout_seconds: int = 15) -> dict:
    """Look up CVEs on NIST NVD by exact CVE-ID (e.g. `CVE-2021-44228`) or
    keyword (e.g. `apache log4j`). Enriches a service/version finding with
    CVSS score + description. Reaches the network."""
    return await enrich.cve_search(query, limit=limit, timeout_seconds=timeout_seconds)


@mcp.tool()
async def cve_package_audit(
    package: str,
    version: str = "",
    ecosystem: str = "PyPI",
    timeout_seconds: int = 15,
) -> dict:
    """Audit a dependency against OSV.dev for known vulnerabilities.

    `ecosystem` examples: PyPI, npm, Go, Maven, crates.io, Debian. Pass
    `version` to filter to vulns affecting it. Reaches the network."""
    return await enrich.cve_package_audit(
        package, version=version, ecosystem=ecosystem, timeout_seconds=timeout_seconds,
    )


@mcp.tool()
async def hash_identify(value: str) -> dict:
    """Identify a captured hash's likely type(s) with the hashcat `-m` mode
    and john `--format` to crack it (offline regex table; no network).
    Pairs with `hashcat_crack` / `john_crack`."""
    return enrich.identify_hash(value)


@mcp.tool()
async def cert_dump(host: str, port: int = 443, timeout_seconds: int = 30) -> dict:
    """Dump TLS cert chain for `host:port` via openssl s_client.

    Single TLS handshake, equivalent to a browser visiting the site.
    Useful for pre-engagement cert / CN / SAN review.
    """
    return await passive.cert_dump(host=host, port=port, timeout_seconds=timeout_seconds)


# ---------- loot triage ----------
# Read-only analysis of a file already on disk (a captured pcap or a
# pulled binary). No target probe — audited as passive_invoke.

@mcp.tool()
async def tshark_pcap(
    pcap: str,
    mode: str = "summary",
    display_filter: str = "",
    timeout_seconds: int = 120,
) -> dict:
    """Analyze a capture file with tshark (read-only; never live capture).

    Modes: `summary`, `http`, `protocol_hierarchy`, `conversations`,
    `expert`. `display_filter` is an optional Wireshark display filter.
    """
    return await passive.tshark_pcap(
        pcap=pcap,
        mode=mode,
        display_filter=display_filter,
        timeout_seconds=timeout_seconds,
    )


@mcp.tool()
async def strings_extract(
    path: str,
    min_length: int = 4,
    encoding: str = "s",
    timeout_seconds: int = 60,
) -> dict:
    """Extract printable strings from a binary (`strings -n -e`)."""
    return await passive.strings_extract(
        path=path,
        min_length=min_length,
        encoding=encoding,
        timeout_seconds=timeout_seconds,
    )


@mcp.tool()
async def nm_symbols(
    path: str,
    demangle: bool = True,
    dynamic: bool = False,
    timeout_seconds: int = 60,
) -> dict:
    """List symbols in an object/library via nm (optionally demangled)."""
    return await passive.nm_symbols(
        path=path,
        demangle=demangle,
        dynamic=dynamic,
        timeout_seconds=timeout_seconds,
    )


@mcp.tool()
async def objdump_inspect(
    path: str,
    mode: str = "headers",
    timeout_seconds: int = 120,
) -> dict:
    """Inspect an object file via objdump.

    Modes: `headers`, `sections`, `symbols`, `disasm`.
    """
    return await passive.objdump_inspect(
        path=path,
        mode=mode,
        timeout_seconds=timeout_seconds,
    )


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

    Non-blocking: if the finding has no `source_tool` and no evidence field
    in `payload` (evidence/proof/loot/output/...), the result carries an
    `advisory` nudge to attach proof — the finding is still recorded.
    """
    ok = engagement.record_finding(category, host, payload, source_tool=source_tool)
    result: dict[str, object] = {"ok": ok}
    advisory = engagement.evidence_advisory(payload, source_tool)
    if advisory:
        result["advisory"] = advisory
    return result


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
    """Read a loot file. Returns text or base64-encoded bytes, plus its
    sha256 and a `verified` flag (matches the hash recorded at write time)."""
    return engagement.read_loot(blob_name)


@mcp.tool()
async def loot_verify(blob_name: str, expected_sha256: str = "") -> dict:
    """Checksum-verify a loot blob's SHA-256.

    Compares the blob's current hash to `expected_sha256` if given (e.g. a
    hash from the source host), otherwise to the hash recorded when it was
    written. Use after transferring loot to confirm it arrived intact.
    """
    return engagement.verify_loot(blob_name, expected_sha256)


@mcp.tool()
async def note_append(text: str) -> dict:
    """Append a timestamped block to the engagement's notes.md."""
    ok = engagement.note_append(text)
    return {"ok": ok}


@mcp.tool()
async def report_export(format: str = "markdown") -> dict:
    """Export the active engagement's findings store as a report.

    `format`: `markdown` (human report), `sarif` (SARIF v2.1.0 for GitHub
    Code Scanning), `junit` (JUnit XML — error-severity findings become
    `<failure>` so CI goes red), `client` (customer-facing deliverable with
    exec summary, severity rollup, per-finding remediation and CVSS), or
    `html` (the `client` report wrapped in a self-contained HTML doc).
    Credential secrets are masked. Returns `content`; pass it to `loot_write`
    to save it.
    """
    return report.generate(format)


@mcp.tool()
async def wordlist_list() -> dict:
    """Enumerate wordlists under /usr/share/wordlists + /usr/share/seclists."""
    return {"wordlists": engagement.list_wordlists()}


# ---------- process control ----------
# Live view + kill switch for running tool subprocesses, so a runaway scan
# can be stopped without killing the MCP session (issue #13). The listing is
# secret-free (binary + arg count only); kill refuses any PID we didn't
# launch.

@mcp.tool()
async def process_list() -> dict:
    """List tool subprocesses currently running.

    Each entry: `pid`, `binary`, `argc` (argv length — the argv itself is
    withheld so a password on a command line can't leak), `elapsed_s`,
    `timeout_s`, and the `engagement` active when it launched.
    """
    return {"processes": process_registry.snapshot()}


@mcp.tool()
async def process_kill(pid: int, force: bool = False) -> dict:
    """Stop a running tool subprocess by PID (from `process_list`).

    Sends SIGTERM, or SIGKILL when `force=True`, to the process group.
    Only PIDs KaliMCP launched can be killed; anything else is refused.
    """
    import signal as _signal
    result = process_registry.kill(pid, sig=_signal.SIGKILL if force else _signal.SIGTERM)
    audit.log("process_kill", pid=pid, force=force, ok=result.get("ok", False))
    return result


# ---------- server health / capability probe ----------

@mcp.tool()
async def health_check(check_versions: bool = False) -> dict:
    """Report which wrapped binaries are installed so the agent can degrade
    gracefully. `check_versions=True` also probes each present binary for a
    version string (slower — one subprocess per tool)."""
    return await health.capabilities(check_versions=check_versions)


# ---------- interactive sessions ----------
# Long-lived SSH (OpenSSH ControlMaster) and reverse-shell sessions, keyed
# by session id. Audited, not scope-gated (per the no-gates rule).

@mcp.tool()
async def ssh_session_start(
    host: str,
    user: str,
    password: str = "",
    key: str = "",
    port: int = 22,
    timeout_seconds: int = 30,
) -> dict:
    """Open a persistent multiplexed SSH session; returns a `session_id`.

    Pass `password` (via sshpass, redacted in the audit log) or `key` (a
    private-key path). Reuse the session with `ssh_session_exec`.
    """
    return await sessions.ssh_start(
        host=host, user=user, password=password, key=key,
        port=port, timeout_seconds=timeout_seconds,
    )


@mcp.tool()
async def ssh_session_exec(session_id: str, command: str, timeout_seconds: int = 60) -> dict:
    """Run a command on an open SSH session (reuses the master connection)."""
    return await sessions.ssh_exec(session_id, command, timeout_seconds=timeout_seconds)


@mcp.tool()
async def ssh_session_stop(session_id: str) -> dict:
    """Close an SSH session (tear down the master connection)."""
    return await sessions.ssh_stop(session_id)


@mcp.tool()
async def revshell_listen(
    port: int,
    trigger: str = "",
    wait_seconds: int = 5,
) -> dict:
    """Start a reverse-shell listener on `port`.

    Optional `trigger` is a local command that makes the target connect
    back; it's fired in the background and the call returns after
    `wait_seconds` with listener status — it never blocks waiting for the
    shell. Interact via `revshell_exec`.
    """
    return await sessions.revshell_listen(port=port, trigger=trigger, wait_seconds=wait_seconds)


@mcp.tool()
async def revshell_exec(session_id: str, command: str = "") -> dict:
    """Send a command to a connected reverse shell and return new output.
    Empty `command` just drains pending output."""
    return await sessions.revshell_exec(session_id, command)


@mcp.tool()
async def revshell_stop(session_id: str) -> dict:
    """Stop a reverse-shell listener (and reap its payload-trigger process)."""
    return await sessions.revshell_stop(session_id)


@mcp.tool()
async def session_status(session_id: str) -> dict:
    """Status of an SSH or reverse-shell session by id."""
    return sessions.session_status(session_id)


@mcp.tool()
async def session_list() -> dict:
    """List all open SSH and reverse-shell sessions."""
    return sessions.session_list()


@mcp.tool()
async def system_network_info() -> dict:
    """Local interface addresses + a recommended LHOST for a reverse shell
    (prefers a VPN/tun address on an engagement)."""
    return sessions.system_network_info()


# ---------- OAST / out-of-band callback catcher ----------
# Self-hosted (no third-party collaborator), off until oast_start. For blind
# vuln detection: the target calls back to a host we control.

@mcp.tool()
async def oast_start(host: str = "127.0.0.1", port: int = 8000) -> dict:
    """Start the self-hosted OOB callback catcher (HTTP). Off by default.

    Bind `host` to an address the target can reach (e.g. your VPN/tun IP —
    see `system_network_info`). Then `oast_register` payloads and `oast_poll`
    for callbacks."""
    return await oast.oast_start(host=host, port=port)


@mcp.tool()
async def oast_register(vuln_class: str = "generic") -> dict:
    """Mint a correlation token + `{OAST}` payloads for a vuln class
    (ssrf / rce / xxe / log4shell / sqli_oob / generic) and persist a
    `pending_oob` record. Inject a returned payload into the target."""
    return oast.oast_register(vuln_class)


@mcp.tool()
async def oast_poll() -> dict:
    """Return captured OOB interactions; any whose path/Host carries a
    pending token materializes an `oob_confirmed` finding."""
    return oast.oast_poll()


@mcp.tool()
async def oast_stop() -> dict:
    """Stop the OOB catcher and discard in-process interactions."""
    return await oast.oast_stop()


# ======================================================================
# Pentest gap-coverage tools (recon baseline, AD analysis, traversal,
# capture, cloud, exploitation, reverse-engineering, correlation).
# Same rules apply throughout: no authorization gates — audit log +
# non-blocking scope warning are the only accountability.
# ======================================================================

# ---------- recon baseline ----------

@mcp.tool()
async def nuclei_scan(
    target: str,
    severity: str = "",
    tags: str = "",
    templates: str = "",
    rate_limit: int = 150,
    timeout_seconds: int = 600,
) -> dict:
    """Scan a target URL with nuclei's templated vulnerability checks.

    `severity` filters (e.g. `critical,high`); `tags` selects template tags;
    `templates` is a custom template path/dir. Returns parsed findings."""
    return await nuclei.scan(
        target=target,
        severity=severity,
        tags=tags,
        templates=templates,
        rate_limit=rate_limit,
        timeout_seconds=timeout_seconds,
    )


@mcp.tool()
async def subfinder_enum(domain: str, timeout_seconds: int = 300) -> dict:
    """Passive subdomain OSINT enumeration for a domain (subfinder, no probe)."""
    return await discovery.subfinder_enum(domain=domain, timeout_seconds=timeout_seconds)


@mcp.tool()
async def httpx_probe(target: str, timeout_seconds: int = 120) -> dict:
    """Active web probe (httpx): status, title, tech-detect, web-server banner."""
    return await discovery.probe(target=target, timeout_seconds=timeout_seconds)


@mcp.tool()
async def dnsx_resolve(
    target: str, record_types: str = "a", timeout_seconds: int = 120
) -> dict:
    """Active DNS resolution against a target (dnsx); records returned as JSON."""
    return await discovery.resolve(
        target=target, record_types=record_types, timeout_seconds=timeout_seconds
    )


@mcp.tool()
async def wpscan_scan(
    target: str,
    enumerate: str = "vp,u",
    api_token: str = "",
    timeout_seconds: int = 600,
) -> dict:
    """Scan a WordPress site with wpscan (version, vulnerable plugins/themes, users).

    `api_token` (redacted in the audit log) unlocks the WPVulnDB vuln data."""
    return await wpscan.scan(
        target=target,
        enumerate=enumerate,
        api_token=api_token,
        timeout_seconds=timeout_seconds,
    )


@mcp.tool()
async def gowitness_capture(
    target: str, output_dir: str = "", timeout_seconds: int = 120
) -> dict:
    """Screenshot a web URL with gowitness (headless Chrome).

    Defaults `output_dir` to the active engagement's `screenshots/` dir so
    captures land in the workspace; pass an explicit dir to override."""
    if not output_dir:
        output_dir = engagement.screenshots_dir().get("path", "")
    return await gowitness.capture(
        target=target, output_dir=output_dir, timeout_seconds=timeout_seconds
    )


# ---------- Active Directory analysis (AD CS + BloodHound) ----------

@mcp.tool()
async def certipy_find(
    target: str,
    username: str,
    password: str = "",
    nthash: str = "",
    dc_ip: str = "",
    timeout_seconds: int = 300,
) -> dict:
    """Enumerate AD CS templates/CAs and flag ESC1-16 vulnerabilities (certipy).

    `target` is the AD domain. Authenticate with `password` XOR `nthash`
    (both redacted in the audit log)."""
    return await certipy.find(
        target=target,
        username=username,
        password=password,
        nthash=nthash,
        dc_ip=dc_ip,
        timeout_seconds=timeout_seconds,
    )


@mcp.tool()
async def certipy_request(
    target: str,
    username: str,
    password: str = "",
    nthash: str = "",
    ca: str = "",
    template: str = "",
    upn: str = "",
    ca_host: str = "",
    dc_ip: str = "",
    timeout_seconds: int = 300,
) -> dict:
    """Request a certificate from a CA — ESC1-style abuse (certipy req).

    Pass an alternate `upn` to impersonate via the issued cert. Set `ca_host`
    (the CA enrollment server) when the CA isn't reachable from `ca` alone.
    Returns the saved `.pfx` path."""
    return await certipy.request(
        target=target,
        username=username,
        password=password,
        nthash=nthash,
        ca=ca,
        template=template,
        upn=upn,
        ca_host=ca_host,
        dc_ip=dc_ip,
        timeout_seconds=timeout_seconds,
    )


@mcp.tool()
async def bloodhound_collect(
    target: str,
    username: str,
    password: str = "",
    nthash: str = "",
    dc_ip: str = "",
    nameserver: str = "",
    collection: str = "Default",
    output_dir: str = "",
    timeout_seconds: int = 600,
) -> dict:
    """Collect BloodHound AD graph data with bloodhound-python (the COLLECTOR).

    Binds a DC with domain creds (`password` XOR `nthash`, redacted) and writes
    a `.zip` of the AD graph for ingest into a neo4j-backed BloodHound. This
    collects only; path analysis happens in the BloodHound GUI."""
    return await bloodhound.collect(
        target=target,
        username=username,
        password=password,
        nthash=nthash,
        dc_ip=dc_ip,
        nameserver=nameserver,
        collection=collection,
        output_dir=output_dir,
        timeout_seconds=timeout_seconds,
    )


# ---------- traversal / pivoting (SOCKS + file transfer over SSH) ----------

@mcp.tool()
async def socks_start(
    host: str,
    user: str,
    password: str = "",
    key: str = "",
    port: int = 22,
    socks_port: int = 1080,
    timeout_seconds: int = 30,
) -> dict:
    """Open an SSH pivot with a dynamic SOCKS5 forward.

    Point other tools at the returned `socks5://127.0.0.1:<socks_port>` via
    proxychains or a tool-native `--proxy` flag. Password redacted in audit."""
    return await sessions.socks_start(
        host=host, user=user, password=password, key=key,
        port=port, socks_port=socks_port, timeout_seconds=timeout_seconds,
    )


@mcp.tool()
async def ssh_put(
    session_id: str, local_path: str, remote_path: str, timeout_seconds: int = 120
) -> dict:
    """Upload a local file to the target over an open SSH/SOCKS session (scp)."""
    return await sessions.ssh_put(
        session_id, local_path, remote_path, timeout_seconds=timeout_seconds
    )


@mcp.tool()
async def ssh_get(
    session_id: str, remote_path: str, local_path: str, timeout_seconds: int = 120
) -> dict:
    """Download a file from the target over an open SSH/SOCKS session (scp)."""
    return await sessions.ssh_get(
        session_id, remote_path, local_path, timeout_seconds=timeout_seconds
    )


@mcp.tool()
async def enum_upload_run(
    session_id: str,
    local_script: str,
    remote_path: str = "/tmp/.km_enum",
    interpreter: str = "sh",
    timeout_seconds: int = 300,
) -> dict:
    """Upload a local-enum script (e.g. linpeas) and run it on the target."""
    return await sessions.enum_upload_run(
        session_id, local_script, remote_path, interpreter,
        timeout_seconds=timeout_seconds,
    )


# ---------- credential-capture listeners (long-running; poll for hashes) ----------

@mcp.tool()
async def capture_start(
    tool: str = "responder",
    interface: str = "eth0",
    target: str = "",
    domain: str = "",
    relay_target: str = "",
    extra: str = "",
    wait_seconds: int = 3,
) -> dict:
    """Start a credential-capture listener (responder / mitm6 / ntlmrelayx).

    Long-running: returns a `capture_id`; poll it with `capture_poll` for
    captured NetNTLM hashes."""
    return await capture.capture_start(
        tool=tool, interface=interface, target=target, domain=domain,
        relay_target=relay_target, extra=extra, wait_seconds=wait_seconds,
    )


@mcp.tool()
async def capture_poll(capture_id: str) -> dict:
    """Drain new listener output; return captured NetNTLM hashes + alive status."""
    return capture.capture_poll(capture_id)


@mcp.tool()
async def capture_stop(capture_id: str) -> dict:
    """Terminate a capture listener and unregister it."""
    return capture.capture_stop(capture_id)


@mcp.tool()
async def capture_list() -> dict:
    """List active capture listeners (id, tool, alive)."""
    return capture.capture_list()


# ---------- cloud-security audit (Tier 3) ----------

@mcp.tool()
async def cloud_scoutsuite(
    provider: str = "aws",
    report_dir: str = "",
    extra_args: str = "",
    timeout_seconds: int = 900,
) -> dict:
    """ScoutSuite multi-cloud audit (aws/azure/gcp/aliyun/oci) via local creds.

    No target host; passive-style audit. `extra_args` is shlex-split."""
    return await cloud.scoutsuite(
        provider=provider, report_dir=report_dir,
        extra_args=extra_args, timeout_seconds=timeout_seconds,
    )


@mcp.tool()
async def cloud_prowler(
    provider: str = "aws",
    output_dir: str = "",
    extra_args: str = "",
    timeout_seconds: int = 1800,
) -> dict:
    """Prowler cloud-security audit (OCSF JSON) via local cloud credentials.

    No target host; passive-style audit. `extra_args` is shlex-split."""
    return await cloud.prowler(
        provider=provider, output_dir=output_dir,
        extra_args=extra_args, timeout_seconds=timeout_seconds,
    )


@mcp.tool()
async def cloud_kube_hunter(
    target: str = "", remote: bool = True, timeout_seconds: int = 600
) -> dict:
    """kube-hunter Kubernetes weakness scan. With a target + remote=True probes
    `--remote <target>`; otherwise `--pod` in-cluster."""
    return await cloud.kube_hunter(
        target=target, remote=remote, timeout_seconds=timeout_seconds
    )


# ---------- exploitation / delivery (Tier 3) ----------

@mcp.tool()
async def msf_run_module(
    target: str,
    module: str,
    options: str = "",
    payload: str = "",
    lhost: str = "",
    lport: int = 0,
    password: str = "",
    timeout_seconds: int = 600,
) -> dict:
    """Execute a Metasploit module against a target (TIER 3: delivery/execution).

    Unlike `msfvenom_payload` (which only generates bytes), this DELIVERS and
    RUNS a module at `target` (set as RHOSTS) via `msfconsole -x` — it can open
    a session on the host. `module` is a full module path; `options` is
    `KEY=VAL;KEY=VAL`. `password` is redacted from the audit log."""
    return await metasploit.run_module(
        target=target, module=module, options=options, payload=payload,
        lhost=lhost, lport=lport, password=password,
        timeout_seconds=timeout_seconds,
    )


# ---------- reverse engineering / loot triage (read a file on disk) ----------

@mcp.tool()
async def gdb_inspect(
    path: str, command: str = "info functions", timeout_seconds: int = 60
) -> dict:
    """Inspect a binary already on disk with gdb in batch mode (loot triage).

    Runs gdb non-interactively (`-batch -nx`) with one `-ex` command. Reads a
    local file only; never attaches to a live process or the network."""
    return await reversing.gdb_inspect(
        path=path, command=command, timeout_seconds=timeout_seconds
    )


@mcp.tool()
async def r2_analyze(
    path: str, commands: str = "aaa;afl", timeout_seconds: int = 120
) -> dict:
    """Analyze a binary already on disk with radare2 (loot triage).

    Runs r2 quiet/color-stripped with one `-c` command string. Default
    `aaa;afl` runs full analysis then lists functions."""
    return await reversing.r2_analyze(
        path=path, commands=commands, timeout_seconds=timeout_seconds
    )


# ---------- engagement correlation / analysis ----------

@mcp.tool()
async def host_correlate() -> dict:
    """Per-host rollup of findings + creds for the active engagement."""
    return engagement.correlate_hosts()


@mcp.tool()
async def findings_dedupe() -> dict:
    """Deduplicated view of the active engagement's findings (read-only report)."""
    return engagement.dedupe_findings()


# ---------- gap-coverage round 2 (kerbrute / ZAP / Shodan) ----------

@mcp.tool()
async def kerbrute_userenum(
    target: str, dc_ip: str, user_list: str, timeout_seconds: int = 300
) -> dict:
    """Enumerate valid AD usernames via Kerberos pre-auth (no lockout, low noise).

    `target` = AD domain (e.g. corp.local); `dc_ip` = the KDC; `user_list` = a
    newline-delimited username file. Returns parsed.valid_users."""
    return await kerbrute.userenum(
        target=target, dc_ip=dc_ip, user_list=user_list, timeout_seconds=timeout_seconds
    )


@mcp.tool()
async def kerbrute_passwordspray(
    target: str, dc_ip: str, user_list: str, password: str, timeout_seconds: int = 300
) -> dict:
    """Spray a single password across an AD username list via Kerberos.

    `password` (redacted in the audit log) is tried for every user in
    `user_list`. Returns parsed.valid_logins ([{user, password}])."""
    return await kerbrute.passwordspray(
        target=target, dc_ip=dc_ip, user_list=user_list,
        password=password, timeout_seconds=timeout_seconds,
    )


@mcp.tool()
async def zap_baseline(target: str, report_path: str = "", timeout_seconds: int = 900) -> dict:
    """Run an OWASP ZAP headless baseline/quick scan against a web target.

    Spiders `target`, runs ZAP's passive + light active scan, writes a JSON
    report (default /tmp/kalimcp_zap_report.json), and returns parsed alerts
    [{name, risk, confidence, url}]. Active scan — audit-logged."""
    return await zap.baseline_scan(
        target=target, report_path=report_path, timeout_seconds=timeout_seconds,
    )


@mcp.tool()
async def shodan_host(ip: str, api_key: str, timeout_seconds: int = 15) -> dict:
    """Look up a host on Shodan by IP — ports, hostnames, org, OS, known vulns.

    External intel: reaches the Shodan API (needs a Shodan `api_key`, kept out
    of the logs), does NOT probe the target itself."""
    return await shodan_lookup.host_lookup(ip, api_key=api_key, timeout_seconds=timeout_seconds)


@mcp.tool()
async def shodan_search(query: str, api_key: str, limit: int = 20, timeout_seconds: int = 15) -> dict:
    """Search Shodan's index (e.g. `apache port:443`) — matching hosts.

    External intel: reaches the Shodan API (needs a Shodan `api_key`), does NOT
    probe any target."""
    return await shodan_lookup.search(query, api_key=api_key, limit=limit, timeout_seconds=timeout_seconds)


# ---------- reverse-tunnel pivots (Chisel / Ligolo-ng) ----------

@mcp.tool()
async def pivot_start(
    tool: str = "chisel", port: int = 0, extra: str = "", wait_seconds: int = 2
) -> dict:
    """Start a reverse-tunnel listener (Chisel server / Ligolo-ng proxy) the
    target connects back to — pivots into an internal segment when the target
    has no SSH. Returns a `pivot_id` and an `operator_hint`: the command to run
    ON THE TARGET to connect back. Long-running; poll with `pivot_poll`, drive
    Ligolo's console with `pivot_send`."""
    return await pivot.pivot_start(tool=tool, port=port, extra=extra, wait_seconds=wait_seconds)


@mcp.tool()
async def pivot_send(pivot_id: str, command: str) -> dict:
    """Feed a console command to a pivot (Ligolo: `session` / `start` / `ifconfig`)
    and return new output. For Chisel (non-interactive) this just drains output."""
    return pivot.pivot_send(pivot_id, command)


@mcp.tool()
async def pivot_poll(pivot_id: str) -> dict:
    """Drain new pivot output (new tunnel connections / status)."""
    return pivot.pivot_poll(pivot_id)


@mcp.tool()
async def pivot_stop(pivot_id: str) -> dict:
    """Terminate a pivot server and unregister it."""
    return pivot.pivot_stop(pivot_id)


@mcp.tool()
async def pivot_list() -> dict:
    """List active reverse-tunnel pivots (id, tool, port, alive)."""
    return pivot.pivot_list()


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
