# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Aaron K. Clark
"""Tests for the per-tool wrapper modules.

These verify the argv each wrapper hands to ``run.run`` — the
contract is "given these args, the right CLI invocation comes
out." No real subprocess runs; ``run.run`` is patched.

The active-tool decorator's refuse-list guard is exercised here
incidentally — every wrapper goes through it. We pass safe
targets (127.0.0.1, example.com) to avoid the refuse path.
"""

from __future__ import annotations

from unittest.mock import AsyncMock, patch

import pytest

from kalimcp.tools import gobuster, hydra, nikto, nmap, passive, sqlmap, sslscan


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
