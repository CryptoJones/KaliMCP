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

from kalimcp.tools import gobuster, nikto, nmap, passive, sslscan


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
    assert argv == ["nmap", "-Pn", "-T4", "--top-ports", "100", "127.0.0.1"]


@pytest.mark.asyncio
async def test_nmap_service_scan_argv():
    with patch("kalimcp.tools.nmap.run.run", new=AsyncMock(return_value=_fake_result())) as m:
        await nmap.scan(target="127.0.0.1", profile="service-scan")
    argv = m.call_args.args[0]
    assert "-sV" in argv
    assert argv[-1] == "127.0.0.1"


@pytest.mark.asyncio
async def test_nmap_ping_sweep_argv():
    with patch("kalimcp.tools.nmap.run.run", new=AsyncMock(return_value=_fake_result())) as m:
        await nmap.scan(target="10.0.0.0/24", profile="ping-sweep")
    argv = m.call_args.args[0]
    assert "-sn" in argv
    assert argv[-1] == "10.0.0.0/24"


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


# ---------- sslscan ----------

@pytest.mark.asyncio
async def test_sslscan_default_port():
    with patch("kalimcp.tools.sslscan.run.run", new=AsyncMock(return_value=_fake_result())) as m:
        await sslscan.scan(target="example.com")
    argv = m.call_args.args[0]
    assert argv == ["sslscan", "--port=443", "example.com"]


@pytest.mark.asyncio
async def test_sslscan_explicit_port():
    with patch("kalimcp.tools.sslscan.run.run", new=AsyncMock(return_value=_fake_result())) as m:
        await sslscan.scan(target="example.com", port=8443)
    argv = m.call_args.args[0]
    assert "--port=8443" in argv


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
