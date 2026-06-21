# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Aaron K. Clark
"""Tests for the ProjectDiscovery trio: subfinder / dnsx / httpx.

Argv-contract + stdout-parse tests. No real subprocess runs;
``run.run`` is patched. No network.
"""

from __future__ import annotations

from unittest.mock import AsyncMock, patch

import pytest

from kalimcp.tools import discovery


def _fake_result(stdout: str = "") -> dict:
    return {
        "exit_code": 0,
        "elapsed_s": 0.01,
        "stdout": stdout,
        "stderr": "",
        "truncated": False,
        "timed_out": False,
        "argv": [],
    }


# ---------- subfinder (passive) ----------


@pytest.mark.asyncio
async def test_subfinder_argv_shape():
    with patch("kalimcp.tools.discovery.run.run", new=AsyncMock(return_value=_fake_result())) as m:
        await discovery.subfinder_enum(domain="example.com")
    assert m.call_args.args[0] == ["subfinder", "-d", "example.com", "-silent"]
    assert m.call_args.kwargs.get("timeout") == 300


@pytest.mark.asyncio
async def test_subfinder_parses_host_lines():
    out = "www.example.com\nmail.example.com\n"
    with patch("kalimcp.tools.discovery.run.run", new=AsyncMock(return_value=_fake_result(out))):
        result = await discovery.subfinder_enum(domain="example.com")
    parsed = result["parsed"]
    assert parsed["count"] == 2
    assert parsed["subdomains"] == ["www.example.com", "mail.example.com"]


@pytest.mark.asyncio
async def test_subfinder_empty_stdout():
    with patch("kalimcp.tools.discovery.run.run", new=AsyncMock(return_value=_fake_result(""))):
        result = await discovery.subfinder_enum(domain="example.com")
    assert result["parsed"] == {"subdomains": [], "count": 0}


@pytest.mark.asyncio
async def test_subfinder_dash_domain_rejected_without_running():
    with patch("kalimcp.tools.discovery.run.run", new=AsyncMock()) as m:
        result = await discovery.subfinder_enum(domain="-d/evil")
    m.assert_not_called()
    assert result["exit_code"] == -1
    assert result["parsed"] == {"subdomains": [], "count": 0}


@pytest.mark.asyncio
async def test_subfinder_timeout_passed_through():
    with patch("kalimcp.tools.discovery.run.run", new=AsyncMock(return_value=_fake_result())) as m:
        await discovery.subfinder_enum(domain="example.com", timeout_seconds=42)
    assert m.call_args.kwargs.get("timeout") == 42


# ---------- httpx (active web probe) ----------

_HTTPX_JSON_SAMPLE = (
    '{"url":"https://example.com","status_code":200,"title":"Example Domain",'
    '"webserver":"ECS (dcb/7F84)","tech":["Apache","PHP"]}\n'
    '{"url":"https://www.example.com","status_code":301,"title":"",'
    '"webserver":"nginx","tech":["Nginx"]}\n'
)


@pytest.mark.asyncio
async def test_httpx_argv_shape():
    with patch("kalimcp.tools.discovery.run.run", new=AsyncMock(return_value=_fake_result())) as m:
        result = await discovery.probe(target="https://example.com")
    assert result["ok"] is True
    assert m.call_args.args[0] == [
        "httpx",
        "-u", "https://example.com",
        "-json",
        "-silent",
        "-status-code",
        "-title",
        "-tech-detect",
        "-web-server",
    ]


@pytest.mark.asyncio
async def test_httpx_parses_json_lines():
    fake = _fake_result(_HTTPX_JSON_SAMPLE)
    with patch("kalimcp.tools.discovery.run.run", new=AsyncMock(return_value=fake)):
        result = await discovery.probe(target="https://example.com")
    parsed = result["parsed"]
    assert parsed["count"] == 2
    first = parsed["results"][0]
    assert first["url"] == "https://example.com"
    assert first["status_code"] == 200
    assert first["title"] == "Example Domain"
    assert first["webserver"] == "ECS (dcb/7F84)"
    assert first["tech"] == ["Apache", "PHP"]


@pytest.mark.asyncio
async def test_httpx_empty_stdout():
    with patch("kalimcp.tools.discovery.run.run", new=AsyncMock(return_value=_fake_result(""))):
        result = await discovery.probe(target="https://example.com")
    assert result["parsed"] == {"results": [], "count": 0}


@pytest.mark.asyncio
async def test_httpx_dash_target_rejected_without_running():
    with patch("kalimcp.tools.discovery.run.run", new=AsyncMock()) as m:
        result = await discovery.probe(target="-bad")
    m.assert_not_called()
    assert result["exit_code"] == -1
    assert result["parsed"] == {"results": [], "count": 0}


# ---------- dnsx (active DNS resolution) ----------

_DNSX_JSON_SAMPLE = (
    '{"host":"example.com","a":["93.184.216.34"],"resolver":["1.1.1.1:53"]}\n'
    '{"host":"www.example.com","a":["93.184.216.34"]}\n'
)


@pytest.mark.asyncio
async def test_dnsx_argv_shape():
    with patch("kalimcp.tools.discovery.run.run", new=AsyncMock(return_value=_fake_result())) as m:
        await discovery.resolve(target="example.com")
    argv = m.call_args.args[0]
    assert argv[:3] == ["dnsx", "-silent", "-json"]
    # The host is fed on stdin (dnsx resolve input), NOT via -d (which is the
    # bruteforce base flag and resolves nothing on its own).
    assert "-d" not in argv
    assert "-a" in argv
    assert m.call_args.kwargs.get("stdin") == b"example.com\n"


@pytest.mark.asyncio
async def test_dnsx_record_types_become_flags():
    with patch("kalimcp.tools.discovery.run.run", new=AsyncMock(return_value=_fake_result())) as m:
        await discovery.resolve(target="example.com", record_types="a,aaaa cname")
    argv = m.call_args.args[0]
    assert "-a" in argv
    assert "-aaaa" in argv
    assert "-cname" in argv


@pytest.mark.asyncio
async def test_dnsx_parses_json_lines():
    fake = _fake_result(_DNSX_JSON_SAMPLE)
    with patch("kalimcp.tools.discovery.run.run", new=AsyncMock(return_value=fake)):
        result = await discovery.resolve(target="example.com")
    parsed = result["parsed"]
    assert parsed["count"] == 2
    assert parsed["records"][0]["host"] == "example.com"
    assert parsed["records"][0]["a"] == ["93.184.216.34"]


@pytest.mark.asyncio
async def test_dnsx_empty_stdout():
    with patch("kalimcp.tools.discovery.run.run", new=AsyncMock(return_value=_fake_result(""))):
        result = await discovery.resolve(target="example.com")
    assert result["parsed"] == {"records": [], "count": 0}


@pytest.mark.asyncio
async def test_dnsx_dash_target_rejected_without_running():
    with patch("kalimcp.tools.discovery.run.run", new=AsyncMock()) as m:
        result = await discovery.resolve(target="-x")
    m.assert_not_called()
    assert result["exit_code"] == -1
    assert result["parsed"] == {"records": [], "count": 0}
