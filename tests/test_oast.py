# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Aaron K. Clark
"""OAST / OOB callback-catcher tests (issue #17).

The HTTP listener is replaced via a patched `oast._serve`, so no real port
is bound; callbacks are injected by calling the catcher's `record`.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from kalimcp import oast


@pytest.fixture(autouse=True)
def _reset_and_workspace(tmp_path, monkeypatch):
    # Isolate the engagement workspace (findings get written) and the catcher.
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.delenv("KALIMCP_ENGAGEMENT", raising=False)
    from kalimcp import engagement
    engagement.ROOT_DIR = Path.home() / ".kalimcp"
    engagement.ENGAGEMENTS_DIR = engagement.ROOT_DIR / "engagements"
    engagement.ACTIVE_STATE_FILE = engagement.ROOT_DIR / "active_engagement"
    oast.reset_for_test()
    # Never bind a real socket.
    monkeypatch.setattr(oast, "_serve", lambda host, port, catcher: object())
    yield
    oast.reset_for_test()


async def _start():
    return await oast.oast_start(host="127.0.0.1", port=8000)


@pytest.mark.asyncio
async def test_register_before_start_fails():
    assert oast.oast_register("ssrf")["error"] == "not_running"


@pytest.mark.asyncio
async def test_start_then_register_templates_payloads():
    await _start()
    reg = oast.oast_register("log4shell")
    assert reg["ok"] is True
    token = reg["correlation_token"]
    # {OAST_HOST} got the token-prefixed host; payload is materialized.
    assert any(token in p for p in reg["payloads"])
    assert any("jndi:ldap://" in p for p in reg["payloads"])


@pytest.mark.asyncio
async def test_unknown_vuln_class():
    await _start()
    res = oast.oast_register("nope")
    assert res["error"] == "unknown_vuln_class"
    assert "ssrf" in res["known"]


@pytest.mark.asyncio
async def test_poll_correlates_hit_and_materializes_finding():
    from kalimcp import engagement
    await _start()
    reg = oast.oast_register("ssrf")
    token = reg["correlation_token"]

    # No callback yet -> no hits.
    first = oast.oast_poll()
    assert first["hits"] == []
    assert first["pending"] == 1

    # Simulate the target calling back to /<token>.
    oast._active.record({
        "ts": "now", "method": "GET", "path": f"/{token}",
        "host": "127.0.0.1:8000", "source_ip": "10.0.0.9", "body": "",
    })

    res = oast.oast_poll()
    assert len(res["hits"]) == 1
    assert res["hits"][0]["vuln_class"] == "ssrf"
    assert res["confirmed"] == 1
    # An oob_confirmed finding was recorded for the source IP.
    confirmed = engagement.query_findings(category="oob_confirmed")
    assert len(confirmed) == 1
    assert confirmed[0]["host"] == "10.0.0.9"

    # Idempotent: polling again doesn't double-count.
    again = oast.oast_poll()
    assert again["hits"] == []
    assert again["confirmed"] == 1


@pytest.mark.asyncio
async def test_correlation_via_host_subdomain():
    await _start()
    reg = oast.oast_register("rce")
    token = reg["correlation_token"]
    oast._active.record({
        "ts": "now", "method": "GET", "path": "/",
        "host": f"{token}.127.0.0.1", "source_ip": "10.0.0.5", "body": "",
    })
    res = oast.oast_poll()
    assert len(res["hits"]) == 1


@pytest.mark.asyncio
async def test_double_start_rejected_and_stop():
    await _start()
    second = await oast.oast_start()
    assert second["error"] == "already_running"
    stop = await oast.oast_stop()
    assert stop["ok"] is True
    # After stop, register fails again.
    assert oast.oast_register("ssrf")["error"] == "not_running"


@pytest.mark.asyncio
async def test_start_audits_with_redacted_key(tmp_path, monkeypatch):
    from kalimcp import audit
    log = tmp_path / "audit.log"
    monkeypatch.setenv("KALIMCP_LOG_FILE", str(log))
    audit.configure()
    await _start()
    key = oast._active.key
    audit.reset_for_test()
    text = log.read_text()
    assert "oast_start" in text
    assert key not in text  # raw key never logged
