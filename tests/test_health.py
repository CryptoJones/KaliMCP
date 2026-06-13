# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Aaron K. Clark
"""Capability/health-probe tests (issue #19)."""

from __future__ import annotations

from unittest.mock import AsyncMock, patch

import pytest

from kalimcp.tools import health


@pytest.mark.asyncio
async def test_capabilities_reports_presence():
    # Pretend nothing is installed.
    with patch("kalimcp.tools.health.shutil.which", return_value=None):
        result = await health.capabilities()
    assert result["available"] == 0
    assert result["total"] == len(health._BINARIES)
    assert all(t["available"] is False for t in result["tools"])
    assert all("path" not in t for t in result["tools"])


@pytest.mark.asyncio
async def test_capabilities_marks_available():
    with patch("kalimcp.tools.health.shutil.which", return_value="/usr/bin/x"):
        result = await health.capabilities()
    assert result["available"] == result["total"]
    sample = result["tools"][0]
    assert sample["available"] is True
    assert sample["path"] == "/usr/bin/x"
    assert "version" not in sample  # versions are opt-in


@pytest.mark.asyncio
async def test_capabilities_presence_does_not_spawn():
    """Default probe must not run any subprocess."""
    with patch("kalimcp.tools.health.shutil.which", return_value="/usr/bin/x"), \
            patch("kalimcp.tools.health.run.run", new=AsyncMock()) as m:
        await health.capabilities()
    m.assert_not_called()


@pytest.mark.asyncio
async def test_capabilities_versions_opt_in_probes():
    fake = {"stdout": "Nmap version 7.95\n", "stderr": ""}
    with patch("kalimcp.tools.health.shutil.which", return_value="/usr/bin/nmap"), \
            patch("kalimcp.tools.health.run.run", new=AsyncMock(return_value=fake)) as m:
        result = await health.capabilities(check_versions=True)
    assert m.called
    nmap = next(t for t in result["tools"] if t["tool"] == "nmap_scan")
    assert nmap["version"] == "Nmap version 7.95"
