# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Aaron K. Clark
"""Tests for the Tier-3 cloud-audit wrappers (cloud.py).

Verify the argv each wrapper hands to ``run.run``. No real subprocess
runs and no network is touched — ``run.run`` is patched.
"""

from __future__ import annotations

from unittest.mock import AsyncMock, patch

import pytest

from kalimcp.tools import cloud


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


# ---------- scoutsuite ----------


@pytest.mark.asyncio
async def test_scoutsuite_aws_argv():
    with patch("kalimcp.tools.cloud.run.run", new=AsyncMock(return_value=_fake_result())) as m:
        result = await cloud.scoutsuite(provider="aws")
    assert result["parsed"] == {"provider": "aws", "report_dir": ""}
    argv = m.call_args.args[0]
    assert argv == ["scout", "aws", "--no-browser"]


@pytest.mark.asyncio
async def test_scoutsuite_azure_with_report_dir_and_extra_args():
    with patch("kalimcp.tools.cloud.run.run", new=AsyncMock(return_value=_fake_result())) as m:
        await cloud.scoutsuite(
            provider="azure",
            report_dir="/tmp/out",
            extra_args="--all-subscriptions",
        )
    argv = m.call_args.args[0]
    assert argv == [
        "scout", "azure", "--no-browser",
        "--report-dir", "/tmp/out",
        "--all-subscriptions",
    ]


@pytest.mark.asyncio
async def test_scoutsuite_invalid_provider():
    with patch("kalimcp.tools.cloud.run.run", new=AsyncMock()) as m:
        result = await cloud.scoutsuite(provider="bogus")
    assert "invalid provider" in result["stderr"]
    m.assert_not_called()


# ---------- prowler ----------


@pytest.mark.asyncio
async def test_prowler_aws_argv():
    with patch("kalimcp.tools.cloud.run.run", new=AsyncMock(return_value=_fake_result())) as m:
        result = await cloud.prowler(provider="aws")
    assert result["parsed"] == {"provider": "aws"}
    argv = m.call_args.args[0]
    assert argv == ["prowler", "aws", "--output-formats", "json-ocsf"]


@pytest.mark.asyncio
async def test_prowler_with_output_dir_and_extra_args():
    with patch("kalimcp.tools.cloud.run.run", new=AsyncMock(return_value=_fake_result())) as m:
        await cloud.prowler(
            provider="gcp",
            output_dir="/tmp/prowler",
            extra_args="--severity high critical",
        )
    argv = m.call_args.args[0]
    assert argv == [
        "prowler", "gcp", "--output-formats", "json-ocsf",
        "--output-directory", "/tmp/prowler",
        "--severity", "high", "critical",
    ]


@pytest.mark.asyncio
async def test_prowler_invalid_provider():
    with patch("kalimcp.tools.cloud.run.run", new=AsyncMock()) as m:
        result = await cloud.prowler(provider="bogus")
    assert "invalid provider" in result["stderr"]
    m.assert_not_called()


# ---------- kube-hunter ----------


@pytest.mark.asyncio
async def test_kube_hunter_remote_argv():
    with patch("kalimcp.tools.cloud.run.run", new=AsyncMock(return_value=_fake_result())) as m:
        result = await cloud.kube_hunter(target="10.0.0.5")
    assert result["ok"] is True
    assert result["parsed"] == {"target": "10.0.0.5"}
    argv = m.call_args.args[0]
    assert argv == ["kube-hunter", "--report", "json", "--remote", "10.0.0.5"]


@pytest.mark.asyncio
async def test_kube_hunter_pod_mode_argv():
    with patch("kalimcp.tools.cloud.run.run", new=AsyncMock(return_value=_fake_result())) as m:
        await cloud.kube_hunter(target="")
    argv = m.call_args.args[0]
    assert argv == ["kube-hunter", "--report", "json", "--pod"]


@pytest.mark.asyncio
async def test_kube_hunter_remote_false_forces_pod():
    with patch("kalimcp.tools.cloud.run.run", new=AsyncMock(return_value=_fake_result())) as m:
        await cloud.kube_hunter(target="10.0.0.5", remote=False)
    argv = m.call_args.args[0]
    assert argv == ["kube-hunter", "--report", "json", "--pod"]
