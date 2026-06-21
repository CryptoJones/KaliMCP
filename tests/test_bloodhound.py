# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Aaron K. Clark
"""Tests for the bloodhound-python collector wrapper.

argv-contract + stdout-parse + redaction tests. ``run.run`` is patched,
so nothing spawns a subprocess or touches the network.
"""

from __future__ import annotations

from unittest.mock import AsyncMock, patch

import pytest

from kalimcp import audit
from kalimcp.tools import bloodhound


def _fake_result(stdout: str = "", stderr: str = "") -> dict:
    return {
        "exit_code": 0,
        "elapsed_s": 0.01,
        "stdout": stdout,
        "stderr": stderr,
        "truncated": False,
        "timed_out": False,
        "argv": [],
    }


# ---------- argv contract ----------


@pytest.mark.asyncio
async def test_collect_argv_password():
    with patch(
        "kalimcp.tools.bloodhound.run.run",
        new=AsyncMock(return_value=_fake_result()),
    ) as m:
        result = await bloodhound.collect(
            target="corp.local", username="svc", password="hunter2",
        )
    assert result["ok"] is True
    argv = m.call_args.args[0]
    assert argv == [
        "bloodhound-python",
        "-d", "corp.local",
        "-u", "svc",
        "-c", "Default",
        "--zip",
        "-p", "hunter2",
    ]


@pytest.mark.asyncio
async def test_collect_argv_nthash_omits_password():
    with patch(
        "kalimcp.tools.bloodhound.run.run",
        new=AsyncMock(return_value=_fake_result()),
    ) as m:
        await bloodhound.collect(
            target="corp.local", username="svc",
            nthash="aad3b435b51404eeaad3b435b51404ee",
        )
    argv = m.call_args.args[0]
    assert "-p" not in argv
    assert "--hashes" in argv
    assert argv[argv.index("--hashes") + 1] == ":aad3b435b51404eeaad3b435b51404ee"


@pytest.mark.asyncio
async def test_collect_argv_dc_ip_and_nameserver():
    with patch(
        "kalimcp.tools.bloodhound.run.run",
        new=AsyncMock(return_value=_fake_result()),
    ) as m:
        await bloodhound.collect(
            target="corp.local", username="svc", password="pw",
            dc_ip="10.0.0.1", nameserver="10.0.0.1", collection="All",
        )
    argv = m.call_args.args[0]
    assert argv[argv.index("-c") + 1] == "All"
    assert argv[argv.index("-dc") + 1] == "10.0.0.1"
    assert argv[argv.index("-ns") + 1] == "10.0.0.1"


@pytest.mark.asyncio
async def test_collect_missing_creds_returns_error():
    with patch("kalimcp.tools.bloodhound.run.run", new=AsyncMock()) as m:
        result = await bloodhound.collect(target="corp.local", username="svc")
    assert result["ok"] is True  # active_tool wraps the error_result
    assert "password" in result["stderr"].lower()
    m.assert_not_called()


# ---------- stdout/stderr parsing ----------


@pytest.mark.asyncio
async def test_collect_parses_counts_and_zip():
    stderr = (
        "INFO: Found AD domain: corp.local\n"
        "INFO: Found 41 users\n"
        "INFO: Found 8 computers\n"
        "INFO: Found 52 groups\n"
        "INFO: Compressing output into 20260621_bloodhound.zip\n"
    )
    fake = _fake_result(stderr=stderr)
    with patch(
        "kalimcp.tools.bloodhound.run.run", new=AsyncMock(return_value=fake)
    ):
        result = await bloodhound.collect(
            target="corp.local", username="svc", password="pw",
        )
    parsed = result["parsed"]
    assert parsed["zip"] == "20260621_bloodhound.zip"
    assert parsed["counts"] == {"users": 41, "computers": 8, "groups": 52}


@pytest.mark.asyncio
async def test_collect_empty_skeleton_on_no_output():
    with patch(
        "kalimcp.tools.bloodhound.run.run",
        new=AsyncMock(return_value=_fake_result()),
    ):
        result = await bloodhound.collect(
            target="corp.local", username="svc", password="pw",
        )
    assert result["parsed"] == {"zip": "", "counts": {}}


# ---------- redaction ----------


@pytest.mark.asyncio
async def test_collect_password_redacted_in_logged_argv():
    """The declared secret_flag ``-p`` value must be hashed before logging."""
    captured: dict = {}

    def _capture(event, **fields):
        if event == "tool_invoke":
            captured.update(fields)

    real_argv = [
        "bloodhound-python", "-d", "corp.local", "-u", "svc",
        "-c", "Default", "--zip", "-p", "hunter2",
    ]
    fake = {**_fake_result(), "argv": real_argv}
    with patch("kalimcp.tools.bloodhound.run.run", new=AsyncMock(return_value=fake)), \
            patch.object(audit, "log", new=_capture):
        await bloodhound.collect(target="corp.local", username="svc", password="hunter2")

    logged = captured["argv"]
    assert "hunter2" not in logged
    assert captured["secrets_redacted"] is True
    assert any(tok.startswith("sha256:") for tok in logged)
