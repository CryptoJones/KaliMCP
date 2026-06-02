# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Aaron K. Clark
"""SMB enumeration wrapper — uses enum4linux-ng.

enum4linux-ng emits structured YAML/JSON when run with ``-oJ`` (JSON
to a file). We invoke it with ``-A`` (all simple-mode probes) and
parse its JSON into the recon-friendly fields agents care about:
shares, users, groups, OS, signing, null-session ability.
"""

from __future__ import annotations

import json
import os
import tempfile
from typing import Any

from .. import run
from ._active import active_tool


def _empty_parsed() -> dict[str, Any]:
    return {
        "target": "",
        "os": {},
        "signing": "",
        "null_session": False,
        "shares": [],
        "users": [],
        "groups": [],
        "domain": "",
    }


def _parse_output(text: str) -> dict[str, Any]:
    """Distill enum4linux-ng JSON into the parsed shape."""
    try:
        data = json.loads(text)
    except (json.JSONDecodeError, ValueError):
        return _empty_parsed()
    if not isinstance(data, dict):
        return _empty_parsed()

    parsed = _empty_parsed()
    parsed["target"] = data.get("target", "")

    os_info = data.get("os_info") or {}
    if isinstance(os_info, dict):
        parsed["os"] = {
            k: v for k, v in os_info.items()
            if k in ("native_os", "native_lan_manager", "os_version", "server_type")
        }

    smb_dialects = data.get("smb_dialects") or {}
    if isinstance(smb_dialects, dict):
        signing = smb_dialects.get("Signing enabled")
        if signing is not None:
            parsed["signing"] = str(signing).lower()

    sessions = data.get("sessions") or {}
    if isinstance(sessions, dict):
        parsed["null_session"] = bool(sessions.get("sessions_possible"))

    shares = data.get("shares") or {}
    if isinstance(shares, dict):
        for share_name, share_info in shares.items():
            entry = {"name": share_name}
            if isinstance(share_info, dict):
                for k in ("type", "comment", "access"):
                    if k in share_info:
                        entry[k] = share_info[k]
            parsed["shares"].append(entry)

    users = data.get("users") or {}
    if isinstance(users, dict):
        for rid, user_info in users.items():
            entry = {"rid": rid}
            if isinstance(user_info, dict):
                if "username" in user_info:
                    entry["username"] = user_info["username"]
                if "name" in user_info:
                    entry["name"] = user_info["name"]
            parsed["users"].append(entry)

    groups = data.get("groups") or {}
    if isinstance(groups, dict):
        for rid, group_info in groups.items():
            entry = {"rid": rid}
            if isinstance(group_info, dict) and "groupname" in group_info:
                entry["groupname"] = group_info["groupname"]
            parsed["groups"].append(entry)

    domain_info = data.get("domain_info") or {}
    if isinstance(domain_info, dict):
        parsed["domain"] = domain_info.get("NetBIOS domain name", "") or domain_info.get("DNS domain", "")

    return parsed


@active_tool(tool_name="smb-enum")
async def enumerate(
    *,
    target: str,
    timeout_seconds: int = 300,
) -> dict[str, Any]:
    """Run enum4linux-ng -A against an SMB target.

    Args:
      target: hostname or IP of the SMB host.
      timeout_seconds: hard wallclock cap (default 300).

    Returns the structured ``kalimcp.run.run`` result dict augmented
    with ``parsed``: ``{target, os, signing, null_session, shares,
    users, groups, domain}``. enum4linux-ng's full report stays in
    ``stdout`` (we capture from a tempfile and return the JSON in
    stdout so operators can re-parse).
    """
    # enum4linux-ng's -oJ writes to FILE.json; "-" or /dev/stdout
    # behavior is inconsistent. Use a tempfile + read.
    tmp = tempfile.NamedTemporaryFile(
        mode="w", suffix=".json", prefix="enum4linux-", delete=False,
    )
    tmp.close()
    json_path = tmp.name

    argv = ["enum4linux-ng", "-A", "-oJ", json_path, target]
    try:
        result = await run.run(argv, timeout=timeout_seconds)
        try:
            with open(json_path, encoding="utf-8") as fh:
                json_text = fh.read()
        except OSError:
            json_text = ""
        # Surface the JSON in stdout so operators can re-parse.
        if json_text:
            result["stdout"] = json_text
        result["parsed"] = _parse_output(json_text) if json_text.strip() else _empty_parsed()
        return result
    finally:
        try:
            os.unlink(json_path)
        except OSError:
            pass
