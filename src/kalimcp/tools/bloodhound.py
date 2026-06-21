# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Aaron K. Clark
"""bloodhound-python wrapper — the BloodHound AD data *collector*.

This wraps ``bloodhound-python`` (the Python ingestor), which binds to
a domain controller with domain credentials, walks LDAP/SMB, and writes
a ``.zip`` of JSON files describing the Active Directory graph.

NOTE: this is the **collector only**. It produces a zip the operator
ingests into a neo4j-backed BloodHound GUI to *query* the graph
(attack paths, etc.). Running neo4j and the GUI is out of scope for the
MCP server — the agent collects, the operator analyzes. This wrapper
therefore reports *what was collected* (object counts + the output zip
name), not graph answers.

Goes through ``@active_tool`` with ``secret_flags`` declared so the
domain password / NT hash never lands in the audit log verbatim.
"""

from __future__ import annotations

import os
import re
from pathlib import Path
from typing import Any

from .. import run
from ._active import active_tool

# bloodhound-python progress lines look like:
#   INFO: Found 41 users
#   INFO: Found 8 computers
#   INFO: Found 52 groups
_COUNT_LINE = re.compile(
    r"Found\s+(?P<n>\d+)\s+(?P<kind>users|computers|groups|domains|ous|gpos|containers|trusts)\b",
    re.IGNORECASE,
)

# The collector announces its output file, e.g.:
#   INFO: Compressing output into 20260621_bloodhound.zip
_ZIP_LINE = re.compile(r"(?P<zip>[\w./-]+\.zip)\b")


@active_tool(
    tool_name="bloodhound-python",
    secret_flags={"-p", "--hashes"},
)
async def collect(
    *,
    target: str,
    username: str,
    password: str = "",
    nthash: str = "",
    dc_ip: str = "",
    nameserver: str = "",
    collection: str = "Default",
    output_dir: str = "",
    timeout_seconds: int = 600,
) -> dict[str, Any]:
    """Collect BloodHound data from an Active Directory domain.

    Args:
      target: the AD domain to collect (e.g. ``corp.local``). Passed as
        ``-d``.
      username: domain user to authenticate as.
      password: password literal. Mutually exclusive with ``nthash``.
      nthash: NT hash for pass-the-hash auth (sent as ``--hashes :<nt>``).
      dc_ip: domain-controller IP (``-dc``). Useful when DNS can't
        resolve the DC.
      nameserver: DNS server to use (``-ns``), typically the DC.
      collection: BloodHound collection method (``-c``). Default
        ``Default``; common alternatives ``All``, ``DCOnly``, ``Group``.
      output_dir: directory the run should produce the zip in. When set
        it is validated as a usable directory and passed through
        ``--outputprefix`` so the zip name is prefixed with that path.
        When empty, the zip lands in the server's CWD.
      timeout_seconds: hard wallclock cap (default 600 — collection of a
        large domain can be slow).

    Returns ``parsed``: ``{"zip": "<output zip name>", "counts":
    {"users": N, "computers": N, ...}}``. Empty skeleton
    ``{"zip": "", "counts": {}}`` when nothing was parsed.

    The collected zip is the deliverable: the operator ingests it into a
    BloodHound GUI to query attack paths. This wrapper does not query the
    graph.
    """
    empty: dict[str, Any] = {"zip": "", "counts": {}}

    if not username:
        return run.error_result("bloodhound-python needs `username`.", parsed=empty)

    # Reject values a tool would re-read as its own flags / inject a line.
    for value, label in ((target, "target"), (username, "username")):
        bad = run.validate_arg(value, label, parsed=empty)
        if bad is not None:
            return bad

    if nthash:
        auth_args = ["--hashes", f":{nthash}"]
    elif password:
        auth_args = ["-p", password]
    else:
        return run.error_result(
            "bloodhound-python needs `password=` or `nthash=`.", parsed=empty
        )

    argv: list[str] = [
        "bloodhound-python",
        "-d", target,
        "-u", username,
        "-c", collection,
        "--zip",
        *auth_args,
    ]
    if dc_ip:
        argv.extend(["-dc", dc_ip])
    if nameserver:
        argv.extend(["-ns", nameserver])
    if output_dir:
        bad = run.validate_arg(output_dir, "output_dir", parsed=empty)
        if bad is not None:
            return bad
        try:
            usable = Path(output_dir).is_dir() and os.access(output_dir, os.W_OK)
        except OSError:
            usable = False
        if not usable:
            return run.error_result(
                f"output_dir not a writable directory: {output_dir}", parsed=empty
            )
        # bloodhound-python prefixes every output file (incl. the zip)
        # with --outputprefix; a trailing slash lands them in the dir.
        argv.extend(["--outputprefix", str(Path(output_dir) / "bloodhound")])

    result = await run.run(argv, timeout=timeout_seconds)

    # Collector prints progress to stderr; parse both streams.
    text = (result.get("stdout", "") or "") + "\n" + (result.get("stderr", "") or "")
    parsed: dict[str, Any] = {"zip": "", "counts": {}}
    for line in text.splitlines():
        m = _COUNT_LINE.search(line)
        if m:
            parsed["counts"][m.group("kind").lower()] = int(m.group("n"))
        z = _ZIP_LINE.search(line)
        if z:
            parsed["zip"] = z.group("zip")
    result["parsed"] = parsed
    return result
