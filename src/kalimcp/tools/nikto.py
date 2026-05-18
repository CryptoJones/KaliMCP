# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Aaron K. Clark
"""nikto wrapper — web server vulnerability scanner."""

from __future__ import annotations

from typing import Any

from .. import run
from ._active import active_tool


@active_tool(tool_name="nikto")
async def scan(
    *,
    target: str,
    ssl: bool = False,
    timeout_seconds: int = 600,
) -> dict[str, Any]:
    """Run nikto against `target` (URL or host).

    Args:
      target: URL like `https://example.com/` or host:port.
      ssl: force-enable SSL/TLS detection.
      timeout_seconds: hard wallclock cap (default 600 — nikto is slow).
    """
    argv = ["nikto", "-host", target, "-ask", "no"]
    if ssl:
        argv.append("-ssl")
    result = await run.run(argv, timeout=timeout_seconds)
    return result
