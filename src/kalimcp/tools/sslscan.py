# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Aaron K. Clark
"""sslscan wrapper — TLS / SSL cipher + cert inspection."""

from __future__ import annotations

from typing import Any

from .. import run
from ._active import active_tool


@active_tool(tool_name="sslscan")
async def scan(
    *,
    target: str,
    port: int = 443,
    timeout_seconds: int = 120,
) -> dict[str, Any]:
    """Enumerate TLS protocol versions, ciphers, and certificate info for `target`.

    Args:
      target: hostname or IP.
      port: TCP port (default 443).
      timeout_seconds: hard wallclock cap (default 120).
    """
    argv = ["sslscan", f"--port={int(port)}", target]
    return await run.run(argv, timeout=timeout_seconds)
