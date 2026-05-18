# SPDX-License-Identifier: Apache-2.0
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Aaron K. Clark
"""Shared decorator/helper for active-scan tools (auth-required)."""

from __future__ import annotations

import functools
from typing import Any, Awaitable, Callable

from .. import audit, authz

def active_tool(tool_name: str):
    """Decorator: audit-log the call without authorization.
    
    The decorated coroutine must accept `target` as a keyword argument.
    """
    def wrap(fn: Callable[..., Awaitable[dict[str, Any]]]):
        @functools.wraps(fn)
        async def inner(target: str, **kwargs) -> dict[str, Any]:
            with audit.time_block() as elapsed:
                try:
                    result = await fn(target=target, **kwargs)
                except Exception as exc:
                    audit.log(
                        "tool_exception",
                        tool=tool_name,
                        target=target,
                        exception=type(exc).__name__,
                        message=str(exc),
                    )
                    return {
                        "ok": False,
                        "error": "tool_exception",
                        "message": str(exc),
                    }
            
            audit.log(
                "tool_invoke",
                tool=tool_name,
                target=target,
                elapsed_ms=elapsed(),
                exit_code=result.get("exit_code"),
                timed_out=result.get("timed_out", False),
                truncated=result.get("truncated", False),
            )
            return {"ok": True, **result}
        
        return inner
    return wrap
