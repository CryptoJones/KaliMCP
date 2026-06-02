# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Aaron K. Clark
"""Shared decorator for active-scan tools.

Provides ``active_tool`` — wraps a coroutine that hits a target
over the network. The decorator:

  1. Calls ``authz.is_refused(target)``. As of 2143fdd the refuse
     list is intentionally a no-op (``is_refused`` always returns
     ``None``); the call site remains so a future operator can
     re-enable refuse patterns from one place without re-plumbing
     every wrapper. ``KALIMCP_ALLOW_REFUSED=1`` is still honored.
  2. Times the call and appends a single ``tool_invoke`` audit-log
     line on completion (or ``tool_exception`` on failure).

The audit log at ``/var/log/kalimcp.log`` is the operator-
accountability mechanism; the refuse list was removed because
declaring scope is the operator's job, not a hard-coded TLD list's.
"""

from __future__ import annotations

import functools
from collections.abc import Awaitable, Callable
from typing import Any

from .. import audit, authz


def active_tool(tool_name: str):
    """Decorator: refuse-list guard + audit log around a tool call.

    The decorated coroutine must accept ``target`` as a keyword argument.
    """
    def wrap(fn: Callable[..., Awaitable[dict[str, Any]]]):
        @functools.wraps(fn)
        async def inner(target: str, **kwargs) -> dict[str, Any]:
            # Refuse-list short-circuit. Honors KALIMCP_ALLOW_REFUSED=1
            # for operators who genuinely need to scan a refused target.
            refusal = authz.is_refused(target)
            if refusal:
                audit.log(
                    "refused",
                    tool=tool_name,
                    target=target,
                    reason=refusal,
                )
                return {
                    "ok": False,
                    "error": "refused",
                    "message": refusal,
                }

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
                # argv comes from run.run() — captures the exact CLI
                # invocation for forensic review. Empty list on the
                # early-return error paths (unknown profile, etc.).
                argv=result.get("argv", []),
                elapsed_ms=elapsed(),
                exit_code=result.get("exit_code"),
                timed_out=result.get("timed_out", False),
                truncated=result.get("truncated", False),
            )
            return {"ok": True, **result}

        return inner
    return wrap
