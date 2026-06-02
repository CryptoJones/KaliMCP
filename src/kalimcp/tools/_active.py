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
from collections.abc import Awaitable, Callable, Iterable
from typing import Any

from .. import audit, authz


def active_tool(
    tool_name: str,
    *,
    secret_flags: Iterable[str] | None = None,
):
    """Decorator: refuse-list guard + audit log around a tool call.

    The decorated coroutine must accept ``target`` as a keyword
    argument.

    ``secret_flags`` — set of CLI flags whose immediately-following
    argv value carries a secret (password literal, cred file path).
    The audit-log ``argv`` field has those values rewritten to
    ``sha256:<8hex>`` via ``audit.redact_argv`` before being
    written. Default ``None`` means log argv verbatim. Credential
    tools (hydra, medusa, netexec, ...) should set this; recon
    tools should not.
    """
    secret_flag_set: tuple[str, ...] = tuple(secret_flags) if secret_flags else ()

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

            raw_argv = result.get("argv", [])
            if secret_flag_set:
                logged_argv = audit.redact_argv(raw_argv, secret_flag_set)
                secrets_redacted = logged_argv != raw_argv
            else:
                logged_argv = raw_argv
                secrets_redacted = False
            audit.log(
                "tool_invoke",
                tool=tool_name,
                target=target,
                # argv comes from run.run(), redacted if the wrapper
                # marked any flags as secret-bearing. Empty list on
                # the early-return error paths (unknown profile, etc.).
                argv=logged_argv,
                secrets_redacted=secrets_redacted,
                elapsed_ms=elapsed(),
                exit_code=result.get("exit_code"),
                timed_out=result.get("timed_out", False),
                truncated=result.get("truncated", False),
            )
            return {"ok": True, **result}

        return inner
    return wrap
