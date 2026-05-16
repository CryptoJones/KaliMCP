# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Aaron K. Clark
"""Shared decorator/helper for active-scan tools (auth-required)."""

from __future__ import annotations

import functools
from typing import Any, Awaitable, Callable

from .. import audit, authz


def authorized(tool_name: str):
    """Decorator: validate authorization_token + scope, audit-log the call.

    The decorated coroutine must accept `target` and `authorization_token`
    as keyword arguments. It receives `_auth` (the Authorization record)
    on success.
    """
    def wrap(fn: Callable[..., Awaitable[dict[str, Any]]]):
        @functools.wraps(fn)
        async def inner(*args, target: str, authorization_token: str, **kwargs) -> dict[str, Any]:
            try:
                auth_record = authz.check(target=target, token=authorization_token)
            except authz.AuthzError as exc:
                audit.log(
                    "authz_denied",
                    tool=tool_name,
                    target=target,
                    reason=str(exc),
                )
                return {
                    "ok": False,
                    "error": "authorization_denied",
                    "message": str(exc),
                }

            with audit.time_block() as elapsed:
                try:
                    result = await fn(*args, target=target, _auth=auth_record, **kwargs)
                except Exception as exc:  # pragma: no cover — caught for audit safety
                    audit.log(
                        "tool_exception",
                        tool=tool_name,
                        target=target,
                        authz_id=auth_record.token_id(),
                        authz_name=auth_record.name,
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
                authz_id=auth_record.token_id(),
                authz_name=auth_record.name,
                elapsed_ms=elapsed(),
                exit_code=result.get("exit_code"),
                timed_out=result.get("timed_out", False),
                truncated=result.get("truncated", False),
            )
            return {"ok": True, **result, "authz_name": auth_record.name}

        return inner
    return wrap
