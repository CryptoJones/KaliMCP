# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Aaron K. Clark
"""Shared decorator for active-scan tools.

Provides ``active_tool`` — wraps a coroutine that hits a target
over the network. The decorator times the call and appends a single
``tool_invoke`` audit-log line on completion (or ``tool_exception``
on failure).

The audit log at ``/var/log/kalimcp.log`` is the operator-
accountability mechanism. There is no hard-coded refuse list:
declaring scope is the operator's job. An active engagement with a
``scope`` list gets a non-blocking ``out_of_scope`` warning per
out-of-scope target (see ``engagement.scope_matches``).
"""

from __future__ import annotations

import functools
import os
from collections.abc import Awaitable, Callable, Iterable
from typing import Any

from .. import audit, engagement, ratelimit, untrusted


def _autorecord_enabled() -> bool:
    return os.environ.get("KALIMCP_AUTORECORD") == "1"


# Keyword-argument names whose *value* is a secret, regardless of how a
# given wrapper splices it into argv. The decorator hashes these values
# out of the logged argv by substring match (see ``audit.redact_argv``).
# This is the fail-closed half of the redaction story: even a wrapper
# that embeds a password in a positional (``user:pass@host``) or forgets
# the right ``secret_flags`` still gets the secret redacted, because the
# raw value is right here in kwargs. Per-wrapper ``secret_kwargs`` unions
# with this default set.
_DEFAULT_SECRET_KWARGS: tuple[str, ...] = (
    "password", "nthash", "hashes", "secret", "ntlm_hash",
)


# Mapping from a key in result["parsed"] to a (category, payload_keys)
# tuple. When the engagement workspace's auto-record is enabled, the
# decorator iterates this mapping and records each matched item.
#
# Each entry's value must contain ``host_key`` (the field in the
# extracted item that names the target host) and optional ``payload``
# (extra fields to copy into the finding payload).
_FINDING_RULES: dict[str, dict[str, Any]] = {
    # nmap: parsed.hosts -> {addr, state, ports[]}
    "hosts": {"category": "host", "host_key": "addr",
              "payload_keys": ["state", "ports", "addrtype"]},
    # sqlmap: parsed.injection_points -> {parameter, type, confidence}
    "injection_points": {"category": "sqli", "host_key": None,
                         "payload_keys": ["parameter", "type", "confidence"]},
    # impacket secretsdump: parsed.secrets -> {principal, rid,
    # lmhash, nthash} (also recorded as creds below)
    "secrets": {"category": "secret_dump", "host_key": "principal",
                "payload_keys": ["rid", "lmhash", "nthash"]},
    # wpscan: parsed.vulnerabilities -> {title, fixed_in, references}.
    # host_key None -> filed against the scan target (wpscan vulns aren't
    # per-host). The key is unique across wrappers, so no cross-tool
    # mis-record (cf. nuclei's `findings` which would collide with nikto's,
    # and httpx's `results` which would collide with ffuf's — those tools
    # would need a unique parsed key before they can safely auto-record).
    "vulnerabilities": {"category": "wordpress", "host_key": None,
                        "payload_keys": ["title", "fixed_in", "references"]},
    # zap: parsed.alerts -> {name, risk, confidence, url}. Unique key, filed
    # against the scan target (ZAP alerts aren't per-host).
    "alerts": {"category": "web_alert", "host_key": None,
               "payload_keys": ["name", "risk", "confidence", "url"]},
}

# parsed-key -> (proto, user_key, secret_key, host_key) for cred-shaped
# records.
_CRED_RULES: dict[str, dict[str, Any]] = {
    # hydra / medusa: parsed.credentials_found -> {host, service,
    # username, password}
    "credentials_found": {"proto_key": "service", "user_key": "username",
                          "secret_key": "password", "host_key": "host"},
    # netexec: parsed.successes -> {host, proto, user, secret}
    "successes": {"proto_key": "proto", "user_key": "user",
                  "secret_key": "secret", "host_key": "host"},
    # john / hashcat: parsed.cracked -> {user, password} / {hash, password}
    "cracked": {"proto_key": None, "user_key": "user",
                "secret_key": "password", "host_key": None},
    # kerbrute passwordspray: parsed.valid_logins -> {user, password}. Unique
    # key; proto left empty (no proto field on the item).
    "valid_logins": {"proto_key": None, "user_key": "user",
                     "secret_key": "password", "host_key": None},
}


def _autorecord(tool_name: str, target: str, parsed: dict[str, Any]) -> None:
    """Mirror tool findings into the active engagement workspace.

    Best-effort: any I/O failure is silently swallowed. The audit
    log remains ground truth.
    """
    for key, rule in _FINDING_RULES.items():
        items = parsed.get(key) or []
        if not isinstance(items, list):
            continue
        for item in items:
            if not isinstance(item, dict):
                continue
            host_key = rule.get("host_key")
            host = (item.get(host_key) if host_key else target) or target
            payload = {k: item[k] for k in rule.get("payload_keys", []) if k in item}
            try:
                engagement.record_finding(
                    rule["category"], host, payload, source_tool=tool_name,
                )
            except Exception:
                pass

    for key, rule in _CRED_RULES.items():
        items = parsed.get(key) or []
        if not isinstance(items, list):
            continue
        for item in items:
            if not isinstance(item, dict):
                continue
            host_key = rule.get("host_key")
            host = (item.get(host_key) if host_key else target) or target
            user = item.get(rule["user_key"])
            secret = item.get(rule["secret_key"])
            if not user or not secret:
                continue
            proto_key = rule.get("proto_key")
            proto = (item.get(proto_key) if proto_key else "") or ""
            try:
                engagement.record_cred(
                    host, proto, str(user), str(secret), source_tool=tool_name,
                )
            except Exception:
                pass


def _mark_untrusted_output(result: dict[str, Any], tool_name: str, target: str) -> None:
    """Bound the model-facing output and flag the result as untrusted data.

    Mutates ``result`` in place: hands the model a bounded copy of
    ``stdout``/``stderr`` (so a hostile target can't flood the context),
    sets ``untrusted_output`` + ``untrusted_note``, and on truncation
    mirrors the full ``stdout`` to the engagement loot store when
    auto-record is on (best-effort — tool behavior never depends on it).
    """
    full_stdout = result.get("stdout") if isinstance(result.get("stdout"), str) else ""
    truncated_for_model = False
    for key in ("stdout", "stderr"):
        val = result.get(key)
        if isinstance(val, str):
            bounded, was_cut = untrusted.bound(val)
            if was_cut:
                result[key] = bounded
                truncated_for_model = True

    result["untrusted_output"] = True
    result["untrusted_note"] = untrusted.UNTRUSTED_NOTE

    if truncated_for_model:
        result["output_truncated_for_model"] = True
        if _autorecord_enabled() and full_stdout:
            blob = f"{tool_name}_{target}_output.txt".replace("/", "_").replace(":", "_")
            try:
                saved = engagement.write_loot(blob, full_stdout)
                if saved.get("ok"):
                    result["full_output_loot"] = saved.get("path")
            except Exception:
                pass


def active_tool(
    tool_name: str,
    *,
    secret_flags: Iterable[str] | None = None,
    secret_kwargs: Iterable[str] | None = None,
):
    """Decorator: audit log + scope warning around a tool call.

    The decorated coroutine must accept ``target`` as a keyword
    argument.

    ``secret_flags`` — set of CLI flags whose argv value carries a
    secret (password literal, cred file path), in either the
    ``-flag value`` or ``--flag=value`` shape. Those values are
    rewritten to ``sha256:<8hex>`` via ``audit.redact_argv`` before
    the ``argv`` field is written.

    ``secret_kwargs`` — extra keyword-argument names (beyond the
    always-on ``_DEFAULT_SECRET_KWARGS``) whose value is a secret.
    The decorator hashes those values out of the logged argv *by
    substring match*, which catches secrets fused into positionals
    (``user:pass@host``) that no flag points at. This makes
    redaction fail-closed: a wrapper that forgets ``secret_flags``
    still won't leak a known secret kwarg.
    """
    secret_flag_set: tuple[str, ...] = tuple(secret_flags) if secret_flags else ()
    secret_kwarg_set: tuple[str, ...] = (
        *_DEFAULT_SECRET_KWARGS, *(tuple(secret_kwargs) if secret_kwargs else ())
    )

    def wrap(fn: Callable[..., Awaitable[dict[str, Any]]]):
        @functools.wraps(fn)
        async def inner(target: str, **kwargs) -> dict[str, Any]:
            # Opt-in rate limit (KALIMCP_RATE_PER_MINUTE): bound how fast an agent
            # can launch active scans. No-op unless the operator configured it.
            try:
                ratelimit.acquire()
            except ratelimit.RateLimitError as exc:
                audit.log("rate_limited", tool=tool_name, target=target)
                return {"ok": False, "error": "rate_limited", "message": str(exc)}
            # Computed up front so both the exception sink and the argv
            # log redact the same known secrets (see audit.redact_*).
            secret_values = [
                v for name in secret_kwarg_set
                if isinstance(v := kwargs.get(name), str) and v
            ]
            with audit.time_block() as elapsed:
                try:
                    result = await fn(target=target, **kwargs)
                except Exception as exc:
                    # A raw exception string can quote argv, a cred-bearing
                    # path, or a tool's own error text — redact known
                    # secrets before it reaches the log *or* the client.
                    message = audit.redact_text(str(exc), secret_values)
                    audit.log(
                        "tool_exception",
                        tool=tool_name,
                        target=target,
                        exception=type(exc).__name__,
                        message=message,
                    )
                    return {
                        "ok": False,
                        "error": "tool_exception",
                        "message": message,
                    }

            raw_argv = result.get("argv", [])
            if secret_flag_set or secret_values:
                logged_argv = audit.redact_argv(
                    raw_argv, secret_flag_set, secret_values,
                )
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

            # Non-blocking scope warning. If the active engagement
            # has a scope and `target` doesn't match any pattern, we
            # annotate the result and emit a separate audit event.
            # We do NOT block — operator declared scope, operator
            # also has reason to scan outside it occasionally.
            try:
                if not engagement.scope_matches(target):
                    result = {**result, "warning": "out_of_scope"}
                    audit.log(
                        "out_of_scope_warning",
                        tool=tool_name,
                        target=target,
                        engagement=engagement.current_engagement(),
                    )
            except Exception:
                pass

            if _autorecord_enabled():
                parsed = result.get("parsed") or {}
                if isinstance(parsed, dict):
                    _autorecord(tool_name, target, parsed)

            # Tool output is attacker-controlled (issue #11). Only mark a
            # result that came from an actual subprocess — a pre-launch
            # validation error_result has an empty argv and no output.
            if result.get("argv"):
                _mark_untrusted_output(result, tool_name, target)

            return {"ok": True, **result}

        return inner
    return wrap
