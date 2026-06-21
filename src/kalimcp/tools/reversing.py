# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Aaron K. Clark
"""Tier-3 reverse-engineering / binary-analysis loot triage: gdb (batch
mode) and radare2.

These read a binary that's already been pulled to disk — the same loot-
triage posture as the strings / nm / objdump wrappers in ``passive.py``.
They never attach to a live process, never spawn a debuggee that touches
the network, and never hit the network themselves. gdb runs non-
interactively (``-batch -nx``) and radare2 in quiet mode (``-q``); the
operator-supplied commands run *inside* the analysis engine, not the
shell, because ``argv`` is always a list handed to ``run.run`` (no shell,
no injection surface).

Like ``passive.py`` these do not go through the ``active_tool``
decorator — they carry no scope warning or auto-record hook, because
neither is a probe of a target. They still get audited: each emits a
``passive_invoke`` event so operators have a record of what was inspected.
"""

from __future__ import annotations

from typing import Any

from .. import audit, run


async def _audited_run(tool: str, argv: list[str], timeout: int) -> dict[str, Any]:
    with audit.time_block() as elapsed:
        result = await run.run(argv, timeout=timeout)
    audit.log(
        "passive_invoke",
        tool=tool,
        argv=argv,
        elapsed_ms=elapsed(),
        exit_code=result.get("exit_code"),
    )
    return result


async def gdb_inspect(
    *,
    path: str,
    command: str = "info functions",
    timeout_seconds: int = 60,
) -> dict[str, Any]:
    """Inspect a binary with gdb in batch (non-interactive) mode.

    Runs ``gdb -batch -nx -ex <command> -- <path>``. ``-batch`` exits when
    the command list is done (no interactive prompt); ``-nx`` skips any
    ``.gdbinit``. ``command`` is a single gdb command run inside gdb — e.g.
    ``info functions`` (the default), ``info files``, ``disassemble main``.
    Raw gdb stdout is the return value.
    """
    if err := run.validate_file(path, "path"):
        return err
    argv = ["gdb", "-batch", "-nx", "-ex", command, "--", path]
    return await _audited_run("gdb", argv, timeout_seconds)


async def r2_analyze(
    *,
    path: str,
    commands: str = "aaa;afl",
    timeout_seconds: int = 120,
) -> dict[str, Any]:
    """Analyze a binary with radare2 in quiet, scriptable mode.

    Runs ``r2 -q -e scr.color=0 -c <commands> <path>``. ``-q`` quits
    after the command runs (no interactive shell), ``-e scr.color=0``
    strips ANSI color so stdout stays parseable. ``commands`` is one
    semicolon-separated string of r2 commands — the default ``aaa;afl``
    runs full analysis then lists functions. Raw r2 stdout is the value.

    Note: radare2 has **no** ``--`` end-of-options separator — there it
    means "open no file" (``malloc://512``), which would silently analyze
    an empty buffer. The file is r2's final positional argument; an
    existing path that begins with ``-`` is the only edge ``validate_file``
    can't see, so it's normalized to ``./<path>`` when relative.
    """
    if err := run.validate_file(path, "path"):
        return err
    # r2 reads the final positional as the file; guard a leading-dash
    # relative path (which r2 would read as a flag) by prefixing "./".
    safe_path = path if path.startswith(("/", "./", "../")) else f"./{path}"
    argv = ["r2", "-q", "-e", "scr.color=0", "-c", commands, safe_path]
    return await _audited_run("r2", argv, timeout_seconds)
