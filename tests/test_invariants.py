# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Aaron K. Clark
"""Cross-cutting security invariants (issue #15).

A tool-wrapper server lives or dies on two guarantees:

  1. It never builds a shell string — every subprocess is an argv list
     launched with ``create_subprocess_exec`` (no ``shell=True``).
  2. Attacker- or agent-controlled values can't forge or corrupt an
     audit-log record (newline / ANSI / control-char injection).

These are asserted here as repository-wide tests so a future wrapper
that reintroduces a shell string, or a logging change that stops
JSON-encoding fields, fails CI loudly.
"""

from __future__ import annotations

import json
from pathlib import Path

from kalimcp import audit

_SRC = Path(__file__).resolve().parent.parent / "src" / "kalimcp"

# Patterns that would (re)introduce a shell-string execution surface.
_FORBIDDEN = (
    "shell=True",
    "create_subprocess_shell",
    "os.system",
    "os.popen",
    "subprocess.getoutput",
    "subprocess.getstatusoutput",
)


def _python_sources() -> list[Path]:
    return sorted(_SRC.rglob("*.py"))


def test_no_shell_string_execution_anywhere():
    """No source file may use shell=True or a string-command launcher."""
    offenders: list[str] = []
    for path in _python_sources():
        text = path.read_text(encoding="utf-8")
        for needle in _FORBIDDEN:
            if needle in text:
                offenders.append(f"{path.relative_to(_SRC.parent.parent)}: {needle}")
    assert not offenders, "shell-string execution surface reintroduced:\n" + "\n".join(offenders)


def test_runner_uses_exec_not_shell():
    """run.run must launch via the argv-list create_subprocess_exec."""
    run_src = (_SRC / "run.py").read_text(encoding="utf-8")
    assert "create_subprocess_exec" in run_src
    assert "create_subprocess_shell" not in run_src


def test_argv_newline_cannot_forge_a_record(tmp_path):
    """A newline-bearing argv token stays one JSON record, not two."""
    log_path = tmp_path / "audit.log"
    audit.configure(path=log_path)
    forged = 'x\n{"event": "forged", "tool": "evil"}'
    audit.log("tool_invoke", tool="nmap", target="t", argv=["nmap", "-sV", forged])
    audit.reset_for_test()

    raw = log_path.read_text(encoding="utf-8")
    lines = [ln for ln in raw.splitlines() if ln]
    assert len(lines) == 1, "newline in argv split the record into multiple lines"
    row = json.loads(lines[0])
    assert row["event"] == "tool_invoke"
    # The literal newline survives inside the value, escaped in the file.
    assert row["argv"][2] == forged
    assert "\\n" in raw  # the newline was JSON-escaped, not written raw


def test_control_chars_in_target_are_escaped(tmp_path):
    """ANSI/control chars in a field are JSON-escaped, never written raw."""
    log_path = tmp_path / "audit.log"
    audit.configure(path=log_path)
    nasty = "host\x1b[31m\x07\x00evil"
    audit.log("tool_invoke", tool="nmap", target=nasty)
    audit.reset_for_test()

    raw = log_path.read_text(encoding="utf-8")
    assert "\x1b" not in raw and "\x07" not in raw and "\x00" not in raw
    rows = [json.loads(ln) for ln in raw.splitlines() if ln]
    assert rows[0]["target"] == nasty  # round-trips losslessly
