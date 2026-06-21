# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Aaron K. Clark
"""gowitness wrapper — headless-Chrome web screenshotter.

gowitness drives headless Chrome to capture a screenshot of a target
URL. Its CLI is version-sensitive: older releases used
``gowitness single <url>``; modern (v3+) releases use the
``scan single --url <url>`` subcommand with ``--screenshot-path`` for
the output directory. We target the modern form (assumption noted in
``capture``). The wrapper returns the screenshot path(s) it expects to
have been written under ``output_dir``.
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any

from .. import run
from ._active import active_tool


def _empty_parsed(out_dir: str = "") -> dict[str, Any]:
    return {"screenshots": [], "output_dir": out_dir}


def _scan_output_dir(out_dir: Path) -> list[str]:
    """List screenshot files written under ``out_dir`` (best-effort)."""
    exts = {".png", ".jpg", ".jpeg"}
    found: list[str] = []
    try:
        for p in sorted(out_dir.iterdir()):
            if p.is_file() and p.suffix.lower() in exts:
                found.append(str(p))
    except OSError:
        pass
    return found


@active_tool(tool_name="gowitness")
async def capture(
    *,
    target: str,
    output_dir: str = "",
    timeout_seconds: int = 120,
) -> dict[str, Any]:
    """Screenshot a web URL with gowitness.

    Args:
      target: URL like ``https://example.com/``.
      output_dir: directory to write the screenshot into. If empty,
        defaults to ``~/.kalimcp/screenshots`` (created best-effort).
        The integrator may override this to the active engagement's
        screenshots dir.
      timeout_seconds: hard wallclock cap (default 120 — Chrome startup
        plus page load).

    Returns the structured ``kalimcp.run.run`` result dict augmented
    with ``parsed``: ``{screenshots: [paths], output_dir: str}``.
    """
    if output_dir:
        # Syntactic well-formedness only — not an authorization gate.
        err = run.validate_arg(output_dir, "output_dir")
        if err is not None:
            return run.error_result(err["stderr"], parsed=_empty_parsed())
        out_dir = Path(output_dir)
    else:
        out_dir = Path.home() / ".kalimcp" / "screenshots"

    # Best-effort: gowitness can create this itself, but pre-creating it
    # keeps the path stable for the post-run file listing.
    try:
        out_dir.mkdir(parents=True, exist_ok=True)
    except OSError:
        pass

    # Modern gowitness (v3+) CLI form. Older releases used
    # ``gowitness single <url>``; we assume v3+ here (ships in current Kali).
    argv = [
        "gowitness",
        "scan",
        "single",
        "--url",
        target,
        "--screenshot-path",
        str(out_dir),
    ]

    result = await run.run(argv, timeout=timeout_seconds)

    parsed = _empty_parsed(str(out_dir))
    # Prefer the actual files on disk; fall back to any path gowitness
    # printed to stdout.
    screenshots = _scan_output_dir(out_dir)
    if not screenshots:
        for line in (result.get("stdout") or "").splitlines():
            for token in line.split():
                low = token.lower()
                if low.endswith((".png", ".jpg", ".jpeg")) and os.sep in token:
                    screenshots.append(token)
    parsed["screenshots"] = screenshots
    result["parsed"] = parsed
    return result
