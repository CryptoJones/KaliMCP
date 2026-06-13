# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Aaron K. Clark
"""ffuf wrapper — fast web fuzzer for directories / vhosts / params.

ffuf is gobuster's flexible cousin. Where ``gobuster_dir`` only walks
URL paths, ffuf can fuzz vhosts (`Host:` header), GET/POST parameter
names, and file extensions, all with response-code/size/word
filtering. Output is requested as JSON on stdout so the agent gets a
clean ``parsed`` block instead of decorated text.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from .. import run
from ._active import active_tool

_WORDLIST_CANDIDATES = [
    "/usr/share/wordlists/dirb/common.txt",
    "/usr/share/wordlists/seclists/Discovery/Web-Content/common.txt",
    "/usr/share/seclists/Discovery/Web-Content/common.txt",
]

_MODES = ("dir", "vhost", "param", "ext")


def _default_wordlist() -> str | None:
    for p in _WORDLIST_CANDIDATES:
        if Path(p).is_file():
            return p
    return None


def _empty_parsed() -> dict[str, Any]:
    return {"results": []}


def _parse_output(text: str) -> dict[str, Any]:
    """Distill ffuf's JSON output into a flat ``results`` list.

    ffuf emits a top-level object with a ``results`` array; each
    entry has ``input`` (the fuzzed value), ``url``, ``status``,
    ``length``, ``words``, ``lines``, ``redirectlocation``, etc.
    The parser keeps the fields agents are most likely to filter on.
    """
    try:
        data = json.loads(text)
    except (json.JSONDecodeError, ValueError):
        return _empty_parsed()
    if not isinstance(data, dict):
        return _empty_parsed()
    raw_results = data.get("results") or []
    if not isinstance(raw_results, list):
        return _empty_parsed()

    out: list[dict[str, Any]] = []
    for r in raw_results:
        if not isinstance(r, dict):
            continue
        entry: dict[str, Any] = {
            "url": r.get("url", ""),
            "status": r.get("status"),
            "length": r.get("length"),
            "words": r.get("words"),
            "lines": r.get("lines"),
        }
        if isinstance(r.get("input"), dict):
            entry["input"] = r["input"]
        redirect = r.get("redirectlocation")
        if redirect:
            entry["redirect"] = redirect
        ctype = r.get("content-type")
        if ctype:
            entry["content_type"] = ctype
        out.append(entry)
    return {"results": out}


def _build_argv(
    *,
    target: str,
    wordlist: str,
    mode: str,
    vhost_template: str | None,
    threads: int,
) -> list[str]:
    """Build ffuf argv per mode. ``target`` must already contain FUZZ
    where appropriate (dir/param/ext), except in vhost mode where the
    Host header is fuzzed instead.
    """
    base = [
        "ffuf",
        "-w", wordlist,
        "-t", str(threads),
        "-of", "json",
        "-o", "/dev/stdout",
        "-s",  # suppress progress bar on stderr from leaking into stdout
    ]
    if mode == "vhost":
        # User passes the base URL; we fuzz the Host header.
        host_hdr = vhost_template or "FUZZ"
        return [*base, "-u", target, "-H", f"Host: {host_hdr}"]
    # dir / param / ext: target itself contains FUZZ. We don't try to
    # rewrite it; the caller is responsible.
    return [*base, "-u", target]


@active_tool(tool_name="ffuf")
async def fuzz(
    *,
    target: str,
    mode: str = "dir",
    wordlist: str | None = None,
    vhost_template: str | None = None,
    threads: int = 40,
    timeout_seconds: int = 600,
) -> dict[str, Any]:
    """Fuzz ``target`` with ffuf.

    Args:
      target: URL containing ``FUZZ`` where the wordlist value should
        be substituted (e.g. ``https://example.com/FUZZ`` for
        dir-mode, ``https://example.com/?FUZZ=test`` for param-mode).
        In ``vhost`` mode pass the base URL with no FUZZ in it; the
        Host header is fuzzed instead.
      mode: ``dir`` (default), ``vhost``, ``param``, or ``ext``.
      wordlist: path to wordlist; defaults to a known Kali path.
      vhost_template: format string for the Host header in vhost mode,
        e.g. ``"FUZZ.example.com"``. Defaults to bare ``FUZZ``.
      threads: concurrent requests (default 40; capped 1..200).
      timeout_seconds: hard wallclock cap (default 600).

    Returns the structured ``kalimcp.run.run`` result dict augmented
    with ``parsed``: ``{results: [{url, status, length, words, lines,
    input?, redirect?, content_type?}]}``.
    """
    if mode not in _MODES:
        return run.error_result(
            f"unknown mode: {mode!r}. Known: {list(_MODES)}",
            parsed=_empty_parsed(),
        )
    wl = wordlist or _default_wordlist()
    if not wl:
        return run.error_result(
            "no wordlist available. Pass `wordlist=...` or install "
            "wordlists (apt install wordlists seclists).",
            parsed=_empty_parsed(),
        )
    if err := run.validate_file(wl, "wordlist", parsed=_empty_parsed()):
        return err

    threads = max(1, min(int(threads), 200))
    argv = _build_argv(
        target=target,
        wordlist=wl,
        mode=mode,
        vhost_template=vhost_template,
        threads=threads,
    )
    result = await run.run(argv, timeout=timeout_seconds)

    stdout = result.get("stdout", "") or ""
    if stdout.strip():
        result["parsed"] = _parse_output(stdout)
    else:
        result["parsed"] = _empty_parsed()
    return result
