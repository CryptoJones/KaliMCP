# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Aaron K. Clark
"""Passive lookups: whois, dig, searchsploit, openssl cert dump, plus
local loot triage (tshark pcap analysis, strings / nm / objdump).

These do NOT actively probe the target's services. Whois and dig
hit registry / DNS infrastructure (not the target itself);
searchsploit is a local Exploit-DB grep; the openssl cert dump
opens a TLS handshake which is technically a network touch but
returns immediately after the cert exchange and is a normal
pre-engagement information-gathering step. The loot-triage tools
(tshark, strings, nm, objdump) only read a file already on disk — a
captured pcap or a pulled binary — and never touch the network at all.

These do not go through the `active_tool` decorator — they carry no
scope warning or auto-record hook, because none of them is a probe of
the target. Passive calls still get audited (a `passive_invoke` event)
so operators have a record of what was looked up.
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


async def whois_lookup(*, query: str, timeout_seconds: int = 30) -> dict[str, Any]:
    """Whois registration lookup for a domain or IP."""
    return await _audited_run("whois", ["whois", "--", query], timeout_seconds)


async def dig_record(
    *,
    domain: str,
    record_type: str = "A",
    timeout_seconds: int = 30,
) -> dict[str, Any]:
    """DNS query via dig. record_type is A / AAAA / MX / TXT / NS / etc."""
    rtype = (record_type or "A").upper()
    if not rtype.isalpha() or len(rtype) > 16:
        return run.error_result(f"invalid record_type: {record_type!r}")
    return await _audited_run("dig", ["dig", "+short", "+timeout=5", domain, rtype], timeout_seconds)


async def searchsploit_search(*, keyword: str, timeout_seconds: int = 30) -> dict[str, Any]:
    """Local Exploit-DB search via the `searchsploit` CLI."""
    return await _audited_run("searchsploit", ["searchsploit", "--no-colour", "--", keyword], timeout_seconds)


async def cert_dump(
    *,
    host: str,
    port: int = 443,
    timeout_seconds: int = 30,
) -> dict[str, Any]:
    """Dump the TLS certificate chain via `openssl s_client`."""
    argv = [
        "openssl", "s_client",
        "-connect", f"{host}:{int(port)}",
        "-servername", host,
        "-showcerts",
    ]
    # openssl s_client expects stdin EOF to finish; send empty stdin.
    with audit.time_block() as elapsed:
        result = await run.run(argv, timeout=timeout_seconds, stdin=b"")
    audit.log(
        "passive_invoke",
        tool="openssl-cert",
        argv=argv,
        elapsed_ms=elapsed(),
        exit_code=result.get("exit_code"),
    )
    return result


# ---------- loot triage (read a file already on disk) ----------
# These analyze a captured pcap or a pulled binary. They take a file path,
# never a live interface (tshark live capture needs root + an iface and is
# deliberately not exposed). Paths are existence-checked via
# run.validate_file; binutils get `--` so a dash-leading filename can't be
# read as a flag. Output is capped by run.run's 2 MB ceiling.

# tshark sub-analyses. `summary` is the default packet list; the rest map
# to a -Y display filter and/or a -z statistic.
_TSHARK_EXTRA: dict[str, list[str]] = {
    "summary": [],
    "http": [
        "-T", "fields",
        "-e", "frame.number", "-e", "ip.src", "-e", "ip.dst",
        "-e", "http.request.method", "-e", "http.request.full_uri",
        "-e", "http.response.code",
    ],
    "protocol_hierarchy": ["-q", "-z", "io,phs"],
    "conversations": ["-q", "-z", "conv,ip"],
    "expert": ["-q", "-z", "expert"],
}
_TSHARK_DEFAULT_FILTER: dict[str, str] = {"http": "http"}


async def tshark_pcap(
    *,
    pcap: str,
    mode: str = "summary",
    display_filter: str = "",
    timeout_seconds: int = 120,
) -> dict[str, Any]:
    """Analyze a capture file with tshark (read-only, never live).

    Modes: ``summary`` (packet list), ``http`` (request/response fields),
    ``protocol_hierarchy`` (``-z io,phs``), ``conversations``
    (``-z conv,ip``), ``expert`` (``-z expert``). ``display_filter`` is an
    optional Wireshark display filter (``-Y``); it overrides the mode's
    default filter.
    """
    if err := run.validate_file(pcap, "pcap"):
        return err
    if mode not in _TSHARK_EXTRA:
        return run.error_result(
            f"unknown mode: {mode!r}. Known: {sorted(_TSHARK_EXTRA)}"
        )
    argv = ["tshark", "-r", pcap]
    eff_filter = display_filter or _TSHARK_DEFAULT_FILTER.get(mode, "")
    if eff_filter:
        argv += ["-Y", eff_filter]
    argv += _TSHARK_EXTRA[mode]
    return await _audited_run("tshark", argv, timeout_seconds)


async def strings_extract(
    *,
    path: str,
    min_length: int = 4,
    encoding: str = "s",
    timeout_seconds: int = 60,
) -> dict[str, Any]:
    """Extract printable strings from a binary (``strings -n -e``).

    ``encoding`` is a strings ``-e`` selector: ``s`` (7-bit, default),
    ``S`` (8-bit), ``b``/``l`` (16-bit big/little), ``B``/``L`` (32-bit).
    """
    if err := run.validate_file(path, "path"):
        return err
    n = max(1, min(int(min_length), 1024))
    enc = encoding if encoding in ("s", "S", "b", "l", "B", "L") else "s"
    argv = ["strings", "-n", str(n), "-e", enc, "--", path]
    return await _audited_run("strings", argv, timeout_seconds)


async def nm_symbols(
    *,
    path: str,
    demangle: bool = True,
    dynamic: bool = False,
    timeout_seconds: int = 60,
) -> dict[str, Any]:
    """List symbols in an object/library (``nm``).

    ``demangle`` renders C++ names readable; ``dynamic`` lists only the
    dynamic symbol table (useful for stripped shared objects).
    """
    if err := run.validate_file(path, "path"):
        return err
    argv = ["nm"]
    if demangle:
        argv.append("--demangle")
    if dynamic:
        argv.append("--dynamic")
    argv += ["--", path]
    return await _audited_run("nm", argv, timeout_seconds)


_OBJDUMP_MODES: dict[str, str] = {
    "headers": "-x",      # all headers
    "sections": "-h",     # section headers
    "symbols": "-t",      # symbol table
    "disasm": "-d",       # disassemble executable sections
}


async def objdump_inspect(
    *,
    path: str,
    mode: str = "headers",
    timeout_seconds: int = 120,
) -> dict[str, Any]:
    """Inspect an object file with objdump.

    Modes: ``headers`` (``-x``), ``sections`` (``-h``), ``symbols``
    (``-t``), ``disasm`` (``-d``).
    """
    if err := run.validate_file(path, "path"):
        return err
    if mode not in _OBJDUMP_MODES:
        return run.error_result(
            f"unknown mode: {mode!r}. Known: {sorted(_OBJDUMP_MODES)}"
        )
    argv = ["objdump", _OBJDUMP_MODES[mode], "--", path]
    return await _audited_run("objdump", argv, timeout_seconds)
