# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Aaron K. Clark
"""Tier-3 cloud-security auditing wrappers: ScoutSuite, Prowler, kube-hunter.

These are *Tier-3* additions: they are not shipped in the Kali apt
repos and are installed via pip/pipx in the Dockerfile.

ScoutSuite and Prowler audit a *cloud account* through whatever cloud
credentials are configured locally (AWS profile, Azure CLI login, GCP
ADC, …). There is no single "target" host, so they are **not**
``active_tool`` probes — they are modelled like ``passive.py``: a
``_audited_run`` that logs a ``passive_invoke`` event. They carry no
scope warning and no auto-record hook (their findings are large JSON
report trees, not the small per-host/cred records the engagement
workspace mirrors).

kube-hunter, by contrast, *can* probe a remote host (``--remote
<host>``), so it **is** an ``active_tool`` with a ``target`` kwarg and
gets the usual audit / scope-warning treatment. Mixing both styles in
one module is intentional — the split mirrors what each tool actually
does on the network.

Pacu is intentionally omitted: it is an interactive AWS-exploitation
REPL, not a one-shot non-interactive CLI, so it does not fit the
``run.run`` single-invocation model.
"""

from __future__ import annotations

import shlex
from typing import Any

from .. import audit, run
from ._active import active_tool

_PROVIDERS = {"aws", "azure", "gcp", "aliyun", "oci"}


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


async def scoutsuite(
    *,
    provider: str = "aws",
    report_dir: str = "",
    extra_args: str = "",
    timeout_seconds: int = 900,
) -> dict[str, Any]:
    """Audit a cloud account with ScoutSuite (the ``scout`` CLI).

    Args:
      provider: one of ``aws``, ``azure``, ``gcp``, ``aliyun``, ``oci``.
      report_dir: optional ``--report-dir`` output directory.
      extra_args: extra CLI flags, split with ``shlex.split`` and passed
        through as argv items (no shell, so no injection surface).
      timeout_seconds: hard wallclock cap (default 900).

    Uses locally-configured cloud credentials; there is no target host.
    """
    if provider not in _PROVIDERS:
        return run.error_result(
            f"invalid provider: {provider!r}. Known: {sorted(_PROVIDERS)}",
            parsed={"provider": provider, "report_dir": report_dir},
        )
    argv = ["scout", provider, "--no-browser"]
    if report_dir:
        argv += ["--report-dir", report_dir]
    argv += shlex.split(extra_args)
    result = await _audited_run("scoutsuite", argv, timeout_seconds)
    # ScoutSuite writes an HTML + scoutsuite_results_*.js report to a
    # directory; it is NOT parsed inline. Report where it landed and say so,
    # rather than echoing the inputs as if they were findings.
    result["parsed"] = {
        "provider": provider,
        "report_dir": report_dir or "scoutsuite-report",
        "results_parsed_inline": False,
        "note": "findings are in the ScoutSuite report dir (scoutsuite_results_*.js); read them there.",
    }
    return result


async def prowler(
    *,
    provider: str = "aws",
    output_dir: str = "",
    extra_args: str = "",
    timeout_seconds: int = 1800,
) -> dict[str, Any]:
    """Audit a cloud account with Prowler.

    Args:
      provider: one of ``aws``, ``azure``, ``gcp``, ``aliyun``, ``oci``.
      output_dir: optional ``--output-directory`` for report files.
      extra_args: extra CLI flags, split with ``shlex.split`` and passed
        through as argv items (no shell, so no injection surface).
      timeout_seconds: hard wallclock cap (default 1800).

    Emits OCSF JSON (``--output-formats json-ocsf``). Uses locally-
    configured cloud credentials; there is no target host.
    """
    if provider not in _PROVIDERS:
        return run.error_result(
            f"invalid provider: {provider!r}. Known: {sorted(_PROVIDERS)}",
            parsed={"provider": provider},
        )
    # Always pass an output directory so the caller can find the report
    # (Prowler otherwise scatters it under a default ./output relative to
    # CWD). The OCSF JSON is not parsed inline.
    eff_dir = output_dir or "/tmp/kalimcp_prowler"
    argv = ["prowler", provider, "--output-formats", "json-ocsf",
            "--output-directory", eff_dir]
    argv += shlex.split(extra_args)
    result = await _audited_run("prowler", argv, timeout_seconds)
    result["parsed"] = {
        "provider": provider,
        "output_dir": eff_dir,
        "results_parsed_inline": False,
        "note": "findings are the OCSF JSON files in output_dir; read them there.",
    }
    return result


@active_tool(tool_name="kube-hunter")
async def kube_hunter(
    *,
    target: str = "",
    remote: bool = True,
    timeout_seconds: int = 600,
) -> dict[str, Any]:
    """Hunt for Kubernetes security weaknesses with kube-hunter.

    Args:
      target: a remote host/IP to probe. When set (and ``remote`` is
        true), runs ``--remote <target>``; when empty, falls back to
        ``--pod`` (in-cluster scan from the current pod).
      remote: probe ``target`` remotely (default). Set false to force
        the ``--pod`` in-cluster mode even if a target is given.
      timeout_seconds: hard wallclock cap (default 600).

    Unlike ScoutSuite/Prowler, this *does* touch the network, so it is
    an ``active_tool`` and takes a ``target`` kwarg.
    """
    if target and remote:
        if err := run.validate_arg(target, "target"):
            return err
        mode = ["--remote", target]
    else:
        mode = ["--pod"]
    argv = ["kube-hunter", "--report", "json", *mode]
    result = await run.run(argv, timeout=timeout_seconds)
    result["parsed"] = {"target": target}
    return result
