# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Aaron K. Clark
"""Tool wrappers exposed as MCP tool functions.

Each module here exposes an ``async`` entry point that the server
registers as an MCP tool. Active-scan modules use the
``kalimcp.tools._active.active_tool`` decorator for audit logging;
passive modules use the lighter-weight wrapper in ``passive``.
"""

from . import (
    ffuf,
    gobuster,
    hydra,
    ldap,
    nikto,
    nmap,
    passive,
    smb,
    snmp,
    sqlmap,
    sslscan,
    whatweb,
)

__all__ = [
    "ffuf",
    "gobuster",
    "hydra",
    "ldap",
    "nikto",
    "nmap",
    "passive",
    "smb",
    "snmp",
    "sqlmap",
    "sslscan",
    "whatweb",
]
