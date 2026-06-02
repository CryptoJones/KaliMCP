# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Aaron K. Clark
"""Tool wrappers exposed as MCP tool functions.

Each module here exposes an ``async`` entry point that the server
registers as an MCP tool. Active-scan modules import and use
``kalimcp.tools._active.active_tool`` for audit logging; passive
modules use the lighter-weight wrapper in ``passive``.
"""

from . import gobuster, hydra, nikto, nmap, passive, sqlmap, sslscan

__all__ = ["gobuster", "hydra", "nikto", "nmap", "passive", "sqlmap", "sslscan"]
