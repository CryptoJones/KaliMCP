# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Aaron K. Clark
"""Tool wrappers exposed as MCP tool functions.

Each module here exposes ``async def run(...)`` that the server
registers as an MCP tool. Active-scan modules import + use
``kalimcp.authz`` to enforce scope; passive modules don't.
"""
