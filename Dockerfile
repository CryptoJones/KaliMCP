# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Aaron K. Clark
#
# KaliMCP runtime image. Kali Linux base + the security tools the MCP
# server wraps + the kalimcp Python package itself.
#
# Build:
#   docker build -t kalimcp .
#
# Run as MCP server (stdio):
#   docker run -i --rm \
#       -v ~/.kalimcp:/root/.kalimcp \
#       -v /var/log/kalimcp.log:/var/log/kalimcp.log \
#       kalimcp
#
# Wire into Claude Code via ~/.claude/mcp.json — see README.
#
# Image is rebuilt against the upstream kali-rolling tag, so refresh
# regularly (`docker pull kalilinux/kali-rolling`) to track upstream
# tool updates.

FROM kalilinux/kali-rolling

ENV DEBIAN_FRONTEND=noninteractive

# Tool installs. Each line is the smallest grouping that maps to one
# of the wrapped tools, so it's easy to see which Dockerfile change
# enabled which MCP tool.
RUN apt-get update && apt-get install -y --no-install-recommends \
        python3 python3-pip python3-venv \
        nmap \
        nikto \
        gobuster \
        whois \
        dnsutils \
        exploitdb \
        sslscan \
        openssl \
        hydra \
        sqlmap \
        ffuf \
        whatweb \
        enum4linux-ng \
        snmp \
        ldap-utils \
        netexec \
        medusa \
        john \
        hashcat \
        impacket-scripts \
        metasploit-framework \
        openssh-client \
        sshpass \
        netcat-traditional \
        wordlists seclists \
        ca-certificates \
        && apt-get clean \
        && rm -rf /var/lib/apt/lists/*

WORKDIR /opt/kalimcp

# Install the Python package itself. Copying the manifest first
# keeps the deps layer cached when only source changed.
COPY pyproject.toml ./
COPY src ./src

# Use a venv so we don't fight the system Python (Kali enforces
# PEP 668 — pip install --user requires --break-system-packages or
# a venv).
RUN python3 -m venv /opt/kalimcp/.venv \
    && /opt/kalimcp/.venv/bin/pip install --no-cache-dir --upgrade pip \
    && /opt/kalimcp/.venv/bin/pip install --no-cache-dir .

# Default audit log path — caller bind-mounts a writable file here.
ENV PATH="/opt/kalimcp/.venv/bin:${PATH}" \
    KALIMCP_LOG_FILE=/var/log/kalimcp.log

# MCP servers talk JSON-RPC over stdio. Don't try to listen on a port.
CMD ["kalimcp"]
