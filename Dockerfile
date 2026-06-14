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
# The base is pinned by digest, not the moving `kali-rolling` tag, so a
# build is reproducible and can't silently pull a changed (or tampered)
# upstream image. To intentionally track upstream tool updates, refresh
# the digest:
#
#   skopeo inspect --format '{{.Digest}}' docker://kalilinux/kali-rolling
#
# then update the pin below (the `:kali-rolling` tag is kept alongside the
# digest purely as a human-readable label — Docker resolves by digest).

FROM kalilinux/kali-rolling@sha256:6ae2813f51a2adf265e0a740c5fe3645406a8fc39711a45386aa43f036c79bd5

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
        tshark \
        binutils \
        traceroute \
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
