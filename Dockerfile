# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Aaron K. Clark
#
# KaliMCP runtime image. Kali Linux base + the security tools the MCP
# server wraps + the kalimcp Python package itself.
#
# Build:
#   docker build -t kalimcp .
#
# Run as MCP server (stdio) — the container runs as the non-root `kalimcp`
# user, so mount the state dir at its home:
#   docker run -i --rm \
#       -v ~/.kalimcp:/home/kalimcp/.kalimcp \
#       kalimcp
#
# nmap is granted cap_net_raw via setcap so SYN/OS scans work without root.
# A tool that genuinely needs more (raw 802.11, etc.) can be re-enabled per
# run with `--cap-add=NET_ADMIN` or, as a last resort, `--privileged` — the
# image itself stays unprivileged.
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
        libcap2-bin \
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
        openssh-client \
        sshpass \
        netcat-traditional \
        wordlists seclists \
        ca-certificates \
        && apt-get clean \
        && rm -rf /var/lib/apt/lists/*

# Grant nmap only the capabilities it needs (raw sockets for SYN/OS scans,
# low-port bind) instead of running the whole container as root. Other
# wrapped tools degrade gracefully without elevated privileges (e.g. nmap
# falls back to a TCP connect scan). `|| true` keeps the build working on
# arches/filesystems where setcap isn't applicable.
RUN setcap cap_net_raw,cap_net_bind_service+eip "$(command -v nmap)" || true

WORKDIR /opt/kalimcp

# Install the Python package itself. Copying the manifest first
# keeps the deps layer cached when only source changed. README.md is
# copied too because pyproject declares `readme = "README.md"`, which
# hatchling reads when building the wheel metadata.
COPY pyproject.toml README.md ./
COPY src ./src

# Use a venv so we don't fight the system Python (Kali enforces
# PEP 668 — pip install --user requires --break-system-packages or
# a venv).
RUN python3 -m venv /opt/kalimcp/.venv \
    && /opt/kalimcp/.venv/bin/pip install --no-cache-dir --upgrade pip \
    && /opt/kalimcp/.venv/bin/pip install --no-cache-dir .

# Run as an unprivileged user. Create it, give it the app + a home for the
# engagement/loot/audit state, and drop to it for CMD.
RUN useradd --create-home --uid 1000 --shell /bin/bash kalimcp \
    && mkdir -p /home/kalimcp/.kalimcp \
    && chown -R kalimcp:kalimcp /opt/kalimcp /home/kalimcp

ENV PATH="/opt/kalimcp/.venv/bin:${PATH}" \
    HOME=/home/kalimcp \
    KALIMCP_LOG_FILE=/home/kalimcp/.kalimcp/kalimcp.log

USER kalimcp

# MCP servers talk JSON-RPC over stdio. Don't try to listen on a port.
CMD ["kalimcp"]
