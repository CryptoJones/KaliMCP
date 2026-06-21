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

# ---- builder stage: compile the Go tools that aren't in the Kali apt repos ----
# nuclei + gowitness ship only as Go source. Build them in a throwaway stage so
# the Go toolchain (golang-go, ~hundreds of MB) never lands in the runtime image
# — only the two compiled binaries are copied across.
FROM kalilinux/kali-rolling@sha256:6ae2813f51a2adf265e0a740c5fe3645406a8fc39711a45386aa43f036c79bd5 AS gobuilder

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y --no-install-recommends \
        golang-go git ca-certificates \
    && rm -rf /var/lib/apt/lists/*
RUN go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest \
    && go install github.com/sensepost/gowitness@latest \
    && go install github.com/ropnop/kerbrute@latest \
    && go install github.com/jpillora/chisel@latest \
    && go install github.com/nicocha30/ligolo-ng/cmd/proxy@latest \
    && mv /root/go/bin/proxy /root/go/bin/ligolo-proxy
# binaries land in /root/go/bin/{nuclei,gowitness,kerbrute,chisel,ligolo-proxy}
# (ligolo's cmd/proxy compiles to `proxy`; renamed so the wrapper's `ligolo-proxy` resolves)


# ---- runtime stage ----
FROM kalilinux/kali-rolling@sha256:6ae2813f51a2adf265e0a740c5fe3645406a8fc39711a45386aa43f036c79bd5

ENV DEBIAN_FRONTEND=noninteractive

# Image variants. The two heaviest groups are optional — build a leaner image
# with `--build-arg INCLUDE_CLOUD=false` (drops ScoutSuite/Prowler/kube-hunter)
# and/or `--build-arg INCLUDE_ZAP=false` (drops OWASP ZAP + its JRE). Both
# default to the full toolset; the corresponding MCP tools just report
# ToolNotInstalled if their binary was excluded.
ARG INCLUDE_CLOUD=true
ARG INCLUDE_ZAP=true

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
        \
        # --- pentest gap-coverage additions ---
        subfinder \
        dnsx \
        httpx-toolkit \
        wpscan \
        gdb \
        radare2 \
        responder \
        mitm6 \
        bloodhound.py \
        proxychains4 \
        chromium \
        pipx \
        && apt-get clean \
        && rm -rf /var/lib/apt/lists/*

# nuclei + gowitness + kerbrute: copy the binaries compiled in the gobuilder
# stage onto PATH. The Go toolchain itself never enters this image.
COPY --from=gobuilder /root/go/bin/nuclei /root/go/bin/gowitness /root/go/bin/kerbrute \
     /root/go/bin/chisel /root/go/bin/ligolo-proxy /usr/local/bin/

# OWASP ZAP (zaproxy) pulls a full JRE — the single heaviest apt package here.
# Gated behind INCLUDE_ZAP so a lean build can skip it.
RUN if [ "$INCLUDE_ZAP" != "false" ]; then \
        apt-get update && apt-get install -y --no-install-recommends zaproxy \
        && apt-get clean && rm -rf /var/lib/apt/lists/*; \
    fi

# Tier-3 cloud-audit tools (ScoutSuite -> `scout`, Prowler, kube-hunter) are
# large and not in Kali apt. Install them isolated via pipx into a shared
# location so the unprivileged runtime user can run them. (This is the
# heaviest part of the image; drop this block if you don't need cloud audit.)
ENV PIPX_HOME=/opt/pipx PIPX_BIN_DIR=/opt/pipx/bin
# Tier-3 cloud tools, gated behind INCLUDE_CLOUD. kube-hunter has a native
# dependency with no prebuilt arm64 wheel, so it builds from sdist and needs a
# C toolchain + Python headers at install time — installed just for this layer
# and purged in the same RUN so the runtime image stays slim (the built wheels
# don't need a compiler).
RUN if [ "$INCLUDE_CLOUD" != "false" ]; then \
        apt-get update && apt-get install -y --no-install-recommends gcc python3-dev \
        && pipx install scoutsuite \
        && pipx install prowler \
        && pipx install kube-hunter \
        && apt-get purge -y gcc python3-dev && apt-get autoremove -y \
        && apt-get clean && rm -rf /var/lib/apt/lists/*; \
    fi

# Grant nmap only the capabilities it needs (raw sockets for SYN/OS scans,
# low-port bind) instead of running the whole container as root. Two
# Kali-specific subtleties (both verified by running `nmap -sS` as the
# unprivileged user in the built image):
#   1. /usr/bin/nmap is a wrapper *script* that execs the real ELF at
#      /usr/lib/nmap/nmap — file caps must go on the real binary, not the
#      script (caps on a #!-script are silently ignored).
#   2. The Kali package ships the binary with cap_net_admin set, but Docker's
#      default capability bounding set excludes NET_ADMIN, and a binary with
#      an *effective* cap outside the bounding set fails execve with EPERM
#      (so nmap won't even start). We pin it to exactly the two caps in
#      Docker's default set; -sS/-O don't need NET_ADMIN.
# `|| true` keeps the build working on arches/filesystems where setcap is N/A.
RUN NMAP_BIN="$(readlink -f /usr/lib/nmap/nmap 2>/dev/null || command -v nmap)" \
    && setcap cap_net_raw,cap_net_bind_service+eip "$NMAP_BIN" || true

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
# certipy-ad is installed into the same venv (it exposes the `certipy` binary
# the AD CS wrapper invokes; the Kali apt package renames it to `certipy-ad`).
RUN python3 -m venv /opt/kalimcp/.venv \
    && /opt/kalimcp/.venv/bin/pip install --no-cache-dir --upgrade pip \
    && /opt/kalimcp/.venv/bin/pip install --no-cache-dir . certipy-ad

# Run as an unprivileged user. Create it, give it the app + a home for the
# engagement/loot/audit state, and drop to it for CMD.
RUN useradd --create-home --uid 1000 --shell /bin/bash kalimcp \
    && mkdir -p /home/kalimcp/.kalimcp \
    && chown -R kalimcp:kalimcp /opt/kalimcp /home/kalimcp

ENV PATH="/opt/kalimcp/.venv/bin:/opt/pipx/bin:${PATH}" \
    HOME=/home/kalimcp \
    KALIMCP_LOG_FILE=/home/kalimcp/.kalimcp/kalimcp.log

USER kalimcp

# MCP servers talk JSON-RPC over stdio. Don't try to listen on a port.
CMD ["kalimcp"]
