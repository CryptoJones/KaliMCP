#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Aaron K. Clark
#
# Local verification helper for the KaliMCP container surface.
#
#   1. Preflight: can this shell talk to the Docker daemon?
#   2. Lint the Dockerfile with hadolint (honouring ./.hadolint.yaml).
#   3. Optionally build the full image (heavy — opt in).
#
# Run it from the repo root:
#
#   ./scripts/verify_docker.sh         # preflight + hadolint
#   ./scripts/verify_docker.sh --build # also do the full docker build
#
# This script never changes your system. If Docker access is missing it
# prints the command to fix it and exits — it does not run anything
# privileged for you.

set -euo pipefail

# Resolve repo root from this script's location so it works from anywhere.
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
cd "${REPO_ROOT}"

DO_BUILD=0
if [[ "${1:-}" == "--build" ]]; then
    DO_BUILD=1
fi

# ---------- 1. Docker preflight ----------

if ! command -v docker >/dev/null 2>&1; then
    echo "error: docker is not installed or not on PATH." >&2
    exit 1
fi

if ! docker version >/dev/null 2>&1; then
    cat >&2 <<EOF
error: this shell can't reach the Docker daemon.

You are probably not in the 'docker' group. To fix it (one-time):

    sudo usermod -aG docker "\$USER"

Then fully log out and back in (or restart your terminal) so the new
group takes effect, and re-run this script. Note: docker-group
membership is effectively root-equivalent on this host.

Alternatively, run this script's steps under sudo:

    sudo ./scripts/verify_docker.sh
EOF
    exit 1
fi

echo "==> Docker reachable: $(docker version --format '{{.Server.Version}}' 2>/dev/null || echo '?')"

# ---------- 2. hadolint the Dockerfile ----------

echo "==> Linting Dockerfile (config: .hadolint.yaml)"
if command -v hadolint >/dev/null 2>&1; then
    # Local binary picks up ./.hadolint.yaml from the working dir.
    hadolint Dockerfile
else
    # Mount the repo so hadolint can read ./.hadolint.yaml. (Piping the
    # Dockerfile on stdin would skip the config file and the ignores.)
    docker run --rm -v "${REPO_ROOT}:/repo:ro" -w /repo \
        hadolint/hadolint hadolint Dockerfile
fi
echo "==> hadolint: clean"

# ---------- 3. Optional full image build ----------

if [[ "${DO_BUILD}" -eq 1 ]]; then
    echo "==> Building image 'kalimcp' (this pulls Kali + the tool set; multi-GB, several minutes)"
    docker build -t kalimcp .
    echo "==> Build OK. Smoke-check the install (non-blocking; the real"
    echo "    entrypoint is a stdio server, so we just confirm it imports):"
    docker run --rm kalimcp python -c "import kalimcp; print('kalimcp import OK')"
else
    echo "==> Skipping full image build. Re-run with --build to include it."
fi

echo "==> Done."
