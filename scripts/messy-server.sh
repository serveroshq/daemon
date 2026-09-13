#!/usr/bin/env bash
# Build serverosd for Linux inside Docker, then run its discovery scan on
# the messy-server fixture and check the report. Proves the importer on a
# real (if containerised) Linux userland, not just that the crate compiles.
#
# Limits worth knowing: there is no systemd inside the container, so unit
# discovery is exercised only as the "systemd not reachable" path, and
# the docker socket is absent. Both need a VM; see tests/fixtures/README.
set -euo pipefail

cd "$(dirname "$0")/.."

echo "== building serverosd for linux (cached in target-linux/)"
docker run --rm \
    -v "$PWD":/src \
    -v "$HOME/.cargo/registry":/usr/local/cargo/registry \
    -w /src -e CARGO_TARGET_DIR=/src/target-linux \
    rust:1-bookworm cargo build -q -p serverosd

echo "== building the messy-server image"
docker build -q -t serveros-messy-server tests/fixtures/messy-server >/dev/null

echo "== running"
# SYS_PTRACE: a real host's root can read /proc/<pid>/fd for every user;
# Docker drops that capability by default, which would hide postgres.
docker run --rm --cap-add SYS_PTRACE \
    -v "$PWD/target-linux/debug/serverosd":/opt/serverosd:ro \
    serveros-messy-server
