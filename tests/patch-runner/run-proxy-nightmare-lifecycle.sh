#!/usr/bin/env bash
set -euo pipefail

[[ $# -ge 2 ]] || { echo "usage: $0 OUTPUT_ROOT COMMAND..." >&2; exit 2; }
OUTPUT_ROOT=$1
shift
mkdir -p "$OUTPUT_ROOT"
RUN=$(mktemp -d "$OUTPUT_ROOT/run-XXXXXX")
ip link set lo up
# The caller supplies a private mount namespace.  A private tmpfs prevents
# `ip netns` from publishing handles in the host's /run/netns directory.
mount -t tmpfs -o mode=755 tmpfs /run/netns
exec "$@" --output "$RUN/results"
