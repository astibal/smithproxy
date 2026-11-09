#!/usr/bin/env bash
# Invoked by CTest inside an ephemeral user + network namespace.
set -euo pipefail
ip link set lo up
root=${1:?result root required}
shift
mkdir -p "$root"
run=$(mktemp -d "$root/run-XXXXXX")
exec "$@" --output "$run/results"
