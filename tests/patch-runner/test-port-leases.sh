#!/usr/bin/env bash
set -euo pipefail
HERE=$(cd "$(dirname "$0")" && pwd)
TMP=$(mktemp -d)
pids=()
cleanup() {
    trap - EXIT INT TERM
    ((${#pids[@]} == 0)) || kill "${pids[@]}" 2>/dev/null || true
    ((${#pids[@]} == 0)) || wait "${pids[@]}" 2>/dev/null || true
    rm -rf "$TMP"
}
trap cleanup EXIT
trap 'cleanup; exit 130' INT TERM

worker() {
    local slot=$1 first second
    PATCH_TEST_PORT_LOCK_ROOT=$TMP/locks
    PATCH_TEST_PORT_MIN=24000
    PATCH_TEST_PORT_MAX=24127
    # shellcheck source=port-lease.sh
    source "$HERE/port-lease.sh"
    patch_runner_port_leases_init
    patch_runner_lease_port first "$((slot * 2))"
    patch_runner_lease_port second "$((slot * 2 + 1))"
    printf '%s\n%s\n' "$first" "$second" > "$TMP/$slot.ports"
    : > "$TMP/$slot.ready"
    for _ in $(seq 1 200); do
        [[ $(find "$TMP" -name '*.ready' -type f | wc -l) -ge 6 ]] && return 0
        sleep 0.01
    done
    return 1
}

for slot in $(seq 1 6); do worker "$slot" & pids+=("$!"); done
for pid in "${pids[@]}"; do wait "$pid"; done
[[ $(cat "$TMP"/*.ports | sort -u | wc -l) == 12 ]]

echo 'PASS: six parallel labs held twelve distinct host-port leases'
