#!/usr/bin/env bash
set -euo pipefail

usage() {
    echo "usage: $0 privileged|rootless" >&2
    exit 2
}

MODE=${1:-}
[[ $MODE == privileged || $MODE == rootless ]] || usage

missing=()
for command in bash ip nft mount umount unshare mktemp; do
    command -v "$command" >/dev/null 2>&1 || missing+=("$command")
done
((${#missing[@]} == 0)) || {
    printf 'preflight: missing command(s): %s\n' "${missing[*]}" >&2
    exit 2
}

probe_body='set -euo pipefail
mount -t tmpfs -o mode=755 tmpfs /run/netns
ip link set lo up
name=spf$$
cleanup() { ip netns del "$name" >/dev/null 2>&1 || true; }
trap cleanup EXIT
ip netns add "$name"
ip netns exec "$name" ip link set lo up
ip netns exec "$name" nft list ruleset >/dev/null
ip netns del "$name"
trap - EXIT'

case "$MODE" in
    privileged)
        ((EUID == 0)) || {
            echo 'preflight: privileged probe must run as root (use root or sudo -n)' >&2
            exit 1
        }
        # Match the capabilities used by the lab: a private mount namespace,
        # a private /run/netns registry, nested network namespaces and nft.
        if ! output=$(unshare --mount --propagation private --net \
                bash -c "$probe_body" 2>&1); then
            echo 'preflight: privileged namespace probe failed' >&2
            echo 'preflight: run outside a restricted sandbox or select a prepared --remote target' >&2
            echo "$output" >&2
            exit 1
        fi
        ;;
    rootless)
        # Match the lifecycle wrapper exactly. This catches disabled user
        # namespaces, missing capability retention and mount/net EPERM early.
        if ! output=$(unshare --user --map-root-user --keep-caps --mount \
                --propagation private --net bash -c "$probe_body" 2>&1); then
            echo 'preflight: rootless namespace probe failed' >&2
            echo 'preflight: run outside a restricted sandbox or select a prepared --remote target' >&2
            echo "$output" >&2
            exit 1
        fi
        ;;
esac

echo "preflight: $MODE namespace/mount/netfilter probe PASS"
