#!/usr/bin/env bash
set -euo pipefail

usage() {
    cat <<'EOF'
Usage:
  tproxy-netns-runner.sh [--dry-run] start TENANT CONFIG NETWORK IN_IF OUT_IF [BINARY]
  tproxy-netns-runner.sh [--dry-run] stop|status|logs|inspect TENANT

NETWORK is a trusted, root-owned file defining INPUT_CIDR, OUTPUT_CIDR and
OUTPUT_GATEWAY. IN_IF and OUT_IF must be dedicated, unconfigured interfaces.

Environment overrides:
  SMITHPROXY_MEMORY_HIGH=32M  SMITHPROXY_MEMORY_MAX=48M
  SMITHPROXY_CPU_QUOTA=25%    SMITHPROXY_TASKS_MAX=64
  SMITHPROXY_RUNTIME_MAX=4h   SMITHPROXY_USER=smithproxy
  SMITHPROXY_GROUP=smithproxy
EOF
}

DRY_RUN=0
if [[ ${1:-} == --dry-run ]]; then DRY_RUN=1; shift; fi
ACTION=${1:-}; TENANT=${2:-}
[[ -n $ACTION && -n $TENANT ]] || { usage >&2; exit 2; }
[[ $TENANT =~ ^[A-Za-z0-9][A-Za-z0-9_.-]{0,40}$ ]] || {
    echo "Invalid tenant ID: $TENANT" >&2; exit 2;
}

UNIT="smithproxy-mc-tproxy-${TENANT}.service"
NS="sx-mc-${TENANT}"
MEMORY_HIGH=${SMITHPROXY_MEMORY_HIGH:-32M}
MEMORY_MAX=${SMITHPROXY_MEMORY_MAX:-48M}
CPU_QUOTA=${SMITHPROXY_CPU_QUOTA:-25%}
TASKS_MAX=${SMITHPROXY_TASKS_MAX:-64}
RUNTIME_MAX=${SMITHPROXY_RUNTIME_MAX:-4h}
RUN_USER=${SMITHPROXY_USER:-smithproxy}
RUN_GROUP=${SMITHPROXY_GROUP:-smithproxy}

run() {
    if ((DRY_RUN)); then printf '%q ' "$@"; printf '\n'; else "$@"; fi
}

case "$ACTION" in
    start)
        CONFIG=${3:-}; NETWORK=${4:-}; IN_IF=${5:-}; OUT_IF=${6:-}
        BINARY=${7:-/usr/bin/smithproxy}
        [[ -n $CONFIG && -n $NETWORK && -n $IN_IF && -n $OUT_IF ]] || { usage >&2; exit 2; }
        CONFIG=$(readlink -f -- "$CONFIG")
        NETWORK=$(readlink -f -- "$NETWORK")
        BINARY=$(readlink -f -- "$BINARY")
        SELF=$(readlink -f -- "$0")
        [[ -f $CONFIG ]] || { echo "Config not found: $CONFIG" >&2; exit 2; }
        [[ -f $NETWORK ]] || { echo "Network config not found: $NETWORK" >&2; exit 2; }
        if ((!DRY_RUN)); then
            [[ -x $BINARY ]] || { echo "Binary is not executable: $BINARY" >&2; exit 2; }
            [[ $EUID == 0 ]] || { echo 'start must run as root' >&2; exit 1; }
            getent passwd "$RUN_USER" >/dev/null || { echo "User not found: $RUN_USER" >&2; exit 2; }
            getent group "$RUN_GROUP" >/dev/null || { echo "Group not found: $RUN_GROUP" >&2; exit 2; }
            NETWORK_OWNER=$(stat -c %u -- "$NETWORK")
            NETWORK_MODE=$(stat -c %a -- "$NETWORK")
            [[ $NETWORK_OWNER == 0 && $((8#$NETWORK_MODE & 8#022)) == 0 ]] || {
                echo 'NETWORK must be root-owned and not group/other-writable' >&2; exit 2;
            }
            for tool in ip nft setpriv; do command -v "$tool" >/dev/null || { echo "Missing command: $tool" >&2; exit 127; }; done
            [[ $IN_IF != "$OUT_IF" ]] || { echo 'IN_IF and OUT_IF must differ' >&2; exit 2; }
            for dev in "$IN_IF" "$OUT_IF"; do
                [[ $dev =~ ^[A-Za-z0-9_.-]+$ ]] || { echo "Invalid interface: $dev" >&2; exit 2; }
                ip link show dev "$dev" >/dev/null
                [[ -z $(ip -o addr show dev "$dev") ]] || { echo "Interface has addresses: $dev" >&2; exit 2; }
            done
        fi
        run systemd-run --unit="$UNIT" --collect --service-type=exec \
            --property="MemoryHigh=$MEMORY_HIGH" --property="MemoryMax=$MEMORY_MAX" \
            --property=MemorySwapMax=0 --property="CPUQuota=$CPU_QUOTA" \
            --property="TasksMax=$TASKS_MAX" --property="RuntimeMaxSec=$RUNTIME_MAX" \
            --property=TimeoutStopSec=25s --property=KillMode=mixed --property=Restart=no \
            --property=ProtectSystem=full --property=ProtectHome=read-only \
            --property=ProtectKernelModules=yes --property=ProtectControlGroups=yes \
            --property="RuntimeDirectory=smithproxy-mc-tproxy-$TENANT" \
            "$SELF" _run "$TENANT" "$CONFIG" "$NETWORK" "$IN_IF" "$OUT_IF" "$BINARY" "$RUN_USER" "$RUN_GROUP"
        ;;
    stop) run systemctl stop "$UNIT" ;;
    status) run systemctl status --no-pager "$UNIT" ;;
    logs) run journalctl --no-pager -u "$UNIT" ;;
    inspect) run systemctl show "$UNIT" \
        --property=ActiveState,SubState,MainPID,MemoryCurrent,MemoryPeak,CPUUsageNSec,TasksCurrent,RuntimeMaxUSec ;;
    _run)
        [[ $EUID == 0 ]] || { echo '_run must run as root' >&2; exit 1; }
        CONFIG=$3; NETWORK=$4; IN_IF=$5; OUT_IF=$6; BINARY=$7; RUN_USER=$8; RUN_GROUP=$9
        NETWORK_OWNER=$(stat -c %u -- "$NETWORK")
        NETWORK_MODE=$(stat -c %a -- "$NETWORK")
        [[ $NETWORK_OWNER == 0 && $((8#$NETWORK_MODE & 8#022)) == 0 ]] || {
            echo 'NETWORK trust check failed' >&2; exit 2;
        }
        # This file is administrative input and intentionally supports shell assignments.
        source "$NETWORK"
        : "${INPUT_CIDR:?Missing INPUT_CIDR}" "${OUTPUT_CIDR:?Missing OUTPUT_CIDR}" \
          "${OUTPUT_GATEWAY:?Missing OUTPUT_GATEWAY}"
        ip netns add "$NS"
        MOVED=()
        PROXY_PID=
        cleanup() {
            local rc=$?
            trap - EXIT INT TERM
            set +e
            [[ -z $PROXY_PID ]] || kill -TERM "$PROXY_PID" 2>/dev/null
            [[ -z $PROXY_PID ]] || wait "$PROXY_PID" 2>/dev/null
            ip netns exec "$NS" nft list ruleset
            for dev in "${MOVED[@]}"; do
                ip -n "$NS" addr flush dev "$dev"
                ip -n "$NS" link set "$dev" down
                ip -n "$NS" link set "$dev" netns 1
            done
            ip netns del "$NS"
            exit "$rc"
        }
        trap cleanup EXIT
        trap 'exit 130' INT
        trap 'exit 143' TERM
        for dev in "$IN_IF" "$OUT_IF"; do ip link set "$dev" netns "$NS"; MOVED+=("$dev"); done
        ip -n "$NS" link set lo up
        ip -n "$NS" addr add "$INPUT_CIDR" dev "$IN_IF"
        ip -n "$NS" addr add "$OUTPUT_CIDR" dev "$OUT_IF"
        ip -n "$NS" link set "$IN_IF" up
        ip -n "$NS" link set "$OUT_IF" up
        ip -n "$NS" route add default via "$OUTPUT_GATEWAY" dev "$OUT_IF"
        ip netns exec "$NS" sysctl -qw net.ipv4.ip_forward=1
        for dev in all default "$IN_IF" "$OUT_IF"; do
            ip netns exec "$NS" sysctl -qw "net.ipv4.conf.$dev.rp_filter=0"
        done
        ip -n "$NS" rule add pref 100 fwmark 1/1 lookup 100
        ip -n "$NS" route add local 0.0.0.0/0 dev lo table 100
        ip netns exec "$NS" nft -f - <<NFT
table ip smithproxy_mc {
    chain forward { type filter hook forward priority filter; policy drop; }
    chain prerouting {
        type filter hook prerouting priority mangle; policy accept;
        meta l4proto tcp socket transparent 1 meta mark set 1 accept
        iifname != "$IN_IF" return
        fib daddr type local return
        tcp dport 443 tproxy to :50443 meta mark set 1 accept
        udp dport 443 tproxy to :50443 meta mark set 1 accept
        meta l4proto tcp tproxy to :50080 meta mark set 1 accept
        meta l4proto udp tproxy to :50080 meta mark set 1 accept
    }
}
NFT
        RUNTIME_DIR="/run/smithproxy-mc-tproxy-$TENANT"
        install -d -o "$RUN_USER" -g "$RUN_GROUP" -m 0700 "$RUNTIME_DIR/data"
        ip netns exec "$NS" setpriv --reuid="$RUN_USER" --regid="$RUN_GROUP" --init-groups \
            env SMITHPROXY_PID_FILE="$RUNTIME_DIR/smithproxy.pid" \
            "$BINARY" --config-file "$CONFIG" &
        PROXY_PID=$!
        wait "$PROXY_PID"
        ;;
    *) usage >&2; exit 2 ;;
esac
