#!/usr/bin/env bash
set -euo pipefail

usage() {
    cat <<'EOF'
Usage:
  systemd-runner.sh [--dry-run] start TENANT CONFIG [BINARY]
  systemd-runner.sh [--dry-run] stop|status|logs|inspect TENANT

Environment overrides:
  SMITHPROXY_MEMORY_HIGH=40M  SMITHPROXY_MEMORY_MAX=48M
  SMITHPROXY_CPU_QUOTA=25%    SMITHPROXY_TASKS_MAX=64
  SMITHPROXY_RUNTIME_MAX=4h   SMITHPROXY_USER=smithproxy
  SMITHPROXY_GROUP=smithproxy
EOF
}

DRY_RUN=0
if [[ ${1:-} == --dry-run ]]; then DRY_RUN=1; shift; fi
ACTION=${1:-}; TENANT=${2:-}
[[ -n $ACTION && -n $TENANT ]] || { usage >&2; exit 2; }
[[ $TENANT =~ ^[A-Za-z0-9][A-Za-z0-9_.-]{0,62}$ ]] || {
    echo "Invalid tenant ID: $TENANT" >&2; exit 2;
}

UNIT="smithproxy-mc-${TENANT}.service"
MEMORY_HIGH=${SMITHPROXY_MEMORY_HIGH:-40M}
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
        CONFIG=${3:-}
        BINARY=${4:-/usr/bin/smithproxy}
        [[ -n $CONFIG ]] || { usage >&2; exit 2; }
        CONFIG=$(readlink -f -- "$CONFIG")
        BINARY=$(readlink -f -- "$BINARY")
        [[ -f $CONFIG ]] || { echo "Config not found: $CONFIG" >&2; exit 2; }
        if ((!DRY_RUN)); then
            [[ -x $BINARY ]] || { echo "Binary is not executable: $BINARY" >&2; exit 2; }
            getent passwd "$RUN_USER" >/dev/null || { echo "User not found: $RUN_USER" >&2; exit 2; }
            getent group "$RUN_GROUP" >/dev/null || { echo "Group not found: $RUN_GROUP" >&2; exit 2; }
        fi
        run systemd-run \
            --unit="$UNIT" --collect --service-type=exec \
            --property="User=$RUN_USER" --property="Group=$RUN_GROUP" \
            --property="MemoryHigh=$MEMORY_HIGH" --property="MemoryMax=$MEMORY_MAX" \
            --property=MemorySwapMax=0 --property="CPUQuota=$CPU_QUOTA" \
            --property="TasksMax=$TASKS_MAX" --property="RuntimeMaxSec=$RUNTIME_MAX" \
            --property=TimeoutStopSec=20s --property=KillMode=control-group \
            --property=Restart=no --property=NoNewPrivileges=yes \
            --property=PrivateTmp=yes --property=PrivateDevices=yes \
            --property=ProtectSystem=full --property=ProtectHome=read-only \
            --property=ProtectKernelTunables=yes --property=ProtectKernelModules=yes \
            --property=ProtectControlGroups=yes \
            --property='RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6' \
            --property="RuntimeDirectory=smithproxy-mc-$TENANT" \
            --setenv="SMITHPROXY_PID_FILE=/run/smithproxy-mc-$TENANT/smithproxy.pid" \
            "$BINARY" --config-file "$CONFIG"
        ;;
    stop) run systemctl stop "$UNIT" ;;
    status) run systemctl status --no-pager "$UNIT" ;;
    logs) run journalctl --no-pager -u "$UNIT" ;;
    inspect) run systemctl show "$UNIT" \
        --property=ActiveState,SubState,MainPID,MemoryCurrent,MemoryPeak,CPUUsageNSec,TasksCurrent,RuntimeMaxUSec ;;
    *) usage >&2; exit 2 ;;
esac
