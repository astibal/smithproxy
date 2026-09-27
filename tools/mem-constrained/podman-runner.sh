#!/usr/bin/env bash
set -euo pipefail

usage() {
    cat <<'EOF'
Usage:
  podman-runner.sh [--dry-run] start TENANT CONFIG_DIR HOST_PORT [IMAGE]
  podman-runner.sh [--dry-run] stop|status|logs|inspect TENANT

CONFIG_DIR must contain smithproxy.cfg and any referenced certificates. Paths
inside that config should use /config and /var/smithproxy/data.

Environment overrides:
  SMITHPROXY_MEMORY_RESERVATION=32m  SMITHPROXY_MEMORY_MAX=48m
  SMITHPROXY_CPUS=0.25               SMITHPROXY_PIDS_LIMIT=64
  SMITHPROXY_RUNTIME_SECONDS=14400   SMITHPROXY_CONTAINER_USER=65532:65532
EOF
}

DRY_RUN=0
if [[ ${1:-} == --dry-run ]]; then DRY_RUN=1; shift; fi
ACTION=${1:-}; TENANT=${2:-}
[[ -n $ACTION && -n $TENANT ]] || { usage >&2; exit 2; }
[[ $TENANT =~ ^[A-Za-z0-9][A-Za-z0-9_.-]{0,62}$ ]] || {
    echo "Invalid tenant ID: $TENANT" >&2; exit 2;
}

NAME="smithproxy-mc-$TENANT"
MEMORY_RESERVATION=${SMITHPROXY_MEMORY_RESERVATION:-32m}
MEMORY_MAX=${SMITHPROXY_MEMORY_MAX:-48m}
CPUS=${SMITHPROXY_CPUS:-0.25}
PIDS_LIMIT=${SMITHPROXY_PIDS_LIMIT:-64}
RUNTIME_SECONDS=${SMITHPROXY_RUNTIME_SECONDS:-14400}
CONTAINER_USER=${SMITHPROXY_CONTAINER_USER:-65532:65532}

run() {
    if ((DRY_RUN)); then printf '%q ' "$@"; printf '\n'; else "$@"; fi
}

if ((!DRY_RUN)); then command -v podman >/dev/null || { echo 'podman not found' >&2; exit 127; }; fi

case "$ACTION" in
    start)
        CONFIG_DIR=${3:-}; HOST_PORT=${4:-}; IMAGE=${5:-localhost/smithproxy:mem-constrained}
        [[ -n $CONFIG_DIR && -n $HOST_PORT ]] || { usage >&2; exit 2; }
        [[ $HOST_PORT =~ ^[0-9]+$ && $HOST_PORT -ge 1024 && $HOST_PORT -le 65535 ]] || {
            echo "Invalid host port: $HOST_PORT" >&2; exit 2;
        }
        CONFIG_DIR=$(readlink -f -- "$CONFIG_DIR")
        [[ -f $CONFIG_DIR/smithproxy.cfg ]] || {
            echo "Missing $CONFIG_DIR/smithproxy.cfg" >&2; exit 2;
        }
        run podman run --detach --rm --name "$NAME" \
            --label "org.smithproxy.tenant=$TENANT" \
            --memory "$MEMORY_MAX" --memory-reservation "$MEMORY_RESERVATION" \
            --memory-swap "$MEMORY_MAX" --cpus "$CPUS" --pids-limit "$PIDS_LIMIT" \
            --timeout "$RUNTIME_SECONDS" --stop-timeout 20 --restart=no \
            --read-only --tmpfs /tmp:rw,noexec,nosuid,nodev,size=8m,mode=1777 \
            --tmpfs /run:rw,noexec,nosuid,nodev,size=4m,mode=1777 \
            --tmpfs /var/smithproxy:rw,noexec,nosuid,nodev,size=16m,mode=1777 \
            --tmpfs /var/log/smithproxy:rw,noexec,nosuid,nodev,size=8m,mode=1777 \
            --cap-drop=ALL --security-opt=no-new-privileges \
            --user "$CONTAINER_USER" --network bridge \
            --publish "127.0.0.1:$HOST_PORT:1080/tcp" \
            --volume "$CONFIG_DIR:/config:ro" \
            --env SMITHPROXY_PID_FILE=/tmp/smithproxy.pid \
            --entrypoint /usr/bin/smithproxy "$IMAGE" \
            --config-file /config/smithproxy.cfg
        ;;
    stop) run podman stop --time 20 "$NAME" ;;
    status) run podman ps --all --filter "name=^${NAME}$" ;;
    logs) run podman logs "$NAME" ;;
    inspect) run podman inspect "$NAME" ;;
    *) usage >&2; exit 2 ;;
esac
