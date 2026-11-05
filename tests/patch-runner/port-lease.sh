#!/usr/bin/env bash
# Cross-process host-port leases for parallel patch-runner labs. Source this
# file, initialize once, then keep the returned FDs open for the lab lifetime.

patch_runner_port_leases_init() {
    PATCH_RUNNER_PORT_LOCK_ROOT=${PATCH_TEST_PORT_LOCK_ROOT:-/var/tmp/smithproxy-patch-runner-port-locks}
    PATCH_RUNNER_PORT_MIN=${PATCH_TEST_PORT_MIN:-20000}
    PATCH_RUNNER_PORT_MAX=${PATCH_TEST_PORT_MAX:-29999}
    [[ $PATCH_RUNNER_PORT_MIN =~ ^[0-9]+$ && $PATCH_RUNNER_PORT_MAX =~ ^[0-9]+$ \
        && $PATCH_RUNNER_PORT_MIN -ge 1024 && $PATCH_RUNNER_PORT_MAX -le 65535 \
        && $PATCH_RUNNER_PORT_MIN -le $PATCH_RUNNER_PORT_MAX ]] || {
        echo 'Invalid patch-runner port lease range' >&2
        return 2
    }
    mkdir -p "$PATCH_RUNNER_PORT_LOCK_ROOT"
    chmod 1777 "$PATCH_RUNNER_PORT_LOCK_ROOT"
    PATCH_RUNNER_PORT_LOCK_FDS=()
}

patch_runner_lease_port() {
    local output_name=$1 offset=${2:-0} range candidate lock fd attempt start bind_rc
    range=$((PATCH_RUNNER_PORT_MAX - PATCH_RUNNER_PORT_MIN + 1))
    start=$((PATCH_RUNNER_PORT_MIN + (($$ * 1103515245 + offset * 7919) % range)))
    for ((attempt=0; attempt<range; ++attempt)); do
        candidate=$((PATCH_RUNNER_PORT_MIN + (start - PATCH_RUNNER_PORT_MIN + attempt) % range))
        lock=$PATCH_RUNNER_PORT_LOCK_ROOT/$candidate.lock
        (umask 000; : >> "$lock") 2>/dev/null || continue
        chmod a+rw "$lock" 2>/dev/null || true
        exec {fd}<>"$lock" || continue
        if flock -n "$fd"; then
            set +e
            python3 -c 'import errno,socket,sys
try:
    s=socket.socket(); s.bind(("127.0.0.1",int(sys.argv[1])))
except OSError as error:
    sys.exit(1 if error.errno == errno.EADDRINUSE else 2)' "$candidate" 2>/dev/null
            bind_rc=$?
            set -e
            if ((bind_rc == 0)); then
                printf -v "$output_name" '%s' "$candidate"
                PATCH_RUNNER_PORT_LOCK_FDS+=("$fd")
                return 0
            elif ((bind_rc == 2)); then
                eval "exec $fd>&-"
                echo "Cannot probe runner ports: loopback socket creation is not permitted" >&2
                return 2
            fi
        fi
        eval "exec $fd>&-"
    done
    echo "Cannot lease a free runner port in $PATCH_RUNNER_PORT_MIN..$PATCH_RUNNER_PORT_MAX" >&2
    return 1
}
