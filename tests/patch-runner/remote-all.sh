#!/usr/bin/env bash
set -euo pipefail

[[ $# -ge 8 ]] || { echo "usage: $0 TARGET ROOT WORK_DIR COMMIT BRANCH DIRTY PROFILE [ARGS...]" >&2; exit 2; }
TARGET=$1 ROOT=$2 WORK_DIR=$3 COMMIT=$4 BRANCH=$5 DIRTY=$6 PROFILE=$7
shift 7
ORIGINAL_ARGS=("$@")
REMOTE_SOURCE=$WORK_DIR/remote-source
REMOTE_RUN=$WORK_DIR/remote-run
LOCAL_RESULTS=$WORK_DIR/results
SSH_OPTIONS=(-o BatchMode=yes -o ConnectTimeout=10 -o ServerAliveInterval=10 -o ServerAliveCountMax=3)

remote_args=("$PROFILE")
for ((i=1; i<${#ORIGINAL_ARGS[@]}; i++)); do
    argument=${ORIGINAL_ARGS[$i]}
    case "$argument" in
        --remote) ((i += 1)) ;;
        --local) ;;
        --dir) ((i += 1)) ;;
        --build-dir|--shared-binary|--proxy-nightmare-root)
            echo "$argument names a coordinator-local path and cannot be used with remote-all execution" >&2
            exit 2
            ;;
        *) remote_args+=("$argument") ;;
    esac
done
remote_args+=(--local --dir "$REMOTE_RUN")

cleanup_remote() {
    ssh "${SSH_OPTIONS[@]}" "$TARGET" \
        "pkill -TERM -f '$REMOTE_RUN/' >/dev/null 2>&1 || true" >/dev/null 2>&1 || true
}
trap 'cleanup_remote; exit 130' INT TERM HUP

echo "REMOTE-ALL stage source target=$TARGET"
ssh "${SSH_OPTIONS[@]}" "$TARGET" "mkdir -p '$REMOTE_SOURCE' '$REMOTE_RUN'"
tar -C "$ROOT" --anchored --exclude='./.git' --exclude='./build' \
    --exclude='./build-*' --exclude='./cmake-build-*' --exclude='./Testing' -cf - . | \
    ssh "${SSH_OPTIONS[@]}" "$TARGET" "tar -C '$REMOTE_SOURCE' -xf -"

for runtime in curl-http3 quic-python; do
    local_runtime=$ROOT/../$runtime
    [[ ! -d $local_runtime ]] || {
        echo "REMOTE-ALL stage runtime=$runtime"
        ssh "${SSH_OPTIONS[@]}" "$TARGET" "mkdir -p '$WORK_DIR/$runtime'"
        tar -C "$local_runtime" -cf - . | \
            ssh "${SSH_OPTIONS[@]}" "$TARGET" "tar -C '$WORK_DIR/$runtime' -xf -"
    }
done

printf -v remote_command 'cd %q && env PATCH_TEST_REMOTE_COORDINATOR=1 PATCH_TEST_ROOT_OVERRIDE=%q PATCH_TEST_COMMIT_OVERRIDE=%q PATCH_TEST_BRANCH_OVERRIDE=%q PATCH_TEST_DIRTY_OVERRIDE=%q PATCH_TEST_REPORT_HOST=%q PATCH_TEST_RECORD_HISTORY=0' \
    "$REMOTE_SOURCE" "$REMOTE_SOURCE" "$COMMIT" "$BRANCH" "$DIRTY" "$TARGET"
[[ -z ${CXXFLAGS:-} ]] || printf -v remote_command '%s CXXFLAGS=%q' "$remote_command" "$CXXFLAGS"
printf -v quoted_args ' %q' "${remote_args[@]}"
remote_command+=" ./tests/patch-runner/test-patch.sh$quoted_args"

echo "REMOTE-ALL execute target=$TARGET work=$REMOTE_RUN"
set +e
ssh "${SSH_OPTIONS[@]}" "$TARGET" "$remote_command"
rc=$?
set -e

mkdir -p "$LOCAL_RESULTS"
scp "${SSH_OPTIONS[@]}" -r "$TARGET:$REMOTE_RUN/results/." "$LOCAL_RESULTS/" >/dev/null 2>&1 || {
    echo "remote run exited rc=$rc and its report could not be retrieved" >&2
    exit "$rc"
}
report=$(find "$LOCAL_RESULTS" -mindepth 1 -maxdepth 1 -type d -print | sort | tail -1)
echo "REMOTE-ALL report retrieved: $report"
[[ ! -f $report/summary.txt ]] || cat "$report/summary.txt"
exit "$rc"
