#!/usr/bin/env bash
set -euo pipefail

usage() {
    cat <<'EOF'
Usage: tests/paranoid/run.sh [OPTIONS]

Build and repeatedly exercise the privilege-separation and communication
boundaries with sanitizers, randomized test order and strict runtime checks.

Options:
  --profile smoke|soak   Smoke is suitable for CI; soak is intentionally long.
  --seed N               Reproducible GoogleTest random seed (default: random).
  --build-root DIR       Build directories (default: ./test-runs/paranoid/build).
  --report-dir DIR       Logs and metadata (default: ./test-runs/paranoid/report).
  --jobs N               Build jobs (default: nproc).
  --skip-build           Reuse already configured build directories.
EOF
}

ROOT=$(cd "$(dirname "$0")/../.." && pwd)
PROFILE=smoke
SEED=
BUILD_ROOT="$ROOT/test-runs/paranoid/build"
REPORT_DIR="$ROOT/test-runs/paranoid/report"
JOBS=$(nproc)
SKIP_BUILD=0

while (($#)); do
    case "$1" in
        --profile) PROFILE=${2:?missing profile}; shift 2 ;;
        --seed) SEED=${2:?missing seed}; shift 2 ;;
        --build-root) BUILD_ROOT=${2:?missing build root}; shift 2 ;;
        --report-dir) REPORT_DIR=${2:?missing report directory}; shift 2 ;;
        --jobs) JOBS=${2:?missing jobs}; shift 2 ;;
        --skip-build) SKIP_BUILD=1; shift ;;
        -h|--help) usage; exit 0 ;;
        *) echo "Unknown option: $1" >&2; usage >&2; exit 2 ;;
    esac
done

[[ $PROFILE == smoke || $PROFILE == soak ]] || {
    echo "Invalid profile: $PROFILE" >&2
    exit 2
}
[[ $JOBS =~ ^[1-9][0-9]*$ ]] || { echo 'jobs must be positive' >&2; exit 2; }
if [[ -z $SEED ]]; then
    # GoogleTest accepts seeds in the inclusive range 1..99999.
    SEED=$(( (10#$(date -u +%H%M%S) + $$) % 99999 + 1 ))
fi
[[ $SEED =~ ^[1-9][0-9]*$ ]] && ((SEED <= 99999)) || {
    echo 'seed must be between 1 and 99999' >&2
    exit 2
}

mkdir -p "$BUILD_ROOT" "$REPORT_DIR"
BUILD_ROOT=$(cd "$BUILD_ROOT" && pwd)
REPORT_DIR=$(cd "$REPORT_DIR" && pwd)
[[ $BUILD_ROOT != / && $REPORT_DIR != / ]] || { echo 'refusing root directory' >&2; exit 2; }

targets=(
    sx_gtests_privsep
    sx_gtests_file_privsep
    sx_gtests_gre_broker
    sx_gtests_cli_broker
    sx_gtests_api_broker
)

configure_build() {
    local name=$1 flags=$2
    local directory="$BUILD_ROOT/$name"
    if ((SKIP_BUILD)); then
        [[ -x $directory/sx_gtests_privsep ]] || {
            echo "Missing reusable paranoid build: $directory" >&2
            exit 2
        }
        return
    fi
    cmake -S "$ROOT" -B "$directory" \
        -DCMAKE_BUILD_TYPE=Debug -DBUILD_TESTING=ON \
        -DCMAKE_POLICY_VERSION_MINIMUM=3.5 \
        -DCMAKE_C_FLAGS="$flags" -DCMAKE_CXX_FLAGS="$flags" \
        -DCMAKE_EXE_LINKER_FLAGS="$flags" \
        >"$REPORT_DIR/configure-$name.log" 2>&1
    cmake --build "$directory" -j"$JOBS" --target "${targets[@]}" \
        >"$REPORT_DIR/build-$name.log" 2>&1
}

case "$PROFILE" in
    smoke) normal_repeat=5; sanitizer_repeat=2; target_timeout=90 ;;
    soak) normal_repeat=100; sanitizer_repeat=25; target_timeout=600 ;;
esac

common_flags='-fno-omit-frame-pointer -fno-common -D_GLIBCXX_ASSERTIONS'
configure_build normal "$common_flags"
configure_build asan "$common_flags -fsanitize=address,undefined"
configure_build tsan "$common_flags -fsanitize=thread"

run_suite() {
    local variant=$1 repeat=$2
    local directory="$BUILD_ROOT/$variant"
    local log="$REPORT_DIR/$variant.log"
    local filter
    : >"$log"
    for target in "${targets[@]}"; do
        filter='*'
        if [[ $variant == tsan && $target == sx_gtests_gre_broker ]]; then
            echo "[$variant] SKIP $target: tests fork brokers after TSan initialization" \
                | tee -a "$log"
            continue
        fi
        if [[ $variant == tsan && $target == sx_gtests_privsep ]]; then
            filter='-PrivilegedSocketTest.ForkedStandaloneHelperServesFacadeAndStopsCleanly:PrivilegedSocketTest.StopAcceptsHelperAutoReapedByDaemonSigchldPolicy'
        fi
        echo "[$variant] $target repeat=$repeat seed=$SEED" | tee -a "$log"
        timeout --foreground "${target_timeout}s" env \
            ASAN_OPTIONS='abort_on_error=1:check_initialization_order=1:detect_leaks=1:strict_string_checks=1' \
            UBSAN_OPTIONS='halt_on_error=1:print_stacktrace=1' \
            TSAN_OPTIONS='halt_on_error=1:second_deadlock_stack=1' \
            "$directory/$target" \
                --gtest_shuffle --gtest_random_seed="$SEED" \
                --gtest_repeat="$repeat" --gtest_break_on_failure \
                --gtest_filter="$filter" \
                2>&1 | tee -a "$log"
    done
}

cat >"$REPORT_DIR/metadata.txt" <<EOF
profile=$PROFILE
seed=$SEED
commit=$(git -C "$ROOT" rev-parse HEAD)
socle_commit=$(git -C "$ROOT/socle" rev-parse HEAD)
compiler=$(${CXX:-c++} --version | head -1)
kernel=$(uname -srmo)
tsan_exclusions=fork-based_GRE_and_local-helper_process-lifecycle_tests
utc_started=$(date -u +%Y-%m-%dT%H:%M:%SZ)
EOF

run_suite normal "$normal_repeat"
run_suite asan "$sanitizer_repeat"
run_suite tsan "$sanitizer_repeat"

date -u +utc_finished=%Y-%m-%dT%H:%M:%SZ >>"$REPORT_DIR/metadata.txt"
printf 'PASS: paranoid %s profile (seed %s)\nReport: %s\n' \
    "$PROFILE" "$SEED" "$REPORT_DIR"
