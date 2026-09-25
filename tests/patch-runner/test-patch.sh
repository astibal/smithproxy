#!/usr/bin/env bash
set -euo pipefail

HERE=$(cd "$(dirname "$0")" && pwd)
ORIGINAL_ARGS=("$@")

usage() {
    cat <<'EOF'
Smithproxy patch runner

Usage:
  test-patch.sh PROFILE [OPTIONS]
  test-patch.sh --run [OPTIONS]
  test-patch.sh --help

Profiles:
  quick       Build the production smithproxy target only. No lab is started.
  sanity      Build and run the standard isolated traffic validation.
              Runs IPv4 and IPv6 TLS, policy, RTT, HTTP/1, HTTP/2, UDP and
              PCAP/GRE validation, plus management and cleanup checks.
  full        Build once, run a smoke gate, then isolated parallel sections for
              TLS/policy/CLI, RTT, churn, capture/HTTP2 and all corpus categories.
  benchmark   Measure TCP, UDP and TLS latency without PASS/FAIL latency gates.
              Prints IPv4/IPv6 absolute and native-delta tables and keeps JSON.
  --run       Start an interactive isolated lab and keep Smithproxy in the
              foreground until Ctrl-C. Prints host-side CLI and API access.
              With --remote, both ports bind to the remote host's loopback.

Options:
  --suite NAME       Run only one suite. Besides tls, policy, rtt and session-list,
                     full-run sections are available: smoke, tls-policy, tcp-churn,
                     udp-churn, capture, corpus-regular, corpus-edge, corpus-insanity.
                     Use with the sanity or full profile.
  --remote HOST      Run the isolated lab over SSH on [USER@]HOST. A root@
                     target runs directly; other users are invoked via sudo.
                     Without this option the lab runs on the current computer.
  --env NAME=VALUE   Pass an environment variable to the test lab. Repeatable;
                     supplied values override profile defaults.
  --dir DIR          Work root for build, retained labs and results.
                     Default: /tmp/patch-runner/<branch>_@_<commit>/
  --unique[=TAG]     Give this invocation a collision-safe work root. TAG defaults
                     to `date -I`; collisions get -2, -3, ... suffixes.
  --parallel N       Maximum concurrent post-smoke full sections. Default: 3.
  --build-dir DIR    Use this CMake build directory instead of DIR/build.
  --shared-binary PATH
                     Reuse an executable already present on the lab host.
  --jobs N           Parallel build jobs. Default: nproc.
  --churn-port-range MIN:MAX
                     Client source-port range for TCP/UDP churn (default: 20000:29999).
  --skip-build       Use an existing executable BUILD_DIR/smithproxy.
  --quiet            Print only verdict lines. Complete output remains in logs.
  -h, --help         Show this help and exit.

Common environment variables:
  PATCH_TEST_DIR                 Default work root (overridden by --dir).
  PATCH_TEST_BUILD_DIR           Default build directory.
  PATCH_TEST_RESULTS_DIR         Store reports under this directory.
  PATCH_TEST_JOBS                Default build parallelism.
  PATCH_TEST_PARALLEL            Default full-section concurrency (default: 3).
  MATCH                           Comma-separated corpus case-name globs
                                  to include (default: *).
  EXCLUDE                         Comma-separated corpus case-name globs to skip.
  RTT_SAMPLES                    Measured TCP/UDP samples (default: 200).
  RTT_HANDSHAKE_SAMPLES          Fresh TCP/TLS connections (default: 40).
  RTT_WARMUP                     Unreported warm-up exchanges (default: 20).
  RTT_TLS_TOTAL_P50_LIMIT_MS     Sanity/full TLS total-connect P50 gate (default: 7).
  RTT_HTTPS_P50_LIMIT_MS         Sanity/full HTTPS RTT P50 gate (default: 2).
  RTT_P95_LIMIT_MS               General RTT P95 gate (default: 50).
  RTT_MAX_LIMIT_MS               General RTT maximum gate (default: 250).
  RTT_HANDSHAKE_P95_LIMIT_MS     Handshake P95 gate (default: 500).
  RTT_HANDSHAKE_MAX_LIMIT_MS     Handshake maximum gate (default: 2000).
  CHURN_MIN_PORT                 TCP/UDP churn source-port minimum (default: 20000).
  CHURN_MAX_PORT                 TCP/UDP churn source-port maximum (default: 29999).

Examples:
  test-patch.sh quick
  test-patch.sh sanity --remote root@tt-bs1
  test-patch.sh sanity --suite policy --remote root@tt-bs1
  test-patch.sh sanity --quiet --remote root@tt-bs1
  test-patch.sh sanity --remote root@tt-bs1 --env RTT_SAMPLES=500
  test-patch.sh full --remote root@tt-bs1 --env MATCH='h2_generated_*' \
      --env EXCLUDE='h2_generated_003,h2_generated_017'
  test-patch.sh full --remote root@tt-bs1 --jobs 8
  test-patch.sh full --remote root@tt-bs1 --unique=udp-flaky-results
  test-patch.sh full --remote root@tt-bs1 --unique --parallel 3
  test-patch.sh full --remote root@tt-bs1 --churn-port-range 20000:29999
  test-patch.sh benchmark --remote root@tt-bs1
  test-patch.sh --run --remote root@tt-bs1
  test-patch.sh sanity --build-dir /tmp/smithproxy-build --skip-build

Reports:
  Every run records the commit, dirty-tree state, logs and lab artifacts under
  <report-root>/<UTC timestamp>-<commit>-<profile>[-<suite>]/, where report-root
  defaults to <work-root>/results and PATCH_TEST_RESULTS_DIR overrides it.
  Remote lab directories are retained for inspection until explicitly removed.
EOF
}

if [[ ${1:-} == -h || ${1:-} == --help ]]; then
    usage
    exit 0
fi

ROOT=$(git -C "$HERE" rev-parse --show-toplevel)
PROFILE=${1:-}
[[ $PROFILE == --run ]] && PROFILE=run
[[ $PROFILE == quick || $PROFILE == sanity || $PROFILE == full || $PROFILE == benchmark || $PROFILE == run ]] || {
    usage >&2
    exit 2
}
shift
ONLY_SUITE=
SKIP_BUILD=0
QUIET=0
UNIQUE_LABEL=
EXTRA_ENV=()
CHURN_PORT_RANGE=

REMOTE=
SHARED_BINARY=
WORK_DIR=${PATCH_TEST_DIR:-}
JOBS=${PATCH_TEST_JOBS:-$(nproc)}
PARALLEL=${PATCH_TEST_PARALLEL:-3}
while (($#)); do
    case "$1" in
        --remote) REMOTE=${2:?missing remote host}; shift 2 ;;
        --dir) WORK_DIR=${2:?missing work directory}; shift 2 ;;
        --build-dir) BUILD_DIR=${2:?missing build directory}; shift 2 ;;
        --shared-binary) SHARED_BINARY=${2:?missing shared binary}; shift 2 ;;
        --jobs) JOBS=${2:?missing job count}; shift 2 ;;
        --parallel) PARALLEL=${2:?missing parallelism}; shift 2 ;;
        --suite) ONLY_SUITE=${2:?missing suite}; shift 2 ;;
        --unique) UNIQUE_LABEL=$(date -I); shift ;;
        --unique=*) UNIQUE_LABEL=${1#--unique=}; shift ;;
        --churn-port-range) CHURN_PORT_RANGE=${2:?missing churn port range}; shift 2 ;;
        --env)
            [[ ${2:-} =~ ^[A-Za-z_][A-Za-z0-9_]*=.*$ ]] || {
                echo "Invalid --env value: ${2:-<missing>} (expected NAME=VALUE)" >&2
                exit 2
            }
            EXTRA_ENV+=("$2")
            shift 2
            ;;
        --skip-build) SKIP_BUILD=1; shift ;;
        --quiet) QUIET=1; shift ;;
        *) echo "Unknown option: $1" >&2; exit 2 ;;
    esac
done
[[ $QUIET == 0 || ( $PROFILE != benchmark && $PROFILE != run ) ]] || {
    echo "--quiet is not supported by benchmark or --run" >&2
    exit 2
}
[[ -z $ONLY_SUITE || $PROFILE == sanity || $PROFILE == full ]] || {
    echo "--suite is supported only by sanity and full" >&2
    exit 2
}
[[ -z $REMOTE || $REMOTE =~ ^[A-Za-z0-9_.@-]+$ ]] || { echo "Invalid remote: $REMOTE" >&2; exit 2; }
[[ -z $SHARED_BINARY || $SHARED_BINARY == /* ]] || { echo "Shared binary must be an absolute path: $SHARED_BINARY" >&2; exit 2; }
[[ $JOBS =~ ^[1-9][0-9]*$ ]] || { echo "Invalid job count: $JOBS" >&2; exit 2; }
[[ $PARALLEL =~ ^[1-9][0-9]*$ ]] || { echo "Invalid parallelism: $PARALLEL" >&2; exit 2; }
if [[ -n $CHURN_PORT_RANGE ]]; then
    [[ $CHURN_PORT_RANGE =~ ^([0-9]+):([0-9]+)$ ]] || {
        echo "Invalid churn port range: $CHURN_PORT_RANGE (expected MIN:MAX)" >&2
        exit 2
    }
    CHURN_MIN_PORT=${BASH_REMATCH[1]}
    CHURN_MAX_PORT=${BASH_REMATCH[2]}
    ((CHURN_MIN_PORT >= 1 && CHURN_MIN_PORT <= CHURN_MAX_PORT && CHURN_MAX_PORT <= 65535)) || {
        echo "Invalid churn port range: $CHURN_PORT_RANGE" >&2
        exit 2
    }
    EXTRA_ENV+=("CHURN_MIN_PORT=$CHURN_MIN_PORT" "CHURN_MAX_PORT=$CHURN_MAX_PORT")
fi
case "$ONLY_SUITE" in
    ''|tls|policy|rtt|session-list|smoke|tls-policy|tcp-churn|udp-churn|capture|corpus-regular|corpus-edge|corpus-insanity) ;;
    *) echo "Unknown suite: $ONLY_SUITE" >&2; exit 2 ;;
esac

COMMIT=$(git -C "$ROOT" rev-parse HEAD)
SHORT_COMMIT=${COMMIT:0:8}
BRANCH=$(git -C "$ROOT" symbolic-ref --quiet --short HEAD || printf 'detached')
BRANCH=$(printf '%s' "$BRANCH" | tr -c 'A-Za-z0-9._-' '-')
WORK_DIR=${WORK_DIR:-/tmp/patch-runner/${BRANCH}_@_$SHORT_COMMIT}
if [[ -n $UNIQUE_LABEL ]]; then
    UNIQUE_LABEL=$(printf '%s' "$UNIQUE_LABEL" | tr -c 'A-Za-z0-9._-' '-')
    UNIQUE_LABEL=${UNIQUE_LABEL#-}; UNIQUE_LABEL=${UNIQUE_LABEL%-}
    [[ -n $UNIQUE_LABEL ]] || { echo 'Empty --unique label after sanitizing' >&2; exit 2; }
    UNIQUE_BASE=${WORK_DIR}_$UNIQUE_LABEL
    mkdir -p "$(dirname "$UNIQUE_BASE")"
    WORK_DIR=$UNIQUE_BASE
    UNIQUE_INDEX=1
    while ! mkdir "$WORK_DIR" 2>/dev/null; do
        [[ -e $WORK_DIR ]] || { echo "Cannot create unique work root: $WORK_DIR" >&2; exit 1; }
        ((UNIQUE_INDEX += 1))
        WORK_DIR=$UNIQUE_BASE-$UNIQUE_INDEX
    done
    printf '%s\n' "$UNIQUE_LABEL" > "$WORK_DIR/unique-label.txt"
fi
BUILD_DIR=${BUILD_DIR:-${PATCH_TEST_BUILD_DIR:-$WORK_DIR/build}}
STAMP=$(date -u +%Y%m%dT%H%M%SZ)
RUN_LABEL=$PROFILE${ONLY_SUITE:+-$ONLY_SUITE}
RUN_ID=${STAMP}-${SHORT_COMMIT}-${RUN_LABEL}
REPORT_ROOT=${PATCH_TEST_RESULTS_DIR:-$WORK_DIR/results}
REPORT=$REPORT_ROOT/$RUN_ID
mkdir -p "$REPORT"

if [[ -n $(git -C "$ROOT" status --porcelain) ]]; then
    DIRTY=true
else
    DIRTY=false
fi
REPORT_HOST=${REMOTE:-local}
git -C "$ROOT" status --short > "$REPORT/git-status.txt"

run_parallel_full() {
    local -a sections=(smoke tls-policy rtt tcp-churn udp-churn capture corpus-regular corpus-edge corpus-insanity)
    local -a child_common=(sanity --skip-build --build-dir "$BUILD_DIR" --quiet)
    local -a forwarded=()
    local section section_dir output rc_file rc display child_report reason
    local running=0 any_fail=0 any_flaky=0

    [[ -z $REMOTE ]] || child_common+=(--remote "$REMOTE")
    for variable in "${EXTRA_ENV[@]}"; do forwarded+=(--env "$variable"); done
    mkdir -p "$REPORT/sections" "$WORK_DIR/sections"
    : > "$REPORT/test.log"
    printf 'section\tresult\trc\treason\treport\n' > "$REPORT/sections.tsv"

    if [[ -n $REMOTE ]]; then
        SHARED_BINARY="$WORK_DIR/shared/smithproxy"
        set +e
        {
            ssh "$REMOTE" "mkdir -p '$WORK_DIR/shared'"
            scp "$BUILD_DIR/smithproxy" "$REMOTE:$SHARED_BINARY"
            ssh "$REMOTE" "chmod 0555 '$SHARED_BINARY'"
        } > "$REPORT/sections/stage-binary.log" 2>&1
        rc=$?
        set -e
        if ((rc != 0)); then
            reason=$(grep -E '(scp:|No space left|Permission denied|[Ee]rror|[Ff]ailure)' "$REPORT/sections/stage-binary.log" | tail -1 || true)
            [[ -n $reason ]] || reason="remote binary staging exited with rc=$rc"
            reason=${reason//$'\r'/}
            printf 'stage-binary\tFAIL\t%s\t%s\t%s\n' "$rc" "$reason" "$REPORT/sections/stage-binary.log" >> "$REPORT/sections.tsv"
            cp "$REPORT/sections/stage-binary.log" "$REPORT/test.log"
            printf '| Section | Result | Reason |\n|---|---:|---|\n| stage-binary | FAIL | %s |\n' "$reason" > "$REPORT/sections.md"
            STATUS=FAIL; TEST_RC=1
            return
        fi
    else
        SHARED_BINARY="$BUILD_DIR/smithproxy"
    fi
    child_common+=(--shared-binary "$SHARED_BINARY")

    run_one_section() {
        local name=$1 dir="$WORK_DIR/sections/$1" log="$REPORT/sections/$1.log"
        set +e
        env -u PATCH_TEST_DIR -u PATCH_TEST_RESULTS_DIR \
            "$HERE/test-patch.sh" "${child_common[@]}" --suite "$name" --dir "$dir" \
            "${forwarded[@]}" > "$log" 2>&1
        local child_rc=$?
        set -e
        printf '%s\n' "$child_rc" > "$REPORT/sections/$name.rc"
        echo "SECTION DONE: $name rc=$child_rc"
    }

    # A cheap end-to-end smoke gate avoids launching eight expensive labs for
    # a binary that cannot start or pass basic dual-stack traffic.
    echo 'SECTION START: smoke'
    run_one_section smoke
    rc=$(<"$REPORT/sections/smoke.rc")
    if ((rc != 0)); then
        any_fail=1
    else
        for section in "${sections[@]:1}"; do
            echo "SECTION START: $section"
            run_one_section "$section" &
            ((running += 1))
            if ((running >= PARALLEL)); then
                wait
                running=0
            fi
        done
        ((running == 0)) || wait
    fi

    for section in "${sections[@]}"; do
        output="$REPORT/sections/$section.log"
        rc_file="$REPORT/sections/$section.rc"
        if [[ ! -f $rc_file ]]; then
            printf '%s\n' SKIP > "$REPORT/sections/$section.status"
            printf '%s\tSKIP\t-\tblocked by smoke failure\t-\n' "$section" >> "$REPORT/sections.tsv"
            continue
        fi
        rc=$(<"$rc_file")
        section_dir="$WORK_DIR/sections/$section"
        child_report=$(find "$section_dir/results" -mindepth 1 -maxdepth 1 -type d -print 2>/dev/null | sort | tail -1 || true)
        reason=
        if ((rc != 0)); then
            display=FAIL
            any_fail=1
            [[ -z $child_report || ! -f $child_report/failure.txt ]] || reason=$(sed -n 's/^reason: //p' "$child_report/failure.txt" | head -1)
            [[ -n $reason ]] || reason=$(grep -E '(^FAIL[46]?:|FAIL:|Traceback|AssertionError|[Ee]rror|failed)' "$output" | tail -1 || true)
            [[ -n $reason ]] || reason="section exited with rc=$rc"
            reason=${reason//$'\r'/}
        elif grep -Eq 'flaky=[1-9][0-9]*|FLAKY_PASS' "$output"; then
            display=FLAKY_PASS
            any_flaky=1
            reason='UDP corpus case passed on retry'
        else
            display=PASS
            reason='all checks passed'
        fi
        printf '%s\n' "$display" > "$REPORT/sections/$section.status"
        printf '%s\t%s\t%s\t%s\t%s\n' "$section" "$display" "$rc" "$reason" "${child_report:--}" >> "$REPORT/sections.tsv"
        {
            echo "===== section: $section ($display) ====="
            cat "$output"
            echo
        } >> "$REPORT/test.log"
    done

    if [[ -f $REPORT/sections/corpus-regular.rc ]]; then
        CORPUS_SELECTED=$(grep -hE '^family=IPv[46] ' \
            "$REPORT/sections/corpus-regular.log" "$REPORT/sections/corpus-edge.log" \
            "$REPORT/sections/corpus-insanity.log" 2>/dev/null | \
            awk '{for (i=1;i<=NF;i++) if ($i ~ /^(passed|flaky|failed|xfailed)=/) {split($i,a,"="); n+=a[2]}} END {print n+0}') || CORPUS_SELECTED=0
        if ((CORPUS_SELECTED == 0)); then
            any_fail=1
            printf 'corpus-selection\tFAIL\t2\tno corpus case matched MATCH/EXCLUDE\t-\n' >> "$REPORT/sections.tsv"
        fi
    fi

    {
        echo '| Section | Result | Reason |'
        echo '|---|---:|---|'
        tail -n +2 "$REPORT/sections.tsv" | while IFS=$'\t' read -r section display rc reason child_report; do
            printf '| %s | %s | %s |\n' "$section" "$display" "$reason"
        done
    } > "$REPORT/sections.md"

    if ((any_fail)); then
        STATUS=FAIL; TEST_RC=1
    elif ((any_flaky)); then
        STATUS=FLAKY_PASS; TEST_RC=0
    else
        STATUS=PASS; TEST_RC=0
    fi
}

BUILD_RC=0
if ((SKIP_BUILD == 0)); then
    if [[ ! -f $BUILD_DIR/CMakeCache.txt ]]; then
        if ((QUIET)); then
            cmake -S "$ROOT" -B "$BUILD_DIR" -DCMAKE_BUILD_TYPE=RelWithDebInfo \
                > "$REPORT/configure.log" 2>&1
        else
            cmake -S "$ROOT" -B "$BUILD_DIR" -DCMAKE_BUILD_TYPE=RelWithDebInfo \
                2>&1 | tee "$REPORT/configure.log"
        fi
    fi
    set +e
    if ((QUIET)); then
        cmake --build "$BUILD_DIR" --target smithproxy -j"$JOBS" \
            > "$REPORT/build.log" 2>&1
        BUILD_RC=$?
    else
        cmake --build "$BUILD_DIR" --target smithproxy -j"$JOBS" \
            2>&1 | tee "$REPORT/build.log"
        BUILD_RC=${PIPESTATUS[0]}
    fi
    set -e
else
    [[ -x $BUILD_DIR/smithproxy ]] || {
        echo "--skip-build requires an existing executable: $BUILD_DIR/smithproxy" >&2
        exit 2
    }
    echo "Build skipped; using $BUILD_DIR/smithproxy" > "$REPORT/build.log"
fi
if ((BUILD_RC != 0)); then
    STATUS=FAIL
    TEST_RC=$BUILD_RC
    ((QUIET == 0)) || echo "FAIL build (see $REPORT/build.log)"
elif [[ $PROFILE == quick ]]; then
    STATUS=PASS
    TEST_RC=0
elif [[ $PROFILE == full && -z $ONLY_SUITE ]]; then
    run_parallel_full
else
    BINARY=$BUILD_DIR/smithproxy
    [[ -x $BINARY ]] || { echo "Missing executable: $BINARY" >&2; exit 1; }

    TAG=$(printf '%x' $$)
    TAG=${TAG:0:6}
    CLIENT_NS=sxp${TAG}c
    SERVER_NS=sxp${TAG}o
    DATA_NS=sxp${TAG}d
    IN_IF=sp${TAG}i
    OUT_IF=sp${TAG}o
    PORT_PICKER='import socket; s=[]
for _ in range(2):
    x=socket.socket(); x.bind(("127.0.0.1",0)); s.append(x)
print(*(x.getsockname()[1] for x in s))'
    if [[ -n $REMOTE ]]; then
        printf -v PORT_COMMAND 'python3 -c %q' "$PORT_PICKER"
        read -r API_PORT CLI_PORT < <(ssh "$REMOTE" "$PORT_COMMAND")
    else
        read -r API_PORT CLI_PORT < <(python3 -c "$PORT_PICKER")
    fi
    LAB_ROOT=$WORK_DIR/labs/$RUN_ID-$TAG

    if [[ -n $REMOTE ]]; then
        ssh "$REMOTE" "mkdir -p '$LAB_ROOT/bin' '$LAB_ROOT/runner/tests' '$LAB_ROOT/corpus' '$LAB_ROOT/src/etc/msg/en'"
        if [[ -n $SHARED_BINARY ]]; then
            ssh "$REMOTE" "test -x '$SHARED_BINARY' && ln -s '$SHARED_BINARY' '$LAB_ROOT/bin/smithproxy'"
        else
            scp "$BINARY" "$REMOTE:$LAB_ROOT/bin/smithproxy" >/dev/null
        fi
        scp "$HERE/smithproxy.runner" "$REMOTE:$LAB_ROOT/runner/" >/dev/null
        scp -r "$HERE/harness/." "$REMOTE:$LAB_ROOT/runner/tests/" >/dev/null
        scp -r "$HERE/corpus/." "$REMOTE:$LAB_ROOT/corpus/" >/dev/null
        scp "$HERE/vendor/pplay.py" "$REMOTE:$LAB_ROOT/pplay.py" >/dev/null
        scp "$ROOT/etc/smithproxy.cfg" "$REMOTE:$LAB_ROOT/src/etc/" >/dev/null
        scp -r "$ROOT/etc/msg/en/." "$REMOTE:$LAB_ROOT/src/etc/msg/en/" >/dev/null
    else
        mkdir -p "$LAB_ROOT/bin" "$LAB_ROOT/runner/tests" "$LAB_ROOT/corpus" "$LAB_ROOT/src/etc/msg/en"
        if [[ -n $SHARED_BINARY ]]; then
            [[ -x $SHARED_BINARY ]] || { echo "Shared binary is not executable: $SHARED_BINARY" >&2; exit 2; }
            ln -s "$SHARED_BINARY" "$LAB_ROOT/bin/smithproxy"
        else
            cp "$BINARY" "$LAB_ROOT/bin/smithproxy"
        fi
        cp "$HERE/smithproxy.runner" "$LAB_ROOT/runner/"
        cp -a "$HERE/harness/." "$LAB_ROOT/runner/tests/"
        cp -a "$HERE/corpus/." "$LAB_ROOT/corpus/"
        cp "$HERE/vendor/pplay.py" "$LAB_ROOT/pplay.py"
        cp "$ROOT/etc/smithproxy.cfg" "$LAB_ROOT/src/etc/"
        cp -a "$ROOT/etc/msg/en/." "$LAB_ROOT/src/etc/msg/en/"
    fi

    LAB_ENV=(
        "CLIENT_NS=$CLIENT_NS" "SERVER_NS=$SERVER_NS" "DATA_NS=$DATA_NS"
        "LAB_IN_IF=$IN_IF" "LAB_OUT_IF=$OUT_IF" "LAB_API_PORT=$API_PORT" "LAB_CLI_PORT=$CLI_PORT"
        "CAPTURE_TEST=1" "HTTP2_OBSERVABILITY_TEST=1" "CAPTURE_MATRIX_TEST=1" "RTT_TEST=1" "TLS_SUITE_TEST=1" "POLICY_TEST=1" "SESSION_LIST_STRESS_TEST=1"
        "PPLAY_PY=$LAB_ROOT/pplay.py" "PPLAY_SUITE=$LAB_ROOT/corpus"
        "PPLAY_RESULTS_NAME=corpus-all" "PPLAY_SMOKE_TEST=1"
    )
    for variable in RTT_SAMPLES RTT_HANDSHAKE_SAMPLES RTT_WARMUP \
        RTT_TLS_TOTAL_P50_LIMIT_MS RTT_HTTPS_P50_LIMIT_MS \
        RTT_P95_LIMIT_MS RTT_MAX_LIMIT_MS \
        RTT_HANDSHAKE_P95_LIMIT_MS RTT_HANDSHAKE_MAX_LIMIT_MS \
        SESSION_LIST_CONNECTIONS SESSION_LIST_SAMPLES \
        SESSION_LIST_P95_LIMIT_MS SESSION_LIST_MAX_LIMIT_MS \
        CHURN_MIN_PORT CHURN_MAX_PORT; do
        [[ -z ${!variable:-} ]] || LAB_ENV+=("$variable=${!variable}")
    done
    if [[ $PROFILE == benchmark ]]; then
        LAB_ENV+=("CAPTURE_TEST=0" "HTTP2_OBSERVABILITY_TEST=0" "CAPTURE_MATRIX_TEST=0"
            "TLS_SUITE_TEST=0" "POLICY_TEST=0" "SESSION_LIST_STRESS_TEST=0" "RTT_TEST=1" "RTT_REPORT_ONLY=1"
            "RTT_NATIVE_BASELINE=1"
            "PPLAY_SMOKE_TEST=0" "PPLAY_SUITE_SKIP_RUN=1")
    fi
    if [[ $PROFILE == run ]]; then
        LAB_ENV+=("RUN_MODE=1" "CAPTURE_TEST=0" "HTTP2_OBSERVABILITY_TEST=0"
            "CAPTURE_MATRIX_TEST=0" "TLS_SUITE_TEST=0" "POLICY_TEST=0" "SESSION_LIST_STRESS_TEST=0" "RTT_TEST=0"
            "PPLAY_SMOKE_TEST=0" "PPLAY_SUITE_SKIP_RUN=1")
    fi
    if [[ -n $ONLY_SUITE ]]; then
        LAB_ENV+=("BASE_TRAFFIC_TEST=1" "CAPTURE_TEST=0" "HTTP2_OBSERVABILITY_TEST=0" "CAPTURE_MATRIX_TEST=0" "RTT_TEST=0" "TLS_SUITE_TEST=0" "POLICY_TEST=0" "SESSION_LIST_STRESS_TEST=0" "TCP_CHURN_TEST=0" "UDP_CHURN_TEST=0" "PPLAY_SMOKE_TEST=0" "PPLAY_SUITE_SKIP_RUN=1")
        case "$ONLY_SUITE" in
            tls) LAB_ENV+=("TLS_SUITE_TEST=1") ;;
            policy) LAB_ENV+=("POLICY_TEST=1") ;;
            rtt) LAB_ENV+=("RTT_TEST=1") ;;
            session-list) LAB_ENV+=("SESSION_LIST_STRESS_TEST=1") ;;
            smoke) LAB_ENV+=("PPLAY_SMOKE_TEST=1") ;;
            tls-policy) LAB_ENV+=("BASE_TRAFFIC_TEST=0" "TLS_SUITE_TEST=1" "POLICY_TEST=1" "SESSION_LIST_STRESS_TEST=1") ;;
            tcp-churn) LAB_ENV+=("BASE_TRAFFIC_TEST=0" "TCP_CHURN_TEST=1") ;;
            udp-churn) LAB_ENV+=("BASE_TRAFFIC_TEST=0" "UDP_CHURN_TEST=1") ;;
            capture) LAB_ENV+=("CAPTURE_TEST=1" "HTTP2_OBSERVABILITY_TEST=1" "CAPTURE_MATRIX_TEST=1") ;;
            corpus-regular) LAB_ENV+=("BASE_TRAFFIC_TEST=0" "PPLAY_SUITE_SKIP_RUN=0" "PPLAY_SUITE_CATEGORY=regular" "PPLAY_RESULTS_NAME=corpus-regular" "PPLAY_SUITE_EXCLUDE=capture_*" "PPLAY_SUITE_ALLOW_EMPTY=1") ;;
            corpus-edge) LAB_ENV+=("BASE_TRAFFIC_TEST=0" "PPLAY_SUITE_SKIP_RUN=0" "PPLAY_SUITE_CATEGORY=edge" "PPLAY_RESULTS_NAME=corpus-edge" "PPLAY_SUITE_EXCLUDE=capture_*" "PPLAY_SUITE_ALLOW_EMPTY=1") ;;
            corpus-insanity) LAB_ENV+=("BASE_TRAFFIC_TEST=0" "PPLAY_SUITE_SKIP_RUN=0" "PPLAY_SUITE_CATEGORY=insanity" "PPLAY_RESULTS_NAME=corpus-insanity" "PPLAY_SUITE_EXCLUDE=capture_*" "PPLAY_SUITE_ALLOW_EMPTY=1") ;;
        esac
    fi
    if [[ $PROFILE == full && -z $ONLY_SUITE ]]; then
        LAB_ENV+=("TCP_CHURN_TEST=1" "UDP_CHURN_TEST=1" "PPLAY_SUITE_CATEGORY=all")
    elif [[ -z $ONLY_SUITE ]]; then
        LAB_ENV+=("PPLAY_SUITE_SKIP_RUN=1")
    fi
    LAB_ENV+=("${EXTRA_ENV[@]}")

    set +e
    if [[ -n $REMOTE ]]; then
        printf -v ENV_STRING ' %q' "${LAB_ENV[@]}"
        if [[ $REMOTE == root@* ]]; then REMOTE_SUDO=; else REMOTE_SUDO='sudo '; fi
        SSH_RUN=(ssh)
        [[ $PROFILE != run ]] || SSH_RUN=(ssh -tt)
        if [[ $PROFILE == benchmark ]]; then
            "${SSH_RUN[@]}" "$REMOTE" "${REMOTE_SUDO}env$ENV_STRING '$LAB_ROOT/runner/tests/lab-test.sh' '$LAB_ROOT'" \
                > "$REPORT/test.log" 2>&1
            TEST_RC=$?
        elif ((QUIET)); then
            "${SSH_RUN[@]}" "$REMOTE" "${REMOTE_SUDO}env$ENV_STRING '$LAB_ROOT/runner/tests/lab-test.sh' '$LAB_ROOT'" \
                2>&1 | tee "$REPORT/test.log" | grep --line-buffered -E '(^PASS[46]? |^FAIL[46]?:| (PASS|FLAKY_PASS|FAIL|XFAIL|XPASS)[46]?$|^(TCP churn:|UDP churn:|family=IPv|Capture matrix summary:|RTT summary:|Session-list summary:)|^RESULT:)'
            TEST_RC=${PIPESTATUS[0]}
        else
            "${SSH_RUN[@]}" "$REMOTE" "${REMOTE_SUDO}env$ENV_STRING '$LAB_ROOT/runner/tests/lab-test.sh' '$LAB_ROOT'" \
                2>&1 | tee "$REPORT/test.log"
            TEST_RC=${PIPESTATUS[0]}
        fi
    else
        if ((EUID == 0)); then LOCAL_RUN=(env); else LOCAL_RUN=(sudo env); fi
        if [[ $PROFILE == benchmark ]]; then
            "${LOCAL_RUN[@]}" "${LAB_ENV[@]}" "$LAB_ROOT/runner/tests/lab-test.sh" "$LAB_ROOT" \
                > "$REPORT/test.log" 2>&1
            TEST_RC=$?
        elif ((QUIET)); then
            "${LOCAL_RUN[@]}" "${LAB_ENV[@]}" "$LAB_ROOT/runner/tests/lab-test.sh" "$LAB_ROOT" \
                2>&1 | tee "$REPORT/test.log" | grep --line-buffered -E '(^PASS[46]? |^FAIL[46]?:| (PASS|FLAKY_PASS|FAIL|XFAIL|XPASS)[46]?$|^(TCP churn:|UDP churn:|family=IPv|Capture matrix summary:|RTT summary:|Session-list summary:)|^RESULT:)'
            TEST_RC=${PIPESTATUS[0]}
        else
            "${LOCAL_RUN[@]}" "${LAB_ENV[@]}" "$LAB_ROOT/runner/tests/lab-test.sh" "$LAB_ROOT" \
                2>&1 | tee "$REPORT/test.log"
            TEST_RC=${PIPESTATUS[0]}
        fi
    fi
    set -e

    mkdir -p "$REPORT/lab-results"
    if [[ -n $REMOTE ]]; then
        scp -r "$REMOTE:$LAB_ROOT/results/." "$REPORT/lab-results/" >/dev/null 2>&1 || true
        ssh "$REMOTE" "find '$LAB_ROOT/results' -type f -printf '%P\n' | sort" \
            > "$REPORT/lab-artifacts.txt" 2>/dev/null || true
    else
        cp -a "$LAB_ROOT/results/." "$REPORT/lab-results/" 2>/dev/null || true
        find "$LAB_ROOT/results" -type f -printf '%P\n' | sort > "$REPORT/lab-artifacts.txt" 2>/dev/null || true
    fi
    printf '%s\n' "$LAB_ROOT" > "$REPORT/lab-root.txt"
    echo "Lab retained for inspection: $LAB_ROOT" > "$REPORT/lab-retention.txt"
    if [[ $PROFILE == run && ( $TEST_RC == 129 || $TEST_RC == 130 || $TEST_RC == 143 || $TEST_RC == 255 ) ]] \
        && grep -q 'Smithproxy interactive lab READY' "$REPORT/test.log"; then
        STATUS=STOPPED
        TEST_RC=0
    elif ((TEST_RC == 0)); then STATUS=PASS; else STATUS=FAIL; fi
fi

TCP_SUMMARY=$(grep -E '^TCP churn:' "$REPORT/test.log" 2>/dev/null | tail -2 | paste -sd ';' - || true)
UDP_SUMMARY=$(grep -E '^UDP churn:' "$REPORT/test.log" 2>/dev/null | tail -2 | paste -sd ';' - || true)
CORPUS_SUMMARY=$(grep -E '^(family=IPv[46] )?passed=' "$REPORT/test.log" 2>/dev/null | tail -2 | paste -sd ';' - || true)
CAPTURE_MATRIX_SUMMARY=$(grep -E '^Capture matrix summary:' "$REPORT/test.log" 2>/dev/null | tail -2 | paste -sd ';' - || true)
RTT_SUMMARY=$(grep -E '^RTT summary:' "$REPORT/test.log" 2>/dev/null | tail -2 | paste -sd ';' - || true)

FAIL_REASON=
FAIL_LIKELY=
if [[ $STATUS == FAIL ]]; then
    if ((BUILD_RC != 0)); then
        FAIL_REASON="smithproxy build exited with rc=$BUILD_RC"
    elif [[ -f $REPORT/sections.tsv ]]; then
        FAIL_REASON=$(awk -F '\t' '$2 == "FAIL" {print $1 ": " $4; exit}' "$REPORT/sections.tsv")
    else
        FAILED_CASES=$(awk '$NF ~ /^FAIL[46]$/ {print $1 "/" $2}' "$REPORT/test.log" 2>/dev/null | paste -sd, - || true)
        if [[ -n $FAILED_CASES ]]; then
            FAIL_REASON="corpus cases failed: $FAILED_CASES"
        elif grep -q '^No cases matched ' "$REPORT/test.log" 2>/dev/null; then
            FAIL_REASON=$(grep '^No cases matched ' "$REPORT/test.log" | head -1)
        elif grep -q '^ABORT:' "$REPORT/test.log" 2>/dev/null; then
            FAIL_REASON=$(grep '^ABORT:' "$REPORT/test.log" | tail -1)
        else
            FAIL_REASON=$(grep -E '(^FAIL[46]?:|FAIL:|ABORT:|Traceback|AssertionError|[Ee]rror|failed)' "$REPORT/test.log" 2>/dev/null | tail -1 || true)
        fi
        [[ -n $FAIL_REASON ]] || FAIL_REASON="test process exited with rc=$TEST_RC"
    fi
    if grep -q 'PASS runner shutdown:' "$REPORT/test.log" 2>/dev/null \
        && grep -q 'AssertionError' "$REPORT/test.log" 2>/dev/null; then
        FAIL_REASON='cleanup host-state comparison failed'
        FAIL_LIKELY='host addresses or routes differed after this lab was removed'
    elif grep -Rqs 'expected one stream, got 2' "$REPORT/lab-results" "$REPORT/test.log" 2>/dev/null; then
        FAIL_LIKELY='capture cases were executed twice and reused the same stream tuple'
    elif grep -qs 'Address already in use' "$REPORT/test.log" 2>/dev/null; then
        FAIL_LIKELY='a listener port collided with another process'
    fi
fi
printf -v REPRO '%q ' "$HERE/test-patch.sh" "${ORIGINAL_ARGS[@]}"
if [[ -n $FAIL_REASON ]]; then
    {
        echo "reason: $FAIL_REASON"
        [[ -z $FAIL_LIKELY ]] || echo "likely: $FAIL_LIKELY"
        echo "test log: $REPORT/test.log"
        echo "reproduce: $REPRO"
    } > "$REPORT/failure.txt"
fi

cat > "$REPORT/summary.md" <<EOF
# Smithproxy patch test

- Result: **$STATUS**
- Profile: $PROFILE
- Commit: $COMMIT
- Dirty working tree: $DIRTY
- Host: $REPORT_HOST
- Build directory: $BUILD_DIR
- Build: $([[ $BUILD_RC == 0 ]] && echo PASS || echo FAIL)
- TCP churn: ${TCP_SUMMARY:-N/A}
- UDP churn: ${UDP_SUMMARY:-N/A}
- Corpus: ${CORPUS_SUMMARY:-N/A}
- Capture matrix: ${CAPTURE_MATRIX_SUMMARY:-N/A}
- RTT: ${RTT_SUMMARY:-N/A}
- Expected failure: edge/http1_connect_ipv6
EOF
if [[ -f $REPORT/sections.md ]]; then
    printf '\n## Sections\n\n' >> "$REPORT/summary.md"
    cat "$REPORT/sections.md" >> "$REPORT/summary.md"
fi
if [[ -n $FAIL_REASON ]]; then
    printf '\n## Failure\n\n- Reason: %s\n' "$FAIL_REASON" >> "$REPORT/summary.md"
    [[ -z $FAIL_LIKELY ]] || printf -- '- Likely cause: %s\n' "$FAIL_LIKELY" >> "$REPORT/summary.md"
fi
printf '\n## Reproduction\n\n```sh\n%s\n```\n' "$REPRO" >> "$REPORT/summary.md"

{
    echo "RESULT: $STATUS"
    echo "profile: $PROFILE"
    echo "commit: $COMMIT"
    echo "host: $REPORT_HOST"
    [[ -z $FAIL_REASON ]] || echo "reason: $FAIL_REASON"
    [[ -z $FAIL_LIKELY ]] || echo "likely: $FAIL_LIKELY"
    echo "reproduce: $REPRO"
    echo "report: $REPORT"
    if [[ -f $REPORT/sections.tsv ]]; then
        echo
        column -t -s $'\t' "$REPORT/sections.tsv" 2>/dev/null || cat "$REPORT/sections.tsv"
    fi
} > "$REPORT/summary.txt"

cat > "$REPORT/summary.json" <<EOF
{
  "result": "$STATUS",
  "profile": "$PROFILE",
  "commit": "$COMMIT",
  "dirty": $DIRTY,
  "host": "$REPORT_HOST",
  "build_rc": $BUILD_RC,
  "test_rc": $TEST_RC,
  "reason": "${FAIL_REASON//\"/\\\"}",
  "likely": "${FAIL_LIKELY//\"/\\\"}",
  "tcp_churn": "${TCP_SUMMARY//\"/\\\"}",
  "udp_churn": "${UDP_SUMMARY//\"/\\\"}",
  "corpus": "${CORPUS_SUMMARY//\"/\\\"}",
  "capture_matrix": "${CAPTURE_MATRIX_SUMMARY//\"/\\\"}",
  "rtt": "${RTT_SUMMARY//\"/\\\"}"
}
EOF

((QUIET)) || echo
if [[ $PROFILE == benchmark ]]; then
    echo 'IPv4'
    python3 "$HERE/harness/suites/rtt/report.py" \
        "$REPORT/lab-results/tcp-rtt.json" "$REPORT/lab-results/native-rtt.json"
    echo
    echo 'IPv6'
    python3 "$HERE/harness/suites/rtt/report.py" \
        "$REPORT/lab-results/tcp-rtt6.json" "$REPORT/lab-results/native-rtt6.json"
    echo "Raw result: $REPORT/lab-results/tcp-rtt.json"
    echo "Native raw result: $REPORT/lab-results/native-rtt.json"
    echo "IPv6 raw result: $REPORT/lab-results/tcp-rtt6.json"
    echo "IPv6 native raw result: $REPORT/lab-results/native-rtt6.json"
    echo "Report: $REPORT"
    exit "$TEST_RC"
fi
echo "RESULT: $STATUS"
if ((QUIET)); then
    [[ -z $FAIL_REASON ]] || echo "Reason: $FAIL_REASON"
    [[ -z $FAIL_LIKELY ]] || echo "Likely: $FAIL_LIKELY"
    if [[ -f $REPORT/sections.tsv ]]; then
        awk -F '\t' 'NR > 1 {printf "%-18s %-10s %s\n", $1, $2, $4}' "$REPORT/sections.tsv"
    fi
    echo "Report: $REPORT"
    exit "$TEST_RC"
fi
echo "Commit: $COMMIT"
echo "Profile: $PROFILE"
[[ -z $FAIL_REASON ]] || echo "Reason: $FAIL_REASON"
[[ -z $FAIL_LIKELY ]] || echo "Likely: $FAIL_LIKELY"
[[ ! -f $REPORT/sections.tsv ]] || { echo 'Sections:'; column -t -s $'\t' "$REPORT/sections.tsv" 2>/dev/null || cat "$REPORT/sections.tsv"; }
[[ -z $TCP_SUMMARY ]] || echo "$TCP_SUMMARY"
[[ -z $UDP_SUMMARY ]] || echo "$UDP_SUMMARY"
[[ -z $CORPUS_SUMMARY ]] || echo "$CORPUS_SUMMARY"
[[ -z $CAPTURE_MATRIX_SUMMARY ]] || echo "$CAPTURE_MATRIX_SUMMARY"
[[ -z $RTT_SUMMARY ]] || echo "$RTT_SUMMARY"
echo "Report: $REPORT"
exit "$TEST_RC"
