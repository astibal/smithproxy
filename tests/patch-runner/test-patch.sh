#!/usr/bin/env bash
set -euo pipefail

HERE=$(cd "$(dirname "$0")" && pwd)

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
  full        Run sanity plus dual-stack TCP/UDP churn and pplay corpus.
  benchmark   Measure TCP, UDP and TLS latency without PASS/FAIL latency gates.
              Prints IPv4/IPv6 absolute and native-delta tables and keeps JSON.
  --run       Start an interactive isolated lab and keep Smithproxy in the
              foreground until Ctrl-C. Prints host-side CLI and API access.
              With --remote, both ports bind to the remote host's loopback.

Options:
  --suite NAME       Run only one virtual sanity suite: tls, policy, rtt or session-list.
                     Use with the sanity or full profile.
  --remote HOST      Run the isolated lab over SSH on [USER@]HOST. A root@
                     target runs directly; other users are invoked via sudo.
                     Without this option the lab runs on the current computer.
  --env NAME=VALUE   Pass an environment variable to the test lab. Repeatable;
                     supplied values override profile defaults.
  --dir DIR          Work root for build, retained labs and results.
                     Default: /tmp/patch-runner/<branch>_@_<commit>/
  --build-dir DIR    Use this CMake build directory instead of DIR/build.
  --jobs N           Parallel build jobs. Default: nproc.
  --churn-port-range MIN:MAX
                     Client source-port range for TCP/UDP churn (default: 20000:29999).
  --skip-build       Use an existing BUILD_DIR/smithproxy. Intended for CMake
                     custom targets, which already depend on smithproxy.
  --quiet            Print only verdict lines. Complete output remains in logs.
  -h, --help         Show this help and exit.

Common environment variables:
  PATCH_TEST_DIR                 Default work root (overridden by --dir).
  PATCH_TEST_BUILD_DIR           Default build directory.
  PATCH_TEST_RESULTS_DIR         Store reports under this directory.
  PATCH_TEST_JOBS                Default build parallelism.
  MATCH                           Comma-separated corpus case-name globs
                                  to include (default: *).
  EXCLUDE                         Comma-separated corpus case-name globs to skip.
  RTT_SAMPLES                    Measured TCP/UDP samples (default: 200).
  RTT_HANDSHAKE_SAMPLES          Fresh TCP/TLS connections (default: 40).
  RTT_WARMUP                     Unreported warm-up exchanges (default: 20).
  RTT_TLS_TOTAL_P50_LIMIT_MS     Sanity TLS total-connect P50 gate (default: 7).
  RTT_HTTPS_P50_LIMIT_MS         Sanity HTTPS RTT P50 gate (default: 2).
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
  test-patch.sh full --remote root@tt-bs1 --churn-port-range 20000:29999
  test-patch.sh benchmark --remote root@tt-bs1
  test-patch.sh --run --remote root@tt-bs1
  test-patch.sh sanity --build-dir /tmp/smithproxy-build --skip-build

CMake targets:
  cmake --build BUILD --target patch-test-tls
  cmake --build BUILD --target patch-test-policy
  cmake --build BUILD --target patch-test-rtt
  cmake --build BUILD --target patch-test-sanity
  cmake --build BUILD --target benchmark

Configure remote CMake targets with:
  cmake -S . -B BUILD -DPATCH_TEST_REMOTE=root@tt-bs1

Reports:
  Every run records the commit, dirty-tree state, logs and lab artifacts under
  <work-root>/results/<UTC timestamp>-<commit>-<profile>[-<suite>]/.
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
EXTRA_ENV=()
CHURN_PORT_RANGE=

REMOTE=
WORK_DIR=${PATCH_TEST_DIR:-}
JOBS=${PATCH_TEST_JOBS:-$(nproc)}
while (($#)); do
    case "$1" in
        --remote) REMOTE=${2:?missing remote host}; shift 2 ;;
        --dir) WORK_DIR=${2:?missing work directory}; shift 2 ;;
        --build-dir) BUILD_DIR=${2:?missing build directory}; shift 2 ;;
        --jobs) JOBS=${2:?missing job count}; shift 2 ;;
        --suite) ONLY_SUITE=${2:?missing suite}; shift 2 ;;
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
[[ $JOBS =~ ^[1-9][0-9]*$ ]] || { echo "Invalid job count: $JOBS" >&2; exit 2; }
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
[[ -z $ONLY_SUITE || $ONLY_SUITE == tls || $ONLY_SUITE == policy || $ONLY_SUITE == rtt || $ONLY_SUITE == session-list ]] || { echo "Unknown suite: $ONLY_SUITE" >&2; exit 2; }

COMMIT=$(git -C "$ROOT" rev-parse HEAD)
SHORT_COMMIT=${COMMIT:0:8}
BRANCH=$(git -C "$ROOT" symbolic-ref --quiet --short HEAD || printf 'detached')
BRANCH=$(printf '%s' "$BRANCH" | tr -c 'A-Za-z0-9._-' '-')
WORK_DIR=${WORK_DIR:-/tmp/patch-runner/${BRANCH}_@_$SHORT_COMMIT}
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
        scp "$BINARY" "$REMOTE:$LAB_ROOT/bin/smithproxy" >/dev/null
        scp "$HERE/smithproxy.runner" "$REMOTE:$LAB_ROOT/runner/" >/dev/null
        scp -r "$HERE/harness/." "$REMOTE:$LAB_ROOT/runner/tests/" >/dev/null
        scp -r "$HERE/corpus/." "$REMOTE:$LAB_ROOT/corpus/" >/dev/null
        scp "$HERE/vendor/pplay.py" "$REMOTE:$LAB_ROOT/pplay.py" >/dev/null
        scp "$ROOT/etc/smithproxy.cfg" "$REMOTE:$LAB_ROOT/src/etc/" >/dev/null
        scp -r "$ROOT/etc/msg/en/." "$REMOTE:$LAB_ROOT/src/etc/msg/en/" >/dev/null
    else
        mkdir -p "$LAB_ROOT/bin" "$LAB_ROOT/runner/tests" "$LAB_ROOT/corpus" "$LAB_ROOT/src/etc/msg/en"
        cp "$BINARY" "$LAB_ROOT/bin/smithproxy"
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
        LAB_ENV+=("CAPTURE_TEST=0" "HTTP2_OBSERVABILITY_TEST=0" "CAPTURE_MATRIX_TEST=0" "RTT_TEST=0" "TLS_SUITE_TEST=0" "POLICY_TEST=0" "SESSION_LIST_STRESS_TEST=0" "PPLAY_SUITE_SKIP_RUN=1")
        case "$ONLY_SUITE" in
            tls) LAB_ENV+=("TLS_SUITE_TEST=1") ;;
            policy) LAB_ENV+=("POLICY_TEST=1") ;;
            rtt) LAB_ENV+=("RTT_TEST=1") ;;
            session-list) LAB_ENV+=("SESSION_LIST_STRESS_TEST=1") ;;
        esac
    fi
    if [[ $PROFILE == full ]]; then
        LAB_ENV+=("TCP_CHURN_TEST=1" "UDP_CHURN_TEST=1" "PPLAY_SUITE_CATEGORY=all")
    else
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
                2>&1 | tee "$REPORT/test.log" | grep --line-buffered -E '(^PASS[46]? |^FAIL[46]?:| (PASS|FAIL|XFAIL|XPASS)[46]?$|^RESULT:)'
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
                2>&1 | tee "$REPORT/test.log" | grep --line-buffered -E '(^PASS[46]? |^FAIL[46]?:| (PASS|FAIL|XFAIL|XPASS)[46]?$|^RESULT:)'
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

cat > "$REPORT/summary.json" <<EOF
{
  "result": "$STATUS",
  "profile": "$PROFILE",
  "commit": "$COMMIT",
  "dirty": $DIRTY,
  "host": "$REPORT_HOST",
  "build_rc": $BUILD_RC,
  "test_rc": $TEST_RC,
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
    exit "$TEST_RC"
fi
echo "Commit: $COMMIT"
echo "Profile: $PROFILE"
[[ -z $TCP_SUMMARY ]] || echo "$TCP_SUMMARY"
[[ -z $UDP_SUMMARY ]] || echo "$UDP_SUMMARY"
[[ -z $CORPUS_SUMMARY ]] || echo "$CORPUS_SUMMARY"
[[ -z $CAPTURE_MATRIX_SUMMARY ]] || echo "$CAPTURE_MATRIX_SUMMARY"
[[ -z $RTT_SUMMARY ]] || echo "$RTT_SUMMARY"
echo "Report: $REPORT"
exit "$TEST_RC"
