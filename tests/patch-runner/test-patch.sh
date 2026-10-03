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
              native tests, TLS/policy/CLI, RTT, churn, capture/HTTP2, QUIC/H3,
              all corpus categories and deterministic protocol fuzz sections.
  native      Run the hermetic CTest, integration and runner self-test layer.
  coverage    Run the native layer and local dataplane sanity with GCC line
              instrumentation; emit text, JSON and browsable HTML reports.
  fuzz        Run the mandatory bounded deterministic protocol fuzz sections.
  fuzz-dyn    Run every protocol fuzz section with one new seed. On complete
              success, append that seed to tests/docs/covered-seeds.
  benchmark   Measure TCP, UDP and TLS latency without PASS/FAIL latency gates.
              Prints IPv4/IPv6 absolute and native-delta tables and keeps JSON.
  --run       Start an interactive isolated lab and keep Smithproxy in the
              foreground until Ctrl-C. Prints host-side CLI and API access.
              With --remote, both ports bind to the remote host's loopback.

Options:
  --suite NAME       Run only one suite. Besides tls, transfer, tls-throughput,
                     starttls, policy, routing,
                     rtt, session-list and quic,
                     full-run sections are available: smoke, tls-policy, routing,
                     rtt, transfer, tls-throughput, quic, tcp-churn, udp-churn, capture,
                     corpus-regular, corpus-edge, corpus-insanity and fuzz.AREA.
                     Use with sanity, full, fuzz or fuzz-dyn.
  --local            Add this computer as an explicit execution target.
  --remote HOST      Add an SSH execution target. Repeat to distribute full/fuzz
                     sections. A root@ target runs directly; others use sudo.
  --env NAME=VALUE   Pass an environment variable to the test lab. Repeatable;
                     supplied values override profile defaults.
  --dir DIR          Work root for build, retained labs and results.
                     Default: /tmp/patch-runner/<branch>_@_<commit>/
  --unique[=TAG]     Give this invocation a collision-safe work root. TAG defaults
                     to `date -I`; collisions get -2, -3, ... suffixes.
  --parallel N       Concurrent section workers per target. Default: 3.
  --seed SEED        Replay an exact fuzz seed instead of selecting/generating one.
  --build-dir DIR    Use this CMake build directory instead of DIR/build.
  --shared-binary PATH
                     Reuse an executable already present on the lab host.
  --jobs N           Parallel build jobs. Default: nproc.
  --churn-port-range MIN:MAX
                     Client source-port range for TCP/UDP churn (default: 20000:29999).
  --include-external Include public-network and privileged native tests.
  --include-benchmarks
                     Include benchmark-shaped tests in native/coverage profiles.
  --include-extended Include long-running soak tests in native/coverage profiles.
  --include-platform Include the Docker distro matrix in native/coverage profiles.
  --skip-build       Use an existing executable BUILD_DIR/smithproxy.
  --quiet            Print only verdict lines. Complete output remains in logs.
  -h, --help         Show this help and exit.

Common environment variables:
  PATCH_TEST_DIR                 Default work root (overridden by --dir).
  PATCH_TEST_BUILD_DIR           Default build directory.
  PATCH_TEST_RESULTS_DIR         Store reports under this directory.
  PATCH_TEST_JOBS                Default build parallelism.
  PATCH_TEST_CTEST_JOBS          Native test parallelism. Coverage defaults to
                                 1 to avoid gcov-induced resource contention.
  PATCH_TEST_PARALLEL            Default full-section concurrency (default: 3).
  MATCH                           Comma-separated corpus case-name globs
                                  to include (default: *).
  EXCLUDE                         Comma-separated corpus case-name globs to skip.
  RTT_SAMPLES                    Measured TCP/UDP samples (default: 200).
  RTT_HANDSHAKE_SAMPLES          Fresh TCP/TLS connections (default: 40).
  RTT_WARMUP                     Unreported warm-up exchanges (default: 20).
  RTT_TLS_TOTAL_P50_LIMIT_MS     Sanity/full TLS total-connect P50 gate (default: 7).
  RTT_TLS_TOTAL_P50_FLAKY_LIMIT_MS  TLS total-connect FLAKY_PASS ceiling (default: 10).
  RTT_HTTPS_P50_LIMIT_MS         Sanity/full HTTPS RTT P50 gate (default: 2).
  RTT_HTTPS_P50_FLAKY_LIMIT_MS   HTTPS RTT FLAKY_PASS ceiling (default: 10).
  RTT_P95_LIMIT_MS               General RTT P95 gate (default: 50).
  RTT_MAX_LIMIT_MS               General RTT maximum gate (default: 250).
  RTT_HANDSHAKE_P95_LIMIT_MS     Handshake P95 gate (default: 500).
  RTT_HANDSHAKE_MAX_LIMIT_MS     Handshake maximum gate (default: 2000).
  TLS_THROUGHPUT_BYTES           Bytes per measured E2E flow (default: 64 MiB).
  TLS_THROUGHPUT_REPEATS         Samples per direction/concurrency (default: 3).
  TLS_THROUGHPUT_CONCURRENCY     Measured flow counts (default: 1,4,16).
  CHURN_MIN_PORT                 TCP/UDP churn source-port minimum (default: 20000).
  CHURN_MAX_PORT                 TCP/UDP churn source-port maximum (default: 29999).
  TCP_CHURN_PARALLEL             Maximum simultaneous TCP churn flows (default: 64).
  TCP_CHURN_SYNCHRONIZED         Release every TCP wave from one barrier (default: 0).
  CURL_HTTP3_PREFIX              curl installation whose bin/curl-h3 supports HTTP/3.
  QUIC_PYTHON_PREFIX             Prepared aioquic runtime copied to test targets.
  FUZZ_RECENT_SEEDS              Recent seeds per fuzz area (default: 4).
  FUZZ_ARCHIVE_SEEDS             Rotating archived seeds per area (default: 4).
  FUZZ_ROTATION_DAYS             Archive rotation period (default: 7).
  FUZZ_SEED_MIN_AGE_DAYS         Covered seed eligibility delay (default: 1).
  FUZZ_LEVEL                     Pplay mutation strength 0-255 (default: 245).

Examples:
  test-patch.sh quick --local
  test-patch.sh native --local
  test-patch.sh coverage --local --jobs 8
  test-patch.sh sanity --local
  test-patch.sh sanity --remote root@test-runner-1
  test-patch.sh sanity --suite policy --remote root@test-runner-1
  test-patch.sh sanity --suite tls-throughput --remote root@test-runner-1
  test-patch.sh sanity --suite quic --remote root@test-runner-1
  test-patch.sh sanity --quiet --remote root@test-runner-1
  test-patch.sh sanity --remote root@test-runner-1 --env RTT_SAMPLES=500
  test-patch.sh full --remote root@test-runner-1 --env MATCH='h2_generated_*' \
      --env EXCLUDE='h2_generated_003,h2_generated_017'
  test-patch.sh full --remote root@test-runner-1 --jobs 8
  test-patch.sh full --remote root@test-runner-1 --unique=udp-flaky-results
  test-patch.sh full --remote root@test-runner-1 --unique --parallel 3
  test-patch.sh full --local --remote root@test-runner-1 --remote root@test-runner-2
  test-patch.sh fuzz-dyn --remote root@test-runner-1 --remote root@test-runner-2
  test-patch.sh full --remote root@test-runner-1 --churn-port-range 20000:29999
  test-patch.sh benchmark --remote root@test-runner-1
  test-patch.sh --run --remote root@test-runner-1
  test-patch.sh sanity --local --build-dir /tmp/smithproxy-build --skip-build

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

if [[ -n ${PATCH_TEST_ROOT_OVERRIDE:-} ]]; then
    [[ $PATCH_TEST_ROOT_OVERRIDE == /* ]] || { echo 'PATCH_TEST_ROOT_OVERRIDE must be absolute' >&2; exit 2; }
    ROOT=$PATCH_TEST_ROOT_OVERRIDE
else
    ROOT=$(git -C "$HERE" rev-parse --show-toplevel)
fi
PROFILE=${1:-}
[[ $PROFILE == --run ]] && PROFILE=run
[[ $PROFILE == quick || $PROFILE == sanity || $PROFILE == full || $PROFILE == native || $PROFILE == coverage || $PROFILE == fuzz || $PROFILE == fuzz-dyn || $PROFILE == benchmark || $PROFILE == run ]] || {
    usage >&2
    exit 2
}
shift
ONLY_SUITE=
SKIP_BUILD=0
QUIET=0
INCLUDE_EXTERNAL=0
INCLUDE_BENCHMARKS=0
INCLUDE_EXTENDED=0
INCLUDE_PLATFORM=0
UNIQUE_LABEL=
EXTRA_ENV=()
CHURN_PORT_RANGE=
INTERNAL_WORKER=0
TARGETS=()
REQUESTED_FUZZ_SEED=

REMOTE=
SHARED_BINARY=
WORK_DIR=${PATCH_TEST_DIR:-}
JOBS=${PATCH_TEST_JOBS:-$(nproc)}
PARALLEL=${PATCH_TEST_PARALLEL:-3}
while (($#)); do
    case "$1" in
        --local) TARGETS+=(local); shift ;;
        --remote) TARGETS+=("${2:?missing remote host}"); shift 2 ;;
        --dir) WORK_DIR=${2:?missing work directory}; shift 2 ;;
        --build-dir) BUILD_DIR=${2:?missing build directory}; shift 2 ;;
        --shared-binary) SHARED_BINARY=${2:?missing shared binary}; shift 2 ;;
        --jobs) JOBS=${2:?missing job count}; shift 2 ;;
        --parallel) PARALLEL=${2:?missing parallelism}; shift 2 ;;
        --seed) REQUESTED_FUZZ_SEED=${2:?missing fuzz seed}; shift 2 ;;
        --suite) ONLY_SUITE=${2:?missing suite}; shift 2 ;;
        --unique) UNIQUE_LABEL=$(date -I); shift ;;
        --unique=*) UNIQUE_LABEL=${1#--unique=}; shift ;;
        --churn-port-range) CHURN_PORT_RANGE=${2:?missing churn port range}; shift 2 ;;
        --include-external) INCLUDE_EXTERNAL=1; shift ;;
        --include-benchmarks) INCLUDE_BENCHMARKS=1; shift ;;
        --include-extended) INCLUDE_EXTENDED=1; shift ;;
        --include-platform) INCLUDE_PLATFORM=1; shift ;;
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
        --worker) INTERNAL_WORKER=1; shift ;;
        *) echo "Unknown option: $1" >&2; exit 2 ;;
    esac
done
[[ $QUIET == 0 || ( $PROFILE != benchmark && $PROFILE != run ) ]] || {
    echo "--quiet is not supported by benchmark or --run" >&2
    exit 2
}
[[ -z $ONLY_SUITE || $PROFILE == sanity || $PROFILE == full || $PROFILE == fuzz || $PROFILE == fuzz-dyn ]] || {
    echo "--suite is supported only by sanity, full, fuzz and fuzz-dyn" >&2
    exit 2
}
(( ${#TARGETS[@]} > 0 )) || { echo 'Specify an execution target with --local or --remote HOST' >&2; exit 2; }
declare -A SEEN_TARGETS=()
for target in "${TARGETS[@]}"; do
    [[ $target == local || $target =~ ^[A-Za-z0-9_][A-Za-z0-9_.@-]*$ ]] || { echo "Invalid target: $target" >&2; exit 2; }
    [[ -z ${SEEN_TARGETS[$target]:-} ]] || { echo "Duplicate target: $target" >&2; exit 2; }
    SEEN_TARGETS[$target]=1
done
if [[ -n $ONLY_SUITE || ( $PROFILE != full && $PROFILE != fuzz && $PROFILE != fuzz-dyn ) ]]; then
    ((${#TARGETS[@]} == 1)) || { echo "$PROFILE${ONLY_SUITE:+ --suite $ONLY_SUITE} requires exactly one target" >&2; exit 2; }
fi
[[ $PROFILE != quick || ${TARGETS[0]} == local ]] || { echo 'quick builds locally and requires --local' >&2; exit 2; }
if [[ $PROFILE == native || $PROFILE == coverage ]]; then
    [[ ${TARGETS[0]} == local ]] || { echo "$PROFILE runs on the coordinator and requires --local" >&2; exit 2; }
    ((SKIP_BUILD == 0)) || { echo "--skip-build is not supported by $PROFILE" >&2; exit 2; }
fi
if ((INCLUDE_EXTERNAL || INCLUDE_BENCHMARKS || INCLUDE_EXTENDED || INCLUDE_PLATFORM)); then
    [[ $PROFILE == native || $PROFILE == coverage ]] || {
        echo '--include-* test layers require native or coverage' >&2
        exit 2
    }
fi
if ((${#TARGETS[@]} == 1)) && [[ ${TARGETS[0]} != local ]]; then
    REMOTE=${TARGETS[0]}
fi
[[ -z $SHARED_BINARY || $SHARED_BINARY == /* ]] || { echo "Shared binary must be an absolute path: $SHARED_BINARY" >&2; exit 2; }
[[ $JOBS =~ ^[1-9][0-9]*$ ]] || { echo "Invalid job count: $JOBS" >&2; exit 2; }
[[ $PARALLEL =~ ^[1-9][0-9]*$ ]] || { echo "Invalid parallelism: $PARALLEL" >&2; exit 2; }
[[ -z $REQUESTED_FUZZ_SEED || $REQUESTED_FUZZ_SEED =~ ^[A-Za-z0-9._-]+$ ]] || { echo "Invalid fuzz seed: $REQUESTED_FUZZ_SEED" >&2; exit 2; }
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
FUZZ_AREAS=(h1 h2 tls socks5 dns quic redis mqtt smtp imap pop3 ftp ssh websocket memcached postgresql mysql amqp telnet ntp syslog stun tftp snmp raw)
case "$ONLY_SUITE" in
    ''|tls|transfer|tls-throughput|starttls|policy|routing|rtt|session-list|quic|smoke|tls-policy|tcp-churn|udp-churn|capture|corpus-regular|corpus-edge|corpus-insanity) ;;
    fuzz.*)
        fuzz_spec=${ONLY_SUITE#fuzz.}
        fuzz_area=${fuzz_spec%%.*}
        fuzz_category=all
        [[ $fuzz_spec != *.* ]] || fuzz_category=${fuzz_spec#*.}
        [[ " ${FUZZ_AREAS[*]} " == *" $fuzz_area "* ]] || { echo "Unknown fuzz area: $fuzz_area" >&2; exit 2; }
        [[ $fuzz_category == all || $fuzz_category == regular || $fuzz_category == edge || $fuzz_category == insanity ]] || {
            echo "Unknown fuzz category: $fuzz_category" >&2; exit 2;
        }
        ;;
    *) echo "Unknown suite: $ONLY_SUITE" >&2; exit 2 ;;
esac
if [[ ( $PROFILE == fuzz || $PROFILE == fuzz-dyn ) && -n $ONLY_SUITE && $ONLY_SUITE != fuzz.* ]]; then
    echo "$PROFILE accepts only fuzz.AREA suites" >&2
    exit 2
fi
if [[ -n $REQUESTED_FUZZ_SEED && -n $ONLY_SUITE && $ONLY_SUITE != fuzz.* ]]; then
    echo '--seed cannot be combined with a non-fuzz suite' >&2
    exit 2
fi
if [[ -n $REQUESTED_FUZZ_SEED && $PROFILE != full && $PROFILE != fuzz && $PROFILE != fuzz-dyn && $ONLY_SUITE != fuzz.* ]]; then
    echo '--seed requires full, fuzz, fuzz-dyn or a fuzz.AREA suite' >&2
    exit 2
fi

COMMIT=${PATCH_TEST_COMMIT_OVERRIDE:-}
[[ -n $COMMIT ]] || COMMIT=$(git -C "$ROOT" rev-parse HEAD)
SHORT_COMMIT=${COMMIT:0:8}
BRANCH=${PATCH_TEST_BRANCH_OVERRIDE:-}
[[ -n $BRANCH ]] || BRANCH=$(git -C "$ROOT" symbolic-ref --quiet --short HEAD || printf 'detached')
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

if [[ -n ${PATCH_TEST_DIRTY_OVERRIDE:-} ]]; then
    [[ $PATCH_TEST_DIRTY_OVERRIDE == true || $PATCH_TEST_DIRTY_OVERRIDE == false ]] || {
        echo 'PATCH_TEST_DIRTY_OVERRIDE must be true or false' >&2
        exit 2
    }
    DIRTY=$PATCH_TEST_DIRTY_OVERRIDE
elif [[ -n $(git -C "$ROOT" status --porcelain) ]]; then
    DIRTY=true
else
    DIRTY=false
fi
REPORT_HOST=$(IFS=,; echo "${TARGETS[*]}")
FUZZ_SEED_REGISTRY=$ROOT/tests/docs/covered-seeds
FUZZ_GENERATOR_VERSION=v1
FUZZ_DYNAMIC_SEED=
if [[ $PROFILE == fuzz-dyn ]]; then
    if [[ -n $REQUESTED_FUZZ_SEED ]]; then
        FUZZ_DYNAMIC_SEED=$REQUESTED_FUZZ_SEED
    else
        while :; do
            FUZZ_DYNAMIC_SEED=$(python3 -c 'import secrets; print(secrets.token_hex(16))')
            awk -F '\t' -v seed="$FUZZ_DYNAMIC_SEED" '$0 !~ /^#/ && $2 == seed {found=1} END {exit !found}' "$FUZZ_SEED_REGISTRY" || break
        done
    fi
    printf '%s\n' "$FUZZ_DYNAMIC_SEED" > "$REPORT/fuzz-seed.txt"
fi
if [[ $ONLY_SUITE == fuzz.* ]]; then
    fuzz_spec=${ONLY_SUITE#fuzz.}
    fuzz_area=${fuzz_spec%%.*}
    supplied_fuzz_seeds=
    for variable in "${EXTRA_ENV[@]}"; do
        [[ $variable != FUZZ_SEEDS=* ]] || supplied_fuzz_seeds=${variable#FUZZ_SEEDS=}
    done
    if [[ -n $supplied_fuzz_seeds ]]; then
        focused_fuzz_seeds=$supplied_fuzz_seeds
    elif [[ -n $REQUESTED_FUZZ_SEED ]]; then
        focused_fuzz_seeds=$REQUESTED_FUZZ_SEED
    elif [[ $PROFILE == fuzz-dyn ]]; then
        focused_fuzz_seeds=$FUZZ_DYNAMIC_SEED
    else
        focused_fuzz_seeds=$(python3 "$HERE/fuzz-seeds.py" "$FUZZ_SEED_REGISTRY" "$fuzz_area" \
            --recent "${FUZZ_RECENT_SEEDS:-4}" --archive "${FUZZ_ARCHIVE_SEEDS:-4}" \
            --rotation-days "${FUZZ_ROTATION_DAYS:-7}" \
            --min-age-days "${FUZZ_SEED_MIN_AGE_DAYS:-1}")
    fi
    [[ -n $supplied_fuzz_seeds ]] || EXTRA_ENV+=("FUZZ_SEEDS=$focused_fuzz_seeds")
    EXTRA_ENV+=("FUZZ_LEVEL=${FUZZ_LEVEL:-245}" "FUZZ_SCATTER=1")
fi
if [[ -d $ROOT/.git || -f $ROOT/.git ]]; then
    git -C "$ROOT" status --short > "$REPORT/git-status.txt"
else
    printf 'staged runner bundle; coordinator dirty=%s\n' "$DIRTY" > "$REPORT/git-status.txt"
fi

run_native_tests() {
    local coverage=${1:-0}
    local native_build=$WORK_DIR/native-build
    local native_report=$REPORT/native
    local -a native_args=(--root "$ROOT" --build-dir "$native_build"
        --report-dir "$native_report" --jobs "$JOBS")
    ((coverage == 0)) || {
        native_build=$WORK_DIR/coverage-build
        native_args=(--root "$ROOT" --build-dir "$native_build"
            --report-dir "$native_report" --jobs "$JOBS" --coverage)
    }
    ((INCLUDE_EXTERNAL == 0)) || native_args+=(--include-external)
    ((INCLUDE_BENCHMARKS == 0)) || native_args+=(--include-benchmarks)
    ((INCLUDE_EXTENDED == 0)) || native_args+=(--include-extended)
    ((INCLUDE_PLATFORM == 0)) || native_args+=(--include-platform)
    "$HERE/native-tests.sh" "${native_args[@]}"
}

write_sections_markdown() {
    {
        echo '| Section | Target | Result | Reason |'
        echo '|---|---|---:|---|'
        tail -n +2 "$REPORT/sections.tsv" | while IFS=$'\t' read -r section target display rc reason child_report; do
            printf '| %s | %s | %s | %s |\n' "$section" "$target" "$display" "$reason"
        done
    } > "$REPORT/sections.md"
}

run_distributed_sections() {
    local -a sections=(smoke) functional=(tls-policy routing transfer quic tcp-churn udp-churn capture corpus-regular corpus-edge corpus-insanity)
    local -a fuzz_sections=() main_sections=() batch_pids=()
    local -A target_manifest=()
    local section fuzz_category target target_label manifest seeds output rc_file rc display child_report reason
    local any_fail=0 any_flaky=0 index=0 batch_rc=0
    local bundle_local="$WORK_DIR/coordinator-bundle-$RUN_ID"
    local bundle_remote="$WORK_DIR/coordinator-bundle-$RUN_ID"
    local manifest_dir="$bundle_local/manifests"

    for section in "${FUZZ_AREAS[@]}"; do
        if [[ $section == h1 || $section == h2 ]]; then
            for fuzz_category in regular edge insanity; do fuzz_sections+=("fuzz.$section.$fuzz_category"); done
        else
            fuzz_sections+=("fuzz.$section")
        fi
    done
    if [[ $PROFILE == full ]]; then
        sections+=(rtt tls-throughput "${functional[@]}" "${fuzz_sections[@]}")
        main_sections=("${functional[@]}" "${fuzz_sections[@]}")
    else
        sections+=("${fuzz_sections[@]}")
        main_sections=("${fuzz_sections[@]}")
    fi

    mkdir -p "$REPORT/sections" "$REPORT/targets" "$WORK_DIR/sections" \
        "$bundle_local/tests" "$bundle_local/etc/msg" "$bundle_local/tools/wireshark" \
        "$bundle_local/tests/docs" "$bundle_local/build" "$manifest_dir"
    : > "$REPORT/test.log"
    printf 'section\ttarget\tresult\trc\treason\treport\n' > "$REPORT/sections.tsv"

    if [[ $PROFILE == full ]]; then
        echo 'SECTION START: native target=local-coordinator'
        set +e
        run_native_tests 0 > "$REPORT/sections/native.log" 2>&1
        rc=$?
        set -e
        if ((rc != 0)); then
            reason=$(grep -E '(^FAIL|failure|FAILED|[Ee]rror)' "$REPORT/sections/native.log" | tail -1 || true)
            [[ -n $reason ]] || reason="native tests exited with rc=$rc"
            printf 'native\tlocal-coordinator\tFAIL\t%s\t%s\t%s\n' \
                "$rc" "$reason" "$REPORT/native" >> "$REPORT/sections.tsv"
            { echo '===== section: native target=local-coordinator (FAIL) ====='; cat "$REPORT/sections/native.log"; } >> "$REPORT/test.log"
            echo "SECTION DONE: native target=local-coordinator rc=$rc"
            write_sections_markdown
            STATUS=FAIL
            TEST_RC=1
            return
        fi
        printf 'native\tlocal-coordinator\tPASS\t0\tall checks passed\t%s\n' \
            "$REPORT/native" >> "$REPORT/sections.tsv"
        { echo '===== section: native target=local-coordinator (PASS) ====='; cat "$REPORT/sections/native.log"; echo; } >> "$REPORT/test.log"
        echo 'SECTION DONE: native target=local-coordinator rc=0'
    fi

    cp -a "$HERE" "$bundle_local/tests/patch-runner"
    cp "$ROOT/etc/smithproxy.cfg" "$bundle_local/etc/"
    cp -a "$ROOT/etc/msg/en" "$bundle_local/etc/msg/"
    cp "$ROOT/tools/wireshark/spquic.lua" "$bundle_local/tools/wireshark/"
    cp "$FUZZ_SEED_REGISTRY" "$bundle_local/tests/docs/covered-seeds"
    cp "$BUILD_DIR/smithproxy" "$bundle_local/build/smithproxy"
    chmod 0555 "$bundle_local/build/smithproxy"
    if [[ $PROFILE == full ]]; then
        quic_curl_prefix=${CURL_HTTP3_PREFIX:-$ROOT/../curl-http3}
        quic_python_prefix=${QUIC_PYTHON_PREFIX:-$ROOT/../quic-python}
        [[ -x $quic_curl_prefix/bin/curl-h3 ]] || {
            echo "Missing HTTP/3 curl: $quic_curl_prefix/bin/curl-h3" >&2
            STATUS=FAIL; TEST_RC=2
            return
        }
        [[ -f $quic_python_prefix/aioquic/__init__.py ]] || {
            echo "Missing QUIC Python runtime: $quic_python_prefix (run $HERE/prepare-quic-runtime.sh)" >&2
            STATUS=FAIL; TEST_RC=2
            return
        }
        cp -a "$quic_curl_prefix" "$bundle_local/curl-http3"
        cp -a "$quic_python_prefix" "$bundle_local/quic-python"
    else
        mkdir -p "$bundle_local/curl-http3"
    fi
    {
        printf 'PATCH_RUN_COMMIT=%q\n' "$COMMIT"
        printf 'PATCH_RUN_BRANCH=%q\n' "$BRANCH"
        printf 'PATCH_RUN_DIRTY=%q\n' "$DIRTY"
        printf 'PATCH_RUN_FUZZ_LEVEL=%q\n' "${FUZZ_LEVEL:-245}"
        printf 'PATCH_RUN_ENV_ARGS=('
        for variable in "${EXTRA_ENV[@]}"; do printf ' --env %q' "$variable"; done
        printf ' )\n'
    } > "$bundle_local/coordinator-config.sh"

    fuzz_seeds_for() {
        local name=$1 area supplied=
        area=${name#fuzz.}; area=${area%%.*}
        for variable in "${EXTRA_ENV[@]}"; do
            [[ $variable != FUZZ_SEEDS=* ]] || supplied=${variable#FUZZ_SEEDS=}
        done
        if [[ -n $supplied ]]; then
            printf '%s\n' "$supplied"
        elif [[ -n $REQUESTED_FUZZ_SEED ]]; then
            printf '%s\n' "$REQUESTED_FUZZ_SEED"
        elif [[ $PROFILE == fuzz-dyn ]]; then
            printf '%s\n' "$FUZZ_DYNAMIC_SEED"
        else
            python3 "$HERE/fuzz-seeds.py" "$FUZZ_SEED_REGISTRY" "$area" \
                --recent "${FUZZ_RECENT_SEEDS:-4}" --archive "${FUZZ_ARCHIVE_SEEDS:-4}" \
                --rotation-days "${FUZZ_ROTATION_DAYS:-7}" \
                --min-age-days "${FUZZ_SEED_MIN_AGE_DAYS:-1}"
        fi
    }

    for index in "${!TARGETS[@]}"; do
        target=${TARGETS[$index]}
        target_label=$(printf '%s-%s' "$index" "${target//[^A-Za-z0-9_.-]/_}")
        manifest="$manifest_dir/main-$target_label.tsv"
        : > "$manifest"
        target_manifest[$target]=$manifest
    done
    printf 'smoke\tsmoke\t-\n' > "$manifest_dir/smoke.tsv"
    printf '%s\n' "${TARGETS[0]}" > "$REPORT/sections/smoke.target"
    if [[ $PROFILE == full ]]; then
        printf 'rtt\trtt\t-\n' > "$manifest_dir/rtt.tsv"
        printf '%s\n' "${TARGETS[0]}" > "$REPORT/sections/rtt.target"
        printf 'tls-throughput\ttls-throughput\t-\n' > "$manifest_dir/tls-throughput.tsv"
        printf '%s\n' "${TARGETS[0]}" > "$REPORT/sections/tls-throughput.target"
    fi
    index=0
    for section in "${main_sections[@]}"; do
        target=${TARGETS[$((index % ${#TARGETS[@]}))]}
        seeds=-
        [[ $section != fuzz.* ]] || seeds=$(fuzz_seeds_for "$section")
        printf '%s\t%s\t%s\n' "$section" "$section" "$seeds" >> "${target_manifest[$target]}"
        printf '%s\n' "$target" > "$REPORT/sections/$section.target"
        [[ $section != fuzz.* ]] || printf '%s\n' "$seeds" > "$REPORT/sections/$section.seeds"
        ((index += 1))
    done

    for target in "${TARGETS[@]}"; do
        [[ $target != local ]] || continue
        target_label=${target//[^A-Za-z0-9_.-]/_}
        set +e
        tar -C "$bundle_local" -cf - . | \
            ssh "$target" "mkdir -p '$bundle_remote' && tar -C '$bundle_remote' -xf -" \
            > "$REPORT/targets/stage-$target_label.log" 2>&1
        rc=${PIPESTATUS[1]}
        set -e
        if ((rc != 0)); then
            reason=$(tail -1 "$REPORT/targets/stage-$target_label.log" || true)
            printf 'stage-bundle\t%s\tFAIL\t%s\t%s\t%s\n' "$target" "$rc" "${reason:-remote bundle staging failed}" "$REPORT/targets/stage-$target_label.log" >> "$REPORT/sections.tsv"
            STATUS=FAIL; TEST_RC=1
            return
        fi
    done

    run_batch() {
        local worker_target=$1 batch=$2 jobs=$3 concurrency=$4
        local label=${worker_target//[^A-Za-z0-9_.-]/_}
        local remote_manifest="$bundle_remote/manifests/$(basename "$jobs")"
        local output_dir="$WORK_DIR/coordinator/$batch-$label"
        local archive="$WORK_DIR/coordinator/$batch-$label.tar"
        local transport_log="$REPORT/targets/$batch-$label.log"
        local command scheduler_rc=0 fetch_rc=0 line job
        if [[ $worker_target == local ]]; then
            "$bundle_local/tests/patch-runner/remote-scheduler.sh" \
                "$bundle_local" "$WORK_DIR" "$jobs" "$concurrency" "$output_dir" \
                > "$transport_log" 2>&1 || scheduler_rc=$?
        else
            printf -v command '%q ' "$bundle_remote/tests/patch-runner/remote-scheduler.sh" \
                "$bundle_remote" "$WORK_DIR" "$remote_manifest" "$concurrency" "$output_dir"
            if [[ $worker_target == root@* ]]; then
                ssh "$worker_target" "$command" > "$transport_log" 2>&1 || scheduler_rc=$?
            else
                ssh "$worker_target" "sudo $command" > "$transport_log" 2>&1 || scheduler_rc=$?
            fi
            if ((scheduler_rc == 0)); then
                mkdir -p "$WORK_DIR/coordinator"
                scp "$worker_target:$archive" "$archive" >> "$transport_log" 2>&1 || fetch_rc=$?
                if ((fetch_rc == 0)); then
                    tar -C "$WORK_DIR" -xf "$archive" || fetch_rc=$?
                fi
            fi
        fi
        batch_rc=$((scheduler_rc != 0 ? scheduler_rc : fetch_rc))
        while IFS=$'\t' read -r job _; do
            [[ -n $job ]] || continue
            if [[ ! -f $output_dir/$job.rc ]]; then
                printf '%s\n' "${batch_rc:-255}" > "$REPORT/sections/$job.rc"
                { echo "remote scheduler transport failed rc=${batch_rc:-255}"; cat "$transport_log"; } > "$REPORT/sections/$job.log"
            else
                cp "$output_dir/$job.rc" "$REPORT/sections/$job.rc"
                cp "$output_dir/$job.log" "$REPORT/sections/$job.log"
            fi
        done < "$jobs"
        return 0
    }

    echo "SECTION START: smoke target=${TARGETS[0]}"
    run_batch "${TARGETS[0]}" smoke "$manifest_dir/smoke.tsv" 1
    rc=$(<"$REPORT/sections/smoke.rc")
    echo "SECTION DONE: smoke target=${TARGETS[0]} rc=$rc"
    if ((rc != 0)); then
        any_fail=1
    else
        if [[ $PROFILE == full ]]; then
            echo "SECTION START: rtt target=${TARGETS[0]} (exclusive)"
            run_batch "${TARGETS[0]}" rtt "$manifest_dir/rtt.tsv" 1
            rc=$(<"$REPORT/sections/rtt.rc")
            echo "SECTION DONE: rtt target=${TARGETS[0]} rc=$rc"
            echo "SECTION START: tls-throughput target=${TARGETS[0]} (exclusive, measurement only)"
            run_batch "${TARGETS[0]}" tls-throughput "$manifest_dir/tls-throughput.tsv" 1
            rc=$(<"$REPORT/sections/tls-throughput.rc")
            echo "SECTION DONE: tls-throughput target=${TARGETS[0]} rc=$rc"
        fi
        for target in "${TARGETS[@]}"; do
            manifest=${target_manifest[$target]}
            [[ -s $manifest ]] || continue
            target_label=${target//[^A-Za-z0-9_.-]/_}
            run_batch "$target" main "$manifest" "$PARALLEL" &
            batch_pids+=("$!")
        done
        for pid in "${batch_pids[@]}"; do wait "$pid" || true; done
    fi

    for section in "${sections[@]}"; do
        output="$REPORT/sections/$section.log"
        rc_file="$REPORT/sections/$section.rc"
        target=$(<"$REPORT/sections/$section.target")
        if [[ ! -f $rc_file ]]; then
            printf '%s\n' SKIP > "$REPORT/sections/$section.status"
            printf '%s\t%s\tSKIP\t-\tblocked by smoke failure\t-\n' "$section" "$target" >> "$REPORT/sections.tsv"
            continue
        fi
        rc=$(<"$rc_file")
        child_report=$(find "$WORK_DIR/sections/$section/results" -mindepth 1 -maxdepth 1 -type d -print 2>/dev/null | sort | tail -1 || true)
        reason=
        if ((rc != 0)); then
            display=FAIL; any_fail=1
            [[ -z $child_report || ! -f $child_report/failure.txt ]] || reason=$(sed -n 's/^reason: //p' "$child_report/failure.txt" | head -1)
            [[ -n $reason ]] || reason=$(grep -E '(^FAIL[46]?:|FAIL:|Traceback|AssertionError|[Ee]rror|failed)' "$output" | tail -1 || true)
            [[ -n $reason ]] || reason="section exited with rc=$rc"
            reason=${reason//$'\r'/}
        elif grep -Eq 'flaky=[1-9][0-9]*|FLAKY_PASS' "$output"; then
            display=FLAKY_PASS; any_flaky=1
            reason=$(grep -E 'flaky=[1-9][0-9]*|FLAKY_PASS' "$output" | tail -1)
        else
            display=PASS; reason='all checks passed'
        fi
        printf '%s\n' "$display" > "$REPORT/sections/$section.status"
        printf '%s\t%s\t%s\t%s\t%s\t%s\n' "$section" "$target" "$display" "$rc" "$reason" "${child_report:--}" >> "$REPORT/sections.tsv"
        { echo "===== section: $section target=$target ($display) ====="; cat "$output"; echo; } >> "$REPORT/test.log"
    done

    if [[ -f $REPORT/sections/corpus-regular.rc ]]; then
        CORPUS_SELECTED=$(grep -hE '^family=IPv[46] ' "$REPORT/sections/"corpus-*.log 2>/dev/null | \
            awk '{for (i=1;i<=NF;i++) if ($i ~ /^(passed|flaky|failed|xfailed)=/) {split($i,a,"="); n+=a[2]}} END {print n+0}') || CORPUS_SELECTED=0
        if ((CORPUS_SELECTED == 0)); then
            any_fail=1
            printf 'corpus-selection\t-\tFAIL\t2\tno corpus case matched MATCH/EXCLUDE\t-\n' >> "$REPORT/sections.tsv"
        fi
    fi
    write_sections_markdown
    if ((any_fail)); then STATUS=FAIL; TEST_RC=1
    elif ((any_flaky)); then STATUS=FLAKY_PASS; TEST_RC=0
    else STATUS=PASS; TEST_RC=0
    fi
}

BUILD_RC=0
if [[ $PROFILE == native || $PROFILE == coverage ]]; then
    echo "Build and test execution delegated to native-tests.sh" > "$REPORT/build.log"
elif ((SKIP_BUILD == 0)); then
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
elif [[ $PROFILE == native || $PROFILE == coverage ]]; then
    native_coverage=0
    [[ $PROFILE != coverage ]] || native_coverage=1
    set +e
    run_native_tests "$native_coverage" \
        > "$REPORT/test.log" 2>&1
    TEST_RC=$?
    set -e
    if [[ $PROFILE == coverage && $TEST_RC == 0 ]]; then
        {
            echo
            echo '===== instrumented local dataplane sanity ====='
        } >> "$REPORT/test.log"
        set +e
        "$HERE/test-patch.sh" sanity --local --worker --quiet --skip-build \
            --build-dir "$WORK_DIR/coverage-build" \
            --dir "$WORK_DIR/coverage-dataplane" \
            >> "$REPORT/test.log" 2>&1
        TEST_RC=$?
        set -e
        if ((TEST_RC == 0)); then
            python3 "$HERE/coverage-report.py" \
                --source-root "$ROOT" --build-dir "$WORK_DIR/coverage-build" \
                --output-dir "$REPORT/native/coverage" \
                >> "$REPORT/test.log" 2>&1
        fi
    fi
    if ((TEST_RC == 0)); then
        STATUS=PASS
        cat "$REPORT/test.log"
    else
        STATUS=FAIL
        tail -80 "$REPORT/test.log" >&2
    fi
elif [[ ( $PROFILE == full || $PROFILE == fuzz || $PROFILE == fuzz-dyn ) && -z $ONLY_SUITE ]]; then
    run_distributed_sections
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
    QUIC_CURL_PREFIX=${CURL_HTTP3_PREFIX:-$ROOT/../curl-http3}
    QUIC_PYTHON_PREFIX=${QUIC_PYTHON_PREFIX:-$ROOT/../quic-python}
    QUIC_PYTHONPATH=$QUIC_PYTHON_PREFIX
    [[ -z $REMOTE ]] || QUIC_PYTHONPATH=$LAB_ROOT/quic-python

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
        if [[ $ONLY_SUITE == quic ]]; then
            [[ -x $QUIC_CURL_PREFIX/bin/curl-h3 ]] || {
                echo "Missing HTTP/3 curl: $QUIC_CURL_PREFIX/bin/curl-h3" >&2
                exit 2
            }
            [[ -f $QUIC_PYTHON_PREFIX/aioquic/__init__.py ]] || {
                echo "Missing QUIC Python runtime: $QUIC_PYTHON_PREFIX (run $HERE/prepare-quic-runtime.sh)" >&2
                exit 2
            }
            ssh "$REMOTE" "mkdir -p '$LAB_ROOT/curl-http3' '$LAB_ROOT/quic-python' '$LAB_ROOT/runner/tools'"
            scp -r "$QUIC_CURL_PREFIX/." "$REMOTE:$LAB_ROOT/curl-http3/" >/dev/null
            scp -r "$QUIC_PYTHON_PREFIX/." "$REMOTE:$LAB_ROOT/quic-python/" >/dev/null
            scp "$ROOT/tools/wireshark/spquic.lua" \
                "$REMOTE:$LAB_ROOT/runner/tools/spquic.lua" >/dev/null
        fi
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
        if [[ $ONLY_SUITE == quic ]]; then
            [[ -x $QUIC_CURL_PREFIX/bin/curl-h3 ]] || {
                echo "Missing HTTP/3 curl: $QUIC_CURL_PREFIX/bin/curl-h3" >&2
                exit 2
            }
            [[ -f $QUIC_PYTHON_PREFIX/aioquic/__init__.py ]] || {
                echo "Missing QUIC Python runtime: $QUIC_PYTHON_PREFIX (run $HERE/prepare-quic-runtime.sh)" >&2
                exit 2
            }
            mkdir -p "$LAB_ROOT/curl-http3" "$LAB_ROOT/runner/tools"
            cp -a "$QUIC_CURL_PREFIX/." "$LAB_ROOT/curl-http3/"
            cp "$ROOT/tools/wireshark/spquic.lua" "$LAB_ROOT/runner/tools/spquic.lua"
        fi
    fi

    LAB_ENV=(
        "CLIENT_NS=$CLIENT_NS" "SERVER_NS=$SERVER_NS" "DATA_NS=$DATA_NS"
        "LAB_IN_IF=$IN_IF" "LAB_OUT_IF=$OUT_IF" "LAB_API_PORT=$API_PORT" "LAB_CLI_PORT=$CLI_PORT"
        "CAPTURE_TEST=1" "HTTP2_OBSERVABILITY_TEST=1" "CAPTURE_MATRIX_TEST=1" "RTT_TEST=1" "TLS_SUITE_TEST=1" "TLS_TRANSFER_TEST=0" "TLS_THROUGHPUT_TEST=0" "STARTTLS_SUITE_TEST=1" "POLICY_TEST=1" "ROUTING_TEST=1" "SESSION_LIST_STRESS_TEST=1"
        "PPLAY_PY=$LAB_ROOT/pplay.py" "PPLAY_SUITE=$LAB_ROOT/corpus"
        "PPLAY_RESULTS_NAME=corpus-all" "PPLAY_SMOKE_TEST=1"
    )
    for variable in RTT_SAMPLES RTT_HANDSHAKE_SAMPLES RTT_WARMUP \
        RTT_TLS_TOTAL_P50_LIMIT_MS RTT_TLS_TOTAL_P50_FLAKY_LIMIT_MS \
        RTT_HTTPS_P50_LIMIT_MS RTT_HTTPS_P50_FLAKY_LIMIT_MS \
        RTT_P95_LIMIT_MS RTT_MAX_LIMIT_MS \
        RTT_HANDSHAKE_P95_LIMIT_MS RTT_HANDSHAKE_MAX_LIMIT_MS \
        SESSION_LIST_CONNECTIONS SESSION_LIST_SAMPLES \
        SESSION_LIST_P95_LIMIT_MS SESSION_LIST_MAX_LIMIT_MS \
        TCP_CHURN_PARALLEL \
        TLS_TRANSFER_BYTES TLS_TRANSFER_REPEATS TLS_TRANSFER_CONCURRENCY \
        TLS_THROUGHPUT_BYTES TLS_THROUGHPUT_REPEATS TLS_THROUGHPUT_CONCURRENCY \
        CHURN_MIN_PORT CHURN_MAX_PORT; do
        [[ -z ${!variable:-} ]] || LAB_ENV+=("$variable=${!variable}")
    done
    if [[ $PROFILE == benchmark ]]; then
        LAB_ENV+=("CAPTURE_TEST=0" "HTTP2_OBSERVABILITY_TEST=0" "CAPTURE_MATRIX_TEST=0"
            "TLS_SUITE_TEST=0" "STARTTLS_SUITE_TEST=0" "POLICY_TEST=0" "ROUTING_TEST=0" "SESSION_LIST_STRESS_TEST=0" "RTT_TEST=1" "RTT_REPORT_ONLY=1"
            "RTT_NATIVE_BASELINE=1"
            "PPLAY_SMOKE_TEST=0" "PPLAY_SUITE_SKIP_RUN=1")
    fi
    if [[ $PROFILE == run ]]; then
        LAB_ENV+=("RUN_MODE=1" "CAPTURE_TEST=0" "HTTP2_OBSERVABILITY_TEST=0"
            "CAPTURE_MATRIX_TEST=0" "TLS_SUITE_TEST=0" "STARTTLS_SUITE_TEST=0" "POLICY_TEST=0" "ROUTING_TEST=0" "SESSION_LIST_STRESS_TEST=0" "RTT_TEST=0"
            "PPLAY_SMOKE_TEST=0" "PPLAY_SUITE_SKIP_RUN=1")
    fi
    if [[ -n $ONLY_SUITE ]]; then
        LAB_ENV+=("BASE_TRAFFIC_TEST=1" "CAPTURE_TEST=0" "HTTP2_OBSERVABILITY_TEST=0" "CAPTURE_MATRIX_TEST=0" "RTT_TEST=0" "TLS_SUITE_TEST=0" "TLS_TRANSFER_TEST=0" "TLS_THROUGHPUT_TEST=0" "STARTTLS_SUITE_TEST=0" "POLICY_TEST=0" "ROUTING_TEST=0" "SESSION_LIST_STRESS_TEST=0" "TCP_CHURN_TEST=0" "UDP_CHURN_TEST=0" "PPLAY_SMOKE_TEST=0" "PPLAY_SUITE_SKIP_RUN=1")
        case "$ONLY_SUITE" in
            tls) LAB_ENV+=("TLS_SUITE_TEST=1") ;;
            transfer) LAB_ENV+=("TLS_TRANSFER_TEST=1") ;;
            tls-throughput) LAB_ENV+=("BASE_TRAFFIC_TEST=0" "TLS_THROUGHPUT_TEST=1") ;;
            starttls) LAB_ENV+=("STARTTLS_SUITE_TEST=1") ;;
            policy) LAB_ENV+=("POLICY_TEST=1") ;;
            routing) LAB_ENV+=("ROUTING_TEST=1") ;;
            rtt) LAB_ENV+=("RTT_TEST=1") ;;
            session-list) LAB_ENV+=("SESSION_LIST_STRESS_TEST=1") ;;
            quic) LAB_ENV+=("QUIC_TEST=1" "QUIC_LAB=1" "QUIC_KEYLOG_TEST=1"
                "QUIC_CURL_BIN=$LAB_ROOT/curl-http3/bin/curl-h3"
                "QUIC_PYTHONPATH=$QUIC_PYTHONPATH"
                "SPQ1_DISSECTOR=$LAB_ROOT/runner/tools/spquic.lua") ;;
            smoke) LAB_ENV+=("PPLAY_SMOKE_TEST=1") ;;
            tls-policy) LAB_ENV+=("BASE_TRAFFIC_TEST=0" "TLS_SUITE_TEST=1" "POLICY_TEST=1" "SESSION_LIST_STRESS_TEST=1") ;;
            tcp-churn) LAB_ENV+=("BASE_TRAFFIC_TEST=0" "TCP_CHURN_TEST=1") ;;
            udp-churn) LAB_ENV+=("BASE_TRAFFIC_TEST=0" "UDP_CHURN_TEST=1") ;;
            capture) LAB_ENV+=("CAPTURE_TEST=1" "HTTP2_OBSERVABILITY_TEST=1" "CAPTURE_MATRIX_TEST=1") ;;
            corpus-regular) LAB_ENV+=("BASE_TRAFFIC_TEST=0" "PPLAY_SUITE_SKIP_RUN=0" "PPLAY_SUITE_CATEGORY=regular" "PPLAY_RESULTS_NAME=corpus-regular" "PPLAY_SUITE_EXCLUDE=capture_*" "PPLAY_SUITE_ALLOW_EMPTY=1") ;;
            corpus-edge) LAB_ENV+=("BASE_TRAFFIC_TEST=0" "PPLAY_SUITE_SKIP_RUN=0" "PPLAY_SUITE_CATEGORY=edge" "PPLAY_RESULTS_NAME=corpus-edge" "PPLAY_SUITE_EXCLUDE=capture_*" "PPLAY_SUITE_ALLOW_EMPTY=1") ;;
            corpus-insanity) LAB_ENV+=("BASE_TRAFFIC_TEST=0" "PPLAY_SUITE_SKIP_RUN=0" "PPLAY_SUITE_CATEGORY=insanity" "PPLAY_RESULTS_NAME=corpus-insanity" "PPLAY_SUITE_EXCLUDE=capture_*" "PPLAY_SUITE_ALLOW_EMPTY=1") ;;
            fuzz.*)
                fuzz_spec=${ONLY_SUITE#fuzz.}
                fuzz_area=${fuzz_spec%%.*}
                fuzz_category=all
                [[ $fuzz_spec != *.* ]] || fuzz_category=${fuzz_spec#*.}
                LAB_ENV+=("BASE_TRAFFIC_TEST=0" "PPLAY_SUITE_SKIP_RUN=0"
                    "PPLAY_SUITE_CATEGORY=$fuzz_category" "PPLAY_RESULTS_NAME=$ONLY_SUITE"
                    "PPLAY_FUZZ_AREA=$fuzz_area"
                    "PPLAY_SUITE_EXCLUDE=capture_*" "PPLAY_SUITE_ALLOW_EMPTY=0"
                    "FUZZ_LEVEL=${FUZZ_LEVEL:-245}" "FUZZ_SCATTER=${FUZZ_SCATTER:-1}")
                ;;
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
                2>&1 | tee "$REPORT/test.log" | grep --line-buffered -E '(^PASS[46]? |^FAIL[46]?:| (PASS|FLAKY_PASS|FAIL|XFAIL|XPASS)[46]?$|^(TCP churn:|UDP churn:|TLS transfer:|TLS throughput:|family=IPv|Capture matrix summary:|RTT summary:|Session-list summary:)|^RESULT:)'
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
                2>&1 | tee "$REPORT/test.log" | grep --line-buffered -E '(^PASS[46]? |^FAIL[46]?:| (PASS|FLAKY_PASS|FAIL|XFAIL|XPASS)[46]?$|^(TCP churn:|UDP churn:|TLS transfer:|TLS throughput:|family=IPv|Capture matrix summary:|RTT summary:|Session-list summary:)|^RESULT:)'
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
    elif ((TEST_RC == 0)) && grep -q 'FLAKY_PASS' "$REPORT/test.log" 2>/dev/null; then
        STATUS=FLAKY_PASS
    elif ((TEST_RC == 0)); then STATUS=PASS; else STATUS=FAIL; fi
fi

TCP_SUMMARY=$(grep -E '^TCP churn:' "$REPORT/test.log" 2>/dev/null | tail -2 | paste -sd ';' - || true)
UDP_SUMMARY=$(grep -E '^UDP churn:' "$REPORT/test.log" 2>/dev/null | tail -2 | paste -sd ';' - || true)
CORPUS_SUMMARY=$(grep -E '^(family=IPv[46] )?passed=' "$REPORT/test.log" 2>/dev/null | tail -2 | paste -sd ';' - || true)
CAPTURE_MATRIX_SUMMARY=$(grep -E '^Capture matrix summary:' "$REPORT/test.log" 2>/dev/null | tail -2 | paste -sd ';' - || true)
RTT_SUMMARY=$(grep -E '^RTT summary:' "$REPORT/test.log" 2>/dev/null | tail -2 | paste -sd ';' - || true)
TLS_TRANSFER_SUMMARY=$(grep -E '^TLS transfer:' "$REPORT/test.log" 2>/dev/null | paste -sd ';' - || true)
TLS_THROUGHPUT_SUMMARY=$(grep -E '^TLS throughput:' "$REPORT/test.log" 2>/dev/null | paste -sd ';' - || true)
FUZZ_SEED_SUMMARY=
if compgen -G "$REPORT/sections/fuzz.*.seeds" >/dev/null; then
    FUZZ_SEED_SUMMARY=$(cat "$REPORT"/sections/fuzz.*.seeds | tr ',' '\n' | sed '/^$/d' | sort -u | paste -sd, -)
elif [[ -n ${focused_fuzz_seeds:-} ]]; then
    FUZZ_SEED_SUMMARY=$focused_fuzz_seeds
elif [[ -n $FUZZ_DYNAMIC_SEED ]]; then
    FUZZ_SEED_SUMMARY=$FUZZ_DYNAMIC_SEED
fi

FAIL_REASON=
FAIL_LIKELY=
if [[ $STATUS == FAIL ]]; then
    if ((BUILD_RC != 0)); then
        FAIL_REASON="smithproxy build exited with rc=$BUILD_RC"
    elif [[ -f $REPORT/sections.tsv ]]; then
        FAIL_REASON=$(awk -F '\t' '$3 == "FAIL" {print $1 "@" $2 ": " $5; exit}' "$REPORT/sections.tsv")
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
if [[ $PROFILE == fuzz-dyn && -z $REQUESTED_FUZZ_SEED ]]; then
    printf -v REPRO_SEED ' --seed %q' "$FUZZ_DYNAMIC_SEED"
    REPRO+=$REPRO_SEED
fi
if [[ -n $FAIL_REASON ]]; then
    {
        echo "reason: $FAIL_REASON"
        [[ -z $FAIL_LIKELY ]] || echo "likely: $FAIL_LIKELY"
        echo "test log: $REPORT/test.log"
        echo "reproduce: $REPRO"
    } > "$REPORT/failure.txt"
fi

LINE_COVERAGE=N/A
if [[ -f $REPORT/native/coverage/summary.txt ]]; then
    LINE_COVERAGE=$(sed -n 's/^line coverage: //p' "$REPORT/native/coverage/summary.txt" | head -1)
fi
cat > "$REPORT/summary.md" <<EOF
# Smithproxy patch test

- Result: **$STATUS**
- Profile: $PROFILE
- Suite: ${ONLY_SUITE:-all}
- Commit: $COMMIT
- Dirty working tree: $DIRTY
- Host: $REPORT_HOST
- Build directory: $BUILD_DIR
- Build: $([[ $BUILD_RC == 0 ]] && echo PASS || echo FAIL)
- Line coverage: $LINE_COVERAGE
- TCP churn: ${TCP_SUMMARY:-N/A}
- UDP churn: ${UDP_SUMMARY:-N/A}
- Corpus: ${CORPUS_SUMMARY:-N/A}
- Capture matrix: ${CAPTURE_MATRIX_SUMMARY:-N/A}
- RTT: ${RTT_SUMMARY:-N/A}
- TLS transfer: ${TLS_TRANSFER_SUMMARY:-N/A}
- TLS throughput: ${TLS_THROUGHPUT_SUMMARY:-N/A}
- Dynamic fuzz seed: ${FUZZ_DYNAMIC_SEED:-N/A}
- Fuzz seeds exercised: ${FUZZ_SEED_SUMMARY:-N/A}
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
    echo "line coverage: $LINE_COVERAGE"
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
  "suite": "${ONLY_SUITE//\"/\\\"}",
  "commit": "$COMMIT",
  "dirty": $DIRTY,
  "host": "$REPORT_HOST",
  "fuzz_seed": "$FUZZ_DYNAMIC_SEED",
  "fuzz_seeds": "$FUZZ_SEED_SUMMARY",
  "build_rc": $BUILD_RC,
  "test_rc": $TEST_RC,
  "reason": "${FAIL_REASON//\"/\\\"}",
  "likely": "${FAIL_LIKELY//\"/\\\"}",
  "tcp_churn": "${TCP_SUMMARY//\"/\\\"}",
  "udp_churn": "${UDP_SUMMARY//\"/\\\"}",
  "corpus": "${CORPUS_SUMMARY//\"/\\\"}",
  "capture_matrix": "${CAPTURE_MATRIX_SUMMARY//\"/\\\"}",
  "rtt": "${RTT_SUMMARY//\"/\\\"}",
  "tls_transfer": "${TLS_TRANSFER_SUMMARY//\"/\\\"}",
  "tls_throughput": "${TLS_THROUGHPUT_SUMMARY//\"/\\\"}",
  "line_coverage": "${LINE_COVERAGE//\"/\\\"}"
}
EOF

HISTORY_RECORDED=0
SEED_RECORDED=0
if ((INTERNAL_WORKER == 0 && TEST_RC == 0)); then
    if [[ $PROFILE == fuzz-dyn && -z $ONLY_SUITE && $STATUS == PASS ]]; then
        exec 9>>"$FUZZ_SEED_REGISTRY"
        flock -x 9
        if ! awk -F '\t' -v seed="$FUZZ_DYNAMIC_SEED" '$0 !~ /^#/ && $2 == seed {found=1} END {exit !found}' "$FUZZ_SEED_REGISTRY"; then
            printf '%s\t%s\t%s\tcovered\n' "$(date -u +%F)" "$FUZZ_DYNAMIC_SEED" "$FUZZ_GENERATOR_VERSION" >&9
            SEED_RECORDED=1
        fi
        flock -u 9
        exec 9>&-
    fi

    if [[ -f $REPORT/sections.tsv ]]; then
        RUN_COVERAGE=$(awk -F '\t' 'NR > 1 {printf "%s%s=%s", sep, $1, $3; sep=","}' "$REPORT/sections.tsv")
    elif [[ -n $ONLY_SUITE ]]; then
        RUN_COVERAGE=$ONLY_SUITE
    else
        case "$PROFILE" in
            quick) RUN_COVERAGE='build:smithproxy' ;;
            native) RUN_COVERAGE='native:ctest,integration,quic,selftests' ;;
            coverage) RUN_COVERAGE='coverage:native,dataplane-sanity,gcov,line-html' ;;
            sanity) RUN_COVERAGE='sanity:dual-stack,tls,policy,rtt,http1,http2,udp,capture,cleanup' ;;
            benchmark) RUN_COVERAGE='benchmark:tcp,udp,tls' ;;
            run) RUN_COVERAGE='interactive-lab' ;;
            *) RUN_COVERAGE=$PROFILE ;;
        esac
    fi
    [[ -z $FUZZ_SEED_SUMMARY ]] || RUN_COVERAGE="$RUN_COVERAGE;seeds=$FUZZ_SEED_SUMMARY"
    RUN_COVERAGE=${RUN_COVERAGE//|/\\|}
    HISTORY_COMMIT=${COMMIT:0:12}
    [[ $DIRTY == false ]] || HISTORY_COMMIT="$HISTORY_COMMIT+dirty"
    HISTORY_TIME=$(date -u +%FT%TZ)
    HISTORY_TARGETS=()
    HISTORY_REMOTE_INDEX=0
    for target in "${TARGETS[@]}"; do
        if [[ $target == local ]]; then
            HISTORY_TARGETS+=(local)
        else
            ((HISTORY_REMOTE_INDEX += 1))
            HISTORY_TARGETS+=("remote-$HISTORY_REMOTE_INDEX")
        fi
    done
    HISTORY_HOST=$(IFS=,; echo "${HISTORY_TARGETS[*]}")
    exec 9>>"$ROOT/tests/docs/patch-run-history"
    flock -x 9
    printf '| %s | `%s` | %s | `%s%s` | `%s` | %s | `%s` |\n' \
        "$HISTORY_TIME" "$HISTORY_COMMIT" "$STATUS" "$PROFILE" "${ONLY_SUITE:+/$ONLY_SUITE}" \
        "$HISTORY_HOST" "$RUN_COVERAGE" "$REPORT" >&9
    HISTORY_RECORDED=1
    flock -u 9
    exec 9>&-
fi
((SEED_RECORDED == 0)) || echo "Covered seed recorded: $FUZZ_DYNAMIC_SEED"
((HISTORY_RECORDED == 0)) || echo "Successful run recorded: $ROOT/tests/docs/patch-run-history"

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
        awk -F '\t' 'NR > 1 {printf "%-18s %-18s %-10s %s\n", $1, $2, $3, $5}' "$REPORT/sections.tsv"
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
