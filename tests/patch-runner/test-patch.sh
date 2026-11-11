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
  sanity      Build and run the small isolated smoke gate.
  traffic     Run synthetic protocol, routing, transfer, churn and capture tests.
  lifecycle   Run ProxyNightmare socket/TLS lifecycle scenarios with CPU monitoring.
  corpus      Replay regular, edge and insanity traffic corpora.
  full        Select native, sanity, traffic, lifecycle, corpus and fuzz profiles.
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
  --suite NAME       Run only one suite. Besides tls, transfer, tls-throughput, quic-throughput,
                     starttls, policy, routing,
                     rtt, session-list and quic,
                     distributed sections are available: smoke, privsep, tls-policy, routing,
                     rtt, transfer, tls-throughput, quic, tcp-churn, udp-churn, capture,
                     corpus-CATEGORY[.1-.4] and fuzz.AREA.
                     Use with a test profile.
                     capture runs capture-traffic, capture-pcapng, quic and
                     quic-pcapng as mandatory, separately reported legs.
  --local            Add this computer as an explicit execution target.
  --remote HOST      Add an SSH execution target. Repeat for distributed profiles
                     sections. A root@ target runs directly; others use sudo.
  --env NAME=VALUE   Pass an environment variable to the test lab. Repeatable;
                     supplied values override profile defaults.
  --note TEXT        Add an operational note to the local report. Repeatable;
                     notes are diagnostic and are not published to Git.
  --proxy-nightmare-root DIR
                     Use a prepared ProxyNightmare source/build root instead of
                     the pinned automatic Git checkout used by lifecycle/full.
  --dir DIR          Work root for build, retained labs and results.
                     Default: /var/tmp/smithproxy-patch-runner/
                              <branch>_@_<commit>_<UTC>-<pid>/
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
  --preflight-only   Validate target access and required privileges, then exit.
  --skip-build       Use an existing executable BUILD_DIR/smithproxy.
  --quiet            Print only verdict lines. Complete output remains in logs.
  -h, --help         Show this help and exit.

Common environment variables:
  PATCH_TEST_DIR                 Default work root (overridden by --dir).
  PATCH_TEST_BUILD_DIR           Default build directory.
  PATCH_TEST_RESULTS_DIR         Store reports under this directory.
  PATCH_TEST_JOBS                Default build parallelism.
  PATCH_TEST_BUILD_TYPE          CMake build type (default: RelWithDebInfo;
                                 use Debug for compiled-in trace logging).
  PATCH_TEST_CTEST_JOBS          Native test parallelism. Coverage defaults to
                                 1 to avoid gcov-induced resource contention.
  PATCH_TEST_PARALLEL            Default full-section concurrency (default: 3).
  MATCH                           Comma-separated corpus case-name globs
                                  to include (default: *).
  EXCLUDE                         Comma-separated corpus case-name globs to skip.
  RTT_SAMPLES                    Measured TCP/UDP samples (default: 200).
  RTT_HANDSHAKE_SAMPLES          Fresh TCP/TLS connections (default: 40).
  RTT_WARMUP                     Unreported warm-up exchanges (default: 20).
  RTT_TLS_TOTAL_P50_LIMIT_MS     Sanity/full TLS total-connect P50 gate (default: 10).
  RTT_TLS_TOTAL_P50_FLAKY_LIMIT_MS  TLS total-connect FLAKY_PASS ceiling (default: 17).
  RTT_HTTPS_P50_LIMIT_MS         Sanity/full HTTPS RTT P50 gate (default: 2).
  RTT_HTTPS_P50_FLAKY_LIMIT_MS   HTTPS RTT FLAKY_PASS ceiling (default: 10).
  RTT_P95_LIMIT_MS               General RTT P95 gate (default: 50).
  RTT_MAX_LIMIT_MS               General RTT maximum gate (default: 250).
  RTT_HANDSHAKE_P95_LIMIT_MS     Handshake P95 gate (default: 500).
  RTT_HANDSHAKE_MAX_LIMIT_MS     Handshake maximum gate (default: 2000).
  QUIC_THROUGHPUT_BYTES          Bytes per H3 flow (default: 8 MiB).
  QUIC_THROUGHPUT_REPEATS        Samples per direction/concurrency (default: 3).
  QUIC_THROUGHPUT_CONCURRENCY    Independent H3 connections (default: 1,4,16).
  QUIC_WORKERS                  QUIC workers per address family (default: 1).
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
[[ $PROFILE == quick || $PROFILE == sanity || $PROFILE == traffic || $PROFILE == lifecycle || $PROFILE == corpus || $PROFILE == full || $PROFILE == native || $PROFILE == coverage || $PROFILE == fuzz || $PROFILE == fuzz-dyn || $PROFILE == benchmark || $PROFILE == run ]] || {
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
RUN_NOTES=()
CHURN_PORT_RANGE=
INTERNAL_WORKER=0
PREFLIGHT_ONLY=0
TARGETS=()
REQUESTED_FUZZ_SEED=
PROXY_NIGHTMARE_ROOT=${PROXY_NIGHTMARE_ROOT:-}

REMOTE=
SHARED_BINARY=
WORK_DIR=${PATCH_TEST_DIR:-}
JOBS=${PATCH_TEST_JOBS:-$(nproc)}
BUILD_TYPE=${PATCH_TEST_BUILD_TYPE:-RelWithDebInfo}
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
        --proxy-nightmare-root) PROXY_NIGHTMARE_ROOT=${2:?missing ProxyNightmare root}; shift 2 ;;
        --suite) ONLY_SUITE=${2:?missing suite}; shift 2 ;;
        --unique) UNIQUE_LABEL=$(date -I); shift ;;
        --unique=*) UNIQUE_LABEL=${1#--unique=}; shift ;;
        --churn-port-range) CHURN_PORT_RANGE=${2:?missing churn port range}; shift 2 ;;
        --include-external) INCLUDE_EXTERNAL=1; shift ;;
        --include-benchmarks) INCLUDE_BENCHMARKS=1; shift ;;
        --include-extended) INCLUDE_EXTENDED=1; shift ;;
        --include-platform) INCLUDE_PLATFORM=1; shift ;;
        --preflight-only) PREFLIGHT_ONLY=1; shift ;;
        --env)
            [[ ${2:-} =~ ^[A-Za-z_][A-Za-z0-9_]*=.*$ ]] || {
                echo "Invalid --env value: ${2:-<missing>} (expected NAME=VALUE)" >&2
                exit 2
            }
            EXTRA_ENV+=("$2")
            shift 2
            ;;
        --note) RUN_NOTES+=("${2:?missing report note}"); shift 2 ;;
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
[[ -z $ONLY_SUITE || $PROFILE == sanity || $PROFILE == traffic || $PROFILE == lifecycle || $PROFILE == corpus || $PROFILE == full || $PROFILE == fuzz || $PROFILE == fuzz-dyn ]] || {
    echo "--suite is supported only by test profiles" >&2
    exit 2
}
(( ${#TARGETS[@]} > 0 )) || { echo 'Specify an execution target with --local or --remote HOST' >&2; exit 2; }
declare -A SEEN_TARGETS=()
for target in "${TARGETS[@]}"; do
    [[ $target == local || $target =~ ^[A-Za-z0-9_][A-Za-z0-9_.@-]*$ ]] || { echo "Invalid target: $target" >&2; exit 2; }
    [[ -z ${SEEN_TARGETS[$target]:-} ]] || { echo "Duplicate target: $target" >&2; exit 2; }
    SEEN_TARGETS[$target]=1
done
if [[ -n $ONLY_SUITE || ( $PROFILE != full && $PROFILE != traffic && $PROFILE != lifecycle && $PROFILE != corpus && $PROFILE != fuzz && $PROFILE != fuzz-dyn ) ]]; then
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
[[ -z $PROXY_NIGHTMARE_ROOT || $PROXY_NIGHTMARE_ROOT == /* ]] || {
    echo '--proxy-nightmare-root must be an absolute path' >&2
    exit 2
}
[[ $JOBS =~ ^[1-9][0-9]*$ ]] || { echo "Invalid job count: $JOBS" >&2; exit 2; }
[[ $BUILD_TYPE == Debug || $BUILD_TYPE == Release || $BUILD_TYPE == RelWithDebInfo || $BUILD_TYPE == MinSizeRel ]] || {
    echo "Invalid PATCH_TEST_BUILD_TYPE: $BUILD_TYPE" >&2
    exit 2
}
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

# Decide and validate the execution backend before configuring, building or
# staging anything. All remote access and sudo probes are non-interactive, so a
# missing credential or capability fails here instead of hanging inside a test.
declare -A TARGET_BACKEND=()
SSH_OPTIONS=(-o BatchMode=yes -o ConnectTimeout=10 -o ServerAliveInterval=10 -o ServerAliveCountMax=3)
SCP_OPTIONS=(-o BatchMode=yes -o ConnectTimeout=10)

profile_needs_lab_privileges() {
    [[ $PROFILE != quick && ( $PROFILE != native || $INCLUDE_EXTERNAL == 1 ) ]]
}

profile_is_rootless_lifecycle() {
    [[ $PROFILE == lifecycle || $ONLY_SUITE == lifecycle || ( $PROFILE == native && $INCLUDE_EXTERNAL == 1 ) ]]
}

preflight_target() {
    local target=$1 mode backend probe_output
    profile_needs_lab_privileges || {
        TARGET_BACKEND[$target]=unprivileged
        echo "PREFLIGHT target=$target backend=unprivileged result=PASS"
        return
    }
    if profile_is_rootless_lifecycle; then mode=rootless; else mode=privileged; fi

    if [[ $target == local ]]; then
        if [[ $mode == rootless ]]; then
            backend=rootless
            probe_output=$("$HERE/privilege-preflight.sh" rootless 2>&1) || {
                echo "PREFLIGHT target=local backend=rootless result=FAIL" >&2
                echo "$probe_output" >&2
                return 1
            }
        elif ((EUID == 0)); then
            backend=root
            probe_output=$("$HERE/privilege-preflight.sh" privileged 2>&1) || {
                echo "PREFLIGHT target=local backend=root result=FAIL" >&2
                echo "$probe_output" >&2
                return 1
            }
        elif sudo -n true >/dev/null 2>&1; then
            backend=sudo-n
            probe_output=$(sudo -n "$HERE/privilege-preflight.sh" privileged 2>&1) || {
                echo "PREFLIGHT target=local backend=sudo-n result=FAIL" >&2
                echo "$probe_output" >&2
                return 1
            }
        else
            echo 'PREFLIGHT target=local result=FAIL: root or passwordless sudo (sudo -n) is required' >&2
            return 1
        fi
    else
        if [[ $mode == rootless ]]; then
            backend=rootless
            probe_output=$(ssh "${SSH_OPTIONS[@]}" "$target" 'bash -s -- rootless' \
                < "$HERE/privilege-preflight.sh" 2>&1) || {
                echo "PREFLIGHT target=$target backend=rootless result=FAIL" >&2
                echo "$probe_output" >&2
                return 1
            }
        else
            backend=$(ssh "${SSH_OPTIONS[@]}" "$target" \
                'if [ "$(id -u)" -eq 0 ]; then echo root; elif sudo -n true >/dev/null 2>&1; then echo sudo-n; else exit 1; fi' \
                2>/dev/null) || {
                echo "PREFLIGHT target=$target result=FAIL: SSH or non-interactive root access unavailable" >&2
                return 1
            }
            if [[ $backend == root ]]; then
                probe_output=$(ssh "${SSH_OPTIONS[@]}" "$target" 'bash -s -- privileged' \
                    < "$HERE/privilege-preflight.sh" 2>&1) || {
                    echo "PREFLIGHT target=$target backend=root result=FAIL" >&2
                    echo "$probe_output" >&2
                    return 1
                }
            elif [[ $backend == sudo-n ]]; then
                probe_output=$(ssh "${SSH_OPTIONS[@]}" "$target" 'sudo -n bash -s -- privileged' \
                    < "$HERE/privilege-preflight.sh" 2>&1) || {
                    echo "PREFLIGHT target=$target backend=sudo-n result=FAIL" >&2
                    echo "$probe_output" >&2
                    return 1
                }
            else
                echo "PREFLIGHT target=$target result=FAIL: invalid backend '$backend'" >&2
                return 1
            fi
        fi
    fi
    TARGET_BACKEND[$target]=$backend
    echo "PREFLIGHT target=$target backend=$backend mode=$mode result=PASS"
}

if ((INTERNAL_WORKER)); then
    # The coordinator already ran the capability probe on this exact target.
    # Keep only the non-interactive backend selection here; repeating nested
    # mount/net probes in every concurrent section adds noise and races setup.
    if ((EUID == 0)); then
        TARGET_BACKEND[local]=root
    elif sudo -n true >/dev/null 2>&1; then
        TARGET_BACKEND[local]=sudo-n
    else
        echo 'worker backend lost preflighted root or sudo-n access' >&2
        exit 1
    fi
else
    for target in "${TARGETS[@]}"; do preflight_target "$target"; done
    ((PREFLIGHT_ONLY == 0)) || exit 0
fi

FUZZ_AREAS=(h1 h2 tls socks5 dns quic redis mqtt smtp imap pop3 ftp ssh websocket memcached postgresql mysql amqp telnet ntp syslog stun tftp snmp raw)
# shellcheck source=profile-plan.sh
source "$HERE/profile-plan.sh"
case "$ONLY_SUITE" in
    ''|tls|transfer|tls-throughput|quic-throughput|starttls|policy|routing|rtt|session-list|quic|smoke|privsep|tls-policy|tcp-churn|udp-churn|capture|lifecycle|corpus-regular|corpus-edge|corpus-insanity) ;;
    capture-traffic|capture-pcapng|quic-pcapng|corpus-regular.[1-4]|corpus-edge.[1-4]|corpus-insanity.[1-4]) ;;
    quic-cert.*)
        [[ " ${PATCH_RUNNER_QUIC_CERT_SECTIONS[*]} " == *" $ONLY_SUITE "* ]] || {
            echo "Unknown certificate case: $ONLY_SUITE" >&2; exit 2;
        }
        ;;
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
INVOCATION_TAG=$(date -u +%Y%m%dT%H%M%SZ)-$$
WORK_DIR=${WORK_DIR:-/var/tmp/smithproxy-patch-runner/${BRANCH}_@_${SHORT_COMMIT}_$INVOCATION_TAG}
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
REPORT_HOST=${PATCH_TEST_REPORT_HOST:-$(IFS=,; echo "${TARGETS[*]}")}
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

# A single explicit remote target owns the complete run. Keep the coordinator
# responsive by staging the current tree and doing dependency preparation,
# configure, build, native tests and all runtime sections on that host.
if [[ -n $REMOTE && $INTERNAL_WORKER == 0 && ${PATCH_TEST_REMOTE_COORDINATOR:-0} != 1 ]]; then
    exec "$HERE/remote-all.sh" "$REMOTE" "$ROOT" "$WORK_DIR" "$COMMIT" "$BRANCH" "$DIRTY" \
        "$PROFILE" "${ORIGINAL_ARGS[@]}"
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
        echo '| Section | Target | Result | Duration (ms) | Reason |'
        echo '|---|---|---:|---:|---|'
        tail -n +2 "$REPORT/sections.tsv" | while IFS=$'\t' read -r section target display rc reason child_report duration_ms; do
            printf '| %s | %s | %s | %s | %s |\n' "$section" "$target" "$display" \
                "${duration_ms:--}" "$reason"
        done
    } > "$REPORT/sections.md"
}

run_distributed_sections() {
    local -a sections=() main_sections=() batch_pids=()
    local -A target_manifest=()
    local section target target_label manifest seeds output rc_file rc display child_report reason duration_ms
    local started_ns finished_ns
    local any_fail=0 any_flaky=0 index=0 batch_rc=0
    local bundle_local="$WORK_DIR/coordinator-bundle-$RUN_ID"
    local bundle_remote="$WORK_DIR/coordinator-bundle-$RUN_ID"
    local manifest_dir="$bundle_local/manifests"

    if [[ $ONLY_SUITE == lifecycle ]]; then
        sections=(lifecycle)
    elif [[ $ONLY_SUITE == capture ]]; then
        sections=("${PATCH_RUNNER_CAPTURE_SECTIONS[@]}")
    else
        mapfile -t sections < <(patch_runner_profile_sections "$PROFILE")
    fi
    for section in "${sections[@]}"; do
        [[ $section == smoke || $section == rtt || $section == tls-throughput || $section == quic-throughput ]] || main_sections+=("$section")
    done

    mkdir -p "$REPORT/sections" "$REPORT/targets" "$WORK_DIR/sections" \
        "$bundle_local/tests" "$bundle_local/etc/msg" "$bundle_local/tools/wireshark" \
        "$bundle_local/tests/docs" "$bundle_local/build" "$manifest_dir"
    : > "$REPORT/test.log"
    printf 'section\ttarget\tresult\trc\treason\treport\tduration_ms\n' > "$REPORT/sections.tsv"

    if patch_runner_profile_has_native "$PROFILE"; then
        echo 'SECTION START: native target=local-coordinator'
        started_ns=$(date +%s%N)
        set +e
        run_native_tests 0 > "$REPORT/sections/native.log" 2>&1
        rc=$?
        set -e
        finished_ns=$(date +%s%N)
        duration_ms=$(( (finished_ns - started_ns) / 1000000 ))
        if ((rc != 0)); then
            reason=$(grep -E '(^FAIL|failure|FAILED|[Ee]rror)' "$REPORT/sections/native.log" | tail -1 || true)
            [[ -n $reason ]] || reason="native tests exited with rc=$rc"
            printf 'native\tlocal-coordinator\tFAIL\t%s\t%s\t%s\t%s\n' \
                "$rc" "$reason" "$REPORT/native" "$duration_ms" >> "$REPORT/sections.tsv"
            { echo '===== section: native target=local-coordinator (FAIL) ====='; cat "$REPORT/sections/native.log"; } >> "$REPORT/test.log"
            echo "SECTION DONE: native target=local-coordinator rc=$rc"
            write_sections_markdown
            STATUS=FAIL
            TEST_RC=1
            return
        fi
        printf 'native\tlocal-coordinator\tPASS\t0\tall checks passed\t%s\t%s\n' \
            "$REPORT/native" "$duration_ms" >> "$REPORT/sections.tsv"
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
    if [[ " ${sections[*]} " == *" lifecycle "* ]]; then
        mkdir -p "$bundle_local/proxy-nightmare/build"
        cp "$PROXY_NIGHTMARE_ROOT/build/pn" "$bundle_local/proxy-nightmare/build/pn"
        cp "$BUILD_DIR/tests/patch-runner/cpu-monitor/smithproxy-cpu-monitor" \
            "$bundle_local/build/smithproxy-cpu-monitor"
        chmod 0555 "$bundle_local/build/smithproxy-cpu-monitor" "$bundle_local/proxy-nightmare/build/pn"
    fi
    if [[ " ${sections[*]} " == *" quic"* ]]; then
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
    if [[ " ${sections[*]} " == *" smoke "* ]]; then
        printf 'smoke\tsmoke\t-\n' > "$manifest_dir/smoke.tsv"
        printf '%s\n' "${TARGETS[0]}" > "$REPORT/sections/smoke.target"
    fi
    if [[ " ${sections[*]} " == *" rtt "* ]]; then
        printf 'rtt\trtt\t-\n' > "$manifest_dir/rtt.tsv"
        printf '%s\n' "${TARGETS[0]}" > "$REPORT/sections/rtt.target"
    fi
    if [[ " ${sections[*]} " == *" tls-throughput "* ]]; then
        printf 'tls-throughput\ttls-throughput\t-\n' > "$manifest_dir/tls-throughput.tsv"
        printf '%s\n' "${TARGETS[0]}" > "$REPORT/sections/tls-throughput.target"
    fi
    if [[ " ${sections[*]} " == *" quic-throughput "* ]]; then
        printf 'quic-throughput\tquic-throughput\t-\n' > "$manifest_dir/quic-throughput.tsv"
        printf '%s\n' "${TARGETS[0]}" > "$REPORT/sections/quic-throughput.target"
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
            ssh "${SSH_OPTIONS[@]}" "$target" "mkdir -p '$bundle_remote' && tar -C '$bundle_remote' -xf -" \
            > "$REPORT/targets/stage-$target_label.log" 2>&1
        rc=${PIPESTATUS[1]}
        set -e
        if ((rc != 0)); then
            reason=$(tail -1 "$REPORT/targets/stage-$target_label.log" || true)
            printf 'stage-bundle\t%s\tFAIL\t%s\t%s\t%s\t-\n' "$target" "$rc" "${reason:-remote bundle staging failed}" "$REPORT/targets/stage-$target_label.log" >> "$REPORT/sections.tsv"
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
        local archive_entries available_inodes required_inodes
        if [[ $worker_target == local ]]; then
            "$bundle_local/tests/patch-runner/remote-scheduler.sh" \
                "$bundle_local" "$WORK_DIR" "$jobs" "$concurrency" "$output_dir" \
                > "$transport_log" 2>&1 || scheduler_rc=$?
        else
            printf -v command '%q ' "$bundle_remote/tests/patch-runner/remote-scheduler.sh" \
                "$bundle_remote" "$WORK_DIR" "$remote_manifest" "$concurrency" "$output_dir"
            case ${TARGET_BACKEND[$worker_target]} in
                root|rootless)
                    ssh "${SSH_OPTIONS[@]}" "$worker_target" "$command" > "$transport_log" 2>&1 || scheduler_rc=$?
                    ;;
                sudo-n)
                    ssh "${SSH_OPTIONS[@]}" "$worker_target" "sudo -n $command" > "$transport_log" 2>&1 || scheduler_rc=$?
                    ;;
                *)
                    echo "invalid execution backend: ${TARGET_BACKEND[$worker_target]}" > "$transport_log"
                    scheduler_rc=2
                    ;;
            esac
            if ((scheduler_rc == 0)); then
                mkdir -p "$WORK_DIR/coordinator"
                scp "${SCP_OPTIONS[@]}" "$worker_target:$archive" "$archive" >> "$transport_log" 2>&1 || fetch_rc=$?
                if ((fetch_rc == 0)); then
                    archive_entries=$(tar -tf "$archive" | wc -l) || fetch_rc=$?
                    available_inodes=$(df -Pi "$WORK_DIR" | awk 'NR == 2 { print $4 }')
                    required_inodes=$((archive_entries + 1024))
                    if ((fetch_rc == 0 && available_inodes < required_inodes)); then
                        printf 'result archive needs %d inodes plus reserve; only %d available under %s\n' \
                            "$archive_entries" "$available_inodes" "$WORK_DIR" >> "$transport_log"
                        fetch_rc=28
                    elif ((fetch_rc == 0)); then
                        tar -C "$WORK_DIR" -xf "$archive" || fetch_rc=$?
                    fi
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
                [[ ! -f $output_dir/$job.duration-ms ]] || \
                    cp "$output_dir/$job.duration-ms" "$REPORT/sections/$job.duration-ms"
            fi
        done < "$jobs"
        return 0
    }

    if [[ " ${sections[*]} " == *" smoke "* ]]; then
        echo "SECTION START: smoke target=${TARGETS[0]}"
        run_batch "${TARGETS[0]}" smoke "$manifest_dir/smoke.tsv" 1
        rc=$(<"$REPORT/sections/smoke.rc")
        echo "SECTION DONE: smoke target=${TARGETS[0]} rc=$rc"
    else
        rc=0
    fi
    if ((rc == 0)); then
        if [[ " ${sections[*]} " == *" rtt "* ]]; then
            echo "SECTION START: rtt target=${TARGETS[0]} (exclusive)"
            run_batch "${TARGETS[0]}" rtt "$manifest_dir/rtt.tsv" 1
            rc=$(<"$REPORT/sections/rtt.rc")
            echo "SECTION DONE: rtt target=${TARGETS[0]} rc=$rc"
        fi
        if [[ " ${sections[*]} " == *" tls-throughput "* ]]; then
            echo "SECTION START: tls-throughput target=${TARGETS[0]} (exclusive, measurement only)"
            run_batch "${TARGETS[0]}" tls-throughput "$manifest_dir/tls-throughput.tsv" 1
            rc=$(<"$REPORT/sections/tls-throughput.rc")
            echo "SECTION DONE: tls-throughput target=${TARGETS[0]} rc=$rc"
        fi
        if [[ " ${sections[*]} " == *" quic-throughput "* ]]; then
            echo "SECTION START: quic-throughput target=${TARGETS[0]} (exclusive, measurement only)"
            run_batch "${TARGETS[0]}" quic-throughput "$manifest_dir/quic-throughput.tsv" 1
            rc=$(<"$REPORT/sections/quic-throughput.rc")
            echo "SECTION DONE: quic-throughput target=${TARGETS[0]} rc=$rc"
        fi
        for target in "${TARGETS[@]}"; do
            manifest=${target_manifest[$target]}
            [[ -s $manifest ]] || continue
            target_label=${target//[^A-Za-z0-9_.-]/_}
            run_batch "$target" main "$manifest" "$PARALLEL" &
            batch_pids+=("$!")
        done
        for pid in "${batch_pids[@]}"; do wait "$pid" || true; done
    else
        any_fail=1
    fi

    for section in "${sections[@]}"; do
        output="$REPORT/sections/$section.log"
        rc_file="$REPORT/sections/$section.rc"
        target=$(<"$REPORT/sections/$section.target")
        if [[ ! -f $rc_file ]]; then
            printf '%s\n' SKIP > "$REPORT/sections/$section.status"
            printf '%s\t%s\tSKIP\t-\tblocked by smoke failure\t-\t-\n' "$section" "$target" >> "$REPORT/sections.tsv"
            continue
        fi
        rc=$(<"$rc_file")
        child_report=$(find "$WORK_DIR/sections/$section/results" -mindepth 1 -maxdepth 1 -type d -print 2>/dev/null | sort | tail -1 || true)
        reason=
        if ((rc != 0)); then
            display=FAIL; any_fail=1
            [[ -z $child_report || ! -f $child_report/failure.txt ]] || reason=$(sed -n 's/^reason: //p' "$child_report/failure.txt" | head -1)
            [[ -n $reason ]] || reason=$(grep -E '(^FAIL[46]?:|FAIL:| FAIL$| XPASS$|Traceback|AssertionError|[Ee]rror|failed)' "$output" | tail -1 || true)
            [[ -n $reason ]] || reason="section exited with rc=$rc"
            reason=${reason//$'\r'/}
        elif grep -Eq 'flaky=[1-9][0-9]*|FLAKY_PASS' "$output"; then
            display=FLAKY_PASS; any_flaky=1
            reason=$(grep -E 'flaky=[1-9][0-9]*|FLAKY_PASS' "$output" | tail -1)
        elif grep -Eq '^[A-Za-z0-9_.-]+ XFAIL$' "$output"; then
            display=PASS
            reason=$(grep -E '^[A-Za-z0-9_.-]+ XFAIL$' "$output" | paste -sd ';' -)
        else
            display=PASS; reason='all checks passed'
        fi
        duration_ms=-
        [[ ! -f $REPORT/sections/$section.duration-ms ]] || \
            duration_ms=$(<"$REPORT/sections/$section.duration-ms")
        printf '%s\n' "$display" > "$REPORT/sections/$section.status"
        printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\n' "$section" "$target" "$display" "$rc" "$reason" "${child_report:--}" "$duration_ms" >> "$REPORT/sections.tsv"
        { echo "===== section: $section target=$target ($display) ====="; cat "$output"; echo; } >> "$REPORT/test.log"
    done

    if compgen -G "$REPORT/sections/corpus-*.rc" >/dev/null; then
        CORPUS_SELECTED=$(grep -hE '^family=IPv[46] ' "$REPORT/sections/"corpus-*.log 2>/dev/null | \
            awk '{for (i=1;i<=NF;i++) if ($i ~ /^(passed|flaky|failed|xfailed)=/) {split($i,a,"="); n+=a[2]}} END {print n+0}') || CORPUS_SELECTED=0
        if ((CORPUS_SELECTED == 0)); then
            any_fail=1
            printf 'corpus-selection\t-\tFAIL\t2\tno corpus case matched MATCH/EXCLUDE\t-\t-\n' >> "$REPORT/sections.tsv"
        fi
    fi
    write_sections_markdown
    if ((any_fail)); then STATUS=FAIL; TEST_RC=1
    elif ((any_flaky)); then STATUS=FLAKY_PASS; TEST_RC=0
    else STATUS=PASS; TEST_RC=0
    fi
}

BUILD_RC=0
BUILD_TARGETS=(smithproxy)
CMAKE_PROFILE_ARGS=()
if [[ $PROFILE == lifecycle || $PROFILE == full || $ONLY_SUITE == lifecycle ]]; then
    if [[ -z $PROXY_NIGHTMARE_ROOT ]]; then
        PROXY_NIGHTMARE_ROOT=$WORK_DIR/deps/proxynightmare
        echo 'DEPENDENCY START: pinned ProxyNightmare checkout, build and tests'
        if ! "$HERE/prepare-proxy-nightmare.sh" "$PROXY_NIGHTMARE_ROOT" \
                "$HERE/proxy-nightmare.lock" "$JOBS" \
                > "$REPORT/proxy-nightmare-build.log" 2>&1; then
            echo "FAIL ProxyNightmare preparation (see $REPORT/proxy-nightmare-build.log)" >&2
            tail -80 "$REPORT/proxy-nightmare-build.log" >&2
            exit 1
        fi
        echo 'DEPENDENCY DONE: ProxyNightmare ready'
        PROXY_NIGHTMARE_MODE=pinned-git
    else
        [[ -x $PROXY_NIGHTMARE_ROOT/build/pn ]] || {
            echo "ProxyNightmare binary is missing: $PROXY_NIGHTMARE_ROOT/build/pn" >&2
            exit 2
        }
        PROXY_NIGHTMARE_MODE=override
    fi
    {
        echo "mode=$PROXY_NIGHTMARE_MODE"
        echo "root=$PROXY_NIGHTMARE_ROOT"
        if [[ -d $PROXY_NIGHTMARE_ROOT/.git ]]; then
            echo "commit=$(git -C "$PROXY_NIGHTMARE_ROOT" rev-parse HEAD)"
            echo "repository=$(git -C "$PROXY_NIGHTMARE_ROOT" remote get-url origin)"
        fi
        echo "binary_sha256=$(sha256sum "$PROXY_NIGHTMARE_ROOT/build/pn" | awk '{print $1}')"
    } > "$REPORT/proxy-nightmare.txt"
    BUILD_TARGETS+=(smithproxy-cpu-monitor)
    CMAKE_PROFILE_ARGS+=("-DBUILD_TESTING=ON" "-DPROXY_NIGHTMARE_ROOT=$PROXY_NIGHTMARE_ROOT")
fi
if [[ $PROFILE == native || $PROFILE == coverage ]]; then
    echo "Build and test execution delegated to native-tests.sh" > "$REPORT/build.log"
elif ((SKIP_BUILD == 0)); then
    if [[ ! -f $BUILD_DIR/CMakeCache.txt || ${#CMAKE_PROFILE_ARGS[@]} -gt 0 ]]; then
        if ((QUIET)); then
            cmake -S "$ROOT" -B "$BUILD_DIR" -DCMAKE_BUILD_TYPE="$BUILD_TYPE" "${CMAKE_PROFILE_ARGS[@]}" \
                > "$REPORT/configure.log" 2>&1
        else
            cmake -S "$ROOT" -B "$BUILD_DIR" -DCMAKE_BUILD_TYPE="$BUILD_TYPE" "${CMAKE_PROFILE_ARGS[@]}" \
                2>&1 | tee "$REPORT/configure.log"
        fi
    fi
    set +e
    if ((QUIET)); then
        cmake --build "$BUILD_DIR" --target "${BUILD_TARGETS[@]}" -j"$JOBS" \
            > "$REPORT/build.log" 2>&1
        BUILD_RC=$?
    else
        cmake --build "$BUILD_DIR" --target "${BUILD_TARGETS[@]}" -j"$JOBS" \
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
elif [[ $ONLY_SUITE == lifecycle || $ONLY_SUITE == capture ]]; then
    run_distributed_sections
elif [[ ( $PROFILE == full || $PROFILE == sanity || $PROFILE == traffic || $PROFILE == lifecycle || $PROFILE == corpus || $PROFILE == fuzz || $PROFILE == fuzz-dyn ) && -z $ONLY_SUITE ]]; then
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
        read -r API_PORT CLI_PORT < <(ssh "${SSH_OPTIONS[@]}" "$REMOTE" "$PORT_COMMAND")
    else
        # shellcheck source=port-lease.sh
        source "$HERE/port-lease.sh"
        patch_runner_port_leases_init
        patch_runner_lease_port API_PORT 0
        patch_runner_lease_port CLI_PORT 1
    fi
    LAB_ROOT=$WORK_DIR/labs/$RUN_ID-$TAG
    QUIC_CURL_PREFIX=${CURL_HTTP3_PREFIX:-$ROOT/../curl-http3}
    QUIC_PYTHON_PREFIX=${QUIC_PYTHON_PREFIX:-$ROOT/../quic-python}
    QUIC_PYTHONPATH=$QUIC_PYTHON_PREFIX
    [[ -z $REMOTE ]] || QUIC_PYTHONPATH=$LAB_ROOT/quic-python

    if [[ -n $REMOTE ]]; then
        ssh "${SSH_OPTIONS[@]}" "$REMOTE" "mkdir -p '$LAB_ROOT/bin' '$LAB_ROOT/runner/tests' '$LAB_ROOT/corpus' '$LAB_ROOT/src/etc/msg/en'"
        if [[ -n $SHARED_BINARY ]]; then
            ssh "${SSH_OPTIONS[@]}" "$REMOTE" "test -x '$SHARED_BINARY' && ln -s '$SHARED_BINARY' '$LAB_ROOT/bin/smithproxy'"
        else
            scp "${SCP_OPTIONS[@]}" "$BINARY" "$REMOTE:$LAB_ROOT/bin/smithproxy" >/dev/null
        fi
        scp "${SCP_OPTIONS[@]}" "$HERE/smithproxy.runner" "$REMOTE:$LAB_ROOT/runner/" >/dev/null
        scp "${SCP_OPTIONS[@]}" -r "$HERE/harness/." "$REMOTE:$LAB_ROOT/runner/tests/" >/dev/null
        scp "${SCP_OPTIONS[@]}" -r "$HERE/corpus/." "$REMOTE:$LAB_ROOT/corpus/" >/dev/null
        scp "${SCP_OPTIONS[@]}" "$HERE/vendor/pplay.py" "$REMOTE:$LAB_ROOT/pplay.py" >/dev/null
        scp "${SCP_OPTIONS[@]}" "$ROOT/etc/smithproxy.cfg" "$REMOTE:$LAB_ROOT/src/etc/" >/dev/null
        scp "${SCP_OPTIONS[@]}" -r "$ROOT/etc/msg/en/." "$REMOTE:$LAB_ROOT/src/etc/msg/en/" >/dev/null
        if [[ $ONLY_SUITE == quic || $ONLY_SUITE == quic-pcapng || $ONLY_SUITE == quic-throughput || $ONLY_SUITE == quic-cert.* ]]; then
            [[ -x $QUIC_CURL_PREFIX/bin/curl-h3 ]] || {
                echo "Missing HTTP/3 curl: $QUIC_CURL_PREFIX/bin/curl-h3" >&2
                exit 2
            }
            [[ -f $QUIC_PYTHON_PREFIX/aioquic/__init__.py ]] || {
                echo "Missing QUIC Python runtime: $QUIC_PYTHON_PREFIX (run $HERE/prepare-quic-runtime.sh)" >&2
                exit 2
            }
            ssh "${SSH_OPTIONS[@]}" "$REMOTE" "mkdir -p '$LAB_ROOT/curl-http3' '$LAB_ROOT/quic-python' '$LAB_ROOT/runner/tools'"
            scp "${SCP_OPTIONS[@]}" -r "$QUIC_CURL_PREFIX/." "$REMOTE:$LAB_ROOT/curl-http3/" >/dev/null
            scp "${SCP_OPTIONS[@]}" -r "$QUIC_PYTHON_PREFIX/." "$REMOTE:$LAB_ROOT/quic-python/" >/dev/null
            scp "${SCP_OPTIONS[@]}" "$ROOT/tools/wireshark/spquic.lua" \
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
        if [[ $ONLY_SUITE == quic || $ONLY_SUITE == quic-pcapng || $ONLY_SUITE == quic-throughput || $ONLY_SUITE == quic-cert.* ]]; then
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
        QUIC_THROUGHPUT_BYTES QUIC_THROUGHPUT_REPEATS QUIC_THROUGHPUT_CONCURRENCY QUIC_WORKERS \
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
            quic|quic-pcapng|quic-throughput|quic-cert.*) LAB_ENV+=("QUIC_TEST=1" "QUIC_LAB=1" "QUIC_KEYLOG_TEST=1"
                "QUIC_CURL_BIN=$LAB_ROOT/curl-http3/bin/curl-h3"
                "QUIC_PYTHONPATH=$QUIC_PYTHONPATH"
                "SPQ1_DISSECTOR=$LAB_ROOT/runner/tools/spquic.lua") ;;
            smoke) LAB_ENV+=("PPLAY_SMOKE_TEST=1") ;;
            privsep) LAB_ENV+=("BASE_TRAFFIC_TEST=0" "PRIVSEP_TEST=1"
                "SMITHPROXY_RUN_AS=root" "SMITHPROXY_RUN_AS_ARGUMENT=nobody" "SKIP_API_READY=1") ;;
            tls-policy) LAB_ENV+=("BASE_TRAFFIC_TEST=0" "TLS_SUITE_TEST=1" "POLICY_TEST=1" "SESSION_LIST_STRESS_TEST=1") ;;
            tcp-churn) LAB_ENV+=("BASE_TRAFFIC_TEST=0" "TCP_CHURN_TEST=1") ;;
            udp-churn) LAB_ENV+=("BASE_TRAFFIC_TEST=0" "UDP_CHURN_TEST=1") ;;
            capture-traffic|capture-pcapng) LAB_ENV+=("CAPTURE_TEST=1" "HTTP2_OBSERVABILITY_TEST=1" "CAPTURE_MATRIX_TEST=1") ;;
            corpus-regular|corpus-edge|corpus-insanity|corpus-regular.[1-4]|corpus-edge.[1-4]|corpus-insanity.[1-4])
                corpus_spec=${ONLY_SUITE#corpus-}
                corpus_category=${corpus_spec%%.*}
                corpus_shard=1
                corpus_shard_count=1
                if [[ $corpus_spec == *.* ]]; then
                    corpus_shard=${corpus_spec##*.}
                    corpus_shard_count=4
                fi
                LAB_ENV+=("BASE_TRAFFIC_TEST=0" "PPLAY_SUITE_SKIP_RUN=0"
                    "PPLAY_SUITE_CATEGORY=$corpus_category" "PPLAY_RESULTS_NAME=$ONLY_SUITE"
                    "PPLAY_SUITE_SHARD_COUNT=$corpus_shard_count" "PPLAY_SUITE_SHARD_INDEX=$corpus_shard"
                    "PPLAY_SUITE_EXCLUDE=capture_*" "PPLAY_SUITE_ALLOW_EMPTY=1")
                ;;
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
    # A named matrix leg must not silently be changed by an inherited override.
    case "$ONLY_SUITE" in
        capture-pcapng|quic-pcapng) LAB_ENV+=("CAPTURE_GRE_FORMAT=pcapng") ;;
        capture-traffic|quic) LAB_ENV+=("CAPTURE_GRE_FORMAT=traffic") ;;
    esac
    [[ $ONLY_SUITE != quic-throughput ]] || LAB_ENV+=("BASE_TRAFFIC_TEST=0" "QUIC_THROUGHPUT_TEST=1" "QUIC_KEYLOG_TEST=0")
    [[ $ONLY_SUITE != quic-cert.* ]] || LAB_ENV+=("BASE_TRAFFIC_TEST=0" "QUIC_TLS_PROFILE_TEST=${ONLY_SUITE#quic-cert.}")
    [[ $ONLY_SUITE != quic-pcapng ]] || LAB_ENV+=("QUIC_REMOTE_PCAPNG_TEST=1")

    set +e
    if [[ -n $REMOTE ]]; then
        printf -v ENV_STRING ' %q' "${LAB_ENV[@]}"
        if [[ ${TARGET_BACKEND[$REMOTE]} == sudo-n ]]; then REMOTE_SUDO='sudo -n '; else REMOTE_SUDO=; fi
        SSH_RUN=(ssh "${SSH_OPTIONS[@]}")
        [[ $PROFILE != run ]] || SSH_RUN=(ssh "${SSH_OPTIONS[@]}" -tt)
        if [[ $PROFILE == benchmark ]]; then
            "${SSH_RUN[@]}" "$REMOTE" "${REMOTE_SUDO}env$ENV_STRING '$LAB_ROOT/runner/tests/lab-test.sh' '$LAB_ROOT'" \
                > "$REPORT/test.log" 2>&1
            TEST_RC=$?
        elif ((QUIET)); then
            "${SSH_RUN[@]}" "$REMOTE" "${REMOTE_SUDO}env$ENV_STRING '$LAB_ROOT/runner/tests/lab-test.sh' '$LAB_ROOT'" \
                2>&1 | tee "$REPORT/test.log" | grep --line-buffered -E '(^PASS[46]? |^FAIL[46]?:| (PASS|FLAKY_PASS|FAIL|XFAIL|XPASS)[46]?$|^(TCP churn:|UDP churn:|TLS transfer:|TLS throughput:|QUIC throughput:|family=IPv|Capture matrix summary:|RTT summary:|Session-list summary:)|^RESULT:)'
            TEST_RC=${PIPESTATUS[0]}
        else
            "${SSH_RUN[@]}" "$REMOTE" "${REMOTE_SUDO}env$ENV_STRING '$LAB_ROOT/runner/tests/lab-test.sh' '$LAB_ROOT'" \
                2>&1 | tee "$REPORT/test.log"
            TEST_RC=${PIPESTATUS[0]}
        fi
    else
        if [[ ${TARGET_BACKEND[local]} == root ]]; then LOCAL_RUN=(env); else LOCAL_RUN=(sudo -n env); fi
        if [[ $PROFILE == benchmark ]]; then
            "${LOCAL_RUN[@]}" "${LAB_ENV[@]}" "$LAB_ROOT/runner/tests/lab-test.sh" "$LAB_ROOT" \
                > "$REPORT/test.log" 2>&1
            TEST_RC=$?
        elif ((QUIET)); then
            "${LOCAL_RUN[@]}" "${LAB_ENV[@]}" "$LAB_ROOT/runner/tests/lab-test.sh" "$LAB_ROOT" \
                2>&1 | tee "$REPORT/test.log" | grep --line-buffered -E '(^PASS[46]? |^FAIL[46]?:| (PASS|FLAKY_PASS|FAIL|XFAIL|XPASS)[46]?$|^(TCP churn:|UDP churn:|TLS transfer:|TLS throughput:|QUIC throughput:|family=IPv|Capture matrix summary:|RTT summary:|Session-list summary:)|^RESULT:)'
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
        scp "${SCP_OPTIONS[@]}" -r "$REMOTE:$LAB_ROOT/results/." "$REPORT/lab-results/" >/dev/null 2>&1 || true
        ssh "${SSH_OPTIONS[@]}" "$REMOTE" "find '$LAB_ROOT/results' -type f -printf '%P\n' | sort" \
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
CORPUS_SUMMARY=$(
    grep -hE '^family=IPv[46] ' "$REPORT/sections"/corpus-*.log 2>/dev/null | awk '
        {
            family=$1
            seen[family]=1
            for (i=2; i<=NF; i++) {
                split($i, item, "=")
                if (item[1] ~ /^(passed|flaky|failed|xfailed|xpassed)$/)
                    total[family,item[1]] += item[2]
            }
        }
        END {
            split("family=IPv4 family=IPv6", families)
            split("passed flaky failed xfailed xpassed", keys)
            for (f=1; f<=2; f++) if (seen[families[f]]) {
                if (printed++) printf ";"
                printf "%s", families[f]
                for (k=1; k<=5; k++) printf " %s=%d", keys[k], total[families[f],keys[k]]
            }
        }' || true
)
if [[ -z $CORPUS_SUMMARY ]]; then
    CORPUS_SUMMARY=$(grep -E '^(family=IPv[46] )?passed=' "$REPORT/test.log" 2>/dev/null | tail -2 | paste -sd ';' - || true)
fi
CAPTURE_MATRIX_SUMMARY=$(grep -E '^Capture matrix summary:' "$REPORT/test.log" 2>/dev/null | tail -2 | paste -sd ';' - || true)
RTT_SUMMARY=$(grep -E '^RTT summary:' "$REPORT/test.log" 2>/dev/null | tail -2 | paste -sd ';' - || true)
TLS_TRANSFER_SUMMARY=$(grep -E '^TLS transfer:' "$REPORT/test.log" 2>/dev/null | paste -sd ';' - || true)
TLS_THROUGHPUT_SUMMARY=$(grep -E '^TLS throughput:' "$REPORT/test.log" 2>/dev/null | paste -sd ';' - || true)
QUIC_THROUGHPUT_SUMMARY=$(grep -E '^QUIC throughput:' "$REPORT/test.log" 2>/dev/null | paste -sd ';' - || true)
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

# Describe both the selected scope and the adjacent test groups that were
# available but deliberately left out of this invocation.
case "$PROFILE:$ONLY_SUITE" in
    full:) INCLUDED_GROUPS=("${PATCH_RUNNER_FULL_PROFILES[@]}") ;;
    *:?*) INCLUDED_GROUPS=("$(patch_runner_section_profile "$ONLY_SUITE")") ;;
    *) INCLUDED_GROUPS=("$PROFILE") ;;
esac
NOT_RUN_GROUPS=()
for candidate in "${PATCH_RUNNER_REPORTABLE_PROFILES[@]}"; do
    included=0
    for selected in "${INCLUDED_GROUPS[@]}"; do
        [[ $candidate != "$selected" ]] || { included=1; break; }
    done
    ((included)) || NOT_RUN_GROUPS+=("$candidate")
done
printf -v INCLUDED_GROUPS_TEXT '%s, ' "${INCLUDED_GROUPS[@]}"
INCLUDED_GROUPS_TEXT=${INCLUDED_GROUPS_TEXT%, }
printf -v NOT_RUN_GROUPS_TEXT '%s, ' "${NOT_RUN_GROUPS[@]}"
NOT_RUN_GROUPS_TEXT=${NOT_RUN_GROUPS_TEXT%, }
[[ -n $ONLY_SUITE ]] && SELECTED_SCOPE="$PROFILE/$ONLY_SUITE" || SELECTED_SCOPE=$PROFILE
if [[ $PROFILE == native || $PROFILE == coverage || ( $PROFILE == full && -z $ONLY_SUITE ) ]]; then
    OPTIONAL_LAYERS_TEXT="external=$([[ $INCLUDE_EXTERNAL == 1 ]] && echo included || echo not-requested), benchmarks=$([[ $INCLUDE_BENCHMARKS == 1 ]] && echo included || echo not-requested), extended=$([[ $INCLUDE_EXTENDED == 1 ]] && echo included || echo not-requested), platform=$([[ $INCLUDE_PLATFORM == 1 ]] && echo included || echo not-requested)"
else
    OPTIONAL_LAYERS_TEXT='not applicable to the selected scope'
fi

cat > "$REPORT/summary.md" <<EOF
# Smithproxy patch test

## Verdict

- Result: **$STATUS**
- Commit: $COMMIT
- Dirty working tree: $DIRTY
- Host: $REPORT_HOST

## Scope

- Requested scope: $SELECTED_SCOPE
- Test groups run: $INCLUDED_GROUPS_TEXT
- Available test groups not run: ${NOT_RUN_GROUPS_TEXT:-none}
- Optional layers: $OPTIONAL_LAYERS_TEXT
EOF
MEASUREMENT_LINES=()
[[ $LINE_COVERAGE == N/A ]] || MEASUREMENT_LINES+=("Line coverage: $LINE_COVERAGE")
[[ -z $TCP_SUMMARY ]] || MEASUREMENT_LINES+=("TCP churn: $TCP_SUMMARY")
[[ -z $UDP_SUMMARY ]] || MEASUREMENT_LINES+=("UDP churn: $UDP_SUMMARY")
[[ -z $CORPUS_SUMMARY ]] || MEASUREMENT_LINES+=("Corpus: $CORPUS_SUMMARY")
[[ -z $CAPTURE_MATRIX_SUMMARY ]] || MEASUREMENT_LINES+=("Capture matrix: $CAPTURE_MATRIX_SUMMARY")
[[ -z $RTT_SUMMARY ]] || MEASUREMENT_LINES+=("RTT: $RTT_SUMMARY")
[[ -z $TLS_TRANSFER_SUMMARY ]] || MEASUREMENT_LINES+=("TLS transfer: $TLS_TRANSFER_SUMMARY")
[[ -z $TLS_THROUGHPUT_SUMMARY ]] || MEASUREMENT_LINES+=("TLS throughput: $TLS_THROUGHPUT_SUMMARY")
[[ -z $QUIC_THROUGHPUT_SUMMARY ]] || MEASUREMENT_LINES+=("QUIC throughput: $QUIC_THROUGHPUT_SUMMARY")
[[ -z $FUZZ_DYNAMIC_SEED ]] || MEASUREMENT_LINES+=("Dynamic fuzz seed: $FUZZ_DYNAMIC_SEED")
[[ -z $FUZZ_SEED_SUMMARY ]] || MEASUREMENT_LINES+=("Fuzz seeds exercised: $FUZZ_SEED_SUMMARY")
if ((${#MEASUREMENT_LINES[@]})); then
    printf '\n## Measurements\n\n' >> "$REPORT/summary.md"
    printf -- '- %s\n' "${MEASUREMENT_LINES[@]}" >> "$REPORT/summary.md"
fi
if [[ -f $REPORT/sections.md ]]; then
    printf '\n## Detailed section results\n\n' >> "$REPORT/summary.md"
    cat "$REPORT/sections.md" >> "$REPORT/summary.md"
fi
python3 "$HERE/test-inventory.py" "$REPORT"
if [[ -s $REPORT/test-inventory.md ]]; then
    cat "$REPORT/test-inventory.md" >> "$REPORT/summary.md"
fi

# Keep operational accommodations separate from the durable compact report.
# This file remains with local/run artifacts and publish-report.sh never stages
# it, while still making a less-than-pristine run immediately visible.
{
    echo '# Local run notes'
    echo
    echo '> Diagnostic companion only. Do not publish this file to Git.'
    echo
    echo '## Operator-supplied notes'
    echo
    if ((${#RUN_NOTES[@]})); then
        printf -- '- %s\n' "${RUN_NOTES[@]}"
    else
        echo '- None.'
    fi
    echo
    echo '## Runner-detected conditions'
    echo
    conditions_written=0
    if [[ -n ${CXXFLAGS:-} ]]; then
        printf -- '- Non-default CXXFLAGS: `%s`\n' "$CXXFLAGS"
        conditions_written=1
    fi
    if [[ $DIRTY == true ]]; then
        echo '- The tested working tree contained uncommitted changes.'
        conditions_written=1
    fi
    ((conditions_written)) || echo '- None.'
    echo
    echo '## Test warnings'
    echo
    warnings=$(grep -hE '(^|[[:space:]])(FLAKY_PASS|XFAIL|XPASS)($|[[:space:]])' \
        "$REPORT/test.log" "$REPORT/sections/"*.log 2>/dev/null | sort -u || true)
    if [[ -n $warnings ]]; then
        while IFS= read -r warning; do printf -- '- `%s`\n' "$warning"; done <<< "$warnings"
    else
        echo '- None.'
    fi
} > "$REPORT/report-notes.md"
if [[ -n $FAIL_REASON ]]; then
    printf '\n## Failure\n\n- Reason: %s\n' "$FAIL_REASON" >> "$REPORT/summary.md"
    [[ -z $FAIL_LIKELY ]] || printf -- '- Likely cause: %s\n' "$FAIL_LIKELY" >> "$REPORT/summary.md"
fi
printf '\n## Run details\n\n- Build: %s\n- Build directory: %s\n- Test log: %s\n' \
    "$([[ $BUILD_RC == 0 ]] && echo PASS || echo FAIL)" "$BUILD_DIR" "$REPORT/test.log" >> "$REPORT/summary.md"
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
  "selected_scope": "$SELECTED_SCOPE",
  "test_groups_run": "$INCLUDED_GROUPS_TEXT",
  "test_groups_not_run": "$NOT_RUN_GROUPS_TEXT",
  "optional_layers": "$OPTIONAL_LAYERS_TEXT",
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
  "quic_throughput": "${QUIC_THROUGHPUT_SUMMARY//\"/\\\"}",
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
    if [[ ${PATCH_TEST_RECORD_HISTORY:-1} == 1 ]]; then
        exec 9>>"$ROOT/tests/docs/patch-run-history"
        flock -x 9
        printf '| %s | `%s` | %s | `%s%s` | `%s` | %s | `%s` |\n' \
            "$HISTORY_TIME" "$HISTORY_COMMIT" "$STATUS" "$PROFILE" "${ONLY_SUITE:+/$ONLY_SUITE}" \
            "$HISTORY_HOST" "$RUN_COVERAGE" "$REPORT" >&9
        HISTORY_RECORDED=1
        flock -u 9
        exec 9>&-
    fi
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
