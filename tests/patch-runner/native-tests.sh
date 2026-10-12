#!/usr/bin/env bash
set -euo pipefail

usage() {
    cat <<'EOF'
Usage: native-tests.sh --root DIR --build-dir DIR --report-dir DIR [OPTIONS]

Build and run Smithproxy's hermetic CTest, integration and patch-runner tests.

Options:
  --jobs N              Parallel build jobs (default: nproc).
  --test-jobs N         Concurrent CTest jobs (default: PATCH_TEST_CTEST_JOBS,
                        then build jobs; coverage defaults to 1).
  --coverage            Enable GCC/gcov line instrumentation and report it.
  --include-external    Include public-network and privileged tests.
  --include-benchmarks  Include benchmark-shaped tests.
  --include-extended    Include long-running soak tests.
  --include-platform    Include the Docker Linux distribution matrix.
EOF
}

ROOT=
BUILD_DIR=
REPORT_DIR=
JOBS=$(nproc)
TEST_JOBS=${PATCH_TEST_CTEST_JOBS:-}
COVERAGE=0
INCLUDE_EXTERNAL=0
INCLUDE_BENCHMARKS=0
INCLUDE_EXTENDED=0
INCLUDE_PLATFORM=0
while (($#)); do
    case "$1" in
        --root) ROOT=${2:?missing root}; shift 2 ;;
        --build-dir) BUILD_DIR=${2:?missing build directory}; shift 2 ;;
        --report-dir) REPORT_DIR=${2:?missing report directory}; shift 2 ;;
        --jobs) JOBS=${2:?missing jobs}; shift 2 ;;
        --test-jobs) TEST_JOBS=${2:?missing test jobs}; shift 2 ;;
        --coverage) COVERAGE=1; shift ;;
        --include-external) INCLUDE_EXTERNAL=1; shift ;;
        --include-benchmarks) INCLUDE_BENCHMARKS=1; shift ;;
        --include-extended) INCLUDE_EXTENDED=1; shift ;;
        --include-platform) INCLUDE_PLATFORM=1; shift ;;
        -h|--help) usage; exit 0 ;;
        *) echo "Unknown option: $1" >&2; usage >&2; exit 2 ;;
    esac
done

[[ $ROOT == /* && $BUILD_DIR == /* && $REPORT_DIR == /* ]] || {
    echo '--root, --build-dir and --report-dir must be absolute paths' >&2
    exit 2
}
[[ $JOBS =~ ^[1-9][0-9]*$ ]] || { echo 'jobs must be positive' >&2; exit 2; }
[[ -f $ROOT/CMakeLists.txt ]] || { echo "Not a Smithproxy source root: $ROOT" >&2; exit 2; }

CTEST_JOBS=${TEST_JOBS:-$JOBS}
if ((COVERAGE)) && [[ -z $TEST_JOBS ]]; then
    # gcov makes the core mempool and large QUIC executables dramatically
    # slower. Running them concurrently has caused resource-driven crashes and
    # timing failures which disappear in isolation.
    CTEST_JOBS=1
fi
[[ $CTEST_JOBS =~ ^[1-9][0-9]*$ ]] || {
    echo 'CTest jobs must be positive' >&2
    exit 2
}

mkdir -p "$BUILD_DIR" "$REPORT_DIR"
cmake -S "$ROOT" -B "$BUILD_DIR" \
    -DCMAKE_BUILD_TYPE=Debug -DBUILD_TESTING=ON \
    -DSMITHPROXY_COVERAGE="$COVERAGE" \
    -DCMAKE_POLICY_VERSION_MINIMUM=3.5 \
    > "$REPORT_DIR/configure.log" 2>&1

cmake --build "$BUILD_DIR" -j"$JOBS" \
    > "$REPORT_DIR/build.log" 2>&1

if ((COVERAGE)); then
    find "$BUILD_DIR" -type f -name '*.gcda' -delete
fi

exclude_labels=()
((INCLUDE_EXTERNAL)) || exclude_labels+=(external privileged)
((INCLUDE_BENCHMARKS)) || exclude_labels+=(benchmark)
((INCLUDE_EXTENDED)) || exclude_labels+=(extended)
((INCLUDE_PLATFORM)) || exclude_labels+=(platform)
ctest_args=(--test-dir "$BUILD_DIR" --output-on-failure -j"$CTEST_JOBS"
    --output-junit "$REPORT_DIR/junit.xml")
if ((${#exclude_labels[@]})); then
    label_regex=$(IFS='|'; echo "${exclude_labels[*]}")
    ctest_args+=(-LE "$label_regex")
fi

set +e
ctest "${ctest_args[@]}" 2>&1 | tee "$REPORT_DIR/ctest.log"
test_rc=${PIPESTATUS[0]}
set -e

if ((COVERAGE)); then
    python3 "$ROOT/tests/patch-runner/coverage-report.py" \
        --source-root "$ROOT" --build-dir "$BUILD_DIR" \
        --output-dir "$REPORT_DIR/coverage"
fi

if ((test_rc != 0)); then
    echo "Native test failure; report: $REPORT_DIR" >&2
    exit "$test_rc"
fi

total=$(grep -Eo '[0-9]+% tests passed, [0-9]+ tests failed out of [0-9]+' \
    "$REPORT_DIR/ctest.log" | tail -1 || true)
printf 'PASS: native Smithproxy tests%s\n' "${total:+ ($total)}"
echo "Report: $REPORT_DIR"
