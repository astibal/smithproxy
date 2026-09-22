#!/usr/bin/env bash

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BUILD_DIR="${QUIC_FUZZ_BUILD_DIR:-${ROOT_DIR}/build-quic-fuzz}"
TARGET="${1:-all}"
DURATION="${2:-60}"

case "${TARGET}" in
    wire|multiflow|lifecycle|all) ;;
    *)
        echo "usage: $0 {wire|multiflow|lifecycle|all} [seconds]" >&2
        exit 2
        ;;
esac

if ! [[ "${DURATION}" =~ ^[1-9][0-9]*$ ]]; then
    echo "duration must be a positive integer" >&2
    exit 2
fi

cmake -S "${ROOT_DIR}" -B "${BUILD_DIR}" \
    -DCMAKE_POLICY_VERSION_MINIMUM=3.5 \
    -DCMAKE_BUILD_TYPE=Debug \
    -DCMAKE_C_COMPILER="${CC:-clang}" \
    -DCMAKE_CXX_COMPILER="${CXX:-clang++}" \
    -DSMITHPROXY_FUZZING=ON

seed_corpus() {
    local destination="$1"
    shift
    mkdir -p "${destination}"
    for source in "$@"; do
        local target="${destination}/$(basename "${source}")"
        if [[ ! -e "${target}" ]]; then
            cp "${source}" "${target}"
        fi
    done
}

run_target() {
    local name="$1"
    local executable="$2"
    local dictionary="$3"
    local max_length="$4"
    shift 4
    local corpus="${BUILD_DIR}/corpus/${name}"
    local artifacts="${BUILD_DIR}/artifacts/${name}"

    seed_corpus "${corpus}" "$@"
    mkdir -p "${artifacts}"
    cmake --build "${BUILD_DIR}" --target "${executable}" \
        -j"${QUIC_FUZZ_JOBS:-2}"

    echo "==> fuzzing ${name} for ${DURATION}s"
    ASAN_OPTIONS="${ASAN_OPTIONS:-detect_leaks=${QUIC_FUZZ_DETECT_LEAKS:-0}:halt_on_error=1}" \
    UBSAN_OPTIONS="${UBSAN_OPTIONS:-halt_on_error=1:print_stacktrace=1}" \
        "${BUILD_DIR}/${executable}" "${corpus}" \
        -dict="${dictionary}" \
        -artifact_prefix="${artifacts}/" \
        -max_len="${max_length}" \
        -max_total_time="${DURATION}" \
        -timeout="${QUIC_FUZZ_TIMEOUT:-5}" \
        -rss_limit_mb="${QUIC_FUZZ_RSS_LIMIT_MB:-2048}"
}

run_wire() {
    run_target wire quic_wire_fuzzer \
        "${ROOT_DIR}/src/proxy/quic/fuzz/quic.dict" 4096 \
        "${ROOT_DIR}/src/proxy/quic/fuzz/corpus/short-header.seed" \
        "${ROOT_DIR}/src/proxy/quic/fuzz/corpus/long-header.seed"
}

run_multiflow() {
    run_target multiflow multiflow_fuzzer \
        "${ROOT_DIR}/src/proxy/multiflow/fuzz/multiflow.dict" 4096 \
        "${ROOT_DIR}/src/proxy/multiflow/fuzz/corpus/lifecycle.seed"
}

run_lifecycle() {
    run_target lifecycle quic_lifecycle_fuzzer \
        "${ROOT_DIR}/src/proxy/multiflow/fuzz/multiflow.dict" 1024 \
        "${ROOT_DIR}/src/proxy/multiflow/fuzz/corpus/lifecycle.seed"
}

cd "${ROOT_DIR}"
case "${TARGET}" in
    wire) run_wire ;;
    multiflow) run_multiflow ;;
    lifecycle) run_lifecycle ;;
    all)
        run_wire
        run_multiflow
        run_lifecycle
        ;;
esac
