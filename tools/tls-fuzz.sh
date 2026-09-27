#!/usr/bin/env bash

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BUILD_DIR="${TLS_FUZZ_BUILD_DIR:-${ROOT_DIR}/build-tls-fuzz}"
TARGET="${1:-all}"
if [[ "${TARGET}" =~ ^[1-9][0-9]*$ ]]; then
    DURATION="${TARGET}"
    TARGET="all"
else
    DURATION="${2:-60}"
fi

if [[ "${TARGET}" != "clienthello" && "${TARGET}" != "revocation" && "${TARGET}" != "all" ]] ||
   ! [[ "${DURATION}" =~ ^[1-9][0-9]*$ ]]; then
    echo "usage: $0 {clienthello|revocation|all} [seconds]" >&2
    exit 2
fi

cmake -S "${ROOT_DIR}" -B "${BUILD_DIR}" \
    -DCMAKE_POLICY_VERSION_MINIMUM=3.5 \
    -DCMAKE_BUILD_TYPE=Debug \
    -DCMAKE_C_COMPILER="${CC:-clang}" \
    -DCMAKE_CXX_COMPILER="${CXX:-clang++}" \
    -DSMITHPROXY_TLS_FUZZING=ON

run_fuzzer() {
    local name="$1"
    local executable="$2"
    local seed="$3"
    local max_length="$4"
    local corpus="${BUILD_DIR}/corpus/${name}"
    local artifacts="${BUILD_DIR}/artifacts/${name}"
    mkdir -p "${corpus}" "${artifacts}"
    if [[ ! -e "${corpus}/$(basename "${seed}")" ]]; then
        cp "${seed}" "${corpus}/"
    fi
    cmake --build "${BUILD_DIR}" --target "${executable}" -j"${TLS_FUZZ_JOBS:-2}"

    local arguments=(
        "${corpus}"
        "-artifact_prefix=${artifacts}/"
        "-max_len=${max_length}"
        "-max_total_time=${DURATION}"
        "-timeout=${TLS_FUZZ_TIMEOUT:-5}"
        "-rss_limit_mb=${TLS_FUZZ_RSS_LIMIT_MB:-2048}")
    if [[ "${name}" == "clienthello" ]]; then
        arguments+=("-dict=${ROOT_DIR}/src/proxy/tls/fuzz/clienthello.dict")
    fi

    echo "==> fuzzing ${name} for ${DURATION}s"
    ASAN_OPTIONS="${ASAN_OPTIONS:-detect_leaks=${TLS_FUZZ_DETECT_LEAKS:-0}:halt_on_error=1}" \
    UBSAN_OPTIONS="${UBSAN_OPTIONS:-halt_on_error=1:print_stacktrace=1}" \
        "${BUILD_DIR}/${executable}" "${arguments[@]}"
}

case "${TARGET}" in
    clienthello)
        run_fuzzer clienthello tls_clienthello_fuzzer \
            "${ROOT_DIR}/src/proxy/tls/fuzz/corpus/minimal.seed" 65536
        ;;
    revocation)
        run_fuzzer revocation tls_revocation_fuzzer \
            "${ROOT_DIR}/src/proxy/tls/fuzz/corpus/revocation.seed" 4096
        ;;
    all)
        run_fuzzer clienthello tls_clienthello_fuzzer \
            "${ROOT_DIR}/src/proxy/tls/fuzz/corpus/minimal.seed" 65536
        run_fuzzer revocation tls_revocation_fuzzer \
            "${ROOT_DIR}/src/proxy/tls/fuzz/corpus/revocation.seed" 4096
        ;;
esac
