#!/usr/bin/env bash

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BUILD_DIR="${TLS_FUZZ_BUILD_DIR:-${ROOT_DIR}/build-tls-fuzz}"
DURATION="${1:-60}"

if ! [[ "${DURATION}" =~ ^[1-9][0-9]*$ ]]; then
    echo "usage: $0 [seconds]" >&2
    exit 2
fi

cmake -S "${ROOT_DIR}" -B "${BUILD_DIR}" \
    -DCMAKE_POLICY_VERSION_MINIMUM=3.5 \
    -DCMAKE_BUILD_TYPE=Debug \
    -DCMAKE_C_COMPILER="${CC:-clang}" \
    -DCMAKE_CXX_COMPILER="${CXX:-clang++}" \
    -DSMITHPROXY_TLS_FUZZING=ON

CORPUS="${BUILD_DIR}/corpus/clienthello"
ARTIFACTS="${BUILD_DIR}/artifacts/clienthello"
mkdir -p "${CORPUS}" "${ARTIFACTS}"

for source in "${ROOT_DIR}"/src/proxy/tls/fuzz/corpus/*.seed; do
    destination="${CORPUS}/$(basename "${source}")"
    if [[ ! -e "${destination}" ]]; then
        cp "${source}" "${destination}"
    fi
done

cmake --build "${BUILD_DIR}" --target tls_clienthello_fuzzer \
    -j"${TLS_FUZZ_JOBS:-2}"

ASAN_OPTIONS="${ASAN_OPTIONS:-detect_leaks=${TLS_FUZZ_DETECT_LEAKS:-0}:halt_on_error=1}" \
UBSAN_OPTIONS="${UBSAN_OPTIONS:-halt_on_error=1:print_stacktrace=1}" \
    "${BUILD_DIR}/tls_clienthello_fuzzer" "${CORPUS}" \
    -dict="${ROOT_DIR}/src/proxy/tls/fuzz/clienthello.dict" \
    -artifact_prefix="${ARTIFACTS}/" \
    -max_len="${TLS_FUZZ_MAX_LEN:-65536}" \
    -max_total_time="${DURATION}" \
    -timeout="${TLS_FUZZ_TIMEOUT:-5}" \
    -rss_limit_mb="${TLS_FUZZ_RSS_LIMIT_MB:-2048}"
