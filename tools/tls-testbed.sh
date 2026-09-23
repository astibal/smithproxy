#!/usr/bin/env bash

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SANITIZE="${TLS_TESTBED_SANITIZE:-0}"
if [[ "${SANITIZE}" == "1" ]]; then
    BUILD_DIR="${TLS_TESTBED_BUILD_DIR:-${ROOT_DIR}/build-tls-sanitize}"
else
    BUILD_DIR="${TLS_TESTBED_BUILD_DIR:-${ROOT_DIR}/build-tls-testbed}"
fi

cmake -S "${ROOT_DIR}" -B "${BUILD_DIR}" \
    -DCMAKE_POLICY_VERSION_MINIMUM=3.5 \
    -DCMAKE_BUILD_TYPE=Debug \
    -DSMITHPROXY_TLS_SANITIZERS="${SANITIZE}"
cmake --build "${BUILD_DIR}" --target tls_testbed -j"${TLS_TESTBED_JOBS:-2}"

cd "${ROOT_DIR}"
ASAN_OPTIONS="${ASAN_OPTIONS:-detect_leaks=${TLS_TESTBED_DETECT_LEAKS:-0}:halt_on_error=1}" \
UBSAN_OPTIONS="${UBSAN_OPTIONS:-halt_on_error=1:print_stacktrace=1}" \
    exec "${BUILD_DIR}/tls_testbed" --gtest_color=yes "$@"
