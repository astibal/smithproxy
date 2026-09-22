#!/usr/bin/env bash

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BUILD_DIR="${QUIC_TESTBED_BUILD_DIR:-${ROOT_DIR}/build-quic-testbed}"

if [[ ! -f "${BUILD_DIR}/CMakeCache.txt" ]]; then
    cmake -S "${ROOT_DIR}" -B "${BUILD_DIR}" -DCMAKE_BUILD_TYPE=Debug \
        -DCMAKE_POLICY_VERSION_MINIMUM=3.5
fi

cmake --build "${BUILD_DIR}" --target quic_testbed -j"${QUIC_TESTBED_JOBS:-2}"
cd "${ROOT_DIR}"
exec "${BUILD_DIR}/quic_testbed" --gtest_color=yes "$@"
