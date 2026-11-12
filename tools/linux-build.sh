#!/usr/bin/env bash

set -euo pipefail

SOURCE_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
BUILD_DIR=${BUILD_DIR:-"${SOURCE_DIR}/build"}
BUILD_TYPE=${BUILD_TYPE:-Release}
BUILD_JOBS=${BUILD_JOBS:-"$(nproc)"}

SMITHPROXY_ENABLE_NGTCP2=${SMITHPROXY_ENABLE_NGTCP2:-ON}
case "$SMITHPROXY_ENABLE_NGTCP2" in
    ON|OFF) ;;
    *) echo "error: SMITHPROXY_ENABLE_NGTCP2 must be ON or OFF" >&2; exit 2 ;;
esac

cmake -E remove_directory "${BUILD_DIR}"
cmake -S "${SOURCE_DIR}" -B "${BUILD_DIR}" -DCMAKE_BUILD_TYPE="${BUILD_TYPE}" \
    -DSMITHPROXY_ENABLE_NGTCP2="${SMITHPROXY_ENABLE_NGTCP2}"
cmake --build "${BUILD_DIR}" --parallel "${BUILD_JOBS}"
cmake --install "${BUILD_DIR}"
