#!/usr/bin/env bash

set -euo pipefail

SOURCE_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
BUILD_DIR=${BUILD_DIR:-"${SOURCE_DIR}/build"}
BUILD_TYPE=${BUILD_TYPE:-Release}
BUILD_JOBS=${BUILD_JOBS:-"$(nproc)"}

cmake -E remove_directory "${BUILD_DIR}"
cmake -S "${SOURCE_DIR}" -B "${BUILD_DIR}" -DCMAKE_BUILD_TYPE="${BUILD_TYPE}"
cmake --build "${BUILD_DIR}" --parallel "${BUILD_JOBS}"
cmake --install "${BUILD_DIR}"
