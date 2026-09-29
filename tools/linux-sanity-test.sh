#!/usr/bin/env sh

set -eu

if [ "${SMITHPROXY_SANITY_CONTAINER:-}" != 1 ]; then
    echo "error: this test installs system packages; run it through tools/test-linux-distros.sh" >&2
    exit 1
fi

SOURCE_MOUNT=${SOURCE_MOUNT:-/src}
WORK_DIR=${WORK_DIR:-/tmp/smithproxy-source}
BUILD_JOBS=${BUILD_JOBS:-2}

if [ ! -x "${SOURCE_MOUNT}/tools/linux-deps.sh" ]; then
    echo "error: smithproxy source is not mounted at ${SOURCE_MOUNT}" >&2
    exit 1
fi

case "${1:-}" in
    dependencies)
        exec "${SOURCE_MOUNT}/tools/linux-deps.sh"
        ;;
    build)
        ;;
    *)
        echo "error: expected phase: dependencies or build" >&2
        exit 2
        ;;
esac

mkdir -p "${WORK_DIR}"
cp -a "${SOURCE_MOUNT}/." "${WORK_DIR}/"

BUILD_JOBS="${BUILD_JOBS}" "${WORK_DIR}/tools/linux-build.sh"

/usr/bin/smithproxy --version

if ldd /usr/bin/smithproxy 2>&1 | grep -q "not found"; then
    echo "error: smithproxy has unresolved shared-library dependencies" >&2
    ldd /usr/bin/smithproxy >&2
    exit 1
fi

echo "SANITY PASS: ${DISTRO_NAME:-unknown distro}"
