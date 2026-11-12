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

# A successful default build must actually link the chosen transport, not just
# accept the option while silently compiling the old backend.
if [ "${SMITHPROXY_ENABLE_NGTCP2:-ON}" = ON ]; then
    ldd /usr/bin/smithproxy | grep 'libngtcp2\.'
    ldd /usr/bin/smithproxy | grep 'libngtcp2_crypto_ossl\.'
fi

# Debian packages use generated shlibs dependencies. Verify them against the
# installed binary as well as checking that the runtime loader resolves it.
if command -v dpkg-shlibdeps >/dev/null 2>&1; then
    SHLIBS_CHECK="${WORK_DIR}/shlibs-check"
    mkdir -p "${SHLIBS_CHECK}/debian"
    printf 'Source: smithproxy\n\nPackage: smithproxy\nArchitecture: any\n' > "${SHLIBS_CHECK}/debian/control"
    (cd "${SHLIBS_CHECK}" && dpkg-shlibdeps -O -e/usr/bin/smithproxy) > "${SHLIBS_CHECK}/depends"
    cat "${SHLIBS_CHECK}/depends"
    if [ "${SMITHPROXY_ENABLE_NGTCP2:-ON}" = ON ]; then
        grep 'libngtcp2-crypto-ossl' "${SHLIBS_CHECK}/depends"
        grep 'libngtcp2-[0-9]' "${SHLIBS_CHECK}/depends"
    fi
fi

echo "SANITY PASS: ${DISTRO_NAME:-unknown distro}"
