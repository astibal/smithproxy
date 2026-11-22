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
# Do not preserve the host runner's ownership. Git metadata is read while the
# container runs as root and Git rejects copied repositories owned by another
# uid as unsafe.
cp -R "${SOURCE_MOUNT}/." "${WORK_DIR}/"

BUILD_JOBS="${BUILD_JOBS}" "${WORK_DIR}/tools/linux-build.sh"

/usr/bin/smithproxy --version

# A Git checkout must retain its source identity through the root-owned
# container copy. Source archives legitimately have no .git metadata.
if [ -e "${WORK_DIR}/.git" ]; then
    grep -Eq '^#define SX_GIT_COMMIT_HASH "[0-9a-f]+"$' \
        "${WORK_DIR}/src/smithproxy_version.h"
    if [ "${SMITHPROXY_ENABLE_NGTCP2:-ON}" = ON ]; then
        grep -Eq '^inline constexpr auto ngtcp2_commit = "[0-9a-f]{40}";$' \
            "${WORK_DIR}/build/generated/dependency_build_info.hpp"
    fi
fi

if ldd /usr/bin/smithproxy 2>&1 | grep -q "not found"; then
    echo "error: smithproxy has unresolved shared-library dependencies" >&2
    ldd /usr/bin/smithproxy >&2
    exit 1
fi

# The transport and its TLS adapter are linked from required static CMake
# targets. A successful executable link proves their referenced symbols were
# resolved. The installed Release binary is stripped, so it has no symbol table
# for nm to inspect. Reject direct shared ngtcp2 links instead; an unrelated
# system dependency (for example curl) may itself use ngtcp2.
if [ "${SMITHPROXY_ENABLE_NGTCP2:-ON}" = ON ]; then
    if readelf -d /usr/bin/smithproxy | grep -E 'NEEDED.*libngtcp2'; then
        echo "error: Smithproxy directly depends on a system ngtcp2 library" >&2
        exit 1
    fi
    test -s /usr/share/smithproxy/docs/licenses/LICENSE.ngtcp2
fi

# Debian packages use generated shlibs dependencies. Verify them against the
# installed binary as well as checking that the runtime loader resolves it.
if command -v dpkg-shlibdeps >/dev/null 2>&1; then
    SHLIBS_CHECK="${WORK_DIR}/shlibs-check"
    mkdir -p "${SHLIBS_CHECK}/debian"
    printf 'Source: smithproxy\n\nPackage: smithproxy\nArchitecture: any\n' > "${SHLIBS_CHECK}/debian/control"
    (cd "${SHLIBS_CHECK}" && dpkg-shlibdeps -O -e/usr/bin/smithproxy) > "${SHLIBS_CHECK}/depends"
    cat "${SHLIBS_CHECK}/depends"
    if grep -q 'libngtcp2' "${SHLIBS_CHECK}/depends"; then
        echo "error: package unexpectedly requires system ngtcp2" >&2
        exit 1
    fi
fi

echo "SANITY PASS: ${DISTRO_NAME:-unknown distro}"
