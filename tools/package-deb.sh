#!/usr/bin/env sh

set -eu

SOURCE_DIR=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
BUILD_JOBS=${BUILD_JOBS:-$(getconf _NPROCESSORS_ONLN 2>/dev/null || printf '1')}
MODE=binary
SIGN=no

usage() {
    cat <<'EOF'
Usage: tools/package-deb.sh [--binary|--source|--both] [--sign]

Builds Debian packages with dpkg-buildpackage. Output is written next to the
source directory, as expected by Debian tooling.

  --binary  Build architecture-dependent packages (default)
  --source  Build a source package; requires a matching ../smithproxy_*.orig.tar.*
  --both    Build source and binary packages
  --sign    Sign source and changes files using the configured GPG identity
EOF
}

while [ "$#" -gt 0 ]; do
    case "$1" in
        --binary) MODE=binary ;;
        --source) MODE=source ;;
        --both) MODE=both ;;
        --sign) SIGN=yes ;;
        -h|--help) usage; exit 0 ;;
        *) echo "error: unknown argument: $1" >&2; usage >&2; exit 2 ;;
    esac
    shift
done

for command_name in dpkg-buildpackage dpkg-checkbuilddeps; do
    if ! command -v "$command_name" >/dev/null 2>&1; then
        echo "error: missing command: $command_name" >&2
        exit 1
    fi
done

if [ ! -f "${SOURCE_DIR}/debian/control" ]; then
    echo "error: Debian packaging metadata is missing" >&2
    exit 1
fi

if command -v git >/dev/null 2>&1 && \
   git -C "${SOURCE_DIR}" submodule status --recursive | grep -q '^-'; then
    echo "error: Git submodules are not initialized" >&2
    echo "hint: git submodule update --init --recursive" >&2
    exit 1
fi

dpkg-checkbuilddeps "${SOURCE_DIR}/debian/control"

set -- -j"${BUILD_JOBS}"
if [ "${SIGN}" = no ]; then
    set -- "$@" -us -uc
fi

case "${MODE}" in
    binary) set -- "$@" -b ;;
    source) set -- "$@" -S ;;
    both) set -- "$@" -F ;;
esac

echo "==> Building Debian package (${MODE}, jobs=${BUILD_JOBS})"
cd "${SOURCE_DIR}"
exec dpkg-buildpackage "$@"
