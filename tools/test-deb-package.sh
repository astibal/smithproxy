#!/usr/bin/env bash

set -euo pipefail

SOURCE_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
BUILD_JOBS=${BUILD_JOBS:-2}
DOCKER_PLATFORM=${DOCKER_PLATFORM:-}

DISTROS=(
    "ubuntu-22.04|ubuntu:22.04"
    "ubuntu-24.04|ubuntu:24.04"
    "ubuntu-26.04|ubuntu:26.04"
    "debian-12|debian:12"
    "debian-13|debian:13"
)

usage() {
    cat <<'EOF'
Usage: tools/test-deb-package.sh [--list] DISTRO

Build a native Smithproxy Debian package and exercise its complete package
lifecycle in a second, clean Docker container. DISTRO is one name printed by
--list.

Environment:
  BUILD_JOBS=N                 compiler jobs (default: 2)
  DOCKER_PLATFORM=linux/arm64  optional Docker platform
EOF
}

list_distros() {
    local entry
    for entry in "${DISTROS[@]}"; do
        printf '%-16s %s\n' "${entry%%|*}" "${entry#*|}"
    done
}

case "${1:-}" in
    --list) list_distros; exit 0 ;;
    -h|--help) usage; exit 0 ;;
    '') usage >&2; exit 2 ;;
esac

requested=$1
image=
for entry in "${DISTROS[@]}"; do
    if [[ ${entry%%|*} == "${requested}" ]]; then
        image=${entry#*|}
        break
    fi
done

if [[ -z ${image} ]]; then
    echo "error: unsupported package test distro: ${requested}" >&2
    list_distros >&2
    exit 2
fi

platform_args=()
if [[ -n ${DOCKER_PLATFORM} ]]; then
    platform_args=(--platform "${DOCKER_PLATFORM}")
fi

volume="smithproxy-deb-test-${requested//[^a-zA-Z0-9]/-}-$$"
docker volume create "${volume}" >/dev/null
cleanup() {
    docker volume rm --force "${volume}" >/dev/null 2>&1 || true
}
trap cleanup EXIT INT TERM

echo "===== build ${requested} (${image}) ====="
docker run --rm \
    "${platform_args[@]}" \
    --env "BUILD_JOBS=${BUILD_JOBS}" \
    --volume "${SOURCE_DIR}:/src:ro" \
    --volume "${volume}:/out" \
    "${image}" \
    sh -ceu '
        export DEBIAN_FRONTEND=noninteractive
        apt-get update -qq
        apt-get install -qq -y --no-install-recommends \
            build-essential ca-certificates devscripts equivs
        mkdir -p /work/source
        cp -a /src/. /work/source/
        cd /work/source
        apt-get build-dep -qq -y .
        DEB_BUILD_OPTIONS=terse BUILD_JOBS="${BUILD_JOBS}" \
            tools/package-deb.sh
        find .. -maxdepth 1 -type f \( \
            -name "smithproxy_*.deb" -o \
            -name "smithproxy-dbgsym_*.deb" -o \
            -name "smithproxy_*.ddeb" -o \
            -name "smithproxy_*.buildinfo" -o \
            -name "smithproxy_*.changes" \
        \) -exec cp {} /out/ \;
    '

echo "===== lifecycle ${requested} (${image}) ====="
docker run --rm \
    "${platform_args[@]}" \
    --volume "${volume}:/packages:ro" \
    "${image}" \
    sh -ceu '
        export DEBIAN_FRONTEND=noninteractive
        check() {
            description=$1
            shift
            if "$@"; then
                printf "PASS: %s\n" "${description}"
            else
                printf "FAIL: %s\n" "${description}" >&2
                exit 1
            fi
        }
        package=$(find /packages -maxdepth 1 -name "smithproxy_*_*.deb" | head -n1)
        check "runtime package found" test -n "${package}"

        apt-get update -qq
        apt-get install -qq -y --no-install-recommends "${package}"

        check "binary reports its version" smithproxy --version
        check "service account exists" getent passwd _sxy
        check "state directory exists" test -d /var/smithproxy/data
        check "log directory exists" test -d /var/log/smithproxy
        check "secret has mode 0600" test "$(stat -c %a /etc/smithproxy/users.key)" = 600
        check "binary has no file capabilities" test -z "$(getcap /usr/bin/smithproxy 2>/dev/null || true)"
        check "package did not start core" test ! -e /run/smithproxy.default.pid
        check "core service is disabled" test ! -e /etc/systemd/system/multi-user.target.wants/sx-core@default.service
        check "network service is disabled" test ! -e /etc/systemd/system/multi-user.target.wants/sx-network@default.service

        printf "\n# package lifecycle test\n" >>/etc/smithproxy/smithproxy.cfg
        apt-get install -qq -y --reinstall "${package}"
        check "reinstall preserves config" grep -q "package lifecycle test" /etc/smithproxy/smithproxy.cfg

        apt-get remove -qq -y smithproxy
        check "remove deletes binary" test ! -e /usr/bin/smithproxy
        check "remove preserves config" grep -q "package lifecycle test" /etc/smithproxy/smithproxy.cfg

        apt-get install -qq -y --no-install-recommends "${package}"
        check "install after remove preserves config" grep -q "package lifecycle test" /etc/smithproxy/smithproxy.cfg

        apt-get purge -qq -y smithproxy
        check "purge deletes binary" test ! -e /usr/bin/smithproxy
        check "purge deletes config" test ! -e /etc/smithproxy/smithproxy.cfg
    '

echo "DEB PACKAGE PASS: ${requested}"
