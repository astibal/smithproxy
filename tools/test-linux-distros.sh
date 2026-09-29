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
    "alpine-3.20|alpine:3.20"
    "alpine-3.22|alpine:3.22"
    "fedora-42|fedora:42"
    "fedora-43|fedora:43"
    "opensuse-tumbleweed|opensuse/tumbleweed:latest"
    "almalinux-9|almalinux:9"
    "almalinux-10|almalinux:10"
    "rockylinux-9|rockylinux:9"
)

usage() {
    cat <<'EOF'
Usage: tools/test-linux-distros.sh [--list] [DISTRO ...]

Run dependency installation, full build, install and binary smoke tests in
fresh Docker containers. With no DISTRO arguments, all supported images run.
DISTRO is a name printed by --list, for example ubuntu-26.04 or alpine-3.22.

Environment:
  BUILD_JOBS=N   parallel compiler jobs per container (default: 2)
  DOCKER_PLATFORM=linux/arm64
                 select another architecture when Docker has QEMU/binfmt support
EOF
}

list_distros() {
    local entry
    for entry in "${DISTROS[@]}"; do
        printf '%-24s %s\n' "${entry%%|*}" "${entry#*|}"
    done
}

if [[ ${1:-} == --help || ${1:-} == -h ]]; then
    usage
    exit 0
fi

if [[ ${1:-} == --list ]]; then
    list_distros
    exit 0
fi

selected=("$@")
failures=()
platform_args=()
if [[ -n ${DOCKER_PLATFORM} ]]; then
    platform_args=(--platform "${DOCKER_PLATFORM}")
fi

for entry in "${DISTROS[@]}"; do
    name=${entry%%|*}
    image=${entry#*|}

    if (( ${#selected[@]} > 0 )); then
        matched=0
        for requested in "${selected[@]}"; do
            if [[ ${requested} == "${name}" ]]; then
                matched=1
                break
            fi
        done
        (( matched == 1 )) || continue
    fi

    echo "===== ${name} (${image}) ====="
    container_id=$(docker run --detach \
        "${platform_args[@]}" \
        --env SMITHPROXY_SANITY_CONTAINER=1 \
        --env "DISTRO_NAME=${name}" \
        --env "BUILD_JOBS=${BUILD_JOBS}" \
        --volume "${SOURCE_DIR}:/src:ro" \
        "${image}" \
        sh -c 'while :; do sleep 3600; done')

    cleanup_container() {
        docker rm --force "${container_id}" >/dev/null 2>&1 || true
    }
    trap cleanup_container EXIT INT TERM

    if ! docker exec "${container_id}" /src/tools/linux-sanity-test.sh dependencies ||
       ! docker exec "${container_id}" /src/tools/linux-sanity-test.sh build; then
        failures+=("${name}")
    fi

    cleanup_container
    trap - EXIT INT TERM
done

if (( ${#selected[@]} > 0 )); then
    for requested in "${selected[@]}"; do
        if ! printf '%s\n' "${DISTROS[@]%%|*}" | grep -Fxq "${requested}"; then
            echo "error: unknown distro: ${requested}" >&2
            exit 2
        fi
    done
fi

if (( ${#failures[@]} > 0 )); then
    printf 'FAILED: %s\n' "${failures[*]}" >&2
    exit 1
fi

echo "ALL SANITY TESTS PASSED"
