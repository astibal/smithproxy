#!/usr/bin/env sh

set -eu

if [ "$(id -u)" -ne 0 ]; then
    echo "error: run this script as root (for example: sudo $0)" >&2
    exit 1
fi

if [ "$(uname -s)" != "Linux" ]; then
    echo "error: only Linux is supported by this dependency installer" >&2
    exit 1
fi

if [ ! -r /etc/os-release ]; then
    echo "error: cannot identify the distribution (/etc/os-release is missing)" >&2
    exit 1
fi

# ID and ID_LIKE are distro-supplied values from os-release, not user input.
# shellcheck disable=SC1091
. /etc/os-release

DIST_ID=${ID:-unknown}
DIST_VERSION=${VERSION_ID:-unknown}
DIST_LIKE=${ID_LIKE:-}

echo "... OS detected: ${DIST_ID} version ${DIST_VERSION}"

is_like() {
    case " ${DIST_LIKE} " in
        *" $1 "*) return 0 ;;
        *) return 1 ;;
    esac
}

install_apt_dependencies() {
    export DEBIAN_FRONTEND=noninteractive

    apt-get update
    apt-get install -y --no-install-recommends \
        ca-certificates wget curl \
        git g++ cmake make build-essential \
        python3 python3-dev python3-cryptography python3-pyroute2 python3-pyparsing \
        libconfig-dev libconfig++-dev \
        libssl-dev libunwind-dev libmicrohttpd-dev libcurl4-openssl-dev \
        libpam0g-dev \
        iptables iproute2 telnet \
        swig libffi-dev libxml2-dev libxslt1-dev xmlsec1
}

install_apk_dependencies() {
    apk add --no-cache \
        ca-certificates wget curl bash \
        git g++ cmake make musl-dev linux-headers bsd-compat-headers \
        python3 python3-dev py3-cryptography py3-pyroute2 \
        libconfig-dev openssl-dev libunwind-dev libmicrohttpd-dev curl-dev \
        linux-pam-dev \
        iptables iproute2 busybox-extras \
        swig libffi-dev libxml2-dev libxslt-dev xmlsec-dev
}

install_dnf_dependencies() {
    # DNF may replace glibc/bash in minimal images. Replacing this process
    # avoids continuing in an interpreter whose runtime was just upgraded.
    exec dnf install -y \
        ca-certificates wget curl-minimal \
        git gcc-c++ cmake make \
        python3 python3-devel python3-cryptography python3-pyroute2 python3-pyparsing \
        libconfig-devel openssl-devel libunwind-devel libmicrohttpd-devel \
        libcurl-devel pam-devel \
        iptables iproute telnet \
        swig libffi-devel libxml2-devel libxslt-devel xmlsec1-devel
}

install_rhel_dependencies() {
    # Several build dependencies live in CRB and EPEL on RHEL derivatives.
    dnf install -y dnf-plugins-core epel-release
    dnf config-manager --set-enabled crb
    install_dnf_dependencies
}

install_zypper_dependencies() {
    zypper --non-interactive refresh
    zypper --non-interactive install --no-recommends \
        ca-certificates wget curl \
        git gcc-c++ cmake make \
        python3 python3-devel python3-cryptography python3-pyroute2 python3-pyparsing \
        libconfig-devel libopenssl-devel libunwind-devel libmicrohttpd-devel \
        libcurl-devel pam-devel \
        iptables iproute2 telnet \
        swig libffi-devel libxml2-devel libxslt-devel xmlsec1-devel
}

case "${DIST_ID}" in
    ubuntu|debian|linuxmint|pop)
        install_apt_dependencies
        ;;
    alpine)
        install_apk_dependencies
        ;;
    fedora)
        install_dnf_dependencies
        ;;
    almalinux|rocky|centos)
        install_rhel_dependencies
        ;;
    opensuse-tumbleweed|opensuse-leap|sles)
        install_zypper_dependencies
        ;;
    *)
        if is_like debian; then
            install_apt_dependencies
        elif is_like fedora; then
            install_dnf_dependencies
        elif is_like suse || is_like opensuse; then
            install_zypper_dependencies
        else
            echo "error: unsupported Linux distribution: ${DIST_ID} ${DIST_VERSION}" >&2
            exit 1
        fi
        ;;
esac

echo "... dependencies installed successfully"
