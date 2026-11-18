#!/usr/bin/env bash
set -euo pipefail
source_dir=$(cd "$(dirname "$0")/../.." && pwd)
build_dir="$source_dir/build"
suite=all
section=all
while (($#)); do
    case "$1" in
        --build-dir) build_dir=$2; shift 2 ;;
        --suite) suite=$2; shift 2 ;;
        --section) section=$2; shift 2 ;;
        *) echo "Usage: $0 [--build-dir PATH] [--suite all|unit|process|regression] [--section all|selection|paths|migration|tls]" >&2; exit 2 ;;
    esac
done
build_dir=$(cd "$build_dir" && pwd)
cd "$source_dir"
ran=0
if [[ $suite == all || $suite == unit ]]; then
    if [[ $section == all || $section == selection ]]; then
        "$build_dir/custom_cert_fallback_tests" --gtest_filter='CustomCertFallback.*-CustomCertFallback.ExternalPathIsAbsoluteAndOutsideManagedTree'
        echo 'PASS: unit/selection'
        ran=1
    fi
    if [[ $section == all || $section == paths ]]; then
        "$build_dir/custom_cert_fallback_tests" --gtest_filter='CustomCertFallback.ExternalPathIsAbsoluteAndOutsideManagedTree'
        echo 'PASS: unit/paths'
        ran=1
    fi
fi
if [[ $suite == all || $suite == process ]]; then
    if [[ $section == all || $section == migration ]]; then
        # No production routes, DNS or webhooks are reachable from this namespace.
        unshare --net bash -c 'ip link set lo up; exec python3 "$@"' _ \
            tests/process/cftar_schema_upgrade.py "$build_dir/smithproxy" \
            --native-archive "$build_dir/defaults/smithproxy.cftar"
        echo 'PASS: process/migration'
        ran=1
    fi
fi
if [[ $suite == all || $suite == regression ]]; then
    if [[ $section == all || $section == tls ]]; then
        unshare --net bash -c 'ip link set lo up; exec "$@"' _ \
            "$build_dir/sx_gtests" --gtest_filter='TLS_Tests.*:CfgValue.*'
        echo 'PASS: regression/tls'
        ran=1
    fi
fi
if (( !ran )); then
    echo "No matching suite/section: $suite/$section" >&2
    exit 2
fi
