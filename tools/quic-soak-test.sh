#!/usr/bin/env bash

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BUILD_DIR="${QUIC_TESTBED_BUILD_DIR:-${ROOT_DIR}/build-quic-testbed}"
REPEATS="${QUIC_SOAK_REPEATS:-50}"
RSS_GROWTH_LIMIT_KB="${QUIC_SOAK_RSS_GROWTH_LIMIT_KB:-32768}"
FD_SPREAD_LIMIT="${QUIC_SOAK_FD_SPREAD_LIMIT:-256}"

cmake -S "${ROOT_DIR}" -B "${BUILD_DIR}" -DCMAKE_BUILD_TYPE=Debug \
    -DCMAKE_POLICY_VERSION_MINIMUM=3.5
cmake --build "${BUILD_DIR}" --target quic_testbed -j"${QUIC_TESTBED_JOBS:-2}"

TMP_DIR="$(mktemp -d /tmp/smithproxy-quic-soak-XXXXXX)"
cleanup() { rm -rf -- "${TMP_DIR}"; }
trap cleanup EXIT

FILTER='QuicTestbed.ConcurrentVerifiedMitmSessionsAndStreams:QuicTestbed.RepeatedVerifiedReconnectsReleaseEveryIdleSession:QuicTestbed.EchoesPayloadsAcrossPacketAndBufferBoundaries'
"${BUILD_DIR}/quic_testbed" --gtest_filter="${FILTER}" \
    --gtest_repeat="${REPEATS}" --gtest_break_on_failure --gtest_color=no \
    >"${TMP_DIR}/test.log" 2>&1 &
TEST_PID=$!

min_rss=2147483647
max_rss=0
min_fd=2147483647
max_fd=0
samples=0
last_ticks=0
while kill -0 "${TEST_PID}" 2>/dev/null; do
    rss="$(awk '/^VmRSS:/ { print $2 }' "/proc/${TEST_PID}/status" 2>/dev/null || true)"
    fd_count="$(find "/proc/${TEST_PID}/fd" -mindepth 1 -maxdepth 1 2>/dev/null | wc -l)"
    ticks="$(awk '{ print $14 + $15 }' "/proc/${TEST_PID}/stat" 2>/dev/null || true)"
    if [[ -n "${rss}" ]]; then
        if (( rss < min_rss )); then min_rss="${rss}"; fi
        if (( rss > max_rss )); then max_rss="${rss}"; fi
        echo "${rss}" >>"${TMP_DIR}/rss.samples"
        samples=$((samples + 1))
    fi
    if [[ -n "${fd_count}" ]]; then
        if (( fd_count < min_fd )); then min_fd="${fd_count}"; fi
        if (( fd_count > max_fd )); then max_fd="${fd_count}"; fi
    fi
    [[ -z "${ticks}" ]] || last_ticks="${ticks}"
    sleep 0.2
done

set +e
wait "${TEST_PID}"
test_status=$?
set -e
if [[ "${test_status}" -ne 0 ]]; then
    cat "${TMP_DIR}/test.log" >&2
    exit "${test_status}"
fi

rss_growth=0
if (( samples >= 8 )); then
    rss_growth="$(awk '
        { value[NR]=$1 }
        END {
            width=int(NR/4); first=0; last=0;
            for (i=1; i<=width; ++i) first+=value[i];
            for (i=NR-width+1; i<=NR; ++i) last+=value[i];
            printf "%.0f", (last-first)/width;
        }' "${TMP_DIR}/rss.samples")"
fi
fd_spread=$((max_fd - min_fd))
clock_ticks="$(getconf CLK_TCK)"
cpu_seconds="$(awk -v ticks="${last_ticks}" -v hz="${clock_ticks}" \
    'BEGIN { printf "%.2f", ticks / hz }')"

if (( rss_growth > RSS_GROWTH_LIMIT_KB )); then
    echo "FAIL: RSS grew by ${rss_growth} KiB (limit ${RSS_GROWTH_LIMIT_KB} KiB)" >&2
    exit 1
fi
if (( fd_spread > FD_SPREAD_LIMIT )); then
    echo "FAIL: fd spread ${fd_spread} exceeded ${FD_SPREAD_LIMIT}" >&2
    exit 1
fi

sessions=$((REPEATS * 24))
streams=$((REPEATS * 55))
echo "PASS: QUIC soak repeats=${REPEATS} sessions=${sessions} streams=${streams}"
echo "      RSS min=${min_rss}KiB max=${max_rss}KiB trend=${rss_growth}KiB"
echo "      FD min=${min_fd} max=${max_fd} spread=${fd_spread}"
echo "      process CPU=${cpu_seconds}s samples=${samples}"
