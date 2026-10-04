#!/usr/bin/env bash
set -euo pipefail

HERE=$(cd "$(dirname "$0")" && pwd)
CORPUS=$HERE/corpus/run-suite.sh
PPLAY=$HERE/vendor/pplay.py
declare -A expected=(
    [h1]=184 [h2]=186 [tls]=15 [socks5]=12 [dns]=57 [quic]=28
    [redis]=38 [mqtt]=15 [smtp]=21 [imap]=4 [pop3]=1 [ftp]=1 [ssh]=1
    [websocket]=6 [memcached]=1 [postgresql]=1 [mysql]=1 [amqp]=1
    [telnet]=1 [ntp]=4 [syslog]=25 [stun]=9 [tftp]=1 [snmp]=2 [raw]=40
)
total=0
temporary=$(mktemp -d)
trap 'rm -rf "$temporary"' EXIT
for area in "${!expected[@]}"; do
    (PPLAY_PY="$PPLAY" FUZZ_AREA="$area" EXCLUDE='capture_*' LIST_ONLY=1 \
        "$CORPUS" all | wc -l > "$temporary/$area") &
done
wait
for area in "${!expected[@]}"; do
    count=$(<"$temporary/$area")
    [[ $count == "${expected[$area]}" ]] || {
        echo "fuzz.$area selected $count cases; expected ${expected[$area]}" >&2
        exit 1
    }
    ((total += count))
done
[[ $total == 655 ]] || { echo "fuzz areas selected $total cases; expected 655" >&2; exit 1; }
echo "PASS: 655 corpus cases map exactly once across ${#expected[@]} fuzz areas"
