#!/usr/bin/env bash
# Run on m-tt-bs1 after copying the build into ROOT/bin/smithproxy.
set -euo pipefail
ROOT=${1:-/opt/lab/smithproxy-runner}
export PATH="$ROOT/bin:$PATH"
export SMITHPROXY_BIN="$ROOT/bin/smithproxy"
CLIENT=${CLIENT_NS:-sxr-client}
SERVER=${SERVER_NS:-sxr-origin}
NS=${DATA_NS:-sxr-data}
IN_IF=${LAB_IN_IF:-di0}
OUT_IF=${LAB_OUT_IF:-do0}
API_RELAY_PORT=${LAB_API_PORT:-55556}
CLI_RELAY_PORT=${LAB_CLI_PORT:-55557}
RUN_MODE=${RUN_MODE:-0}
RUNNER_PID=
CLI_RELAY_PID=
ORIGIN_PID=
PPLAY_SERVER_PID=
GRE_COLLECTOR_PID=
HTTP2_TCPDUMP_PID=
HTTP2_CLIENT_PID=
CAPTURE_MATRIX_GRE_PID=
CAPTURE_TEST=${CAPTURE_TEST:-0}
CAPTURE_MATRIX_TEST=${CAPTURE_MATRIX_TEST:-0}
RTT_TEST=${RTT_TEST:-0}
TLS_SUITE_TEST=${TLS_SUITE_TEST:-0}
POLICY_TEST=${POLICY_TEST:-0}
UDP_CHURN_TEST=${UDP_CHURN_TEST:-0}
TCP_CHURN_TEST=${TCP_CHURN_TEST:-0}
CAPTURE_MARKER=smithproxy-gre-pcap-test
CAPTURE_PREFIX="lab-capture-${BASHPID}-"
mkdir -p "$ROOT/results"
ip -j addr > "$ROOT/results/host-addresses-before.json"
ip -j route > "$ROOT/results/host-routes-before.json"
ip netns add "$CLIENT"
ip netns add "$SERVER"
cleanup() {
    trap - EXIT
    [[ -z $CLI_RELAY_PID ]] || kill -- "-$CLI_RELAY_PID" 2>/dev/null || true
    [[ -z $CLI_RELAY_PID ]] || wait "$CLI_RELAY_PID" 2>/dev/null || true
    [[ -z $RUNNER_PID ]] || kill -TERM "$RUNNER_PID" 2>/dev/null || true
    [[ -z $RUNNER_PID ]] || wait "$RUNNER_PID" 2>/dev/null || true
    [[ -z $ORIGIN_PID ]] || kill "$ORIGIN_PID" 2>/dev/null || true
    [[ -z $ORIGIN_PID ]] || wait "$ORIGIN_PID" 2>/dev/null || true
    [[ -z $PPLAY_SERVER_PID ]] || kill "$PPLAY_SERVER_PID" 2>/dev/null || true
    [[ -z $PPLAY_SERVER_PID ]] || wait "$PPLAY_SERVER_PID" 2>/dev/null || true
    [[ -z $GRE_COLLECTOR_PID ]] || kill "$GRE_COLLECTOR_PID" 2>/dev/null || true
    [[ -z $GRE_COLLECTOR_PID ]] || wait "$GRE_COLLECTOR_PID" 2>/dev/null || true
    [[ -z $HTTP2_TCPDUMP_PID ]] || kill "$HTTP2_TCPDUMP_PID" 2>/dev/null || true
    [[ -z $HTTP2_TCPDUMP_PID ]] || wait "$HTTP2_TCPDUMP_PID" 2>/dev/null || true
    [[ -z $HTTP2_CLIENT_PID ]] || kill "$HTTP2_CLIENT_PID" 2>/dev/null || true
    [[ -z $HTTP2_CLIENT_PID ]] || wait "$HTTP2_CLIENT_PID" 2>/dev/null || true
    [[ -z $CAPTURE_MATRIX_GRE_PID ]] || kill "$CAPTURE_MATRIX_GRE_PID" 2>/dev/null || true
    [[ -z $CAPTURE_MATRIX_GRE_PID ]] || wait "$CAPTURE_MATRIX_GRE_PID" 2>/dev/null || true
    ip link del "$IN_IF" 2>/dev/null || true
    ip link del "$OUT_IF" 2>/dev/null || true
    ip netns del "$CLIENT"
    ip netns del "$SERVER"
    ip -j addr > "$ROOT/results/host-addresses-after.json"
    ip -j route > "$ROOT/results/host-routes-after.json"
    python3 - "$ROOT/results" <<'PYCOMPARE'
import json, pathlib, sys
root = pathlib.Path(sys.argv[1])
def normalized(name):
    value = json.loads((root / name).read_text())
    for interface in value:
        for address in interface['addr_info']:
            # DHCP lease countdown changes naturally while the test is running.
            address.pop('valid_life_time', None)
            address.pop('preferred_life_time', None)
    return value
assert normalized('host-addresses-before.json') == normalized('host-addresses-after.json')
PYCOMPARE
    diff -u "$ROOT/results/host-routes-before.json" "$ROOT/results/host-routes-after.json"
    ! ip netns list | grep -Eq "^(${CLIENT}|${SERVER}|${NS})( |$)"
    ! ss -ltnH "sport = :$API_RELAY_PORT" | grep -q .
    ! ss -ltnH "sport = :$CLI_RELAY_PORT" | grep -q .
    echo 'PASS cleanup: no lab namespaces/API/CLI listeners; host addresses and routes unchanged'
}
trap cleanup EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM
ip link add "$IN_IF" type veth peer name eth0 netns "$CLIENT"
ip link add "$OUT_IF" type veth peer name eth0 netns "$SERVER"
ip -n "$CLIENT" link set lo up
ip -n "$CLIENT" link set eth0 up
ip -n "$CLIENT" addr add 198.18.10.2/24 dev eth0
ip -n "$CLIENT" route add default via 198.18.10.1
ip -n "$SERVER" link set lo up
ip -n "$SERVER" link set eth0 up
ip -n "$SERVER" addr add 198.18.20.2/24 dev eth0
# No route from origin to client: successful replies prove proxy termination.
if [[ $CAPTURE_TEST == 1 ]]; then
    export GRE_CAPTURE_DST=198.18.20.2
    export CAPTURE_FILE_PREFIX="$CAPTURE_PREFIX"
    if [[ $CAPTURE_MATRIX_TEST == 1 ]]; then
        export CAPTURE_CALCULATE_CHECKSUMS=1
        export CAPTURE_UDP_CONTENT_PROFILE=1
    fi
fi
python3 "$ROOT/runner/tests/prepare.py" "$ROOT"
if [[ ${EMPTY_NEIGHBOR_STATE_TEST:-0} == 1 ]]; then
    : > "$ROOT/data/nbr-default.json"
fi
if [[ $CAPTURE_TEST == 1 ]]; then
    rm -f "$ROOT/results/gre-ready" "$ROOT/results/gre-capture.json"
    ip netns exec "$SERVER" python3 "$ROOT/runner/tests/gre-collector.py" \
        "$ROOT/results/gre-capture.json" "$ROOT/results/gre-ready" "$CAPTURE_MARKER" \
        > "$ROOT/results/gre-collector.log" 2>&1 &
    GRE_COLLECTOR_PID=$!
    for attempt in $(seq 1 50); do
        [[ -f $ROOT/results/gre-ready ]] && break
        kill -0 "$GRE_COLLECTOR_PID"
        sleep 0.1
    done
    [[ -f $ROOT/results/gre-ready ]]
fi
ip netns exec "$SERVER" python3 -u "$ROOT/runner/tests/origin.py" "$ROOT/config/certs" > "$ROOT/results/origin.log" 2>&1 &
ORIGIN_PID=$!
"$ROOT/runner/smithproxy.runner" --in "$IN_IF" --out "$OUT_IF" --namespace "$NS" \
    --api-port "$API_RELAY_PORT" --config-dir "$ROOT/config" --data-dir "$ROOT/data" \
    > "$ROOT/results/runner.log" 2>&1 &
RUNNER_PID=$!
for attempt in $(seq 1 60); do
    if curl --noproxy '*' -ksSf --max-time 1 -H "X-API-Key: $(cat "$ROOT/config/api.key")" \
        "https://127.0.0.1:$API_RELAY_PORT/api/status/ping" > "$ROOT/results/api.json" 2>/dev/null; then break; fi
    kill -0 "$RUNNER_PID"
    sleep 1
done
python3 -c 'import json,sys; assert json.load(open(sys.argv[1]))["status"] == "ok"' "$ROOT/results/api.json"
echo 'PASS API: authenticated HTTPS request from host namespace'
if [[ $RUN_MODE == 1 ]]; then
    setsid socat "TCP4-LISTEN:$CLI_RELAY_PORT,bind=127.0.0.1,reuseaddr,fork" \
        "EXEC:ip netns exec $NS socat STDIO TCP4\:127.0.0.1\:50000" \
        > "$ROOT/results/cli-relay.log" 2>&1 &
    CLI_RELAY_PID=$!
    for attempt in $(seq 1 50); do
        ss -ltnH "sport = :$CLI_RELAY_PORT" | grep -q . && break
        kill -0 "$CLI_RELAY_PID"
        sleep 0.1
    done
    ss -ltnH "sport = :$CLI_RELAY_PORT" | grep -q .
    API_KEY=$(<"$ROOT/config/api.key")
    echo
    echo 'Smithproxy interactive lab READY'
    echo "CLI:    nc 127.0.0.1 $CLI_RELAY_PORT"
    echo "API:    https://localhost:$API_RELAY_PORT"
    echo "API key: $API_KEY"
    echo "CA cert: $ROOT/config/certs/ca-cert.pem"
    echo "Example: curl --noproxy '*' --cacert '$ROOT/config/certs/ca-cert.pem' -H 'X-API-Key: $API_KEY' 'https://localhost:$API_RELAY_PORT/api/status/ping'"
    echo "Client namespace: $CLIENT (HTTP origin 198.18.20.2:8080; TLS origin origin.runner.lab:443)"
    echo 'Press Ctrl-C to stop Smithproxy and remove the lab.'
    while kill -0 "$RUNNER_PID" 2>/dev/null; do sleep 1; done
    wait "$RUNNER_PID"
    exit $?
fi
if [[ ${EMPTY_NEIGHBOR_STATE_TEST:-0} == 1 ]]; then
    ! grep -q 'json.exception.parse_error' "$ROOT/data/proxy-console.log"
    echo 'PASS empty neighbor state: no JSON parse error'
fi
ip netns exec "$CLIENT" curl --noproxy '*' -fsS --max-time 15 http://198.18.20.2:8080/ > "$ROOT/results/http.txt"
grep -q 'runner-origin-ok peer=198.18.20.1' "$ROOT/results/http.txt"
echo 'PASS TCP/HTTP: original destination preserved, egress uses do0'
if [[ $CAPTURE_TEST == 1 ]]; then
    ip netns exec "$CLIENT" curl --noproxy '*' -fsS --max-time 15 \
        -H "X-Capture-Marker: $CAPTURE_MARKER" http://198.18.20.2:8080/ \
        > "$ROOT/results/capture-http.txt"
    wait "$GRE_COLLECTOR_PID"
    GRE_COLLECTOR_PID=
    python3 -c 'import json,sys; assert json.load(open(sys.argv[1]))["marker_found"]' \
        "$ROOT/results/gre-capture.json"
    echo 'PASS GRE export: received encapsulated flow with expected payload marker'
fi
ip netns exec "$CLIENT" curl --noproxy '*' -fsS --max-time 20 \
    --cacert "$ROOT/config/certs/ca-cert.pem" --resolve origin.runner.lab:443:198.18.20.2 \
    https://origin.runner.lab/ > "$ROOT/results/https.txt"
grep -q 'runner-origin-ok peer=198.18.20.1' "$ROOT/results/https.txt"
echo 'PASS TLS: client trusts proxy CA only, origin uses a different CA'
ip netns exec "$CLIENT" python3 - <<'PY' > "$ROOT/results/udp.txt"
import socket
s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM)
s.settimeout(10)
for i in range(3):
    payload=b'runner-udp-' + str(i).encode()
    s.sendto(payload,('198.18.20.2',9999))
    reply,peer=s.recvfrom(4096)
    assert peer==('198.18.20.2',9999),peer
    assert reply.startswith(payload+b' peer=198.18.20.1 sport='),reply
    print(reply.decode())
PY
echo 'PASS UDP: three datagrams and original reply address'
if [[ $TLS_SUITE_TEST == 1 ]]; then
    ip netns exec "$CLIENT" python3 "$ROOT/runner/tests/suites/tls/run.py" \
        --ca-file "$ROOT/config/certs/ca-cert.pem" > "$ROOT/results/tls-suite.json"
    python3 "$ROOT/runner/tests/suites/tls/report.py" "$ROOT/results/tls-suite.json"
    echo 'PASS TLS suite: trust, SNI, ALPN and protocol-version matrix'
fi
if [[ $POLICY_TEST == 1 ]]; then
    { printf 'enable\r\ndiag proxy policy list 8\r\n'; sleep 1; printf 'quit\r\n'; } | \
        timeout 5 ip netns exec "$NS" nc 127.0.0.1 50000 > "$ROOT/results/policy-list.txt" 2>&1
    set +e
    ip netns exec "$CLIENT" python3 "$ROOT/runner/tests/suites/policy/run.py" > "$ROOT/results/policy-suite.json"
    POLICY_RC=$?
    set -e
    if ((POLICY_RC != 0)); then
        cat "$ROOT/results/policy-list.txt"
        exit "$POLICY_RC"
    fi
    python3 "$ROOT/runner/tests/suites/policy/report.py" "$ROOT/results/policy-suite.json"
    echo 'PASS policy suite: precedence, disabled, accept/profile and reject rules'
fi
if [[ $RTT_TEST == 1 ]]; then
    RTT_EXTRA_ARGS=()
    [[ ${RTT_REPORT_ONLY:-0} != 1 ]] || RTT_EXTRA_ARGS+=(--report-only)
    ip netns exec "$CLIENT" python3 "$ROOT/runner/tests/protocol-rtt.py" \
        --ca-file "$ROOT/config/certs/ca-cert.pem" \
        --samples "${RTT_SAMPLES:-200}" \
        --handshake-samples "${RTT_HANDSHAKE_SAMPLES:-40}" \
        --warmup "${RTT_WARMUP:-20}" \
        --rtt-p95-limit-ms "${RTT_P95_LIMIT_MS:-50}" \
        --rtt-max-limit-ms "${RTT_MAX_LIMIT_MS:-250}" \
        --handshake-p95-limit-ms "${RTT_HANDSHAKE_P95_LIMIT_MS:-500}" \
        --handshake-max-limit-ms "${RTT_HANDSHAKE_MAX_LIMIT_MS:-2000}" \
        --tls-total-p50-limit-ms "${RTT_TLS_TOTAL_P50_LIMIT_MS:-7}" \
        --https-p50-limit-ms "${RTT_HTTPS_P50_LIMIT_MS:-2}" \
        --cold-sni cold-cert-cache.runner.lab \
        "${RTT_EXTRA_ARGS[@]}" \
        > "$ROOT/results/tcp-rtt.json"
    python3 "$ROOT/runner/tests/suites/rtt/report.py" "$ROOT/results/tcp-rtt.json"
    if [[ ${RTT_NATIVE_BASELINE:-0} == 1 ]]; then
        ip netns exec "$SERVER" python3 "$ROOT/runner/tests/protocol-rtt.py" \
            --ca-file "$ROOT/config/certs/origin-ca.pem" \
            --samples "${RTT_SAMPLES:-200}" \
            --handshake-samples "${RTT_HANDSHAKE_SAMPLES:-40}" \
            --warmup "${RTT_WARMUP:-20}" \
            --report-only > "$ROOT/results/native-rtt.json"
    fi
    echo 'PASS RTT: TCP, UDP and TLS handshakes/round trips validated within limits'
fi
if [[ $TCP_CHURN_TEST == 1 ]]; then
    ip netns exec "$CLIENT" python3 "$ROOT/runner/tests/tcp-churn.py" \
        --waves "${TCP_CHURN_WAVES:-20}" \
        --flows "${TCP_CHURN_FLOWS:-64}" \
        --interval "${TCP_CHURN_INTERVAL:-0.25}" \
        --settle "${TCP_CHURN_SETTLE:-15}" \
        --timeout "${TCP_CHURN_TIMEOUT:-3}" \
        --min-port "${CHURN_MIN_PORT:-20000}" \
        --max-port "${CHURN_MAX_PORT:-29999}" \
        > "$ROOT/results/tcp-churn.txt"
    cat "$ROOT/results/tcp-churn.txt"
    echo 'PASS TCP churn: persistent flow survived proxy creation and deferred cleanup'
fi
if [[ $UDP_CHURN_TEST == 1 ]]; then
    ip netns exec "$CLIENT" python3 "$ROOT/runner/tests/udp-churn.py" \
        --waves "${UDP_CHURN_WAVES:-8}" \
        --flows "${UDP_CHURN_FLOWS:-96}" \
        --interval "${UDP_CHURN_INTERVAL:-3}" \
        --settle "${UDP_CHURN_SETTLE:-12}" \
        --timeout "${UDP_CHURN_TIMEOUT:-1}" \
        --min-port "${CHURN_MIN_PORT:-20000}" \
        --max-port "${CHURN_MAX_PORT:-29999}" \
        > "$ROOT/results/udp-churn.txt"
    cat "$ROOT/results/udp-churn.txt"
    echo 'PASS UDP churn: continuous traffic survived flow expiry and deferred cleanup'
fi
if [[ -n ${PPLAY_PY:-} && ${PPLAY_SMOKE_TEST:-1} == 1 ]]; then
    PPLAY_FIXTURE="$ROOT/runner/tests/pplay/http1_basic_pps.py"
    [[ -f $PPLAY_PY ]] || { echo "FAIL: PPLAY_PY is not a file: $PPLAY_PY" >&2; exit 1; }
    ip netns exec "$SERVER" python3 -u "$PPLAY_PY" \
        --script "$PPLAY_FIXTURE" --server 198.18.20.2:18080 \
        --auto 0.05 --nostdin --exitoneot --exitondiff --die-after 20 \
        --nohex --nocolor > "$ROOT/results/pplay-server.log" 2>&1 &
    PPLAY_SERVER_PID=$!
    for attempt in $(seq 1 50); do
        if ip netns exec "$SERVER" ss -ltnH 'sport = :18080' | grep -q .; then break; fi
        kill -0 "$PPLAY_SERVER_PID"
        sleep 0.1
    done
    ip netns exec "$SERVER" ss -ltnH 'sport = :18080' | grep -q .
    ip netns exec "$CLIENT" python3 -u "$PPLAY_PY" \
        --script "$PPLAY_FIXTURE" --client 198.18.20.2:18080 \
        --auto 0.05 --nostdin --exitoneot --exitondiff --die-after 20 \
        --nohex --nocolor > "$ROOT/results/pplay-client.log" 2>&1
    wait "$PPLAY_SERVER_PID"
    PPLAY_SERVER_PID=
    grep -q 'END OF TRANSMISSION' "$ROOT/results/pplay-client.log"
    grep -q 'END OF TRANSMISSION' "$ROOT/results/pplay-server.log"
    ! grep -q '^# !!!.*DIFFERENT DATA' "$ROOT/results/pplay-client.log"
    ! grep -q '^# !!!.*DIFFERENT DATA' "$ROOT/results/pplay-server.log"
    echo 'PASS pplay: exact HTTP/1 request and response traversed Smithproxy'
fi
if [[ $CAPTURE_MATRIX_TEST == 1 ]]; then
    [[ $CAPTURE_TEST == 1 ]] || { echo 'FAIL: CAPTURE_MATRIX_TEST requires CAPTURE_TEST=1' >&2; exit 1; }
    [[ -n ${PPLAY_PY:-} && -n ${PPLAY_SUITE:-} ]] || {
        echo 'FAIL: CAPTURE_MATRIX_TEST requires PPLAY_PY and PPLAY_SUITE' >&2
        exit 1
    }
    CAPTURE_MATRIX_RESULT="$ROOT/results/capture-matrix"
    CAPTURE_MATRIX_GRE="$CAPTURE_MATRIX_RESULT/gre.pcap"
    CAPTURE_MATRIX_MANIFEST="$CAPTURE_MATRIX_RESULT/manifest.json"
    rm -rf "$CAPTURE_MATRIX_RESULT"
    mkdir -p "$CAPTURE_MATRIX_RESULT"
    env PYTHONPATH="$PPLAY_SUITE${PYTHONPATH:+:$PYTHONPATH}" \
        python3 "$ROOT/runner/tests/build-capture-manifest.py" \
        "$PPLAY_SUITE" "$CAPTURE_MATRIX_MANIFEST"
    ip netns exec "$NS" tcpdump -i "$OUT_IF" -U -s 0 -w "$CAPTURE_MATRIX_GRE" 'ip proto 47' \
        > "$CAPTURE_MATRIX_RESULT/tcpdump.log" 2>&1 &
    CAPTURE_MATRIX_GRE_PID=$!
    sleep 0.5
    env PPLAY_PY="$PPLAY_PY" MODE=runner MATCH='capture_*' \
        RESULTS="$CAPTURE_MATRIX_RESULT/pplay" \
        SMITHPROXY_PID_FILE="$ROOT/data/proxy.pid" \
        CLIENT_NS="$CLIENT" SERVER_NS="$SERVER" \
        "$PPLAY_SUITE/run-suite.sh" all
    kill "$CAPTURE_MATRIX_GRE_PID" 2>/dev/null || true
    wait "$CAPTURE_MATRIX_GRE_PID" 2>/dev/null || true
    CAPTURE_MATRIX_GRE_PID=
    echo 'PASS capture matrix traffic: 30 corpus flows exported to local PCAPNG and GRE'
fi
if [[ ${HTTP2_OBSERVABILITY_TEST:-0} == 1 ]]; then
    [[ ${CAPTURE_TEST:-0} == 1 ]] || { echo 'FAIL: HTTP2_OBSERVABILITY_TEST requires CAPTURE_TEST=1' >&2; exit 1; }
    [[ -n ${PPLAY_PY:-} && -n ${PPLAY_SUITE:-} ]] || {
        echo 'FAIL: HTTP2_OBSERVABILITY_TEST requires PPLAY_PY and PPLAY_SUITE' >&2
        exit 1
    }
    HTTP2_FIXTURE="$PPLAY_SUITE/regular/http2_many_commands.py"
    HTTP2_RESULT="$ROOT/results/http2-observability"
    HTTP2_READY="$HTTP2_RESULT/ready"
    HTTP2_GRE="$HTTP2_RESULT/gre.pcap"
    HTTP2_CLI="$HTTP2_RESULT/cli.txt"
    rm -rf "$HTTP2_RESULT"
    mkdir -p "$HTTP2_RESULT"

    ip netns exec "$NS" tcpdump -i "$OUT_IF" -U -s 0 -w "$HTTP2_GRE" 'ip proto 47' \
        > "$HTTP2_RESULT/tcpdump.log" 2>&1 &
    HTTP2_TCPDUMP_PID=$!

    env PYTHONPATH="$PPLAY_SUITE${PYTHONPATH:+:$PYTHONPATH}" \
        HTTP2_READY_FILE="$HTTP2_READY" HTTP2_OBSERVE_DELAY=15 \
        ip netns exec "$SERVER" python3 -u "$PPLAY_PY" \
        --script "$HTTP2_FIXTURE" --server 198.18.20.2:18080 \
        --auto 0.05 --nostdin --exitoneot --exitondiff --die-after 40 \
        --nohex --nocolor > "$HTTP2_RESULT/server.log" 2>&1 &
    PPLAY_SERVER_PID=$!
    for attempt in $(seq 1 50); do
        ip netns exec "$SERVER" ss -ltnH 'sport = :18080' | grep -q . && break
        kill -0 "$PPLAY_SERVER_PID"
        sleep 0.1
    done

    env PYTHONPATH="$PPLAY_SUITE${PYTHONPATH:+:$PYTHONPATH}" \
        HTTP2_READY_FILE="$HTTP2_READY" HTTP2_OBSERVE_DELAY=15 \
        ip netns exec "$CLIENT" python3 -u "$PPLAY_PY" \
        --script "$HTTP2_FIXTURE" --client 198.18.20.2:18080 \
        --auto 0.05 --nostdin --exitoneot --exitondiff --die-after 40 \
        --nohex --nocolor > "$HTTP2_RESULT/client.log" 2>&1 &
    HTTP2_CLIENT_PID=$!

    for attempt in $(seq 1 400); do
        [[ -f $HTTP2_READY ]] && break
        kill -0 "$RUNNER_PID"
        kill -0 "$HTTP2_CLIENT_PID"
        sleep 0.1
    done
    [[ -f $HTTP2_READY ]]
    { printf 'enable\r\ndiag proxy session list 8\r\n'; sleep 3; printf 'quit\r\n'; } | \
        timeout 10 ip netns exec "$NS" nc 127.0.0.1 50000 > "$HTTP2_CLI" 2>&1

    wait "$HTTP2_CLIENT_PID"
    HTTP2_CLIENT_PID=
    wait "$PPLAY_SERVER_PID"
    PPLAY_SERVER_PID=
    kill "$HTTP2_TCPDUMP_PID" 2>/dev/null || true
    wait "$HTTP2_TCPDUMP_PID" 2>/dev/null || true
    HTTP2_TCPDUMP_PID=
    echo 'PASS HTTP/2 observability traffic and CLI snapshot completed'
fi
if [[ -n ${PPLAY_SUITE:-} && ${PPLAY_SUITE_SKIP_RUN:-0} != 1 ]]; then
    [[ -n ${PPLAY_PY:-} ]] || { echo 'FAIL: PPLAY_SUITE requires PPLAY_PY' >&2; exit 1; }
    [[ -x $PPLAY_SUITE/run-suite.sh ]] || {
        echo "FAIL: suite runner is not executable: $PPLAY_SUITE/run-suite.sh" >&2
        exit 1
    }
    env PPLAY_PY="$PPLAY_PY" MODE=runner RESULTS="$ROOT/results/${PPLAY_RESULTS_NAME:-pplay-suite}" \
        SMITHPROXY_PID_FILE="$ROOT/data/proxy.pid" \
        CLIENT_NS="$CLIENT" SERVER_NS="$SERVER" \
        "$PPLAY_SUITE/run-suite.sh" "${PPLAY_SUITE_CATEGORY:-all}"
    echo 'PASS pplay suite through Smithproxy'
fi
ip netns exec "$NS" nft list ruleset > "$ROOT/results/nft-active.txt"
ip -n "$NS" -j route show table all > "$ROOT/results/data-routes.json"
# A stopped proxy must not silently become an ordinary forwarding router.
kill -STOP "$(cat "$ROOT/data/proxy.pid")"
if ip netns exec "$CLIENT" curl --noproxy '*' -fsS --max-time 2 http://198.18.20.2:8080/ >/dev/null 2>&1; then
    kill -CONT "$(cat "$ROOT/data/proxy.pid")"
    echo 'FAIL: proxy bypass' >&2
    exit 1
fi
kill -CONT "$(cat "$ROOT/data/proxy.pid")"
echo 'PASS no bypass while proxy is stopped'
kill -TERM "$RUNNER_PID"
wait "$RUNNER_PID" || test "$?" = 143
RUNNER_PID=
if [[ $CAPTURE_TEST == 1 ]]; then
    python3 "$ROOT/runner/tests/verify-pcap.py" "$ROOT/data" "$CAPTURE_PREFIX" "$CAPTURE_MARKER" \
        > "$ROOT/results/pcap-validation.json"
    echo 'PASS PCAP export: valid pcapng blocks contain expected payload marker'
fi
if [[ $CAPTURE_MATRIX_TEST == 1 ]]; then
    mkdir -p "$ROOT/results/capture-matrix/local-pcap"
    cp "$ROOT/data/$CAPTURE_PREFIX"*.pcapng "$ROOT/results/capture-matrix/local-pcap/"
    python3 "$ROOT/runner/tests/verify-capture-matrix.py" \
        "$ROOT/results/capture-matrix/manifest.json" "$ROOT/data" "$CAPTURE_PREFIX" \
        "$ROOT/results/capture-matrix/gre.pcap" \
        > "$ROOT/results/capture-matrix/validation.json"
    python3 "$ROOT/runner/tests/suites/capture-report.py" "$ROOT/results/capture-matrix/validation.json"
    echo 'PASS capture matrix: PCAPNG and GRE payload hashes match; simulated TCP is formally valid'
fi
if [[ ${HTTP2_OBSERVABILITY_TEST:-0} == 1 ]]; then
    HTTP2_PCAP=$(find "$ROOT/data" -maxdepth 1 -type f -name "$CAPTURE_PREFIX*.pcapng" \
        -printf '%T@ %p\n' | sort -nr | head -1 | cut -d' ' -f2-)
    python3 "$ROOT/runner/tests/verify-http2-observability.py" \
        "$ROOT/results/http2-observability/cli.txt" "$HTTP2_PCAP" \
        "$ROOT/results/http2-observability/gre.pcap" \
        > "$ROOT/results/http2-observability/validation.json"
    echo 'PASS HTTP/2 observability: CLI, PCAP and GRE contain exactly 12 requests and responses'
fi
# Both interfaces must have been returned by runner, before test destroys them.
ip link show "$IN_IF" > /dev/null
ip link show "$OUT_IF" > /dev/null
echo 'PASS runner shutdown: interfaces returned to host'
