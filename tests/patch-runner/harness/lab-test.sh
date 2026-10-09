#!/usr/bin/env bash
# Run inside a prepared local or remote patch-runner lab.
set -euo pipefail
ROOT=${1:-/opt/lab/smithproxy-runner}
export PATH="$ROOT/bin:$PATH"
export SMITHPROXY_BIN="$ROOT/bin/smithproxy"
if [[ -n ${QUIC_PYTHONPATH:-} ]]; then
    export PYTHONPATH="$QUIC_PYTHONPATH${PYTHONPATH:+:$PYTHONPATH}"
fi
if [[ ${QUIC_KEYLOG_TEST:-0} == 1 ]]; then
    # The production binary honours the conventional opt-in keylog variable.
    # Keep the proof artifact inside this disposable lab and never inherit an
    # unrelated host path into the isolated Smithproxy process.
    export SSLKEYLOGFILE="$ROOT/results/quic-downstream.keys"
    rm -f "$SSLKEYLOGFILE"
fi
CLIENT=${CLIENT_NS:-sxr-client}
SERVER=${SERVER_NS:-sxr-origin}
NS=${DATA_NS:-sxr-data}
IN_IF=${LAB_IN_IF:-di0}
OUT_IF=${LAB_OUT_IF:-do0}
API_RELAY_PORT=${LAB_API_PORT:-55556}
CLI_RELAY_PORT=${LAB_CLI_PORT:-55557}
RUN_MODE=${RUN_MODE:-0}
BASE_TRAFFIC_TEST=${BASE_TRAFFIC_TEST:-1}
PRIVSEP_TEST=${PRIVSEP_TEST:-0}
RUNNER_PID=
CLI_RELAY_PID=
ORIGIN_PID=
PPLAY_SERVER_PID=
GRE_COLLECTOR_PID=
HTTP2_TCPDUMP_PID=
HTTP2_CLIENT_PID=
CAPTURE_MATRIX_GRE_PID=
H3_ORIGIN_PID=
QUIC_CLIENT_PID=
QUIC_GRE_PID=
QUIC_NATIVE_PID=
SESSION_LIST_LOAD_PID=
PPLAY_SUITE4_PID=
PPLAY_SUITE6_PID=
STARTTLS_SERVER_PID=
TLS_EVASION_SERVER_PID=
TLS_AUTODETECT_SERVER_PID=
KTLS_PROBE_PID=
ROUTING_SERVER_PID=
CAPTURE_TEST=${CAPTURE_TEST:-0}
CAPTURE_MATRIX_TEST=${CAPTURE_MATRIX_TEST:-0}
RTT_TEST=${RTT_TEST:-0}
TLS_SUITE_TEST=${TLS_SUITE_TEST:-0}
TLS_TRANSFER_TEST=${TLS_TRANSFER_TEST:-0}
TLS_THROUGHPUT_TEST=${TLS_THROUGHPUT_TEST:-0}
KTLS_PROBE_TEST=${KTLS_PROBE_TEST:-0}
STARTTLS_SUITE_TEST=${STARTTLS_SUITE_TEST:-0}
POLICY_TEST=${POLICY_TEST:-0}
ROUTING_TEST=${ROUTING_TEST:-0}
SESSION_LIST_STRESS_TEST=${SESSION_LIST_STRESS_TEST:-0}
QUIC_TEST=${QUIC_TEST:-0}
UDP_CHURN_TEST=${UDP_CHURN_TEST:-0}
TCP_CHURN_TEST=${TCP_CHURN_TEST:-0}
CAPTURE_MARKER=smithproxy-gre-pcap-v4
CAPTURE_MARKER6=smithproxy-gre-pcap-v6
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
    [[ -z $QUIC_CLIENT_PID ]] || kill "$QUIC_CLIENT_PID" 2>/dev/null || true
    [[ -z $QUIC_CLIENT_PID ]] || wait "$QUIC_CLIENT_PID" 2>/dev/null || true
    [[ -z $QUIC_GRE_PID ]] || kill -INT "$QUIC_GRE_PID" 2>/dev/null || true
    [[ -z $QUIC_GRE_PID ]] || wait "$QUIC_GRE_PID" 2>/dev/null || true
    [[ -z $QUIC_NATIVE_PID ]] || kill -INT "$QUIC_NATIVE_PID" 2>/dev/null || true
    [[ -z $QUIC_NATIVE_PID ]] || wait "$QUIC_NATIVE_PID" 2>/dev/null || true
    [[ -z $H3_ORIGIN_PID ]] || kill "$H3_ORIGIN_PID" 2>/dev/null || true
    [[ -z $H3_ORIGIN_PID ]] || wait "$H3_ORIGIN_PID" 2>/dev/null || true
    [[ -z $SESSION_LIST_LOAD_PID ]] || kill "$SESSION_LIST_LOAD_PID" 2>/dev/null || true
    [[ -z $SESSION_LIST_LOAD_PID ]] || wait "$SESSION_LIST_LOAD_PID" 2>/dev/null || true
    [[ -z $PPLAY_SUITE4_PID ]] || kill -TERM "$PPLAY_SUITE4_PID" 2>/dev/null || true
    [[ -z $PPLAY_SUITE6_PID ]] || kill -TERM "$PPLAY_SUITE6_PID" 2>/dev/null || true
    [[ -z $PPLAY_SUITE4_PID ]] || wait "$PPLAY_SUITE4_PID" 2>/dev/null || true
    [[ -z $PPLAY_SUITE6_PID ]] || wait "$PPLAY_SUITE6_PID" 2>/dev/null || true
    [[ -z $STARTTLS_SERVER_PID ]] || kill "$STARTTLS_SERVER_PID" 2>/dev/null || true
    [[ -z $STARTTLS_SERVER_PID ]] || wait "$STARTTLS_SERVER_PID" 2>/dev/null || true
    [[ -z $TLS_EVASION_SERVER_PID ]] || kill "$TLS_EVASION_SERVER_PID" 2>/dev/null || true
    [[ -z $TLS_EVASION_SERVER_PID ]] || wait "$TLS_EVASION_SERVER_PID" 2>/dev/null || true
    [[ -z $TLS_AUTODETECT_SERVER_PID ]] || kill "$TLS_AUTODETECT_SERVER_PID" 2>/dev/null || true
    [[ -z $TLS_AUTODETECT_SERVER_PID ]] || wait "$TLS_AUTODETECT_SERVER_PID" 2>/dev/null || true
    [[ -z $KTLS_PROBE_PID ]] || kill "$KTLS_PROBE_PID" 2>/dev/null || true
    [[ -z $KTLS_PROBE_PID ]] || wait "$KTLS_PROBE_PID" 2>/dev/null || true
    [[ -z $ROUTING_SERVER_PID ]] || kill "$ROUTING_SERVER_PID" 2>/dev/null || true
    [[ -z $ROUTING_SERVER_PID ]] || wait "$ROUTING_SERVER_PID" 2>/dev/null || true
    ip link del "$IN_IF" 2>/dev/null || true
    ip link del "$OUT_IF" 2>/dev/null || true
    ip netns del "$CLIENT"
    ip netns del "$SERVER"
    ip -j addr > "$ROOT/results/host-addresses-after.json"
    ip -j route > "$ROOT/results/host-routes-after.json"
    python3 - "$ROOT/results" <<'PYCOMPARE'
import json, pathlib, re, sys
root = pathlib.Path(sys.argv[1])
runner_veth = re.compile(r'^sp[0-9a-f]{1,6}[io]$')

def addresses(name):
    return json.loads((root / name).read_text())

before_addresses = addresses('host-addresses-before.json')
after_addresses = addresses('host-addresses-after.json')
# Network-namespace veth endpoints are transient host state.  Other parallel
# labs, containers, or the test controller may create/remove them between our
# two snapshots, so comparing them would make cleanup verification racy.
before_names = {interface.get('ifname', '') for interface in before_addresses}
after_names = {interface.get('ifname', '') for interface in after_addresses}
transient_interfaces = {
    interface.get('ifname', '')
    for interface in before_addresses + after_addresses
    if 'link_netnsid' in interface
    or runner_veth.fullmatch(interface.get('ifname', ''))
}
transient_interfaces.update(before_names ^ after_names)

def normalized_addresses(value):
    value = [interface for interface in value
             if interface.get('ifname', '') not in transient_interfaces]
    for interface in value:
        # Carrier/operational state may change when an unrelated VM or
        # container joins a pre-existing host bridge during a long run.
        interface.pop('flags', None)
        interface.pop('operstate', None)
        # Privacy addresses are rotated and expire independently of the lab.
        # They are host state, but not state that the patch runner owns or can
        # restore, so exclude them from the leak check.
        interface['addr_info'] = [address for address in interface['addr_info']
                                  if not address.get('temporary')]
        for address in interface['addr_info']:
            # DHCP lease countdown changes naturally while the test is running.
            address.pop('valid_life_time', None)
            address.pop('preferred_life_time', None)
    return value
def normalized_routes(name):
    value = json.loads((root / name).read_text())
    value = [route for route in value
             if route.get('dev', '') not in transient_interfaces]
    for route in value:
        # `linkdown` follows carrier state and is not route ownership.
        route.pop('flags', None)
    return value
assert normalized_addresses(before_addresses) == normalized_addresses(after_addresses)
assert normalized_routes('host-routes-before.json') == normalized_routes('host-routes-after.json')
PYCOMPARE
    ! ip link show "$IN_IF" >/dev/null 2>&1
    ! ip link show "$OUT_IF" >/dev/null 2>&1
    ! ip netns list | grep -Eq "^(${CLIENT}|${SERVER}|${NS})( |$)"
    ! ss -ltnH "sport = :$API_RELAY_PORT" | grep -q .
    ! ss -ltnH "sport = :$CLI_RELAY_PORT" | grep -q .
    echo 'PASS cleanup: no lab namespaces/API/CLI listeners; host addresses and routes unchanged'
}
report_error() {
    local rc=$?
    local line=${1:-unknown}
    echo "FAIL: lab command at line $line exited with rc=$rc" >&2
    return "$rc"
}
trap 'report_error "$LINENO"' ERR
trap cleanup EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM
ip link add "$IN_IF" type veth peer name eth0 netns "$CLIENT"
ip link add "$OUT_IF" type veth peer name eth0 netns "$SERVER"
ip -n "$CLIENT" link set lo up
ip -n "$CLIENT" link set eth0 up
ip -n "$CLIENT" addr add 198.18.10.2/24 dev eth0
ip -n "$CLIENT" -6 addr add fd00:10::2/64 dev eth0 nodad
ip -n "$CLIENT" route add default via 198.18.10.1
ip -n "$CLIENT" -6 route add default via fd00:10::1
ip -n "$SERVER" link set lo up
ip -n "$SERVER" link set eth0 up
ip -n "$SERVER" addr add 198.18.20.2/24 dev eth0
if [[ $ROUTING_TEST == 1 ]]; then
    ip -n "$SERVER" addr add 198.18.20.3/24 dev eth0
fi
ip -n "$SERVER" -6 addr add fd00:20::2/64 dev eth0 nodad
if [[ $ROUTING_TEST == 1 ]]; then
    ip -n "$SERVER" -6 addr add fd00:20::3/64 dev eth0 nodad
fi
# No route from origin to client: successful replies prove proxy termination.
if [[ $QUIC_TEST == 1 ]]; then
    export GRE_CAPTURE_DST=198.18.20.2
    export CAPTURE_FILE_PREFIX="$CAPTURE_PREFIX"
elif [[ $CAPTURE_TEST == 1 ]]; then
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
        "$CAPTURE_MARKER6" \
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
if [[ $QUIC_TEST == 1 ]]; then
    [[ -x ${QUIC_CURL_BIN:-} ]] || {
        echo "FAIL: QUIC_CURL_BIN is not executable: ${QUIC_CURL_BIN:-<unset>}" >&2
        exit 1
    }
    "$QUIC_CURL_BIN" --version | grep -q HTTP3 || {
        echo "FAIL: QUIC_CURL_BIN lacks HTTP/3 support" >&2
        exit 1
    }
    python3 -c 'import aioquic' || {
        echo 'FAIL: QUIC runner requires the aioquic Python package' >&2
        exit 1
    }
    command -v tshark >/dev/null
    command -v tcpdump >/dev/null
    [[ -r ${SPQ1_DISSECTOR:-} ]] || {
        echo "FAIL: SPQ1_DISSECTOR is not readable: ${SPQ1_DISSECTOR:-<unset>}" >&2
        exit 1
    }
    ip netns exec "$SERVER" python3 -u "$ROOT/runner/tests/h3-origin.py" \
        --certificate "$ROOT/config/certs/origin-cert.pem" \
        --key "$ROOT/config/certs/origin-key.pem" \
        > "$ROOT/results/h3-origin.log" 2>&1 &
    H3_ORIGIN_PID=$!
    for attempt in $(seq 1 100); do
        grep -q '^READY h3-origin ' "$ROOT/results/h3-origin.log" && break
        kill -0 "$H3_ORIGIN_PID"
        sleep 0.05
    done
    grep -q '^READY h3-origin ' "$ROOT/results/h3-origin.log"
fi
if [[ $PRIVSEP_TEST == 1 ]]; then
    # The core must be able to update its ordinary runtime state after dropping
    # identity.  The config and PID targets deliberately remain root-only;
    # PCAPs and other runtime data remain owned by the unprivileged core.
    getent passwd nobody >/dev/null
    mkdir -p "$ROOT/data/run"
    chown -R nobody "$ROOT/config" "$ROOT/data"
    chown root:root "$ROOT/config/smithproxy.cfg" "$ROOT/data/run"
    chmod 0600 "$ROOT/config/smithproxy.cfg"
    chmod 0755 "$ROOT/data/run"
fi
"$ROOT/runner/smithproxy.runner" --in "$IN_IF" --out "$OUT_IF" --namespace "$NS" \
    --api-port "$API_RELAY_PORT" --config-dir "$ROOT/config" --data-dir "$ROOT/data" \
    > "$ROOT/results/runner.log" 2>&1 &
RUNNER_PID=$!
if [[ ${SKIP_API_READY:-0} != 1 ]]; then
    for attempt in $(seq 1 60); do
        if curl --noproxy '*' -ksSf --max-time 1 -H "X-API-Key: $(cat "$ROOT/config/api.key")" \
            "https://127.0.0.1:$API_RELAY_PORT/api/status/ping" > "$ROOT/results/api.json" 2>/dev/null; then break; fi
        kill -0 "$RUNNER_PID"
        sleep 1
    done
    python3 -c 'import json,sys; assert json.load(open(sys.argv[1]))["status"] == "ok"' "$ROOT/results/api.json"
    echo 'PASS API: authenticated HTTPS request from host namespace'
fi
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
if [[ $PRIVSEP_TEST == 1 ]]; then
    for attempt in $(seq 1 100); do
        [[ -s "$ROOT/data/proxy.pid" ]] && break
        kill -0 "$RUNNER_PID"
        sleep 0.1
    done
    [[ -s "$ROOT/data/proxy.pid" ]]
    proxy_pid=$(<"$ROOT/data/proxy.pid")
    kill -0 "$proxy_pid"
    nobody_uid=$(getent passwd nobody | cut -d: -f3)
    [[ -n $nobody_uid && $nobody_uid != 0 ]]

    for attempt in $(seq 1 50); do
        helper_pids=$(<"/proc/$proxy_pid/task/$proxy_pid/children")
        [[ -n $helper_pids ]] && break
        kill -0 "$proxy_pid"
        sleep 0.1
    done
    read -ra helpers <<<"$helper_pids"
    # File and socket privilege helpers plus the internal CLI broker are
    # mandatory. API and GRE brokers add children when enabled by the profile.
    [[ ${#helpers[@]} -ge 3 ]]
    core_uid=$(awk '/^Uid:/ { print $2 }' "/proc/$proxy_pid/status")
    [[ $core_uid == "$nobody_uid" ]]
    for helper_pid in "${helpers[@]}"; do
        helper_uid=$(awk '/^Uid:/ { print $2 }' "/proc/$helper_pid/status")
        [[ $helper_uid == 0 ]]
    done
    echo "PASS privsep identity: core uid=$core_uid, root helpers/brokers=${helpers[*]}"

    internal_pid="$ROOT/data/run/smithproxy.default.pid"
    [[ -s $internal_pid ]]
    [[ $(stat -c %u "$internal_pid") == 0 ]]
    [[ $(stat -c %a "$internal_pid") == 644 ]]
    echo 'PASS privsep PID: root helper created the private PID file'

    { printf 'enable\r\ndiag priv stats\r\ndiag priv comm cli stats\r\nsave config\r\nexecute reload\r\n'; sleep 1; printf 'quit\r\n'; } | \
        timeout 8 ip netns exec "$NS" nc 127.0.0.1 50000 > "$ROOT/results/privsep-stats.txt" 2>&1
    grep -q 'user: nobody' "$ROOT/results/privsep-stats.txt"
    grep -q "uid: $nobody_uid" "$ROOT/results/privsep-stats.txt"
    grep -q 'Privileged helper stats:' "$ROOT/results/privsep-stats.txt"
    grep -Eq 'setsockopt: [1-9][0-9]*' "$ROOT/results/privsep-stats.txt"
    grep -Eq 'max_ops_per_drain: [1-9][0-9]*' "$ROOT/results/privsep-stats.txt"
    grep -q 'CLI communication worker:' "$ROOT/results/privsep-stats.txt"
    grep -q 'mode: internal' "$ROOT/results/privsep-stats.txt"
    grep -Eq 'accepted: [1-9][0-9]*' "$ROOT/results/privsep-stats.txt"
    grep -q 'config saved successfully' "$ROOT/results/privsep-stats.txt"
    grep -q 'Configuration file reloaded' "$ROOT/results/privsep-stats.txt"
    [[ $(stat -c %u "$ROOT/config/smithproxy.cfg") == 0 ]]
    [[ $(stat -c %a "$ROOT/config/smithproxy.cfg") == 600 ]]
    echo 'PASS privsep CLI/config: stats plus root-only save and reload'

    ip netns exec "$CLIENT" curl --noproxy '*' -fsS --max-time 15 \
        http://198.18.20.2:8080/ > "$ROOT/results/privsep-http4.txt"
    grep -q 'runner-origin-ok peer=198.18.20.1' "$ROOT/results/privsep-http4.txt"
    echo 'PASS4 privsep TCP/HTTP: unprivileged core uses transparent listener'

    ip netns exec "$CLIENT" curl --noproxy '*' -gfsS --max-time 15 \
        'http://[fd00:20::2]:8080/' > "$ROOT/results/privsep-http6.txt"
    grep -q 'runner-origin-ok peer=fd00:20::1' "$ROOT/results/privsep-http6.txt"
    echo 'PASS6 privsep TCP/HTTP: unprivileged core uses transparent listener'
fi
if [[ $BASE_TRAFFIC_TEST == 1 ]]; then
ip netns exec "$CLIENT" curl --noproxy '*' -fsS --max-time 15 http://198.18.20.2:8080/ > "$ROOT/results/http4.txt"
grep -q 'runner-origin-ok peer=198.18.20.1' "$ROOT/results/http4.txt"
echo 'PASS4 TCP/HTTP: original destination preserved, egress uses do0'
ip netns exec "$CLIENT" python3 - <<'PY' > "$ROOT/results/http-half-close.txt"
import socket

request = (b'GET /delayed-half-close HTTP/1.1\r\n'
           b'Host: 198.18.20.2\r\nConnection: close\r\n\r\n')
with socket.create_connection(('198.18.20.2', 8080), timeout=10) as connection:
    connection.sendall(request)
    connection.shutdown(socket.SHUT_WR)
    response = bytearray()
    while True:
        chunk = connection.recv(65536)
        if not chunk:
            break
        response.extend(chunk)
assert b'HTTP/1.0 200 OK' in response, response[:200]
assert b'runner-origin-ok peer=198.18.20.1' in response, response[-200:]
print('half-close response bytes=' + str(len(response)))
PY
echo 'PASS4 TCP half-close: delayed response survived client SHUT_WR'
ip netns exec "$CLIENT" curl --noproxy '*' -gfsS --max-time 15 'http://[fd00:20::2]:8080/' > "$ROOT/results/http6.txt"
grep -q 'runner-origin-ok peer=fd00:20::1' "$ROOT/results/http6.txt"
echo 'PASS6 TCP/HTTP: original destination preserved, egress uses do0'
if [[ $CAPTURE_TEST == 1 ]]; then
    ip netns exec "$CLIENT" curl --noproxy '*' -fsS --max-time 15 \
        -H "X-Capture-Marker: $CAPTURE_MARKER" http://198.18.20.2:8080/ \
        > "$ROOT/results/capture-http4.txt"
    ip netns exec "$CLIENT" curl --noproxy '*' -gfsS --max-time 15 \
        -H "X-Capture-Marker: $CAPTURE_MARKER6" 'http://[fd00:20::2]:8080/' \
        > "$ROOT/results/capture-http6.txt"
    wait "$GRE_COLLECTOR_PID"
    GRE_COLLECTOR_PID=
    python3 -c 'import json,sys; d=json.load(open(sys.argv[1])); assert d["marker_found"] and set(d["inner_protocols"].values()) == {"0x0800", "0x86dd"}' \
        "$ROOT/results/gre-capture.json"
    echo 'PASS4 GRE export: received IPv4 inner flow with expected payload marker'
    echo 'PASS6 GRE export: received IPv6 inner flow with expected payload marker'
fi
ip netns exec "$CLIENT" curl --noproxy '*' --fail-with-body -sS --max-time 20 \
    --cacert "$ROOT/config/certs/ca-cert.pem" --resolve origin.runner.lab:443:198.18.20.2 \
    https://origin.runner.lab/ > "$ROOT/results/https.txt"
grep -q 'runner-origin-ok peer=198.18.20.1' "$ROOT/results/https.txt"
echo 'PASS4 TLS: client trusts proxy CA only, origin uses a different CA'
ip netns exec "$CLIENT" curl --noproxy '*' -g --fail-with-body -sS --max-time 20 \
    --cacert "$ROOT/config/certs/ca-cert.pem" --resolve 'origin.runner.lab:443:[fd00:20::2]' \
    https://origin.runner.lab/ > "$ROOT/results/https6.txt"
grep -q 'runner-origin-ok peer=fd00:20::1' "$ROOT/results/https6.txt"
echo 'PASS6 TLS: client trusts proxy CA only, origin uses a different CA'
ip netns exec "$CLIENT" python3 - <<'PY' > "$ROOT/results/udp.txt"
import socket
for family, host, expected_peer in ((socket.AF_INET, '198.18.20.2', '198.18.20.1'),
                                    (socket.AF_INET6, 'fd00:20::2', 'fd00:20::1')):
    with socket.socket(family,socket.SOCK_DGRAM) as s:
        s.settimeout(10)
        for i in range(3):
            payload=b'runner-udp-' + str(i).encode()
            s.sendto(payload,(host,9999))
            reply,peer=s.recvfrom(4096)
            assert peer[0:2]==(host,9999),peer
            assert reply.startswith(payload+b' peer='+expected_peer.encode()+b' sport='),reply
            print(reply.decode())
PY
echo 'PASS4 UDP: three datagrams and original reply address'
echo 'PASS6 UDP: three datagrams and original reply address'
if [[ $QUIC_TEST == 1 ]]; then
    QUIC_RESULT="$ROOT/results/quic-observability"
    QUIC_GRE="$QUIC_RESULT/gre.pcap"
    QUIC_NATIVE="$QUIC_RESULT/downstream-native.pcapng"
    QUIC_CLI="$QUIC_RESULT/cli.txt"
    rm -rf "$QUIC_RESULT"
    mkdir -p "$QUIC_RESULT"

    # Capture the encrypted downstream wire image and the independently
    # generated keyed-GRE plaintext export during the same H3 connection.
    ip netns exec "$NS" tcpdump -i "$IN_IF" -U -s 0 -w "$QUIC_NATIVE" \
        'udp port 443' > "$QUIC_RESULT/tcpdump-native.log" 2>&1 &
    QUIC_NATIVE_PID=$!
    ip netns exec "$NS" tcpdump -i "$OUT_IF" -U -s 0 -w "$QUIC_GRE" \
        'ip proto 47' > "$QUIC_RESULT/tcpdump-gre.log" 2>&1 &
    QUIC_GRE_PID=$!
    sleep 0.5

    ip netns exec "$CLIENT" "$QUIC_CURL_BIN" --http3-only --parallel --parallel-max 4 \
        --silent --show-error --max-time 30 --limit-rate 8k \
        --cacert "$ROOT/config/certs/ca-cert.pem" \
        --resolve origin.runner.lab:443:198.18.20.2 \
        --output "$QUIC_RESULT/alpha.txt" 'https://origin.runner.lab/alpha' \
        --output "$QUIC_RESULT/beta.txt" 'https://origin.runner.lab/beta?item=2' \
        --output "$QUIC_RESULT/gamma.txt" 'https://origin.runner.lab/gamma/deep' \
        --output "$QUIC_RESULT/hold.txt" 'https://origin.runner.lab/hold?stream=4' \
        > "$QUIC_RESULT/curl.log" 2>&1 &
    QUIC_CLIENT_PID=$!
    for attempt in $(seq 1 200); do
        (( $(grep -c '^REQUEST stream=' "$ROOT/results/h3-origin.log" || true) >= 4 )) && break
        kill -0 "$QUIC_CLIENT_PID"
        sleep 0.05
    done
    (( $(grep -c '^REQUEST stream=' "$ROOT/results/h3-origin.log" || true) >= 4 ))

    { printf 'enable\r\ndiag proxy quic list\r\n'; sleep 1; printf 'quit\r\n'; } | \
        timeout 8 ip netns exec "$NS" nc 127.0.0.1 50000 > "$QUIC_CLI" 2>&1
    wait "$QUIC_CLIENT_PID"
    QUIC_CLIENT_PID=
    kill -INT "$QUIC_GRE_PID" "$QUIC_NATIVE_PID" 2>/dev/null || true
    wait "$QUIC_GRE_PID" 2>/dev/null || true
    wait "$QUIC_NATIVE_PID" 2>/dev/null || true
    QUIC_GRE_PID=
    QUIC_NATIVE_PID=

    grep -q 'smithproxy-h3-origin path=/alpha' "$QUIC_RESULT/alpha.txt"
    grep -q 'smithproxy-h3-origin path=/beta?item=2' "$QUIC_RESULT/beta.txt"
    grep -q 'smithproxy-h3-origin path=/gamma/deep' "$QUIC_RESULT/gamma.txt"
    grep -q 'smithproxy-h3-origin path=/hold?stream=4' "$QUIC_RESULT/hold.txt"
    grep -q 'SNI: origin.runner.lab' "$QUIC_CLI"
    grep -q 'ALPN: downstream=h3 upstream=h3' "$QUIC_CLI"
    echo 'PASS4 QUIC/H3 traffic: verified certificate, SNI, ALPN and four multiplexed requests'
    echo 'PASS4 QUIC diagnostics: active session and streams visible in dedicated CLI'
fi
fi
if [[ $SESSION_LIST_STRESS_TEST == 1 ]]; then
    SESSION_LIST_READY="$ROOT/results/session-list-load.ready"
    SESSION_LIST_STOP="$ROOT/results/session-list-load.stop"
    SESSION_LIST_CONNECTIONS=${SESSION_LIST_CONNECTIONS:-256}
    rm -f "$SESSION_LIST_READY" "$SESSION_LIST_STOP"
    ip netns exec "$CLIENT" python3 "$ROOT/runner/tests/session-list-load.py" \
        --connections "$SESSION_LIST_CONNECTIONS" --ready "$SESSION_LIST_READY" \
        --stop "$SESSION_LIST_STOP" > "$ROOT/results/session-list-load.log" 2>&1 &
    SESSION_LIST_LOAD_PID=$!
    for attempt in $(seq 1 200); do
        [[ -f $SESSION_LIST_READY ]] && break
        kill -0 "$SESSION_LIST_LOAD_PID"
        sleep 0.05
    done
    [[ -f $SESSION_LIST_READY ]]
    ip netns exec "$NS" python3 "$ROOT/runner/tests/session-list-probe.py" \
        --connections "$SESSION_LIST_CONNECTIONS" \
        --samples "${SESSION_LIST_SAMPLES:-24}" \
        --p95-limit-ms "${SESSION_LIST_P95_LIMIT_MS:-1000}" \
        --max-limit-ms "${SESSION_LIST_MAX_LIMIT_MS:-3000}" \
        > "$ROOT/results/session-list.json"
    touch "$SESSION_LIST_STOP"
    wait "$SESSION_LIST_LOAD_PID"
    SESSION_LIST_LOAD_PID=
    python3 "$ROOT/runner/tests/suites/session-list/report.py" \
        "$ROOT/results/session-list.json"
    echo 'PASS session list: detailed snapshots remained complete and responsive under load'
fi
if [[ $TLS_SUITE_TEST == 1 ]]; then
    run_tls_autodetect_test() {
        local family=$1 host=$2 suffix=
        [[ $family == 4 ]] || suffix=6
        ip netns exec "$SERVER" python3 -u "$ROOT/runner/tests/suites/tls/autodetect.py" server \
            --host "$host" > "$ROOT/results/tls-autodetect-server${suffix}.json" &
        TLS_AUTODETECT_SERVER_PID=$!
        for attempt in $(seq 1 50); do
            grep -q '^READY$' "$ROOT/results/tls-autodetect-server${suffix}.json" && break
            kill -0 "$TLS_AUTODETECT_SERVER_PID"
            sleep 0.1
        done
        grep -q '^READY$' "$ROOT/results/tls-autodetect-server${suffix}.json"
        ip netns exec "$CLIENT" python3 "$ROOT/runner/tests/suites/tls/autodetect.py" client \
            --host "$host" > "$ROOT/results/tls-autodetect${suffix}.json"
        wait "$TLS_AUTODETECT_SERVER_PID"
        TLS_AUTODETECT_SERVER_PID=
        python3 "$ROOT/runner/tests/suites/tls/autodetect.py" report \
            --client-result "$ROOT/results/tls-autodetect${suffix}.json" \
            --server-result "$ROOT/results/tls-autodetect-server${suffix}.json"
        echo "PASS$family TLS autodetect: fragmented TLS-like traffic did not bypass inspection"
    }
    run_tls_autodetect_test 4 198.18.20.2
    run_tls_autodetect_test 6 fd00:20::2
    ip netns exec "$CLIENT" python3 "$ROOT/runner/tests/suites/tls/run.py" \
        --host 198.18.20.2 --ca-file "$ROOT/config/certs/ca-cert.pem" > "$ROOT/results/tls-suite4.json"
    python3 "$ROOT/runner/tests/suites/tls/report.py" "$ROOT/results/tls-suite4.json"
    echo 'PASS4 TLS suite: trust, SNI, ALPN and protocol-version matrix'
    ip netns exec "$CLIENT" python3 "$ROOT/runner/tests/suites/tls/run.py" \
        --host fd00:20::2 --ca-file "$ROOT/config/certs/ca-cert.pem" > "$ROOT/results/tls-suite6.json"
    python3 "$ROOT/runner/tests/suites/tls/report.py" "$ROOT/results/tls-suite6.json"
    echo 'PASS6 TLS suite: trust, SNI, ALPN and protocol-version matrix'
    ip netns exec "$SERVER" python3 -u "$ROOT/runner/tests/suites/tls/evasion.py" server \
        --host 198.18.20.2 > "$ROOT/results/tls-evasion-server.json" 2> "$ROOT/results/tls-evasion-server.log" &
    TLS_EVASION_SERVER_PID=$!
    for attempt in $(seq 1 50); do
        grep -q '^READY$' "$ROOT/results/tls-evasion-server.json" && break
        kill -0 "$TLS_EVASION_SERVER_PID"
        sleep 0.1
    done
    grep -q '^READY$' "$ROOT/results/tls-evasion-server.json"
    ip netns exec "$CLIENT" python3 "$ROOT/runner/tests/suites/tls/evasion.py" client \
        --host 198.18.20.2 --ca-file "$ROOT/config/certs/ca-cert.pem" \
        > "$ROOT/results/tls-evasion.json"
    wait "$TLS_EVASION_SERVER_PID"
    TLS_EVASION_SERVER_PID=
    python3 "$ROOT/runner/tests/suites/tls/evasion-report.py" "$ROOT/results/tls-evasion.json"
    echo 'PASS4 TLS MITM evasion: both handshake legs fail closed under timing and transport faults'
    ip netns exec "$SERVER" python3 -u "$ROOT/runner/tests/suites/tls/evasion.py" server \
        --host fd00:20::2 > "$ROOT/results/tls-evasion-server6.json" 2> "$ROOT/results/tls-evasion-server6.log" &
    TLS_EVASION_SERVER_PID=$!
    for attempt in $(seq 1 50); do
        grep -q '^READY$' "$ROOT/results/tls-evasion-server6.json" && break
        kill -0 "$TLS_EVASION_SERVER_PID"
        sleep 0.1
    done
    grep -q '^READY$' "$ROOT/results/tls-evasion-server6.json"
    ip netns exec "$CLIENT" python3 "$ROOT/runner/tests/suites/tls/evasion.py" client \
        --host fd00:20::2 --ca-file "$ROOT/config/certs/ca-cert.pem" \
        > "$ROOT/results/tls-evasion6.json"
    wait "$TLS_EVASION_SERVER_PID"
    TLS_EVASION_SERVER_PID=
    python3 "$ROOT/runner/tests/suites/tls/evasion-report.py" "$ROOT/results/tls-evasion6.json"
    echo 'PASS6 TLS MITM evasion: both handshake legs fail closed under timing and transport faults'
fi
if [[ $KTLS_PROBE_TEST == 1 ]]; then
    KTLS_CURL_ARGS=()
    if [[ -n ${TLS_TEST_VERSION:-} ]]; then
        KTLS_CURL_ARGS+=("--tlsv${TLS_TEST_VERSION}" --tls-max "$TLS_TEST_VERSION")
    fi
    if [[ -n ${TLS_TEST_CIPHER:-} ]]; then
        if [[ ${TLS_TEST_VERSION:-} == 1.3 ]]; then
            KTLS_CURL_ARGS+=(--tls13-ciphers "$TLS_TEST_CIPHER")
        else
            KTLS_CURL_ARGS+=(--ciphers "$TLS_TEST_CIPHER")
        fi
    fi
    ip netns exec "$CLIENT" curl --noproxy '*' --fail --silent --show-error \
        --http1.1 --max-time 30 --limit-rate 2M \
        "${KTLS_CURL_ARGS[@]}" \
        --cacert "$ROOT/config/certs/ca-cert.pem" \
        --resolve origin.runner.lab:443:198.18.20.2 \
        -o /dev/null "https://origin.runner.lab/bulk/${KTLS_PROBE_BYTES:-16777216}?run=ktls-probe" \
        > "$ROOT/results/ktls-probe-curl.log" 2>&1 &
    KTLS_PROBE_PID=$!
    sleep 1
    kill -0 "$KTLS_PROBE_PID"
    { printf 'enable\r\ndiag proxy session list tls 8\r\n'; sleep 1; printf 'quit\r\n'; } | \
        timeout 8 ip netns exec "$NS" nc 127.0.0.1 50000 \
        > "$ROOT/results/ktls-session.txt" 2>&1
    wait "$KTLS_PROBE_PID"
    KTLS_PROBE_PID=
    python3 "$ROOT/runner/tests/ktls-report.py" \
        --expect "${KTLS_EXPECT_ACTIVE:-any}" \
        "$ROOT/results/ktls-session.txt" > "$ROOT/results/ktls.json"
    cat "$ROOT/results/ktls.json"
    echo 'PASS4 KTLS probe: runtime BIO offload state captured for both TLS legs'
fi
if [[ $TLS_TRANSFER_TEST == 1 ]]; then
    TLS_TRANSFER_ARGS=()
    [[ -z ${TLS_TEST_VERSION:-} ]] || TLS_TRANSFER_ARGS+=(--tls-version "$TLS_TEST_VERSION")
    [[ -z ${TLS_TEST_CIPHER:-} ]] || TLS_TRANSFER_ARGS+=(--cipher "$TLS_TEST_CIPHER")
    ip netns exec "$CLIENT" python3 "$ROOT/runner/tests/tls-transfer.py" \
        --host 198.18.20.2 --ca-file "$ROOT/config/certs/ca-cert.pem" \
        --pid "$(cat "$ROOT/data/proxy.pid")" \
        "${TLS_TRANSFER_ARGS[@]}" \
        --bytes "${TLS_TRANSFER_BYTES:-67108864}" \
        --repeats "${TLS_TRANSFER_REPEATS:-5}" \
        --concurrency "${TLS_TRANSFER_CONCURRENCY:-1,4,16}" \
        > "$ROOT/results/tls-transfer.json"
    python3 "$ROOT/runner/tests/tls-transfer-report.py" "$ROOT/results/tls-transfer.json"
    echo 'PASS4 TLS transfer: bounded-drain bulk download/upload matrix completed'
fi
if [[ $TLS_THROUGHPUT_TEST == 1 ]]; then
    TLS_THROUGHPUT_ARGS=()
    [[ -z ${TLS_TEST_VERSION:-} ]] || TLS_THROUGHPUT_ARGS+=(--tls-version "$TLS_TEST_VERSION")
    [[ -z ${TLS_TEST_CIPHER:-} ]] || TLS_THROUGHPUT_ARGS+=(--cipher "$TLS_TEST_CIPHER")
    run_tls_throughput() {
        local family=$1 host=$2
        ip netns exec "$CLIENT" python3 "$ROOT/runner/tests/tls-transfer.py" \
            --host "$host" --ca-file "$ROOT/config/certs/ca-cert.pem" \
            --pid "$(cat "$ROOT/data/proxy.pid")" \
            "${TLS_THROUGHPUT_ARGS[@]}" \
            --bytes "${TLS_THROUGHPUT_BYTES:-67108864}" \
            --repeats "${TLS_THROUGHPUT_REPEATS:-3}" \
            --concurrency "${TLS_THROUGHPUT_CONCURRENCY:-1,4,16}" \
            > "$ROOT/results/tls-throughput-v$family.json"
        python3 "$ROOT/runner/tests/tls-transfer-report.py" \
            --label 'TLS throughput' "$ROOT/results/tls-throughput-v$family.json"
        echo "PASS$family TLS throughput: E2E download/upload measured without a performance gate"
    }
    run_tls_throughput 4 198.18.20.2
    run_tls_throughput 6 fd00:20::2
fi
if [[ $STARTTLS_SUITE_TEST == 1 ]]; then
    STARTTLS_PORT=2525
    ip netns exec "$SERVER" python3 "$ROOT/runner/tests/suites/starttls/run.py" server \
        --host 198.18.20.2 --port "$STARTTLS_PORT" \
        --cert "$ROOT/config/certs/origin-cert.pem" \
        --key "$ROOT/config/certs/origin-key.pem" \
        > "$ROOT/results/starttls-server.json" 2> "$ROOT/results/starttls-server.log" &
    STARTTLS_SERVER_PID=$!
    for attempt in $(seq 1 50); do
        ip netns exec "$SERVER" ss -ltnH "sport = :$STARTTLS_PORT" | grep -q . && break
        kill -0 "$STARTTLS_SERVER_PID"
        sleep 0.1
    done
    ip netns exec "$SERVER" ss -ltnH "sport = :$STARTTLS_PORT" | grep -q .
    ip netns exec "$CLIENT" python3 "$ROOT/runner/tests/suites/starttls/run.py" client \
        --host 198.18.20.2 --port "$STARTTLS_PORT" \
        --ca "$ROOT/config/certs/ca-cert.pem" \
        > "$ROOT/results/starttls-client.json"
    wait "$STARTTLS_SERVER_PID"
    STARTTLS_SERVER_PID=
    python3 - "$ROOT/results/starttls-client.json" <<'PYSTARTTLS'
import json, sys
expected = ["smtp/starttls", "imap/starttls", "pop3/starttls", "ftp/starttls",
            "xmpp/starttls", "http-proxy/starttls"]
results = json.load(open(sys.argv[1]))
assert [item["case"] for item in results] == expected
assert all(item["issuer"] == "Runner Test CA" for item in results)
for item in results:
    print(f'{item["case"]}: PASS ({item["version"]}, {item["cipher"]})')
PYSTARTTLS
    echo 'PASS4 STARTTLS suite: all configured signatures upgraded through TLS MITM'
fi
if [[ $POLICY_TEST == 1 ]]; then
    { printf 'enable\r\ndiag proxy policy list 8\r\n'; sleep 1; printf 'quit\r\n'; } | \
        timeout 5 ip netns exec "$NS" nc 127.0.0.1 50000 > "$ROOT/results/policy-list.txt" 2>&1
    set +e
    ip netns exec "$CLIENT" python3 "$ROOT/runner/tests/suites/policy/run.py" \
        --host 198.18.20.2 > "$ROOT/results/policy-suite4.json"
    POLICY_RC=$?
    set -e
    if ((POLICY_RC != 0)); then
        cat "$ROOT/results/policy-list.txt"
        exit "$POLICY_RC"
    fi
    python3 "$ROOT/runner/tests/suites/policy/report.py" "$ROOT/results/policy-suite4.json"
    echo 'PASS4 policy suite: precedence, source/port/protocol, disabled, profiles and deny rules'
    set +e
    ip netns exec "$CLIENT" python3 "$ROOT/runner/tests/suites/policy/run.py" \
        --host fd00:20::2 > "$ROOT/results/policy-suite6.json"
    POLICY_RC=$?
    set -e
    if ((POLICY_RC != 0)); then
        cat "$ROOT/results/policy-list.txt"
        exit "$POLICY_RC"
    fi
    python3 "$ROOT/runner/tests/suites/policy/report.py" "$ROOT/results/policy-suite6.json"
    echo 'PASS6 policy suite: precedence, source/port/protocol, disabled, profiles and deny rules'
fi
if [[ $ROUTING_TEST == 1 ]]; then
    ip netns exec "$SERVER" python3 -u "$ROOT/runner/tests/suites/routing/run.py" server \
        --cert "$ROOT/config/certs/origin-cert.pem" --key "$ROOT/config/certs/origin-key.pem" \
        > "$ROOT/results/routing-server.log" 2>&1 &
    ROUTING_SERVER_PID=$!
    for attempt in $(seq 1 50); do
        grep -q '^READY$' "$ROOT/results/routing-server.log" 2>/dev/null && break
        kill -0 "$ROUTING_SERVER_PID"
        sleep 0.1
    done
    grep -q '^READY$' "$ROOT/results/routing-server.log"
    ip netns exec "$CLIENT" python3 "$ROOT/runner/tests/suites/routing/run.py" client --family 4 \
        > "$ROOT/results/routing-suite4.json"
    echo 'PASS4 routing: address/port rewrite, RR/L3/L4, SNI rewrite, SOCKS5 and opaque CONNECT tunnel'
    ip netns exec "$CLIENT" python3 "$ROOT/runner/tests/suites/routing/run.py" client --family 6 \
        > "$ROOT/results/routing-suite6.json"
    echo 'PASS6 routing: address/port rewrite, RR/L3/L4, SNI rewrite, SOCKS5 and opaque CONNECT tunnel'
    kill "$ROUTING_SERVER_PID"
    wait "$ROUTING_SERVER_PID" 2>/dev/null || true
    ROUTING_SERVER_PID=
fi
if [[ $RTT_TEST == 1 ]]; then
    RTT_EXTRA_ARGS=()
    [[ ${RTT_REPORT_ONLY:-0} != 1 ]] || RTT_EXTRA_ARGS+=(--report-only)
    ip netns exec "$CLIENT" python3 "$ROOT/runner/tests/protocol-rtt.py" \
        --host 198.18.20.2 \
        --ca-file "$ROOT/config/certs/ca-cert.pem" \
        --samples "${RTT_SAMPLES:-200}" \
        --handshake-samples "${RTT_HANDSHAKE_SAMPLES:-40}" \
        --warmup "${RTT_WARMUP:-20}" \
        --rtt-p95-limit-ms "${RTT_P95_LIMIT_MS:-50}" \
        --rtt-max-limit-ms "${RTT_MAX_LIMIT_MS:-250}" \
        --handshake-p95-limit-ms "${RTT_HANDSHAKE_P95_LIMIT_MS:-500}" \
        --handshake-max-limit-ms "${RTT_HANDSHAKE_MAX_LIMIT_MS:-2000}" \
        --tls-total-p50-limit-ms "${RTT_TLS_TOTAL_P50_LIMIT_MS:-7}" \
        --tls-total-p50-flaky-limit-ms "${RTT_TLS_TOTAL_P50_FLAKY_LIMIT_MS:-10}" \
        --https-p50-limit-ms "${RTT_HTTPS_P50_LIMIT_MS:-2}" \
        --https-p50-flaky-limit-ms "${RTT_HTTPS_P50_FLAKY_LIMIT_MS:-10}" \
        --cold-sni cold-cert-cache.runner.lab \
        "${RTT_EXTRA_ARGS[@]}" \
        > "$ROOT/results/tcp-rtt.json"
    python3 "$ROOT/runner/tests/suites/rtt/report.py" "$ROOT/results/tcp-rtt.json"
    echo 'PASS4 RTT: TCP, UDP and TLS handshakes/round trips validated within limits'
    ip netns exec "$CLIENT" python3 "$ROOT/runner/tests/protocol-rtt.py" \
        --host fd00:20::2 \
        --ca-file "$ROOT/config/certs/ca-cert.pem" \
        --samples "${RTT_SAMPLES:-200}" \
        --handshake-samples "${RTT_HANDSHAKE_SAMPLES:-40}" \
        --warmup "${RTT_WARMUP:-20}" \
        --rtt-p95-limit-ms "${RTT_P95_LIMIT_MS:-50}" \
        --rtt-max-limit-ms "${RTT_MAX_LIMIT_MS:-250}" \
        --handshake-p95-limit-ms "${RTT_HANDSHAKE_P95_LIMIT_MS:-500}" \
        --handshake-max-limit-ms "${RTT_HANDSHAKE_MAX_LIMIT_MS:-2000}" \
        --tls-total-p50-limit-ms "${RTT_TLS_TOTAL_P50_LIMIT_MS:-7}" \
        --tls-total-p50-flaky-limit-ms "${RTT_TLS_TOTAL_P50_FLAKY_LIMIT_MS:-10}" \
        --https-p50-limit-ms "${RTT_HTTPS_P50_LIMIT_MS:-2}" \
        --https-p50-flaky-limit-ms "${RTT_HTTPS_P50_FLAKY_LIMIT_MS:-10}" \
        --cold-sni cold6-cert-cache.runner.lab \
        "${RTT_EXTRA_ARGS[@]}" \
        > "$ROOT/results/tcp-rtt6.json"
    python3 "$ROOT/runner/tests/suites/rtt/report.py" "$ROOT/results/tcp-rtt6.json"
    if [[ ${RTT_NATIVE_BASELINE:-0} == 1 ]]; then
        ip netns exec "$SERVER" python3 "$ROOT/runner/tests/protocol-rtt.py" \
            --ca-file "$ROOT/config/certs/origin-ca.pem" \
            --host 198.18.20.2 \
            --samples "${RTT_SAMPLES:-200}" \
            --handshake-samples "${RTT_HANDSHAKE_SAMPLES:-40}" \
            --warmup "${RTT_WARMUP:-20}" \
            --report-only > "$ROOT/results/native-rtt.json"
        ip netns exec "$SERVER" python3 "$ROOT/runner/tests/protocol-rtt.py" \
            --host fd00:20::2 \
            --ca-file "$ROOT/config/certs/origin-ca.pem" \
            --samples "${RTT_SAMPLES:-200}" \
            --handshake-samples "${RTT_HANDSHAKE_SAMPLES:-40}" \
            --warmup "${RTT_WARMUP:-20}" \
            --report-only > "$ROOT/results/native-rtt6.json"
    fi
    echo 'PASS6 RTT: TCP, UDP and TLS handshakes/round trips validated within limits'
fi
if [[ $TCP_CHURN_TEST == 1 ]]; then
    TCP_CHURN_EXTRA_ARGS=()
    if [[ ${TCP_CHURN_SYNCHRONIZED:-0} == 1 ]]; then
        TCP_CHURN_EXTRA_ARGS+=(--synchronized-start)
    fi
    ip netns exec "$CLIENT" python3 "$ROOT/runner/tests/tcp-churn.py" \
        --host 198.18.20.2 \
        --waves "${TCP_CHURN_WAVES:-20}" \
        --flows "${TCP_CHURN_FLOWS:-64}" \
        --parallel "${TCP_CHURN_PARALLEL:-64}" \
        --interval "${TCP_CHURN_INTERVAL:-0.25}" \
        --settle "${TCP_CHURN_SETTLE:-15}" \
        --timeout "${TCP_CHURN_TIMEOUT:-3}" \
        --min-port "${CHURN_MIN_PORT:-20000}" \
        --max-port "${CHURN_MAX_PORT:-29999}" \
        "${TCP_CHURN_EXTRA_ARGS[@]}" \
        > "$ROOT/results/tcp-churn.txt"
    cat "$ROOT/results/tcp-churn.txt"
    echo 'PASS4 TCP churn: persistent flow survived proxy creation and deferred cleanup'
    ip netns exec "$CLIENT" python3 "$ROOT/runner/tests/tcp-churn.py" \
        --host fd00:20::2 \
        --waves "${TCP_CHURN_WAVES:-20}" \
        --flows "${TCP_CHURN_FLOWS:-64}" \
        --parallel "${TCP_CHURN_PARALLEL:-64}" \
        --interval "${TCP_CHURN_INTERVAL:-0.25}" \
        --settle "${TCP_CHURN_SETTLE:-15}" \
        --timeout "${TCP_CHURN_TIMEOUT:-3}" \
        --min-port "${CHURN_MIN_PORT:-20000}" \
        --max-port "${CHURN_MAX_PORT:-29999}" \
        "${TCP_CHURN_EXTRA_ARGS[@]}" \
        > "$ROOT/results/tcp-churn6.txt"
    cat "$ROOT/results/tcp-churn6.txt"
    echo 'PASS6 TCP churn: persistent flow survived proxy creation and deferred cleanup'
fi
if [[ $UDP_CHURN_TEST == 1 ]]; then
    ip netns exec "$CLIENT" python3 "$ROOT/runner/tests/udp-churn.py" \
        --host 198.18.20.2 --expected-peer 198.18.20.1 \
        --waves "${UDP_CHURN_WAVES:-8}" \
        --flows "${UDP_CHURN_FLOWS:-96}" \
        --workers "${UDP_CHURN_WORKERS:-32}" \
        --interval "${UDP_CHURN_INTERVAL:-3}" \
        --settle "${UDP_CHURN_SETTLE:-12}" \
        --timeout "${UDP_CHURN_TIMEOUT:-1}" \
        --min-port "${CHURN_MIN_PORT:-20000}" \
        --max-port "${CHURN_MAX_PORT:-29999}" \
        > "$ROOT/results/udp-churn.txt"
    cat "$ROOT/results/udp-churn.txt"
    echo 'PASS4 UDP churn: continuous traffic survived flow expiry and deferred cleanup'
    ip netns exec "$CLIENT" python3 "$ROOT/runner/tests/udp-churn.py" \
        --host fd00:20::2 --expected-peer fd00:20::1 \
        --waves "${UDP_CHURN_WAVES:-8}" \
        --flows "${UDP_CHURN_FLOWS:-96}" \
        --workers "${UDP_CHURN_WORKERS:-32}" \
        --interval "${UDP_CHURN_INTERVAL:-3}" \
        --settle "${UDP_CHURN_SETTLE:-12}" \
        --timeout "${UDP_CHURN_TIMEOUT:-1}" \
        --min-port "${CHURN_MIN_PORT:-20000}" \
        --max-port "${CHURN_MAX_PORT:-29999}" \
        > "$ROOT/results/udp-churn6.txt"
    cat "$ROOT/results/udp-churn6.txt"
    echo 'PASS6 UDP churn: continuous traffic survived flow expiry and deferred cleanup'
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
    echo 'PASS4 pplay: exact HTTP/1 request and response traversed Smithproxy'
    ip netns exec "$SERVER" python3 -u "$PPLAY_PY" \
        --script "$PPLAY_FIXTURE" --server '[fd00:20::2]:18080' \
        --auto 0.05 --nostdin --exitoneot --exitondiff --die-after 20 \
        --nohex --nocolor > "$ROOT/results/pplay-server6.log" 2>&1 &
    PPLAY_SERVER_PID=$!
    for attempt in $(seq 1 50); do
        if ip netns exec "$SERVER" ss -ltnH 'sport = :18080' | grep -q .; then break; fi
        kill -0 "$PPLAY_SERVER_PID"
        sleep 0.1
    done
    ip netns exec "$SERVER" ss -ltnH 'sport = :18080' | grep -q .
    ip netns exec "$CLIENT" python3 -u "$PPLAY_PY" \
        --script "$PPLAY_FIXTURE" --client '[fd00:20::2]:18080' \
        --auto 0.05 --nostdin --exitoneot --exitondiff --die-after 20 \
        --nohex --nocolor > "$ROOT/results/pplay-client6.log" 2>&1
    wait "$PPLAY_SERVER_PID"
    PPLAY_SERVER_PID=
    grep -q 'END OF TRANSMISSION' "$ROOT/results/pplay-client6.log"
    grep -q 'END OF TRANSMISSION' "$ROOT/results/pplay-server6.log"
    ! grep -q '^# !!!.*DIFFERENT DATA' "$ROOT/results/pplay-client6.log"
    ! grep -q '^# !!!.*DIFFERENT DATA' "$ROOT/results/pplay-server6.log"
    echo 'PASS6 pplay: exact HTTP/1 request and response traversed Smithproxy'
fi
if [[ $CAPTURE_MATRIX_TEST == 1 ]]; then
    [[ $CAPTURE_TEST == 1 ]] || { echo 'FAIL: CAPTURE_MATRIX_TEST requires CAPTURE_TEST=1' >&2; exit 1; }
    [[ -n ${PPLAY_PY:-} && -n ${PPLAY_SUITE:-} ]] || {
        echo 'FAIL: CAPTURE_MATRIX_TEST requires PPLAY_PY and PPLAY_SUITE' >&2
        exit 1
    }
    CAPTURE_MATRIX_RESULT="$ROOT/results/capture-matrix"
    CAPTURE_MATRIX_GRE4="$CAPTURE_MATRIX_RESULT/gre4.pcap"
    CAPTURE_MATRIX_GRE6="$CAPTURE_MATRIX_RESULT/gre6.pcap"
    CAPTURE_MATRIX_MANIFEST="$CAPTURE_MATRIX_RESULT/manifest.json"
    rm -rf "$CAPTURE_MATRIX_RESULT"
    mkdir -p "$CAPTURE_MATRIX_RESULT"
    env PYTHONPATH="$PPLAY_SUITE${PYTHONPATH:+:$PYTHONPATH}" \
        python3 "$ROOT/runner/tests/build-capture-manifest.py" \
        "$PPLAY_SUITE" "$CAPTURE_MATRIX_MANIFEST"
    ip netns exec "$NS" tcpdump -i "$OUT_IF" -U -s 0 -w "$CAPTURE_MATRIX_GRE4" 'ip proto 47' \
        > "$CAPTURE_MATRIX_RESULT/tcpdump4.log" 2>&1 &
    CAPTURE_MATRIX_GRE_PID=$!
    sleep 0.5
    env PPLAY_PY="$PPLAY_PY" MODE=runner IP_FAMILY=4 MATCH='capture_*' EXCLUDE= \
        RESULTS="$CAPTURE_MATRIX_RESULT/pplay-v4" \
        SMITHPROXY_PID_FILE="$ROOT/data/proxy.pid" \
        CLIENT_NS="$CLIENT" SERVER_NS="$SERVER" \
        "$PPLAY_SUITE/run-suite.sh" all
    kill "$CAPTURE_MATRIX_GRE_PID" 2>/dev/null || true
    wait "$CAPTURE_MATRIX_GRE_PID" 2>/dev/null || true
    CAPTURE_MATRIX_GRE_PID=
    echo 'PASS4 capture matrix traffic: 30 corpus flows exported to local PCAPNG and GRE'
    ip netns exec "$NS" tcpdump -i "$OUT_IF" -U -s 0 -w "$CAPTURE_MATRIX_GRE6" 'ip proto 47' \
        > "$CAPTURE_MATRIX_RESULT/tcpdump6.log" 2>&1 &
    CAPTURE_MATRIX_GRE_PID=$!
    sleep 0.5
    env PPLAY_PY="$PPLAY_PY" MODE=runner IP_FAMILY=6 MATCH='capture_*' EXCLUDE= \
        RESULTS="$CAPTURE_MATRIX_RESULT/pplay-v6" \
        SMITHPROXY_PID_FILE="$ROOT/data/proxy.pid" \
        CLIENT_NS="$CLIENT" SERVER_NS="$SERVER" \
        "$PPLAY_SUITE/run-suite.sh" all
    kill "$CAPTURE_MATRIX_GRE_PID" 2>/dev/null || true
    wait "$CAPTURE_MATRIX_GRE_PID" 2>/dev/null || true
    CAPTURE_MATRIX_GRE_PID=
    echo 'PASS6 capture matrix traffic: 30 corpus flows exported to local PCAPNG and GRE'
fi
if [[ ${HTTP2_OBSERVABILITY_TEST:-0} == 1 ]]; then
    [[ ${CAPTURE_TEST:-0} == 1 ]] || { echo 'FAIL: HTTP2_OBSERVABILITY_TEST requires CAPTURE_TEST=1' >&2; exit 1; }
    [[ -n ${PPLAY_PY:-} && -n ${PPLAY_SUITE:-} ]] || {
        echo 'FAIL: HTTP2_OBSERVABILITY_TEST requires PPLAY_PY and PPLAY_SUITE' >&2
        exit 1
    }
    run_http2_observability() {
        local family=$1 endpoint=$2
        local result="$ROOT/results/http2-observability-v$family"
        local ready="$result/ready" gre="$result/gre.pcap" cli="$result/cli.txt"
        rm -rf "$result"
        mkdir -p "$result"
        ip netns exec "$NS" tcpdump -i "$OUT_IF" -U -s 0 -w "$gre" 'ip proto 47' \
            > "$result/tcpdump.log" 2>&1 &
        HTTP2_TCPDUMP_PID=$!
        env PYTHONPATH="$PPLAY_SUITE${PYTHONPATH:+:$PYTHONPATH}" \
            HTTP2_READY_FILE="$ready" HTTP2_OBSERVE_DELAY=15 \
            ip netns exec "$SERVER" python3 -u "$PPLAY_PY" \
            --script "$PPLAY_SUITE/regular/http2_many_commands.py" --server "$endpoint" \
            --auto 0.05 --nostdin --exitoneot --exitondiff --die-after 40 \
            --nohex --nocolor > "$result/server.log" 2>&1 &
        PPLAY_SERVER_PID=$!
        for attempt in $(seq 1 50); do
            ip netns exec "$SERVER" ss -ltnH 'sport = :18080' | grep -q . && break
            kill -0 "$PPLAY_SERVER_PID"
            sleep 0.1
        done
        env PYTHONPATH="$PPLAY_SUITE${PYTHONPATH:+:$PYTHONPATH}" \
            HTTP2_READY_FILE="$ready" HTTP2_OBSERVE_DELAY=15 \
            ip netns exec "$CLIENT" python3 -u "$PPLAY_PY" \
            --script "$PPLAY_SUITE/regular/http2_many_commands.py" --client "$endpoint" \
            --auto 0.05 --nostdin --exitoneot --exitondiff --die-after 40 \
            --nohex --nocolor > "$result/client.log" 2>&1 &
        HTTP2_CLIENT_PID=$!
        for attempt in $(seq 1 400); do
            [[ -f $ready ]] && break
            kill -0 "$RUNNER_PID"
            kill -0 "$HTTP2_CLIENT_PID"
            sleep 0.1
        done
        [[ -f $ready ]]
        { printf 'enable\r\ndiag proxy session list 8\r\n'; sleep 3; printf 'quit\r\n'; } | \
            timeout 10 ip netns exec "$NS" nc 127.0.0.1 50000 > "$cli" 2>&1
        wait "$HTTP2_CLIENT_PID"; HTTP2_CLIENT_PID=
        wait "$PPLAY_SERVER_PID"; PPLAY_SERVER_PID=
        kill "$HTTP2_TCPDUMP_PID" 2>/dev/null || true
        wait "$HTTP2_TCPDUMP_PID" 2>/dev/null || true
        HTTP2_TCPDUMP_PID=
        find "$ROOT/data" -maxdepth 1 -type f -name "$CAPTURE_PREFIX*.pcapng" \
            -printf '%T@ %f\n' | sort -nr | head -1 | cut -d' ' -f2- > "$result/pcap-file.txt"
        echo "PASS$family HTTP/2 observability traffic and CLI snapshot completed"
    }
    run_http2_observability 4 '198.18.20.2:18080'
    run_http2_observability 6 '[fd00:20::2]:18080'
fi
if [[ -n ${PPLAY_SUITE:-} && ${PPLAY_SUITE_SKIP_RUN:-0} != 1 ]]; then
    [[ -n ${PPLAY_PY:-} ]] || { echo 'FAIL: PPLAY_SUITE requires PPLAY_PY' >&2; exit 1; }
    [[ -x $PPLAY_SUITE/run-suite.sh ]] || {
        echo "FAIL: suite runner is not executable: $PPLAY_SUITE/run-suite.sh" >&2
        exit 1
    }
    # The dedicated capture matrix has already run capture_* once while its
    # GRE collectors were active.  Replaying those cases in the general full
    # corpus would append duplicate marker streams only to the local PCAPNG
    # and make its later one-to-one comparison with GRE invalid.
    PPLAY_CORPUS_EXCLUDE="${PPLAY_SUITE_EXCLUDE:+${PPLAY_SUITE_EXCLUDE}${EXCLUDE:+,}}${EXCLUDE:-}"
    if [[ $CAPTURE_MATRIX_TEST == 1 ]]; then
        PPLAY_CORPUS_EXCLUDE=${PPLAY_CORPUS_EXCLUDE:+$PPLAY_CORPUS_EXCLUDE,}capture_\*
    fi
    env PPLAY_PY="$PPLAY_PY" MODE=runner IP_FAMILY=4 \
        ALLOW_EMPTY="${PPLAY_SUITE_ALLOW_EMPTY:-0}" \
        MATCH="${PPLAY_SUITE_MATCH:-${MATCH:-*}}" \
        EXCLUDE="$PPLAY_CORPUS_EXCLUDE" \
        FUZZ_LEVEL="${FUZZ_LEVEL:-}" FUZZ_SEEDS="${FUZZ_SEEDS:-}" \
        FUZZ_AREA="${PPLAY_FUZZ_AREA:-}" \
        SCATTER="${FUZZ_SCATTER:-0}" \
        RESULTS="$ROOT/results/${PPLAY_RESULTS_NAME:-pplay-suite}-v4" \
        SMITHPROXY_PID_FILE="$ROOT/data/proxy.pid" \
        CLIENT_NS="$CLIENT" SERVER_NS="$SERVER" \
        "$PPLAY_SUITE/run-suite.sh" "${PPLAY_SUITE_CATEGORY:-all}" &
    PPLAY_SUITE4_PID=$!
    env PPLAY_PY="$PPLAY_PY" MODE=runner IP_FAMILY=6 \
        ALLOW_EMPTY="${PPLAY_SUITE_ALLOW_EMPTY:-0}" \
        MATCH="${PPLAY_SUITE_MATCH:-${MATCH:-*}}" \
        EXCLUDE="$PPLAY_CORPUS_EXCLUDE" \
        FUZZ_LEVEL="${FUZZ_LEVEL:-}" FUZZ_SEEDS="${FUZZ_SEEDS:-}" \
        FUZZ_AREA="${PPLAY_FUZZ_AREA:-}" \
        SCATTER="${FUZZ_SCATTER:-0}" \
        RESULTS="$ROOT/results/${PPLAY_RESULTS_NAME:-pplay-suite}-v6" \
        SMITHPROXY_PID_FILE="$ROOT/data/proxy.pid" \
        CLIENT_NS="$CLIENT" SERVER_NS="$SERVER" \
        "$PPLAY_SUITE/run-suite.sh" "${PPLAY_SUITE_CATEGORY:-all}" &
    PPLAY_SUITE6_PID=$!
    set +e
    wait "$PPLAY_SUITE4_PID"; PPLAY_SUITE4_RC=$?
    wait "$PPLAY_SUITE6_PID"; PPLAY_SUITE6_RC=$?
    set -e
    PPLAY_SUITE4_PID=
    PPLAY_SUITE6_PID=
    ((PPLAY_SUITE4_RC == 0 && PPLAY_SUITE6_RC == 0)) || {
        echo "FAIL: pplay suite IPv4 rc=$PPLAY_SUITE4_RC IPv6 rc=$PPLAY_SUITE6_RC" >&2
        exit 1
    }
    echo 'PASS4 pplay suite through Smithproxy'
    echo 'PASS6 pplay suite through Smithproxy'
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
echo 'PASS4 no bypass while proxy is stopped'
if ip netns exec "$CLIENT" curl --noproxy '*' -gfsS --max-time 2 'http://[fd00:20::2]:8080/' >/dev/null 2>&1; then
    kill -CONT "$(cat "$ROOT/data/proxy.pid")"
    echo 'FAIL6: proxy bypass' >&2
    exit 1
fi
kill -CONT "$(cat "$ROOT/data/proxy.pid")"
echo 'PASS6 no bypass while proxy is stopped'
kill -TERM "$RUNNER_PID"
runner_rc=0
wait "$RUNNER_PID" || runner_rc=$?
RUNNER_PID=
case "$runner_rc" in
    0|143|241) ;;
    *) echo "FAIL: runner shutdown exited with rc=$runner_rc" >&2; exit "$runner_rc" ;;
esac
if [[ $PRIVSEP_TEST == 1 ]]; then
    [[ ! -e "$ROOT/data/run/smithproxy.default.pid" ]]
    echo 'PASS privsep PID cleanup: helper removed its owned PID file'
fi
if [[ $CAPTURE_TEST == 1 ]]; then
    python3 "$ROOT/runner/tests/verify-pcap.py" "$ROOT/data" "$CAPTURE_PREFIX" "$CAPTURE_MARKER" "$CAPTURE_MARKER6" \
        > "$ROOT/results/pcap-validation.json"
    echo 'PASS4 PCAP export: valid pcapng contains IPv4 payload marker'
    echo 'PASS6 PCAP export: valid pcapng contains IPv6 payload marker'
fi
if [[ $CAPTURE_MATRIX_TEST == 1 ]]; then
    mkdir -p "$ROOT/results/capture-matrix/local-pcap"
    cp "$ROOT/data/$CAPTURE_PREFIX"*.pcapng "$ROOT/results/capture-matrix/local-pcap/"
    python3 "$ROOT/runner/tests/verify-capture-matrix.py" \
        "$ROOT/results/capture-matrix/manifest.json" "$ROOT/data" "$CAPTURE_PREFIX" \
        "$ROOT/results/capture-matrix/gre4.pcap" 4 \
        > "$ROOT/results/capture-matrix/validation4.json"
    python3 "$ROOT/runner/tests/suites/capture-report.py" "$ROOT/results/capture-matrix/validation4.json"
    echo 'PASS4 capture matrix: PCAPNG and GRE payload hashes match; simulated TCP is formally valid'
    python3 "$ROOT/runner/tests/verify-capture-matrix.py" \
        "$ROOT/results/capture-matrix/manifest.json" "$ROOT/data" "$CAPTURE_PREFIX" \
        "$ROOT/results/capture-matrix/gre6.pcap" 6 \
        > "$ROOT/results/capture-matrix/validation6.json"
    python3 "$ROOT/runner/tests/suites/capture-report.py" "$ROOT/results/capture-matrix/validation6.json"
    echo 'PASS6 capture matrix: PCAPNG and GRE payload hashes match; simulated TCP is formally valid'
fi
if [[ ${HTTP2_OBSERVABILITY_TEST:-0} == 1 ]]; then
    for family in 4 6; do
        HTTP2_RESULT="$ROOT/results/http2-observability-v$family"
        read -r HTTP2_PCAP_NAME < "$HTTP2_RESULT/pcap-file.txt"
        python3 "$ROOT/runner/tests/verify-http2-observability.py" \
            "$HTTP2_RESULT/cli.txt" "$ROOT/data/$HTTP2_PCAP_NAME" \
            "$HTTP2_RESULT/gre.pcap" "$family" \
            > "$HTTP2_RESULT/validation.json"
        echo "PASS$family HTTP/2 observability: CLI, PCAP and GRE contain exactly 12 requests and responses"
    done
fi
if [[ $QUIC_TEST == 1 ]]; then
    [[ -s "$ROOT/results/quic-downstream.keys" ]]
    grep -Eq '_(HANDSHAKE|TRAFFIC)_SECRET ' "$ROOT/results/quic-downstream.keys"
    python3 "$ROOT/runner/tests/verify-quic-observability.py" \
        --data-dir "$ROOT/data" --prefix "$CAPTURE_PREFIX" \
        --gre "$ROOT/results/quic-observability/gre.pcap" \
        --native "$ROOT/results/quic-observability/downstream-native.pcapng" \
        --keylog "$ROOT/results/quic-downstream.keys" \
        --cli "$ROOT/results/quic-observability/cli.txt" \
        --dissector "$SPQ1_DISSECTOR" \
        --url 'https://origin.runner.lab/alpha' \
        --url 'https://origin.runner.lab/beta?item=2' \
        --url 'https://origin.runner.lab/gamma/deep' \
        --url 'https://origin.runner.lab/hold?stream=4' \
        > "$ROOT/results/quic-observability/validation.json"
    echo 'PASS4 QUIC policy: UDP-only content profile selected for multiplexed streams'
    echo 'PASS4 QUIC local PCAP: SPQ1 session, stream, ALPN, FIN, payload and H3 fields validated'
    echo 'PASS4 QUIC GRE: RFC 2890 key matches SPQ1 session and local capture semantics'
    echo 'PASS4 QUIC native PCAP: SSLKEYLOGFILE decrypts requests, responses and independent streams'
    echo 'PASS4 QUIC Wireshark: methods, statuses and composite URLs are filterable'
fi
# Both interfaces must have been returned by runner, before test destroys them.
ip link show "$IN_IF" > /dev/null
ip link show "$OUT_IF" > /dev/null
echo 'PASS runner shutdown: interfaces returned to host'
