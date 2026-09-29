#!/usr/bin/env bash

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BUILD_DIR="${QUIC_TESTBED_BUILD_DIR:-${ROOT_DIR}/build-quic-testbed}"

if [[ "${EUID}" -ne 0 ]]; then
    if sudo -n true 2>/dev/null; then
        exec sudo -n --preserve-env=QUIC_TESTBED_BUILD_DIR "${BASH_SOURCE[0]}" "$@"
    fi
    echo "SKIP: TPROXY test requires root or passwordless sudo" >&2
    exit 77
fi

for tool in ip iptables openssl; do
    command -v "${tool}" >/dev/null || { echo "SKIP: missing ${tool}" >&2; exit 77; }
done

cmake -S "${ROOT_DIR}" -B "${BUILD_DIR}" -DCMAKE_BUILD_TYPE=Debug \
    -DCMAKE_POLICY_VERSION_MINIMUM=3.5
cmake --build "${BUILD_DIR}" --target quic_test_node -j"${QUIC_TESTBED_JOBS:-2}"

TMP_DIR="$(mktemp -d /tmp/smithproxy-quic-tproxy-XXXXXX)"
SUFFIX="$$"
CLIENT_NS="sqc${SUFFIX}"
PROXY_NS="sqp${SUFFIX}"
ORIGIN_NS="sqo${SUFFIX}"
ORIGIN_PID=""
PROXY_PID=""

cleanup() {
    status=$?
    if [[ "${status}" -ne 0 ]]; then
        for log in origin.log proxy.log; do
            [[ ! -f "${TMP_DIR}/${log}" ]] || { echo "--- ${log}" >&2; cat "${TMP_DIR}/${log}" >&2; }
        done
    fi
    [[ -z "${ORIGIN_PID}" ]] || kill "${ORIGIN_PID}" 2>/dev/null || true
    [[ -z "${PROXY_PID}" ]] || kill "${PROXY_PID}" 2>/dev/null || true
    ip netns del "${CLIENT_NS}" 2>/dev/null || true
    ip netns del "${PROXY_NS}" 2>/dev/null || true
    ip netns del "${ORIGIN_NS}" 2>/dev/null || true
    rm -rf -- "${TMP_DIR}"
    return "${status}"
}
trap cleanup EXIT

openssl req -x509 -newkey rsa:2048 -nodes -days 1 \
    -subj '/CN=Smithproxy QUIC TPROXY Test CA' \
    -keyout "${TMP_DIR}/ca-key.pem" -out "${TMP_DIR}/ca-cert.pem" >/dev/null 2>&1
openssl req -newkey rsa:2048 -nodes -subj '/CN=localhost' \
    -keyout "${TMP_DIR}/srv-key.pem" -out "${TMP_DIR}/srv.csr" >/dev/null 2>&1
printf 'subjectAltName=DNS:localhost\nextendedKeyUsage=serverAuth,clientAuth\n' \
    >"${TMP_DIR}/leaf.ext"
openssl x509 -req -days 1 -in "${TMP_DIR}/srv.csr" \
    -CA "${TMP_DIR}/ca-cert.pem" -CAkey "${TMP_DIR}/ca-key.pem" -CAcreateserial \
    -extfile "${TMP_DIR}/leaf.ext" -out "${TMP_DIR}/srv-cert.pem" >/dev/null 2>&1
cp "${TMP_DIR}/ca-cert.pem" "${TMP_DIR}/verify-ca.pem"
cat /etc/ssl/certs/ca-certificates.crt >>"${TMP_DIR}/verify-ca.pem"
for role in cl portal; do
    cp "${TMP_DIR}/srv-key.pem" "${TMP_DIR}/${role}-key.pem"
    cp "${TMP_DIR}/srv-cert.pem" "${TMP_DIR}/${role}-cert.pem"
done

ip netns add "${CLIENT_NS}"
ip netns add "${PROXY_NS}"
ip netns add "${ORIGIN_NS}"
ip link add "qc${SUFFIX}" type veth peer name "qpc${SUFFIX}"
ip link add "qo${SUFFIX}" type veth peer name "qpo${SUFFIX}"
ip link set "qc${SUFFIX}" netns "${CLIENT_NS}"
ip link set "qpc${SUFFIX}" netns "${PROXY_NS}"
ip link set "qo${SUFFIX}" netns "${ORIGIN_NS}"
ip link set "qpo${SUFFIX}" netns "${PROXY_NS}"

ip -n "${CLIENT_NS}" addr add 10.203.1.2/24 dev "qc${SUFFIX}"
ip -n "${PROXY_NS}" addr add 10.203.1.1/24 dev "qpc${SUFFIX}"
ip -n "${ORIGIN_NS}" addr add 10.203.2.2/24 dev "qo${SUFFIX}"
ip -n "${PROXY_NS}" addr add 10.203.2.1/24 dev "qpo${SUFFIX}"
for namespace in "${CLIENT_NS}" "${PROXY_NS}" "${ORIGIN_NS}"; do
    ip -n "${namespace}" link set lo up
done
ip -n "${CLIENT_NS}" link set "qc${SUFFIX}" up
ip -n "${PROXY_NS}" link set "qpc${SUFFIX}" up
ip -n "${ORIGIN_NS}" link set "qo${SUFFIX}" up
ip -n "${PROXY_NS}" link set "qpo${SUFFIX}" up
ip -n "${CLIENT_NS}" route add default via 10.203.1.1
ip -n "${ORIGIN_NS}" route add default via 10.203.2.1
ip netns exec "${PROXY_NS}" sysctl -q -w net.ipv4.ip_forward=1
# A transparent-proxy test must fail closed.  Without this policy a broken
# TPROXY listener can appear healthy because the kernel forwards QUIC directly
# between the client and origin namespaces.
ip netns exec "${PROXY_NS}" iptables -P FORWARD DROP
ip netns exec "${PROXY_NS}" ip rule add fwmark 1 lookup 100
ip netns exec "${PROXY_NS}" ip route add local 0.0.0.0/0 dev lo table 100
ip netns exec "${PROXY_NS}" iptables -t mangle -A PREROUTING \
    -i "qpc${SUFFIX}" -p udp --dport 443 \
    -j TPROXY --on-port 0 --tproxy-mark 0x1/0x1

ip netns exec "${ORIGIN_NS}" "${BUILD_DIR}/quic_test_node" \
    origin "${TMP_DIR}" 0.0.0.0 443 >"${TMP_DIR}/origin.log" 2>&1 &
ORIGIN_PID=$!
ip netns exec "${PROXY_NS}" "${BUILD_DIR}/quic_test_node" \
    proxy "${TMP_DIR}" 0.0.0.0 443 >"${TMP_DIR}/proxy.log" 2>&1 &
PROXY_PID=$!

for _ in {1..100}; do
    grep -q 'READY origin' "${TMP_DIR}/origin.log" \
        && grep -q 'READY proxy' "${TMP_DIR}/proxy.log" && break
    sleep 0.05
done
grep -q 'READY origin' "${TMP_DIR}/origin.log"
grep -q 'READY proxy' "${TMP_DIR}/proxy.log"

ip netns exec "${CLIENT_NS}" "${BUILD_DIR}/quic_test_node" \
    client "${TMP_DIR}" 10.203.2.2 443 localhost
grep -q 'PASS origin echo' "${TMP_DIR}/origin.log"
echo "PASS: transparent QUIC TPROXY preserved destination, SNI, ALPN, certificate and stream data"
