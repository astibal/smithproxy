#!/usr/bin/env bash

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BUILD_DIR="${QUIC_TESTBED_BUILD_DIR:-${ROOT_DIR}/build-quic-testbed}"
ORIGIN_PORT="${QUIC_INTEROP_ORIGIN_PORT:-18443}"
PROXY_PORT="${QUIC_INTEROP_PROXY_PORT:-19443}"
HTTP3_PROXY_PORT="${QUIC_INTEROP_HTTP3_PROXY_PORT:-20443}"
HTTP3_ORIGIN="${QUIC_INTEROP_HTTP3_ORIGIN:-cloudflare.com}"
HTTP3_CURL="${CURL_HTTP3_BIN:-${ROOT_DIR}/../curl-http3/bin/curl-h3}"

if ! openssl s_client -help 2>&1 | grep -q -- '-quic'; then
    echo "SKIP: openssl s_client has no QUIC support" >&2
    exit 77
fi

cmake -S "${ROOT_DIR}" -B "${BUILD_DIR}" -DCMAKE_BUILD_TYPE=Debug \
    -DCMAKE_POLICY_VERSION_MINIMUM=3.5
cmake --build "${BUILD_DIR}" --target quic_test_node -j"${QUIC_TESTBED_JOBS:-2}"

TMP_DIR="$(mktemp -d /tmp/smithproxy-quic-interop-XXXXXX)"
ORIGIN_PID=""
PROXY_PID=""
HTTP3_PROXY_PID=""
cleanup() {
    status=$?
    if [[ "${status}" -ne 0 ]]; then
        for log in origin.log proxy.log http3-proxy.log http3-openssl.err \
            http3-openssl.out client.err client.out; do
            [[ ! -f "${TMP_DIR}/${log}" ]] || { echo "--- ${log}" >&2; cat "${TMP_DIR}/${log}" >&2; }
        done
    fi
    [[ -z "${ORIGIN_PID}" ]] || kill "${ORIGIN_PID}" 2>/dev/null || true
    [[ -z "${PROXY_PID}" ]] || kill "${PROXY_PID}" 2>/dev/null || true
    [[ -z "${HTTP3_PROXY_PID}" ]] || kill "${HTTP3_PROXY_PID}" 2>/dev/null || true
    rm -rf -- "${TMP_DIR}"
    return "${status}"
}
trap cleanup EXIT

openssl req -x509 -newkey rsa:2048 -nodes -days 1 \
    -subj '/CN=Smithproxy QUIC Interop Test CA' \
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

"${BUILD_DIR}/quic_test_node" origin "${TMP_DIR}" 127.0.0.1 "${ORIGIN_PORT}" \
    >"${TMP_DIR}/origin.log" 2>&1 &
ORIGIN_PID=$!
"${BUILD_DIR}/quic_test_node" forward "${TMP_DIR}" 127.0.0.1 \
    "${PROXY_PORT}" "${ORIGIN_PORT}" >"${TMP_DIR}/proxy.log" 2>&1 &
PROXY_PID=$!
for _ in {1..100}; do
    grep -q 'READY origin' "${TMP_DIR}/origin.log" \
        && grep -q 'READY forward' "${TMP_DIR}/proxy.log" && break
    sleep 0.05
done
grep -q 'READY origin' "${TMP_DIR}/origin.log"
grep -q 'READY forward' "${TMP_DIR}/proxy.log"

printf 'openssl-quic-interop\n' | timeout 15 openssl s_client -quic \
    -connect "127.0.0.1:${PROXY_PORT}" -servername localhost -alpn h3 \
    -CAfile "${TMP_DIR}/ca-cert.pem" -verify_return_error -brief \
    >"${TMP_DIR}/client.out" 2>"${TMP_DIR}/client.err"
grep -q 'Verification: OK' "${TMP_DIR}/client.err"
grep -q 'Protocol version: QUICv1' "${TMP_DIR}/client.err"
grep -q 'PASS origin echo=openssl-quic-interop' "${TMP_DIR}/origin.log"

echo "PASS: external openssl s_client negotiated verified QUIC h3 through Smithproxy"
if [[ -x "${HTTP3_CURL}" ]] && "${HTTP3_CURL}" --version | grep -q 'HTTP3'; then
    HTTP3_ORIGIN_ADDRESS="${QUIC_INTEROP_HTTP3_ORIGIN_ADDRESS:-$(getent ahostsv4 "${HTTP3_ORIGIN}" | awk 'NR == 1 { print $1 }')}"
    [[ -n "${HTTP3_ORIGIN_ADDRESS}" ]]
    "${BUILD_DIR}/quic_test_node" forward "${TMP_DIR}" "${HTTP3_ORIGIN_ADDRESS}" \
        "${HTTP3_PROXY_PORT}" 443 >"${TMP_DIR}/http3-proxy.log" 2>&1 &
    HTTP3_PROXY_PID=$!
    for _ in {1..100}; do
        grep -q 'READY forward' "${TMP_DIR}/http3-proxy.log" && break
        sleep 0.05
    done
    grep -q 'READY forward' "${TMP_DIR}/http3-proxy.log"
    timeout 15 openssl s_client -quic \
        -connect "127.0.0.1:${HTTP3_PROXY_PORT}" -servername "${HTTP3_ORIGIN}" -alpn h3 \
        -CAfile "${TMP_DIR}/ca-cert.pem" -verify_return_error -brief </dev/null \
        >"${TMP_DIR}/http3-openssl.out" 2>"${TMP_DIR}/http3-openssl.err"
    grep -q 'Verification: OK' "${TMP_DIR}/http3-openssl.err"
    result="$("${HTTP3_CURL}" --http3-only --silent --show-error --head \
        --max-time 20 --cacert "${TMP_DIR}/ca-cert.pem" \
        --resolve "${HTTP3_ORIGIN}:${HTTP3_PROXY_PORT}:127.0.0.1" \
        --write-out '%{http_code} %{http_version}' --output /dev/null \
        "https://${HTTP3_ORIGIN}:${HTTP3_PROXY_PORT}/")"
    code="${result%% *}"
    version="${result##* }"
    [[ "${version}" == "3" ]]
    (( code >= 200 && code < 400 ))
    echo "PASS: curl HTTP/3 request traversed Smithproxy (${HTTP3_ORIGIN}: ${code}, HTTP/${version})"
else
    echo "INFO: HTTP/3 curl not found at ${HTTP3_CURL}; curl interoperability skipped"
fi
