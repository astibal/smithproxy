#!/usr/bin/env sh
set -eu

SX_CTLOG=$1
SOURCE_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
TMP_DIR=$(mktemp -d "${TMPDIR:-/tmp}/sx-ctlog-test.XXXXXX")
trap 'rm -rf "$TMP_DIR"' EXIT HUP INT TERM

openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 \
    -out "$TMP_DIR/private.pem" 2>/dev/null
openssl pkey -in "$TMP_DIR/private.pem" -pubout \
    -out "$TMP_DIR/public.pem" 2>/dev/null

"$SX_CTLOG" publish \
    --apple-url "file://$SOURCE_DIR/testdata/apple-minimal.json" \
    --cloudflare-url "file://$SOURCE_DIR/testdata/cloudflare-minimal.json" \
    --signer-key "$TMP_DIR/private.pem" \
    --output-dir "$TMP_DIR/publish"

"$SX_CTLOG" update \
    --url "file://$TMP_DIR/publish/log_list.json" \
    --signature-url "file://$TMP_DIR/publish/log_list.sig" \
    --signer-key "$TMP_DIR/public.pem" \
    --cache-dir "$TMP_DIR/cache" \
    --output "$TMP_DIR/client.cnf"

cmp "$TMP_DIR/publish/ct_log_list.cnf" "$TMP_DIR/client.cnf"

sed 's/"USABLE"/"RETIRED"/' "$SOURCE_DIR/testdata/cloudflare-minimal.json" \
    > "$TMP_DIR/cloudflare-state-mismatch.json"
"$SX_CTLOG" publish \
    --apple-url "file://$SOURCE_DIR/testdata/apple-minimal.json" \
    --cloudflare-url "file://$TMP_DIR/cloudflare-state-mismatch.json" \
    --signer-key "$TMP_DIR/private.pem" \
    --output-dir "$TMP_DIR/state-warning"
grep -q 'policy state differs (Apple USABLE, Cloudflare RETIRED)' \
    "$TMP_DIR/state-warning/policy-report.json"

sed 's/"RFC6962"/"STATIC"/' "$SOURCE_DIR/testdata/cloudflare-minimal.json" \
    > "$TMP_DIR/cloudflare-mismatch.json"
if "$SX_CTLOG" publish \
    --apple-url "file://$SOURCE_DIR/testdata/apple-minimal.json" \
    --cloudflare-url "file://$TMP_DIR/cloudflare-mismatch.json" \
    --signer-key "$TMP_DIR/private.pem" \
    --output-dir "$TMP_DIR/rejected"; then
    echo "hard cross-check mismatch was unexpectedly accepted" >&2
    exit 1
fi

test ! -e "$TMP_DIR/rejected/log_list.json"
