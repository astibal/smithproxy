#!/bin/sh
set -eu

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
REPO_DIR=$(CDPATH= cd -- "$SCRIPT_DIR/../.." && pwd)

BUILD_DIR=${CTLOG_BUILD_DIR:-"$REPO_DIR/build-ctlog"}
OUTPUT_DIR=${CTLOG_OUTPUT_DIR:-"/tmp/smithproxy-ct-publish"}
TOKEN_FILE=${CTLOG_CLOUDFLARE_TOKEN_FILE:-"$HOME/.config/smithproxy/ctlog/cloudflare-token"}
PRIVATE_KEY=${CTLOG_SIGNING_KEY:-"$HOME/.config/smithproxy/ctlog/signing-key.pem"}
PUBLIC_KEY=${CTLOG_PUBLIC_KEY:-"$SCRIPT_DIR/smithproxy-ctlog-signer.pem"}

APPLE_URL=${CTLOG_APPLE_URL:-"https://valid.apple.com/ct/log_list/current_log_list.json"}
CLOUDFLARE_URL=${CTLOG_CLOUDFLARE_URL:-"https://api.cloudflare.com/client/v4/radar/ct/logs"}

require_file() {
    if [ ! -r "$1" ]; then
        echo "Chybi citelny soubor: $1" >&2
        exit 1
    fi
}

require_file "$TOKEN_FILE"
require_file "$PRIVATE_KEY"
require_file "$PUBLIC_KEY"

echo "[1/4] Sestavuji sx_ctlog"
cmake -S "$SCRIPT_DIR" -B "$BUILD_DIR"
cmake --build "$BUILD_DIR"

echo "[2/4] Spoustim testy"
ctest --test-dir "$BUILD_DIR" --output-on-failure

echo "[3/4] Stahuji, kontroluji a podepisuji CT log list"
"$BUILD_DIR/sx_ctlog" publish \
    --apple-url "$APPLE_URL" \
    --cloudflare-url "$CLOUDFLARE_URL" \
    --cloudflare-token-file "$TOKEN_FILE" \
    --signer-key "$PRIVATE_KEY" \
    --output-dir "$OUTPUT_DIR"

echo "[4/4] Overuji vysledny podpis"
openssl dgst -sha256 \
    -verify "$PUBLIC_KEY" \
    -signature "$OUTPUT_DIR/log_list.sig" \
    "$OUTPUT_DIR/log_list.json"

echo
echo "Hotovo. Vystupy:"
for artifact in ct_log_list.cnf log_list.json log_list.sig policy-report.json; do
    printf '  %s\n' "$OUTPUT_DIR/$artifact"
done
