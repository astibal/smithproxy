#!/usr/bin/env bash
set -euo pipefail

HERE=$(cd "$(dirname "$0")" && pwd)
ROOT=$(git -C "$HERE" rev-parse --show-toplevel)
DESTINATION=${1:-$ROOT/../quic-python}

[[ $DESTINATION == /* ]] || {
    echo 'QUIC Python runtime destination must be absolute' >&2
    exit 2
}
mkdir -p "$DESTINATION"
python3 -m pip install --upgrade --target "$DESTINATION" \
    --requirement "$HERE/quic-requirements.txt"
PYTHONPATH="$DESTINATION" python3 -c \
    'import aioquic, cryptography, pylsqpack; print("QUIC Python runtime ready:", aioquic.__version__)'
