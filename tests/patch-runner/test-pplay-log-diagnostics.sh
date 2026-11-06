#!/usr/bin/env bash
set -euo pipefail

HERE=$(cd "$(dirname "$0")" && pwd)
source "$HERE/corpus/log-diagnostics.sh"

work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
log="$work/client.log"

printf '%s\n' 'Loading custom script: /tmp/timeout/case.py (pwd=/tmp/timeout)' \
    'Broken pipe' > "$log"
if pplay_has_failure_diagnostic "$log"; then
    echo 'Fixture paths must not count as timeout diagnostics' >&2
    exit 1
fi

# The same metadata must never hide a subsequent real failure.
for diagnostic in TIMEOUT 'DIE-AFTER expired' Traceback AssertionError; do
    printf '%s\n' "$diagnostic" >> "$log"
    pplay_has_failure_diagnostic "$log"
    sed -i '$d' "$log"
done

# Only the exact startup banner is excluded, not arbitrary lines with paths.
printf '%s\n' 'TIMEOUT while reading /tmp/case.py' > "$log"
pplay_has_failure_diagnostic "$log"
printf '%s\n' 'connection closed by peer' > "$log"
if pplay_has_failure_diagnostic "$log"; then
    exit 1
fi

echo 'PASS pplay diagnostic classification'
