#!/usr/bin/env bash
set -euo pipefail

HERE=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT
DUMMY_PPLAY=$TMP/pplay.py
: > "$DUMMY_PPLAY"

for category in regular edge insanity; do
    PPLAY_PY=$DUMMY_PPLAY LIST_ONLY=1 "$HERE/corpus/run-suite.sh" "$category" \
        > "$TMP/$category.all"
    : > "$TMP/$category.shards"
    for shard in 1 2 3 4; do
        PPLAY_PY=$DUMMY_PPLAY LIST_ONLY=1 SHARD_COUNT=4 SHARD_INDEX=$shard \
            "$HERE/corpus/run-suite.sh" "$category" > "$TMP/$category.$shard"
        cat "$TMP/$category.$shard" >> "$TMP/$category.shards"
    done
    [[ $(wc -l < "$TMP/$category.shards") == $(sort -u "$TMP/$category.shards" | wc -l) ]]
    diff -u <(sort "$TMP/$category.all") <(sort "$TMP/$category.shards")
done

echo 'PASS: four corpus shards are deterministic, disjoint and exhaustive'
