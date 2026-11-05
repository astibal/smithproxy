#!/usr/bin/env bash
set -euo pipefail

HERE=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT

BUNDLE=$TMP/bundle
WORK=$TMP/work
OUTPUT=$WORK/coordinator/main-local
HISTORY=$TMP/section-durations.tsv
COLD_WORK=$TMP/cold-work
COLD_OUTPUT=$COLD_WORK/coordinator/main-local
COLD_HISTORY=$TMP/cold-section-durations.tsv
mkdir -p "$BUNDLE/tests/patch-runner" "$BUNDLE/build" "$WORK"
cp "$HERE/remote-scheduler.sh" "$BUNDLE/tests/patch-runner/"

cat > "$BUNDLE/tests/patch-runner/test-patch.sh" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
work=
while (($#)); do
    if [[ $1 == --dir ]]; then work=$2; shift 2; else shift; fi
done
report="$work/results/fake-run"
mkdir -p "$report/lab-results/case-1"
job=${work##*/}
root=${work%/sections/*}
mkdir -p "$root/barrier"
: > "$root/barrier/$job"
for _ in $(seq 1 100); do
    [[ $(find "$root/barrier" -type f | wc -l) -ge 6 ]] && break
    sleep 0.02
done
[[ $(find "$root/barrier" -type f | wc -l) -ge 6 ]]
echo PASS > "$report/summary.txt"
echo "$job" > "$report/worker-id.txt"
echo bulky-diagnostic > "$report/lab-results/case-1/client.log"
echo 'RESULT: PASS'
EOF
chmod +x "$BUNDLE/tests/patch-runner/test-patch.sh"
: > "$BUNDLE/build/smithproxy"
chmod +x "$BUNDLE/build/smithproxy"
cat > "$BUNDLE/coordinator-config.sh" <<'EOF'
PATCH_RUN_COMMIT=test
PATCH_RUN_BRANCH=test
PATCH_RUN_DIRTY=0
PATCH_RUN_FUZZ_LEVEL=1
PATCH_RUN_ENV_ARGS=()
EOF
for index in $(seq 1 12); do
    printf 'sample-%02d\tsample-%02d\t-\n' "$index" "$index"
done > "$BUNDLE/manifest.tsv"

# An empty first-run history must retain manifest order and populate timings.
: > "$COLD_HISTORY"
PATCH_TEST_TIMING_HISTORY=$COLD_HISTORY "$BUNDLE/tests/patch-runner/remote-scheduler.sh" \
    "$BUNDLE" "$COLD_WORK" "$BUNDLE/manifest.tsv" 6 "$COLD_OUTPUT" > "$TMP/cold-scheduler.log"
mapfile -t COLD_FIRST_SIX < <(sed -n 's/^SECTION START: //p' "$TMP/cold-scheduler.log" | head -6)
[[ ${COLD_FIRST_SIX[*]} == 'sample-01 sample-02 sample-03 sample-04 sample-05 sample-06' ]]
[[ $(wc -l < "$COLD_HISTORY") == 12 ]]

for index in $(seq 1 12); do
    printf 'sample-%02d\t%d\t2026-01-01T00:00:00Z\n' "$index" "$((index * 1000))"
done > "$HISTORY"

PATCH_TEST_TIMING_HISTORY=$HISTORY "$BUNDLE/tests/patch-runner/remote-scheduler.sh" \
    "$BUNDLE" "$WORK" "$BUNDLE/manifest.tsv" 6 "$OUTPUT" > "$TMP/scheduler.log"

mapfile -t FIRST_SIX < <(sed -n 's/^SECTION START: //p' "$TMP/scheduler.log" | head -6)
[[ ${FIRST_SIX[*]} == 'sample-12 sample-11 sample-10 sample-09 sample-08 sample-07' ]]

archive=$OUTPUT.tar
for index in $(seq 1 12); do
    job=$(printf 'sample-%02d' "$index")
    [[ $(<"$OUTPUT/$job.rc") == 0 ]]
    [[ $(<"$OUTPUT/$job.duration-ms") =~ ^[0-9]+$ ]]
    grep -Fx "$job" "$WORK/sections/$job/results/fake-run/worker-id.txt" >/dev/null
    tar -tf "$archive" | grep -Fx "sections/$job/results/fake-run/summary.txt" >/dev/null
done
[[ $(wc -l < "$HISTORY") == 12 ]]
awk -F '\t' 'NF != 3 || $2 !~ /^[0-9]+$/ {exit 1}' "$HISTORY"
if tar -tf "$archive" | grep -q '/lab-results/'; then
    echo 'remote result archive contains per-case lab artifacts' >&2
    exit 1
fi

# Two top-level schedulers may finish together and update one history file.
# The result must remain a complete, parseable snapshot rather than interleaved data.
declare -a concurrent_pids=()
for run in a b; do
    concurrent_work=$TMP/concurrent-$run
    PATCH_TEST_TIMING_HISTORY=$HISTORY "$BUNDLE/tests/patch-runner/remote-scheduler.sh" \
        "$BUNDLE" "$concurrent_work" "$BUNDLE/manifest.tsv" 6 \
        "$concurrent_work/coordinator/main-local" > "$TMP/concurrent-$run.log" &
    concurrent_pids+=("$!")
done
for pid in "${concurrent_pids[@]}"; do wait "$pid"; done
[[ $(wc -l < "$HISTORY") == 12 ]]
awk -F '\t' 'NF != 3 || seen[$1]++ || $2 !~ /^[0-9]+$/ {exit 1}' "$HISTORY"

echo 'PASS: P6 scheduler learns longest-first order and safely shares timing history'
