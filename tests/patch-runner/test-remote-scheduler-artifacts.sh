#!/usr/bin/env bash
set -euo pipefail

HERE=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT

BUNDLE=$TMP/bundle
WORK=$TMP/work
OUTPUT=$WORK/coordinator/main-local
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

"$BUNDLE/tests/patch-runner/remote-scheduler.sh" \
    "$BUNDLE" "$WORK" "$BUNDLE/manifest.tsv" 6 "$OUTPUT" >/dev/null

archive=$OUTPUT.tar
for index in $(seq 1 12); do
    job=$(printf 'sample-%02d' "$index")
    [[ $(<"$OUTPUT/$job.rc") == 0 ]]
    grep -Fx "$job" "$WORK/sections/$job/results/fake-run/worker-id.txt" >/dev/null
    tar -tf "$archive" | grep -Fx "sections/$job/results/fake-run/summary.txt" >/dev/null
done
if tar -tf "$archive" | grep -q '/lab-results/'; then
    echo 'remote result archive contains per-case lab artifacts' >&2
    exit 1
fi

echo 'PASS: P6 scheduler isolates 12 workers, keeps metadata and leaves lab artifacts on target'
