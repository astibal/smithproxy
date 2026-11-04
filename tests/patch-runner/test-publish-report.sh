#!/usr/bin/env bash
set -euo pipefail

HERE=$(cd "$(dirname "$0")" && pwd)
TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT
REPO=$TMP/repo
REMOTE=$TMP/remote.git
mkdir -p "$REPO/tests/patch-runner"
cp "$HERE/publish-report.sh" "$REPO/tests/patch-runner/"

git init -q --bare "$REMOTE"
git -C "$REPO" init -q -b report-test
git -C "$REPO" config user.name 'Patch runner selftest'
git -C "$REPO" config user.email 'patch-runner@example.invalid'
git -C "$REPO" remote add origin "$REMOTE"
echo baseline > "$REPO/README"
git -C "$REPO" add README tests/patch-runner/publish-report.sh
git -C "$REPO" commit -q -m baseline

cat > "$TMP/fake-runner" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
commit=$(git -C "$PUBLISH_TEST_REPO" rev-parse HEAD)
report=$PATCH_TEST_RESULTS_DIR/fake-run
mkdir -p "$report"
cat > "$report/summary.json" <<JSON
{"result":"PASS","commit":"$commit","dirty":false,"host":"test-host",
 "test_groups_run":"native, sanity","test_groups_not_run":"benchmark",
 "optional_layers":"external=not-requested","rtt":"RTT summary: HTTPS-P50=1ms"}
JSON
cat > "$report/sections.tsv" <<TSV
section	target	result	rc	reason	report
native	local-coordinator	PASS	0	all checks passed	-
smoke	secret-host	PASS	0	all checks passed	-
TSV
EOF
chmod +x "$TMP/fake-runner"

PUBLISH_REPORT_RUNNER=$TMP/fake-runner \
PUBLISH_REPORT_RESULTS_DIR=$TMP/results \
PUBLISH_TEST_REPO=$REPO \
    "$REPO/tests/patch-runner/publish-report.sh" full --local >/dev/null

[[ $(git -C "$REPO" branch --show-current) == report-test ]]
[[ $(git --git-dir="$REMOTE" rev-parse refs/heads/report-test) == $(git -C "$REPO" rev-parse HEAD) ]]
mapfile -t reports < <(find "$REPO/docs/test-reports" -name '*.md' -type f)
[[ ${#reports[@]} == 1 ]]
grep -q 'Tested branch: `report-test`' "${reports[0]}"
grep -q '| smoke | remote-1 | PASS |' "${reports[0]}"
! grep -q secret-host "${reports[0]}"
[[ $(git -C "$REPO" show --format= --name-only HEAD | sed '/^$/d') == docs/test-reports/* ]]

echo 'PASS: published report is compact, branch-bound, selectively committed and pushed'
