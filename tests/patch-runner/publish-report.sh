#!/usr/bin/env bash
set -euo pipefail

HERE=$(cd "$(dirname "$0")" && pwd)
ROOT=$(git -C "$HERE" rev-parse --show-toplevel)
RUNNER=${PUBLISH_REPORT_RUNNER:-$HERE/test-patch.sh}
FORCE=0
RUNNER_ARGS=()

usage() {
    cat <<'EOF'
Run a clean-tree validation, commit its concise report and push the tested branch.

Usage:
  publish-report.sh PROFILE [PATCH-RUNNER OPTIONS] [--force]

The report is written to:
  docs/test-reports/YYYY/YYYY-MM-DDTHHMMSSZ-<branch>-<commit>-<profile>.md

Successful clean runs are committed and pushed to the same branch that was
tested. Failed or dirty runs do not create a published report.
EOF
}

(($#)) || { usage >&2; exit 2; }
for argument in "$@"; do
    case "$argument" in
        --force) FORCE=1 ;;
        -h|--help) usage; exit 0 ;;
        *) RUNNER_ARGS+=("$argument") ;;
    esac
done

PROFILE=${RUNNER_ARGS[0]:-}
[[ $PROFILE =~ ^(quick|native|sanity|traffic|lifecycle|corpus|full|coverage|fuzz|fuzz-dyn|benchmark)$ ]] || {
    echo "Unsupported report profile: ${PROFILE:-<missing>}" >&2; exit 2;
}
[[ -x $RUNNER ]] || { echo "Patch runner is not executable: $RUNNER" >&2; exit 2; }
[[ -z $(git -C "$ROOT" status --porcelain) ]] || {
    echo "Refusing to publish a report for a dirty working tree." >&2; exit 2;
}

TESTED_COMMIT=$(git -C "$ROOT" rev-parse HEAD)
SHORT_COMMIT=${TESTED_COMMIT:0:8}
TESTED_BRANCH=$(git -C "$ROOT" symbolic-ref --quiet --short HEAD) || {
    echo "Refusing to publish from detached HEAD." >&2; exit 2;
}
REPORT_TIME=$(date -u +%Y-%m-%dT%H%M%SZ)
REPORT_YEAR=${REPORT_TIME:0:4}
REPORT_DIR=$ROOT/docs/test-reports/$REPORT_YEAR
SAFE_BRANCH=$(printf '%s' "$TESTED_BRANCH" | tr -c 'A-Za-z0-9._-' '-')
REPORT_PATH=$REPORT_DIR/$REPORT_TIME-$SAFE_BRANCH-$SHORT_COMMIT-$PROFILE.md
if [[ -e $REPORT_PATH && $FORCE == 0 ]]; then
    echo "Report already exists: $REPORT_PATH" >&2; exit 2
fi

PARALLEL=${PATCH_TEST_PARALLEL:-3}
for ((index=0; index<${#RUNNER_ARGS[@]}; ++index)); do
    [[ ${RUNNER_ARGS[index]} != --parallel || $((index+1)) -ge ${#RUNNER_ARGS[@]} ]] \
        || PARALLEL=${RUNNER_ARGS[index+1]}
done

RESULTS_BASE=${PUBLISH_REPORT_RESULTS_DIR:-/var/tmp/smithproxy-publish-report}
mkdir -p "$RESULTS_BASE"
RUN_RESULTS=$(mktemp -d "$RESULTS_BASE/run.XXXXXXXX")
RUN_LOG=$RUN_RESULTS/runner.log

set +e
PATCH_TEST_RESULTS_DIR=$RUN_RESULTS PATCH_TEST_RECORD_HISTORY=0 \
    "$RUNNER" "${RUNNER_ARGS[@]}" 2>&1 | tee "$RUN_LOG"
RUNNER_RC=${PIPESTATUS[0]}
set -e
mapfile -t SUMMARIES < <(find "$RUN_RESULTS" -mindepth 2 -maxdepth 2 -name summary.json -type f -print)
if ((RUNNER_RC)); then
    echo "Patch runner failed (rc=$RUNNER_RC); no report was published." >&2
    echo "Run artifacts: $RUN_RESULTS" >&2
    exit "$RUNNER_RC"
fi
(("${#SUMMARIES[@]}" == 1)) || {
    echo "Expected one summary.json, found ${#SUMMARIES[@]}." >&2; exit 1;
}
[[ $(git -C "$ROOT" rev-parse HEAD) == "$TESTED_COMMIT" ]] || {
    echo "HEAD changed while tests were running; refusing to publish." >&2; exit 1;
}
[[ $(git -C "$ROOT" branch --show-current) == "$TESTED_BRANCH" ]] || {
    echo "Branch changed while tests were running; refusing to publish." >&2; exit 1;
}

SUMMARY=${SUMMARIES[0]}
RUN_REPORT=$(dirname "$SUMMARY")
mkdir -p "$REPORT_DIR"
python3 - "$SUMMARY" "$RUN_REPORT/sections.tsv" "$REPORT_PATH" \
    "$TESTED_COMMIT" "$TESTED_BRANCH" "$PROFILE" "$PARALLEL" "$REPORT_TIME" <<'PY'
import csv, json, pathlib, re, sys
summary_path, sections_path, output_path = map(pathlib.Path, sys.argv[1:4])
tested_commit, tested_branch, profile, parallel, report_time = sys.argv[4:9]
summary = json.loads(summary_path.read_text())
if summary.get("result") != "PASS":
    raise SystemExit("summary result is not PASS")
if summary.get("commit") != tested_commit or summary.get("dirty") is not False:
    raise SystemExit("summary does not describe the clean tested HEAD")
sections = []
if sections_path.exists():
    with sections_path.open(newline="") as stream:
        sections = list(csv.DictReader(stream, delimiter="\t"))
def values(name):
    return [re.sub(r"\s+results=\S+", "", x.strip())
            for x in summary.get(name, "").split(";") if x.strip()]
lines = [
    "# Smithproxy test report", "",
    f"- Result: **{summary['result']}**",
    f"- Tested commit: `{tested_commit}`",
    f"- Tested branch: `{tested_branch}`",
    f"- Date and time (UTC): {report_time}",
    f"- Profile: `{profile}`",
    f"- Parallel sections: {parallel}",
    "- Environment: remote Linux test host" if summary.get("host") != "local"
        else "- Environment: local Linux test host",
    "- Dirty working tree: false", "",
    "This report is retained as diagnostic evidence for future regression",
    "analysis and reconstruction of historical test coverage.",
]
if summary.get("test_groups_run"):
    lines += ["", "## Scope", "",
              f"- Test groups run: {summary['test_groups_run']}",
              f"- Available groups not run: {summary.get('test_groups_not_run') or 'none'}",
              f"- Optional layers: {summary.get('optional_layers') or 'not recorded'}"]
if sections:
    lines += ["", "## Sections", "", "| Section | Target | Result | Reason |",
              "|---|---|---:|---|"]
    remotes = {}
    for section in sections:
        target = section.get("target", "")
        if target not in ("local", "local-coordinator"):
            remotes.setdefault(target, f"remote-{len(remotes)+1}")
            target = remotes[target]
        reason = section.get("reason", "").replace("|", "\\|")
        lines.append(f"| {section.get('section','')} | {target} | "
                     f"{section.get('result','')} | {reason} |")
metrics = []
for key in ("tcp_churn", "udp_churn", "corpus", "capture_matrix", "rtt",
            "tls_transfer", "tls_throughput"):
    metrics.extend(values(key))
if metrics:
    lines += ["", "## Selected metrics", ""] + [f"- {x}" for x in metrics]
lines += ["", "## Reproduction", "", "```sh",
          f"tests/patch-runner/publish-report.sh {profile} "
          f"--remote <test-host> --parallel {parallel}", "```", ""]
output_path.write_text("\n".join(lines))
PY

mapfile -t CHANGED_PATHS < <(git -C "$ROOT" status --porcelain --untracked-files=all | sed 's/^...//')
ALLOWED_PATHS=("${REPORT_PATH#$ROOT/}")
[[ $PROFILE != fuzz-dyn || ! -f $ROOT/tests/docs/covered-seeds ]] \
    || ALLOWED_PATHS+=(tests/docs/covered-seeds)
for changed in "${CHANGED_PATHS[@]}"; do
    allowed=0
    for candidate in "${ALLOWED_PATHS[@]}"; do
        [[ $changed != "$candidate" ]] || { allowed=1; break; }
    done
    ((allowed)) || {
        echo "Unexpected working-tree change after test: $changed" >&2
        echo "Report was not committed or pushed." >&2
        exit 1
    }
done

git -C "$ROOT" add -- "${ALLOWED_PATHS[@]}"
git -C "$ROOT" commit -m "featura: archivovat $PROFILE test run" \
    -m "- zaznamenat uspesny test commitu $SHORT_COMMIT
- ulozit rozsah testu a diagnosticka mereni
- zachovat podklady pro budouci regresni analyzu"
PUBLISH_REMOTE=${PUBLISH_REPORT_REMOTE:-origin}
git -C "$ROOT" remote get-url "$PUBLISH_REMOTE" >/dev/null
git -C "$ROOT" push "$PUBLISH_REMOTE" "HEAD:refs/heads/$TESTED_BRANCH"

echo "Report committed and pushed: $REPORT_PATH"
echo "Branch: $TESTED_BRANCH"
echo "Run artifacts: $RUN_RESULTS"
