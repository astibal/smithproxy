#!/usr/bin/env bash
set -euo pipefail

HERE=$(cd "$(dirname "$0")" && pwd)
ROOT=$(git -C "$HERE" rev-parse --show-toplevel)
RUNNER=${PUBLISH_REPORT_RUNNER:-$HERE/test-patch.sh}
FORCE=0
RUNNER_ARGS=()

usage() {
    cat <<'EOF'
Publish a successful patch-runner result as a concise Markdown report.

Usage:
  publish-report.sh PROFILE [PATCH-RUNNER OPTIONS] [--force]

Examples:
  publish-report.sh full --remote root@test-host --parallel 3
  publish-report.sh sanity --local --force

The report is written to:
  docs/test-reports/YYYY/YYYY-MM-DD-<commit>-<profile>.md

The script never commits or pushes the generated report. Failed or dirty runs
do not create a report. Existing reports are preserved unless --force is used.
EOF
}

if (($# == 0)); then
    usage >&2
    exit 2
fi

for argument in "$@"; do
    case "$argument" in
        --force) FORCE=1 ;;
        -h|--help) usage; exit 0 ;;
        *) RUNNER_ARGS+=("$argument") ;;
    esac
done

PROFILE=${RUNNER_ARGS[0]:-}
[[ $PROFILE =~ ^(quick|sanity|full|fuzz|fuzz-dyn|benchmark)$ ]] || {
    echo "Unsupported report profile: ${PROFILE:-<missing>}" >&2
    usage >&2
    exit 2
}

[[ -x $RUNNER ]] || { echo "Patch runner is not executable: $RUNNER" >&2; exit 2; }

TESTED_COMMIT=$(git -C "$ROOT" rev-parse HEAD)
SHORT_COMMIT=${TESTED_COMMIT:0:8}
REPORT_DATE=$(date -u +%F)
REPORT_YEAR=${REPORT_DATE:0:4}
REPORT_DIR=$ROOT/docs/test-reports/$REPORT_YEAR
REPORT_PATH=$REPORT_DIR/$REPORT_DATE-$SHORT_COMMIT-$PROFILE.md
if [[ -e $REPORT_PATH && $FORCE == 0 ]]; then
    echo "Report already exists: $REPORT_PATH" >&2
    echo "Use --force to replace it." >&2
    exit 2
fi
if [[ -n $(git -C "$ROOT" status --porcelain) ]]; then
    echo "Refusing to publish a report for a dirty working tree." >&2
    exit 2
fi

PARALLEL=${PATCH_TEST_PARALLEL:-3}
for ((index = 0; index < ${#RUNNER_ARGS[@]}; ++index)); do
    if [[ ${RUNNER_ARGS[index]} == --parallel && $((index + 1)) -lt ${#RUNNER_ARGS[@]} ]]; then
        PARALLEL=${RUNNER_ARGS[index + 1]}
    fi
done

RESULTS_BASE=${PUBLISH_REPORT_RESULTS_DIR:-/tmp/smithproxy-publish-report}
mkdir -p "$RESULTS_BASE"
RUN_RESULTS=$(mktemp -d "$RESULTS_BASE/run.XXXXXXXX")
RUN_LOG=$RUN_RESULTS/runner.log

set +e
PATCH_TEST_RESULTS_DIR=$RUN_RESULTS "$RUNNER" "${RUNNER_ARGS[@]}" 2>&1 | tee "$RUN_LOG"
RUNNER_RC=${PIPESTATUS[0]}
set -e

mapfile -t SUMMARIES < <(find "$RUN_RESULTS" -mindepth 2 -maxdepth 2 -name summary.json -type f -print)
if ((RUNNER_RC != 0)); then
    echo "Patch runner failed (rc=$RUNNER_RC); no report was written." >&2
    echo "Run artifacts: $RUN_RESULTS" >&2
    exit "$RUNNER_RC"
fi
if ((${#SUMMARIES[@]} != 1)); then
    echo "Expected one summary.json, found ${#SUMMARIES[@]}; no report was written." >&2
    echo "Run artifacts: $RUN_RESULTS" >&2
    exit 1
fi

SUMMARY=${SUMMARIES[0]}
RUN_REPORT=$(dirname "$SUMMARY")

mkdir -p "$REPORT_DIR"
python3 - "$SUMMARY" "$RUN_REPORT/sections.tsv" "$REPORT_PATH" \
    "$TESTED_COMMIT" "$PROFILE" "$PARALLEL" "$REPORT_DATE" <<'PY'
import csv
import json
import pathlib
import re
import sys

summary_path, sections_path, output_path = map(pathlib.Path, sys.argv[1:4])
tested_commit, profile, parallel, report_date = sys.argv[4:8]

summary = json.loads(summary_path.read_text(encoding="utf-8"))
if summary.get("result") != "PASS":
    raise SystemExit("summary result is not PASS")
if summary.get("commit") != tested_commit:
    raise SystemExit(
        f"summary commit {summary.get('commit')} does not match HEAD {tested_commit}")
if summary.get("dirty") is not False:
    raise SystemExit("summary describes a dirty working tree")

sections = []
if sections_path.exists():
    with sections_path.open(encoding="utf-8", newline="") as stream:
        sections = list(csv.DictReader(stream, delimiter="\t"))

def values(name):
    value = summary.get(name, "")
    if not value:
        return []
    entries = []
    for item in value.split(";"):
        item = re.sub(r"\s+results=\S+", "", item.strip())
        if item:
            entries.append(item)
    return entries

lines = [
    "# Smithproxy test report",
    "",
    f"- Result: **{summary['result']}**",
    f"- Tested commit: `{tested_commit}`",
    f"- Date (UTC): {report_date}",
    f"- Profile: `{profile}`",
    f"- Parallel sections: {parallel}",
    "- Environment: remote Linux test host" if summary.get("host") != "local"
        else "- Environment: local Linux test host",
    "- Dirty working tree: false",
]

if sections:
    lines += ["", "## Sections", "", "| Section | Target | Result | Reason |",
              "|---|---|---:|---|"]
    for section in sections:
        reason = section.get("reason", "").replace("|", "\\|")
        lines.append(
            f"| {section.get('section', '')} | {section.get('target', '')} | "
            f"{section.get('result', '')} | {reason} |")

metrics = []
for key in ("tcp_churn", "udp_churn", "corpus", "capture_matrix", "rtt"):
    metrics.extend(values(key))
if metrics:
    lines += ["", "## Metrics", ""]
    lines.extend(f"- {metric}" for metric in metrics)

lines += [
    "",
    "## Reproduction",
    "",
    "```sh",
    f"tests/patch-runner/publish-report.sh {profile} --remote <test-host> --parallel {parallel}",
    "```",
    "",
]

output_path.write_text("\n".join(lines), encoding="utf-8")
PY

echo "Report: $REPORT_PATH"
echo "Run artifacts: $RUN_RESULTS"
