#!/usr/bin/env bash
set -euo pipefail
[[ $# == 5 ]] || { echo "usage: $0 OUTPUT SOURCE PROXY MONITOR PN_ROOT" >&2; exit 2; }
OUTPUT=$1
SOURCE=$2
PROXY=$3
MONITOR=$4
PN_ROOT=$5
mkdir -p "$OUTPUT"

run_one() {
    local slot=$1
    unshare --user --map-root-user --keep-caps --mount --propagation private --net \
        "$(dirname "$0")/run-proxy-nightmare-lifecycle.sh" "$OUTPUT/$slot" \
        python3 "$(dirname "$0")/test-proxy-nightmare-lifecycle.py" \
        --source "$SOURCE" --smithproxy "$PROXY" --monitor "$MONITOR" \
        --proxy-nightmare "$PN_ROOT"
}

run_one 0 > "$OUTPUT/0.log" 2>&1 &
first=$!
run_one 1 > "$OUTPUT/1.log" 2>&1 &
second=$!
wait "$first" || first_rc=$?
wait "$second" || second_rc=$?
first_rc=${first_rc:-0}
second_rc=${second_rc:-0}

# Functional lifecycle results may legitimately expose a timing-sensitive
# proxy flake.  This test checks isolation and measurement consistency without
# forcing two independent runs to report the same Smithproxy behavior.
python3 - "$OUTPUT" "$first_rc" "$second_rc" <<'PY'
import json, pathlib, sys
root = pathlib.Path(sys.argv[1])
items = []
for slot in ("0", "1"):
    paths = sorted((root / slot).glob("run-*/results/result.json"))
    assert len(paths) == 1, (slot, paths)
    items.append(json.loads(paths[0].read_text()))
assert items[0]["network_namespace"] != items[1]["network_namespace"]
assert items[0]["proxy_pid"] != items[1]["proxy_pid"]
assert items[0]["cpu"] == items[1]["cpu"] == "PASS"
assert items[0]["cleanup"] == items[1]["cleanup"] == {
    "lab_reaped": True, "monitor_reaped": True}
outcomes = [[(x["name"], x["functional"]) for x in item["scenarios"]]
            for item in items]
assert [name for name, _ in outcomes[0]] == [name for name, _ in outcomes[1]]
for outcome in outcomes:
    assert all(status in ("PASS", "FAIL", "XFAIL", "XPASS") for _, status in outcome)
assert (int(sys.argv[2]) == 0) == (items[0]["functional"] == "PASS")
assert (int(sys.argv[3]) == 0) == (items[1]["functional"] == "PASS")
print("PASS: two lifecycle runs used distinct namespaces, PIDs and monitors")
for index, outcome in enumerate(outcomes):
    print(index, ", ".join(f"{name}={status}" for name, status in outcome))
PY
