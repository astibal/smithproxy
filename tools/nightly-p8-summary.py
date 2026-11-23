#!/usr/bin/env python3
"""Render the nightly Full P8 inventory as a GitHub job summary."""

import argparse
import json
import xml.etree.ElementTree as ET
from collections import Counter
from pathlib import Path


PROFILES = ("native", "sanity", "traffic", "lifecycle", "corpus", "fuzz")
VERDICT_PRIORITY = {
    "FAIL": 3,
    "XPASS": 3,
    "FLAKY_PASS": 2,
    "XFAIL": 1,
    "SKIP": 1,
    "PASS": 0,
    "-": 0,
}


def escape_cell(value):
    return str(value or "-").replace("|", "\\|").replace("\n", " ")


def load_native_inventory(report):
    junit = report / "native" / "junit.xml"
    if not junit.exists():
        return None

    cases = []
    for case in ET.parse(junit).getroot().iter("testcase"):
        if case.find("failure") is not None or case.find("error") is not None:
            result = "FAIL"
        elif case.find("skipped") is not None:
            result = "SKIP"
        else:
            result = "PASS"
        seconds = case.get("time")
        cases.append({
            "name": case.get("name", "unnamed"),
            "family": "-",
            "result": result,
            "detail": f"{seconds} s" if seconds else "",
        })
    return {"sections": [{
        "group": "native",
        "section": "native",
        "result": "PASS",
        "cases": cases,
    }]}


def load_reports(root):
    reports = {}
    for path in root.rglob("summary.json"):
        summary = json.loads(path.read_text())
        profile = summary.get("profile")
        is_profile_summary = summary.get("selected_scope") == profile
        if profile not in PROFILES or not is_profile_summary:
            continue

        inventory_path = path.with_name("test-inventory.json")
        inventory = load_native_inventory(path.parent) if profile == "native" else None
        if inventory is None:
            inventory = (json.loads(inventory_path.read_text())
                         if inventory_path.exists() else {"sections": []})
        reports[profile] = {"summary": summary, "inventory": inventory}
    return reports


def count_cases(report):
    counts = Counter()
    for section in report["inventory"].get("sections", []):
        for case in section.get("cases", []):
            counts[case.get("result", "-")] += 1
    return counts


def case_rows(report):
    for section in report["inventory"].get("sections", []):
        for case in section.get("cases", []):
            yield section.get("section", "unknown"), case


def overall_verdict(reports):
    results = [
        reports.get(profile, {}).get("summary", {}).get("result", "FAIL")
        for profile in PROFILES
    ]
    return max(results, key=lambda result: VERDICT_PRIORITY.get(result, 3))


def render(reports, commit, run_url, freshness):
    verdict = overall_verdict(reports)
    source = ("fresh nightly run" if freshness == "fresh"
              else "master unchanged; reused the last successful Full P8")
    lines = [
        f"# Smithproxy Full P8: {verdict}",
        "",
        f"- **Commit:** `{commit}`",
        f"- **Source:** {source}",
        f"- **Full P8 run:** [open results]({run_url})",
        "",
        "## Profile summary",
        "",
        "| Profile | Result | Cases | Reason |",
        "|---|---|---:|---|",
    ]

    for profile in PROFILES:
        report = reports.get(profile)
        if report is None:
            lines.append(f"| {profile} | **FAIL** | - | report artifact missing |")
            continue
        summary = report["summary"]
        counts = count_cases(report)
        count_text = ", ".join(
            f"{name}={count}" for name, count in sorted(counts.items()))
        lines.append(
            f"| {profile} | **{escape_cell(summary.get('result', 'FAIL'))}** "
            f"| {escape_cell(count_text or 'no named cases')} "
            f"| {escape_cell(summary.get('reason'))} |")

    lines.extend([
        "",
        "> **Not covered by this Full P8:** coverage instrumentation; optional "
        "external, benchmark, extended and platform layers; distro packaging/build "
        "matrix, which is handled by separate workflows.",
        "",
        "## Complete test inventory",
    ])

    for profile in PROFILES:
        lines.extend([
            "",
            f"<details><summary><strong>{profile}</strong></summary>",
            "",
            "| Section | Test | Family | Result | Detail |",
            "|---|---|---|---|---|",
        ])
        report = reports.get(profile)
        if report is None:
            lines.append("| - | report artifact missing | - | **FAIL** | - |")
        else:
            for section, case in case_rows(report):
                values = (
                    section,
                    case.get("name", "unnamed"),
                    case.get("family", "-"),
                    case.get("result", "-"),
                    case.get("detail", ""),
                )
                lines.append("| " + " | ".join(map(escape_cell, values)) + " |")
        lines.extend(["", "</details>"])

    return "\n".join(lines) + "\n"


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--reports", type=Path, required=True)
    parser.add_argument("--commit", required=True)
    parser.add_argument("--run-url", required=True)
    parser.add_argument("--freshness", choices=("fresh", "reused"), required=True)
    args = parser.parse_args()
    reports = load_reports(args.reports)
    print(render(reports, args.commit, args.run_url, args.freshness), end="")


if __name__ == "__main__":
    main()
