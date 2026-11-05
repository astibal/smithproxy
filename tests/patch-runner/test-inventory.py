#!/usr/bin/env python3
"""Build a stable, top-down inventory of every reported test case."""

import argparse
import csv
import json
import re
import xml.etree.ElementTree as ET
from collections import OrderedDict
from pathlib import Path


VERDICTS = "PASS|FAIL|FLAKY_PASS|XFAIL|XPASS|SKIP"
CASE_ROW = re.compile(rf"^(regular|edge|insanity)\s+(\S+)\s+({VERDICTS})([46])?$")
PLAIN_ROW = re.compile(rf"^(\S+)\s+({VERDICTS})([46])?$")
PREFIX_ROW = re.compile(rf"^({VERDICTS})([46])?(?::|\s)\s*(.+)$")
CTEST_ROW = re.compile(
    r"^\s*\d+/\d+ Test\s+#?\d+:\s+(\S+)\s+\.{2,}\s+"
    r"(Passed|Failed|Timeout|Not Run)\s+([0-9.]+) sec$"
)


def group_for(section):
    if section == "native":
        return "native"
    if section == "smoke":
        return "sanity"
    if section == "lifecycle":
        return "lifecycle"
    if section.startswith("corpus-"):
        return "corpus"
    if section.startswith("fuzz."):
        return "fuzz"
    return "traffic"


def normalize(verdict, family):
    return verdict, {"4": "IPv4", "6": "IPv6"}.get(family, "-")


def parse_ctest(path):
    rows = []
    if not path.exists():
        return rows
    for line in path.read_text(errors="replace").splitlines():
        match = CTEST_ROW.match(line)
        if not match:
            continue
        name, raw, seconds = match.groups()
        verdict = {"Passed": "PASS", "Failed": "FAIL", "Timeout": "FAIL", "Not Run": "SKIP"}[raw]
        rows.append({"name": name, "family": "-", "result": verdict,
                     "detail": f"{seconds} s"})
    return rows


def parse_junit(path):
    if not path.exists():
        return []
    rows = []
    for case in ET.parse(path).getroot().iter("testcase"):
        if case.find("failure") is not None or case.find("error") is not None:
            verdict = "FAIL"
        elif case.find("skipped") is not None:
            verdict = "SKIP"
        else:
            verdict = "PASS"
        seconds = case.get("time")
        rows.append({"name": case.get("name", "unnamed"), "family": "-",
                     "result": verdict, "detail": f"{seconds} s" if seconds else ""})
    return rows


def parse_log(path):
    rows = []
    if not path.exists():
        return rows
    for line in path.read_text(errors="replace").splitlines():
        line = line.strip()
        match = CASE_ROW.match(line)
        if match:
            category, name, verdict, family = match.groups()
            verdict, family = normalize(verdict, family)
            rows.append({"name": name, "family": family, "result": verdict,
                         "detail": category})
            continue
        match = PREFIX_ROW.match(line)
        if match:
            verdict, family, name = match.groups()
            if name.startswith("RESULT:"):
                continue
            verdict, family = normalize(verdict, family)
            rows.append({"name": name, "family": family, "result": verdict,
                         "detail": ""})
            continue
        match = PLAIN_ROW.match(line)
        if match:
            name, verdict, family = match.groups()
            if name == "RESULT:":
                continue
            verdict, family = normalize(verdict, family)
            rows.append({"name": name, "family": family, "result": verdict,
                         "detail": ""})
    return rows


def merge_families(rows):
    merged = OrderedDict()
    for row in rows:
        key = (row["name"], row["result"], row["detail"])
        if key not in merged:
            merged[key] = dict(row)
            continue
        families = merged[key]["family"].split("+")
        if row["family"] not in families:
            merged[key]["family"] += "+" + row["family"]
    return list(merged.values())


def escape(value):
    return str(value).replace("|", "\\|").replace("\n", " ")


def load_sections(report):
    path = report / "sections.tsv"
    if not path.exists():
        return []
    with path.open(newline="") as handle:
        return list(csv.DictReader(handle, delimiter="\t"))


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("report", type=Path)
    args = parser.parse_args()
    report = args.report
    inventory = []

    for section in load_sections(report):
        name = section["section"]
        if name == "native":
            cases = parse_junit(report / "native" / "junit.xml")
            if not cases:
                cases = parse_ctest(report / "native" / "ctest.log")
        else:
            cases = parse_log(report / "sections" / f"{name}.log")
        cases = merge_families(cases)
        if not cases:
            cases = [{"name": "section aggregate", "family": "-",
                      "result": section["result"], "detail": section["reason"]}]
        inventory.append({"group": group_for(name), "section": name,
                          "result": section["result"], "cases": cases})

    if not inventory:
        cases = merge_families(parse_log(report / "test.log"))
        inventory.append({"group": "selected", "section": "selected scope",
                          "result": "-", "cases": cases})

    (report / "test-inventory.json").write_text(
        json.dumps({"sections": inventory}, indent=2) + "\n"
    )
    with (report / "test-inventory.md").open("w") as out:
        out.write("---\n\n## Complete test inventory\n\n")
        out.write("Tests are ordered by profile and section, independent of parallel completion order.\n")
        current_group = None
        for section in inventory:
            if section["group"] != current_group:
                current_group = section["group"]
                out.write(f"\n### {current_group}\n")
            out.write(f"\n#### {section['section']} — {section['result']}\n\n")
            out.write("| Test | Address family | Result | Detail |\n")
            out.write("|---|---:|---:|---|\n")
            for case in section["cases"]:
                out.write("| {} | {} | {} | {} |\n".format(
                    escape(case["name"]), escape(case["family"]),
                    escape(case["result"]), escape(case["detail"] or "-")))


if __name__ == "__main__":
    main()
