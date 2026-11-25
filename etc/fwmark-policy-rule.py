#!/usr/bin/python3
"""Install a mark-only policy rule before retiring identical old selectors.

Explicit priorities allow integration with other policy-routing services.
Disjoint mark selectors may share a priority, as parallel tunnels do.
Overlapping or unrecognised selectors at that priority are rejected.
"""
import argparse
import fcntl
import json
import subprocess


def number(value):
    return int(str(value), 0)


def plain_mark_rule(rule):
    allowed = {"priority", "src", "dst", "fwmark", "fwmask", "table", "flags"}
    return (set(rule) <= allowed and rule.get("src", "all") == "all"
            and rule.get("dst", "all") == "all" and not rule.get("flags")
            and "fwmark" in rule and "table" in rule)


def install(family, priority, mark, mask, table):
    command = ["ip", family, "rule"]
    rules = json.loads(subprocess.check_output(["ip", family, "-j", "rule", "show"]))
    same = []
    for rule in rules:
        plain = plain_mark_rule(rule)
        rule_mark = number(rule.get("fwmark", 0))
        rule_mask = number(rule.get("fwmask", "0xffffffff"))
        identical = (plain and rule_mark == mark and rule_mask == mask
                     and str(rule["table"]) == str(table))
        if identical:
            same.append(rule)
        if rule.get("priority") != priority or identical:
            continue
        overlap = ((rule_mark ^ mark) & rule_mask & mask) == 0
        if not plain or overlap:
            raise SystemExit(f"Policy priority {priority} conflicts with {rule!r}")

    selector = ["fwmark", f"{mark:#x}/{mask:#x}", "lookup", str(table)]
    present = any(rule["priority"] == priority for rule in same)
    if not present:
        subprocess.run(command + ["add", "pref", str(priority)] + selector, check=True)
    # Preserve the new rule if migration fails. Never delete a foreign selector.
    for rule in same:
        if rule["priority"] != priority:
            subprocess.run(command + ["del", "pref", str(rule["priority"])] + selector,
                           check=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("family", choices=("4", "6"))
    for name in ("priority", "mark", "mask", "table"):
        parser.add_argument(name, type=number)
    args = parser.parse_args()
    valid = (0 < args.priority < 32766 and 0 < args.table < 4294967296
             and 0 < args.mask <= 0xffffffff and 0 <= args.mark <= 0xffffffff
             and args.mark & args.mask == args.mark)
    if not valid:
        parser.error("Invalid priority, table or masked 32-bit mark")
    with open("/run/lock/fwmark-policy-rule.lock", "w") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        install("-" + args.family, args.priority, args.mark, args.mask, args.table)


if __name__ == "__main__":
    main()
