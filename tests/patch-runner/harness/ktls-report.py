#!/usr/bin/env python3
import argparse
import json
import pathlib
import re


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--expect", choices=("any", "on", "off"), default="any")
    parser.add_argument("input", type=pathlib.Path)
    args = parser.parse_args()
    text = args.input.read_text(errors="replace")
    pattern = re.compile(
        r"^\s*(Left|Right)\s*: version: ([^,]+), cipher: (\S+) "
        r"ktls: r:(\d+)/w:(\d+)", re.MULTILINE)
    legs = {}
    for label, version, cipher, receive, send in pattern.findall(text):
        legs[label.lower()] = {
            "version": version,
            "cipher": cipher,
            "receive": int(receive),
            "send": int(send),
        }
    if set(legs) != {"left", "right"}:
        raise RuntimeError(f"expected left and right TLS legs, found {sorted(legs)}")
    active = any(value[direction] for value in legs.values()
                 for direction in ("receive", "send"))
    if args.expect == "on" and not active:
        raise RuntimeError("KTLS requested but no BIO direction is offloaded")
    if args.expect == "off" and active:
        raise RuntimeError("KTLS disabled but an offloaded BIO direction is active")
    print(json.dumps({"active": active, "legs": legs}, sort_keys=True))


if __name__ == "__main__":
    main()
