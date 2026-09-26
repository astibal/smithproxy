#!/usr/bin/env python3
import json, pathlib, sys
d=json.loads(pathlib.Path(sys.argv[1]).read_text())
print("Policy suite")
print("Case                         Observed")
print("------------------------------------")
for name,c in d['cases'].items():
    print(f"{name:<28} {'ACCEPT' if c['accepted'] else 'DENY'}")
print(f"Cases: {d['passed']}")
