#!/usr/bin/env python3
import json, pathlib, sys
d=json.loads(pathlib.Path(sys.argv[1]).read_text())
print('TLS MITM timing/failure evasion suite')
for name, case in d['cases'].items():
    detail=case.get('version') or case.get('error') or case.get('recovery','')
    print(f"{name:<36} {case['result']:<14} {detail}")
assert d['passed'] == 12
