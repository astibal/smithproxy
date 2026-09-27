#!/usr/bin/env python3
import json, pathlib, sys
d=json.loads(pathlib.Path(sys.argv[1]).read_text())
print("TLS suite")
print("Case                     Result    Version   ALPN       Detail")
print("--------------------------------------------------------------------------")
for name,c in d['cases'].items():
    if c.get('rejected'):
        print(f"{name:<24} {'REJECTED':<9} {'-':<9} {'-':<10} {c['reason']}")
    else:
        detail='hostname verified' if c.get('hostname_verified') else ''
        print(f"{name:<24} {'OK':<9} {c['version']:<9} {str(c['alpn']):<10} {detail}")
print(f"Cipher selection is reported but not guaranteed; cases: {d['passed']}")
