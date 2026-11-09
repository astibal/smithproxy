#!/usr/bin/env python3
"""Build expected directional byte-stream hashes for the capture matrix."""
import hashlib
import json
import os
import pathlib
import runpy
import sys
from capture_tls_cases import cases


corpus = pathlib.Path(sys.argv[1]).resolve()
output = pathlib.Path(sys.argv[2])
entries = []
for case in range(30):
    os.environ["PPLAY_CAPTURE_INDEX"] = str(case)
    namespace = runpy.run_path(str(corpus / "_capture_matrix_case.py"))
    instance = namespace["PPlayScript"](None)
    for direction, role in (("client", "client"), ("server", "server")):
        payload = b"".join(instance.packets[index] for index in instance.origins[role])
        marker = f"CMX{case:02d}{'C' if direction == 'client' else 'S'}"
        if marker.encode() not in payload:
            raise RuntimeError(f"{marker} is not present in expected payload")
        entries.append({
            "case": case,
            "name": instance.case_name,
            "protocol": "tcp" if case < 22 else "udp",
            "direction": direction,
            "marker": marker,
            "length": len(payload),
            "sha256": hashlib.sha256(payload).hexdigest(),
        })

for number, version, request, response in cases():
    for direction, payload in (("client", request), ("server", response)):
        entries.append({
            "case": number, "name": "https-tls-" + version, "protocol": "tcp",
            "direction": direction, "marker": f"CMX{number}{direction[0].upper()}",
            "length": len(payload), "sha256": hashlib.sha256(payload).hexdigest(),
        })
output.write_text(json.dumps({"version": 1, "entries": entries}, indent=2, sort_keys=True) + "\n")
print(f"capture manifest: cases=32 directional_streams={len(entries)} file={output}")
