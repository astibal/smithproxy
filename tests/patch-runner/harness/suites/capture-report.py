#!/usr/bin/env python3
import json, pathlib, sys
d=json.loads(pathlib.Path(sys.argv[1]).read_text())
print("Capture matrix")
for case in d.get('coverage', []):
    remote = 'remote_' + d['gre_format']
    verdict = 'PASS' if case['local_pcapng'] and case[remote] else 'FAIL'
    print(f"{verdict}{d['ip_family']} capture {case['name']} {case['direction']}: local PCAPNG + GRE/{d['gre_format']}")
print(f"Flows: {d['local_matrix_flows']} local / {d['gre_matrix_flows']} GRE; "
      f"streams: {d['directional_streams']}; packets: {d['local_packets']} local / {d['gre_packets']} GRE")
print(f"Payload hashes: {'MATCH' if d['payload_sha256_equal'] else 'MISMATCH'}; "
      f"TCP/IP formal validation: {'OK' if d['tcp_formal_validation'] else 'FAILED'}")
print(f"Content errors: {len(d['content_errors'])}; formal errors: {len(d['formal_errors'])}")
print(f"Capture matrix summary: flows={d['local_matrix_flows']} streams={d['directional_streams']} "
      f"payload={'match' if d['payload_sha256_equal'] else 'MISMATCH'} "
      f"formal={'ok' if d['tcp_formal_validation'] else 'FAILED'}")
