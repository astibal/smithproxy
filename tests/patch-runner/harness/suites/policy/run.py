#!/usr/bin/env python3
import argparse, json, socket
p=argparse.ArgumentParser(); p.add_argument('--host',default='198.18.20.2'); a=p.parse_args()
def tcp(port,expect):
    try:
        with socket.create_connection((a.host,port),timeout=1) as s:
            s.sendall(b'policy-probe'); ok=s.recv(64)==b'policy-probe'
    except OSError: ok=False
    if ok != expect: raise RuntimeError(f'TCP/{port}: expected {expect}, got {ok}')
    return {'accepted':ok}
cases={'disabled_rule_falls_through':tcp(9998,True),'named_accept_profile':tcp(9996,True),
       'named_deny':tcp(9997,False),'legacy_reject_alias':tcp(9995,False)}
print(json.dumps({'cases':cases,'passed':len(cases)},sort_keys=True))
