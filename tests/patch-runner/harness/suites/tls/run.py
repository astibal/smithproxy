#!/usr/bin/env python3
import argparse, json, socket, ssl
p=argparse.ArgumentParser(); p.add_argument('--ca-file',required=True); p.add_argument('--host',default='198.18.20.2'); a=p.parse_args()
def connect(ctx,name='origin.runner.lab'):
    with socket.create_connection((a.host,443),timeout=3) as raw:
        with ctx.wrap_socket(raw,server_hostname=name) as s:
            return {'version':s.version(),'alpn':s.selected_alpn_protocol(),'cipher':s.cipher()[0],
                    'hostname_verified':True}
def trusted(version=None,name='origin.runner.lab'):
    c=ssl.create_default_context(cafile=a.ca_file); c.set_alpn_protocols(['http/1.1'])
    if version: c.minimum_version=c.maximum_version=version
    return connect(c,name)
cases={}; cases['valid_default']=trusted()
for label,version in [('tls12',ssl.TLSVersion.TLSv1_2),('tls13',ssl.TLSVersion.TLSv1_3)]:
    cases[label]=trusted(version)
for label,ctx,name in [('untrusted',ssl.create_default_context(),'origin.runner.lab')]:
    try: connect(ctx,name); raise RuntimeError(label+' unexpectedly accepted')
    except ssl.SSLCertVerificationError as e: cases[label]={'rejected':True,'reason':e.verify_message}
cases['dynamic_sni_certificate']=trusted(name='wrong.runner.lab')
for label in ('valid_default','tls12','tls13'):
    if cases[label]['alpn'] != 'http/1.1': raise RuntimeError(label+' ALPN mismatch: '+repr(cases[label]))
print(json.dumps({'cases':cases,'passed':len(cases),'cipher_guaranteed':False},sort_keys=True))
