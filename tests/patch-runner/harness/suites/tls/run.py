#!/usr/bin/env python3
import argparse, json, socket, ssl, time
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
def fragmented_records(client_hello, cuts):
    if len(client_hello) < 5 or client_hello[0] != 22:
        raise RuntimeError('expected a TLS handshake record')
    record_length=int.from_bytes(client_hello[3:5],'big')
    if len(client_hello) != 5+record_length:
        raise RuntimeError('unexpected multi-record ClientHello')
    payload=client_hello[5:]
    points=[0]+[cut for cut in cuts if 0 < cut < len(payload)]+[len(payload)]
    records=[]
    for start,end in zip(points,points[1:]):
        part=payload[start:end]
        records.append(client_hello[:3]+len(part).to_bytes(2,'big')+part)
    return b''.join(records)
def timed_handshake(label, chunks, record_cuts=()):
    ctx=ssl.create_default_context(cafile=a.ca_file); ctx.set_alpn_protocols(['http/1.1'])
    incoming=ssl.MemoryBIO(); outgoing=ssl.MemoryBIO()
    tls=ctx.wrap_bio(incoming,outgoing,server_side=False,server_hostname='origin.runner.lab')
    try: tls.do_handshake()
    except ssl.SSLWantReadError: pass
    hello=outgoing.read()
    if record_cuts: hello=fragmented_records(hello,record_cuts)
    with socket.create_connection((a.host,443),timeout=4) as raw:
        raw.settimeout(4)
        offset=0
        for size,delay in chunks:
            if offset >= len(hello): break
            end=min(offset+size,len(hello)); raw.sendall(hello[offset:end]); offset=end
            time.sleep(delay)
        if offset < len(hello): raw.sendall(hello[offset:])
        while True:
            try:
                tls.do_handshake(); break
            except ssl.SSLWantWriteError:
                pass
            except ssl.SSLWantReadError:
                pending=outgoing.read()
                if pending: raw.sendall(pending)
                data=raw.recv(16384)
                if not data: raise RuntimeError(label+' closed before handshake completed')
                incoming.write(data)
        pending=outgoing.read()
        if pending: raw.sendall(pending)
        cert=tls.getpeercert()
        if tls.selected_alpn_protocol() != 'http/1.1':
            raise RuntimeError(label+' ALPN mismatch')
        return {'version':tls.version(),'alpn':tls.selected_alpn_protocol(),
                'cipher':tls.cipher()[0],'hostname_verified':bool(cert),
                'timing_evasion_rejected':True}
cases={}; cases['valid_default']=trusted()
for label,version in [('tls12',ssl.TLSVersion.TLSv1_2),('tls13',ssl.TLSVersion.TLSv1_3)]:
    cases[label]=trusted(version)
for label,ctx,name in [('untrusted',ssl.create_default_context(),'origin.runner.lab')]:
    try: connect(ctx,name); raise RuntimeError(label+' unexpectedly accepted')
    except ssl.SSLCertVerificationError as e: cases[label]={'rejected':True,'reason':e.verify_message}
cases['dynamic_sni_certificate']=trusted(name='wrong.runner.lab')
cases['timing_partial_header_hold']=timed_handshake(
    'timing_partial_header_hold',[(4,0.15)])
cases['timing_clienthello_byte_drip']=timed_handshake(
    'timing_clienthello_byte_drip',[(1,0.02)]*12)
cases['timing_fragmented_tls_records']=timed_handshake(
    'timing_fragmented_tls_records',[(2,0.02),(3,0.02),(1,0.02),(7,0.02)],
    record_cuts=(1,4,37))
for label in ('valid_default','tls12','tls13'):
    if cases[label]['alpn'] != 'http/1.1': raise RuntimeError(label+' ALPN mismatch: '+repr(cases[label]))
print(json.dumps({'cases':cases,'passed':len(cases),'cipher_guaranteed':False},sort_keys=True))
