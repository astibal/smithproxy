#!/usr/bin/env python3
"""Measure TCP, UDP and TLS round trips through the isolated proxy lab."""
import argparse, json, socket, ssl, struct, time

p = argparse.ArgumentParser()
p.add_argument("--host", default="198.18.20.2")
p.add_argument("--ca-file", required=True)
p.add_argument("--samples", type=int, default=200)
p.add_argument("--handshake-samples", type=int, default=40)
p.add_argument("--warmup", type=int, default=20)
p.add_argument("--timeout", type=float, default=2.0)
p.add_argument("--rtt-p95-limit-ms", type=float, default=50.0)
p.add_argument("--rtt-max-limit-ms", type=float, default=250.0)
p.add_argument("--handshake-p95-limit-ms", type=float, default=500.0)
p.add_argument("--handshake-max-limit-ms", type=float, default=2000.0)
p.add_argument("--tls-total-p50-limit-ms", type=float, default=7.0)
p.add_argument("--https-p50-limit-ms", type=float, default=2.0)
p.add_argument("--cold-sni", default="")
p.add_argument("--report-only", action="store_true")
a = p.parse_args()
if min(a.samples, a.handshake_samples) < 1 or a.warmup < 0:
    p.error("sample counts must be positive and warmup non-negative")

now = time.perf_counter_ns
def elapsed(start): return (now() - start) / 1_000_000
def recv_exact(s, size):
    data = bytearray()
    while len(data) < size:
        chunk = s.recv(size - len(data))
        if not chunk: raise RuntimeError("peer closed the connection")
        data.extend(chunk)
    return bytes(data)
def summarize(values, p95_limit, max_limit, name):
    values = sorted(values)
    pct = lambda n: round(values[max(0, (len(values)*n+99)//100-1)], 3)
    out = {"samples":len(values), "min_ms":round(values[0],3), "p50_ms":pct(50),
           "p95_ms":pct(95), "p99_ms":pct(99), "max_ms":round(values[-1],3),
           "p95_limit_ms":p95_limit, "max_limit_ms":max_limit}
    if not a.report_only and out["p95_ms"] > p95_limit: raise RuntimeError(f"{name} p95 limit: {out}")
    if not a.report_only and out["max_ms"] > max_limit: raise RuntimeError(f"{name} max limit: {out}")
    return out
def rtt_stats(values, name):
    return summarize(values, a.rtt_p95_limit_ms, a.rtt_max_limit_ms, name)
def hs_stats(values, name):
    return summarize(values, a.handshake_p95_limit_ms, a.handshake_max_limit_ms, name)

tcp_connect=[]
for _ in range(a.handshake_samples):
    started=now()
    with socket.create_connection((a.host,9998),timeout=a.timeout): pass
    tcp_connect.append(elapsed(started))

tcp_echo=[]
with socket.create_connection((a.host,9998),timeout=a.timeout) as s:
    s.settimeout(a.timeout); s.setsockopt(socket.IPPROTO_TCP,socket.TCP_NODELAY,1)
    for seq in range(a.warmup+a.samples):
        payload=struct.pack("!Q",seq)+b"smithproxy-tcp-rtt"; started=now()
        s.sendall(payload); reply=recv_exact(s,len(payload)); value=elapsed(started)
        if reply != payload: raise RuntimeError(f"TCP payload mismatch at {seq}")
        if seq >= a.warmup: tcp_echo.append(value)

udp=[]
with socket.socket(socket.AF_INET,socket.SOCK_DGRAM) as s:
    s.settimeout(a.timeout); s.connect((a.host,9999))
    for seq in range(a.warmup+a.samples):
        payload=struct.pack("!Q",seq)+b"smithproxy-udp-rtt"; started=now()
        s.send(payload); reply=s.recv(65535); value=elapsed(started)
        if not reply.startswith(payload+b" peer="): raise RuntimeError(f"UDP payload mismatch at {seq}")
        if seq >= a.warmup: udp.append(value)

ctx=ssl.create_default_context(cafile=a.ca_file)
tls_tcp=[]; tls_crypto=[]; tls_total=[]; https=[]; versions=set(); ciphers=set()
cold_total=[]
if a.cold_sni:
    total_started=now(); raw=socket.socket(); raw.settimeout(a.timeout)
    raw.connect((a.host,443))
    with ctx.wrap_socket(raw,server_hostname=a.cold_sni,do_handshake_on_connect=False) as s:
        s.do_handshake(); cold_total.append(elapsed(total_started))
for seq in range(a.handshake_samples):
    total_started=now(); raw=socket.socket(); raw.settimeout(a.timeout); started=now()
    raw.connect((a.host,443)); tls_tcp.append(elapsed(started))
    with ctx.wrap_socket(raw,server_hostname="origin.runner.lab",do_handshake_on_connect=False) as s:
        started=now(); s.do_handshake(); tls_crypto.append(elapsed(started)); tls_total.append(elapsed(total_started))
        versions.add(s.version()); ciphers.add(s.cipher()[0])
        request=f"GET /rtt/{seq} HTTP/1.0\r\nHost: origin.runner.lab\r\nConnection: close\r\n\r\n".encode()
        started=now(); s.sendall(request); response=bytearray()
        while True:
            chunk=s.recv(65535)
            if not chunk: break
            response.extend(chunk)
        https.append(elapsed(started))
        if b"200 OK" not in response or b"runner-origin-ok" not in response:
            raise RuntimeError(f"invalid HTTPS response at {seq}")

tls_result={"tcp_connect":hs_stats(tls_tcp,"TLS TCP connect"),"crypto_handshake":hs_stats(tls_crypto,"TLS handshake"),
        "total_connect":hs_stats(tls_total,"TLS total connect"),"https_rtt":hs_stats(https,"HTTPS"),
        "versions":sorted(versions),"ciphers":sorted(ciphers),"certificate_verified":True}
if cold_total:
    tls_result["cold_total_connect"] = hs_stats(cold_total,"TLS cold total connect")
result={
 "tcp":{"connect_handshake":hs_stats(tcp_connect,"TCP connect"),"echo_rtt":rtt_stats(tcp_echo,"TCP echo")},
 "udp":{"datagram_rtt":rtt_stats(udp,"UDP")},
 "tls":tls_result,
 "payload_mismatches":0,"warmup":a.warmup}
print(json.dumps(result,sort_keys=True))
if not a.report_only and result["tls"]["total_connect"]["p50_ms"] > a.tls_total_p50_limit_ms:
    raise RuntimeError(f"TLS total connect p50 exceeds {a.tls_total_p50_limit_ms} ms")
if not a.report_only and result["tls"]["https_rtt"]["p50_ms"] > a.https_p50_limit_ms:
    raise RuntimeError(f"HTTPS RTT p50 exceeds {a.https_p50_limit_ms} ms")
