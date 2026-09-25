#!/usr/bin/env python3
import json, pathlib, sys

def load(path):
    line = pathlib.Path(path).read_text().strip()
    return json.loads(line[5:] if line.startswith("RTT: ") else line)

def metrics(data):
    rows = [
        ("TCP connect", data["tcp"]["connect_handshake"]),
        ("TCP echo RTT", data["tcp"]["echo_rtt"]),
        ("UDP datagram RTT", data["udp"]["datagram_rtt"]),
        ("TLS TCP connect", data["tls"]["tcp_connect"]),
        ("TLS crypto handshake", data["tls"]["crypto_handshake"]),
        ("TLS total connect", data["tls"]["total_connect"]),
        ("HTTPS RTT", data["tls"]["https_rtt"]),
    ]
    if "cold_total_connect" in data["tls"]:
        rows.insert(5, ("TLS cold total connect", data["tls"]["cold_total_connect"]))
    return rows

data = load(sys.argv[1])
native = load(sys.argv[2]) if len(sys.argv) > 2 else None
rows = metrics(data)
name_width = max(len(name) for name, _ in rows)
header = (f"{'Metric':<{name_width}}  {'Samples':>7}  {'Min ms':>8}  "
          f"{'P50 ms':>8}  {'P95 ms':>8}  {'P99 ms':>8}  {'Max ms':>8}")
print(header)
print("-" * len(header))
for name, values in rows:
    print(f"{name:<{name_width}}  {values['samples']:>7d}  "
          f"{values['min_ms']:>8.3f}  {values['p50_ms']:>8.3f}  "
          f"{values['p95_ms']:>8.3f}  {values['p99_ms']:>8.3f}  "
          f"{values['max_ms']:>8.3f}")
print(f"\nTLS: {', '.join(data['tls']['versions'])}; certificate verified; "
      f"payload mismatches: {data['payload_mismatches']}")
print(f"RTT summary: TLS-total-P50={data['tls']['total_connect']['p50_ms']:.3f}ms; "
      f"HTTPS-P50={data['tls']['https_rtt']['p50_ms']:.3f}ms")

if native:
    print("\nProxy overhead against native origin-namespace connection")
    delta_header = (f"{'Metric':<{name_width}}  {'Native P50':>10}  {'Proxy P50':>10}  {'Delta P50':>10}  "
                    f"{'Native P95':>10}  {'Proxy P95':>10}  {'Delta P95':>10}  {'Delta P99':>10}")
    print(delta_header)
    print("-" * len(delta_header))
    native_by_name = dict(metrics(native))
    for name, proxy_values in rows:
        if name not in native_by_name:
            continue
        native_values = native_by_name[name]
        d50 = proxy_values['p50_ms'] - native_values['p50_ms']
        d95 = proxy_values['p95_ms'] - native_values['p95_ms']
        d99 = proxy_values['p99_ms'] - native_values['p99_ms']
        print(f"{name:<{name_width}}  {native_values['p50_ms']:>10.3f}  {proxy_values['p50_ms']:>10.3f}  {d50:>+10.3f}  "
              f"{native_values['p95_ms']:>10.3f}  {proxy_values['p95_ms']:>10.3f}  {d95:>+10.3f}  {d99:>+10.3f}")
