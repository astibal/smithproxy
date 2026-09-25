#!/usr/bin/env python3
"""Capture one GRE-exported flow and prove that its inner packet has our marker."""
import json
import pathlib
import socket
import sys
import time

output = pathlib.Path(sys.argv[1])
ready = pathlib.Path(sys.argv[2])
marker = sys.argv[3].encode()
sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_GRE)
sock.settimeout(10)
ready.write_text("ready\n")

seen = 0
protocols = set()
deadline = time.monotonic() + 15
while time.monotonic() < deadline:
    packet, peer = sock.recvfrom(65535)
    if len(packet) < 24 or packet[0] >> 4 != 4:
        continue
    outer_ihl = (packet[0] & 0x0f) * 4
    if packet[9] != socket.IPPROTO_GRE or len(packet) < outer_ihl + 4:
        continue
    gre = packet[outer_ihl:]
    flags = int.from_bytes(gre[0:2], "big")
    protocol = int.from_bytes(gre[2:4], "big")
    protocols.add(protocol)
    seen += 1
    if flags == 0 and protocol in (0x0800, 0x86DD) and marker in gre[4:]:
        output.write_text(json.dumps({
            "gre_packets": seen,
            "outer_peer": peer[0],
            "inner_protocol": f"0x{protocol:04x}",
            "marker_found": True,
        }, sort_keys=True) + "\n")
        break
else:
    raise SystemExit(f"GRE marker not found; packets={seen}, protocols={sorted(protocols)}")

