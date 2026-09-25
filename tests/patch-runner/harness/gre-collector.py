#!/usr/bin/env python3
"""Capture one GRE-exported flow and prove that its inner packet has our marker."""
import json
import pathlib
import socket
import sys
import time

output = pathlib.Path(sys.argv[1])
ready = pathlib.Path(sys.argv[2])
markers = [value.encode() for value in sys.argv[3:]]
if not markers:
    raise SystemExit("specify at least one marker")
sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_GRE)
sock.settimeout(10)
ready.write_text("ready\n")

seen = 0
protocols = set()
found = {}
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
    for marker in markers:
        if flags == 0 and protocol in (0x0800, 0x86DD) and marker in gre[4:]:
            found[marker.decode()] = f"0x{protocol:04x}"
    if len(found) == len(markers):
        output.write_text(json.dumps({
            "gre_packets": seen,
            "outer_peer": peer[0],
            "inner_protocols": found,
            "marker_found": True,
        }, sort_keys=True) + "\n")
        break
else:
    raise SystemExit(f"GRE markers not found; found={found}, packets={seen}, protocols={sorted(protocols)}")
