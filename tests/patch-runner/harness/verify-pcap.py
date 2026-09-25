#!/usr/bin/env python3
"""Validate a generated pcapng structurally and locate a test marker in an EPB."""
import json
import pathlib
import struct
import sys

data_dir = pathlib.Path(sys.argv[1])
prefix = sys.argv[2]
marker = sys.argv[3].encode()
files = sorted(data_dir.glob(f"{prefix}*.pcapng"), key=lambda p: p.stat().st_mtime_ns)
if not files:
    raise SystemExit(f"no {prefix}*.pcapng found in {data_dir}")
path = files[-1]
data = path.read_bytes()
if len(data) < 28 or data[:4] != b"\x0a\x0d\x0d\x0a":
    raise SystemExit(f"invalid pcapng section header: {path}")

bom = data[8:12]
endian = "<" if bom == b"\x4d\x3c\x2b\x1a" else ">" if bom == b"\x1a\x2b\x3c\x4d" else None
if endian is None:
    raise SystemExit(f"invalid pcapng byte-order magic: {path}")

offset = 0
blocks = 0
enhanced_packets = 0
marker_found = False
while offset < len(data):
    if len(data) - offset < 12:
        raise SystemExit(f"truncated pcapng block header at {offset}: {path}")
    block_type, block_len = struct.unpack_from(endian + "II", data, offset)
    if block_len < 12 or block_len % 4 or offset + block_len > len(data):
        raise SystemExit(f"invalid pcapng block length {block_len} at {offset}: {path}")
    trailing_len = struct.unpack_from(endian + "I", data, offset + block_len - 4)[0]
    if trailing_len != block_len:
        raise SystemExit(f"pcapng block length mismatch at {offset}: {path}")
    block = data[offset:offset + block_len]
    blocks += 1
    if block_type == 6:
        enhanced_packets += 1
        marker_found = marker_found or marker in block
    offset += block_len

if enhanced_packets == 0 or not marker_found:
    raise SystemExit(f"pcapng lacks EPB or marker: packets={enhanced_packets}, file={path}")
print(json.dumps({
    "file": str(path), "bytes": len(data), "blocks": blocks,
    "enhanced_packets": enhanced_packets, "marker_found": marker_found,
}, sort_keys=True))

