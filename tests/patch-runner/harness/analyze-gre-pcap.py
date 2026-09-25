#!/usr/bin/env python3
"""List markers in GRE-encapsulated inner IPv4/TCP streams from a pcap file."""

import collections
import pathlib
import socket
import struct
import sys


def pcap_packets(raw):
    magic = raw[:4]
    endian = {b"\xd4\xc3\xb2\xa1": "<", b"\xa1\xb2\xc3\xd4": ">"}.get(magic)
    if endian is None:
        raise ValueError("unsupported pcap magic")
    offset = 24
    while offset + 16 <= len(raw):
        _, _, captured, _ = struct.unpack_from(endian + "IIII", raw, offset)
        offset += 16
        yield raw[offset:offset + captured]
        offset += captured


def ipv4(packet, offset):
    if offset + 20 > len(packet) or packet[offset] >> 4 != 4:
        return None
    header_len = (packet[offset] & 0x0F) * 4
    total_len = struct.unpack_from("!H", packet, offset + 2)[0]
    protocol = packet[offset + 9]
    source = socket.inet_ntoa(packet[offset + 12:offset + 16])
    destination = socket.inet_ntoa(packet[offset + 16:offset + 20])
    return header_len, total_len, protocol, source, destination


def main(path):
    streams = collections.defaultdict(dict)
    for packet in pcap_packets(pathlib.Path(path).read_bytes()):
        # Ethernet + outer IPv4 + GREv0 (no optional GRE fields in this capture).
        outer = ipv4(packet, 14)
        if not outer or outer[2] != 47:
            continue
        gre_offset = 14 + outer[0]
        flags, protocol = struct.unpack_from("!HH", packet, gre_offset)
        if flags != 0 or protocol != 0x0800:
            continue
        inner_offset = gre_offset + 4
        inner = ipv4(packet, inner_offset)
        if not inner or inner[2] != 6:
            continue
        tcp_offset = inner_offset + inner[0]
        tcp_header_len = (packet[tcp_offset + 12] >> 4) * 4
        source_port, destination_port, sequence = struct.unpack_from("!HHI", packet, tcp_offset)
        payload_offset = tcp_offset + tcp_header_len
        payload_end = inner_offset + inner[1]
        payload = packet[payload_offset:payload_end]
        if payload:
            key = (inner[3], source_port, inner[4], destination_port)
            streams[key].setdefault(sequence, payload)

    for key, segments in streams.items():
        data = b"".join(segments[sequence] for sequence in sorted(segments))
        markers = set()
        for prefix in (b"command-", b"response-"):
            width = len(prefix) + 2
            markers.update(
                data[index:index + width].decode("ascii")
                for index in range(len(data) - width + 1)
                if data[index:index + len(prefix)] == prefix
                and data[index + len(prefix):index + width].isdigit()
            )
        markers = sorted(markers)
        if markers or b"PRI * HTTP/2.0" in data:
            print(f"{key[0]}:{key[1]} -> {key[2]}:{key[3]} bytes={len(data)}")
            print("markers=" + ",".join(markers))


if __name__ == "__main__":
    main(sys.argv[1])
