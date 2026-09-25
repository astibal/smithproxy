#!/usr/bin/env python3
"""Verify HTTP/2 CLI history and request/response markers in PCAP and GRE."""

import collections
import json
import pathlib
import re
import socket
import struct
import sys


EXPECTED_REQUESTS = {f"command-{number:02d}" for number in range(1, 13)}
EXPECTED_RESPONSES = {f"response-{number:02d}" for number in range(1, 13)}


def markers(data):
    found = re.findall(rb"(?:command|response)-\d{2}", data)
    return collections.Counter(value.decode("ascii") for value in found)


def pcap_packets(data):
    endian = {b"\xd4\xc3\xb2\xa1": "<", b"\xa1\xb2\xc3\xd4": ">"}.get(data[:4])
    if endian is None:
        raise AssertionError("unsupported GRE pcap magic")
    offset = 24
    while offset + 16 <= len(data):
        _, _, captured, _ = struct.unpack_from(endian + "IIII", data, offset)
        offset += 16
        yield data[offset:offset + captured]
        offset += captured


def ipv4(packet, offset):
    if offset + 20 > len(packet) or packet[offset] >> 4 != 4:
        return None
    header_len = (packet[offset] & 0x0F) * 4
    total_len = struct.unpack_from("!H", packet, offset + 2)[0]
    return (
        header_len,
        total_len,
        packet[offset + 9],
        socket.inet_ntoa(packet[offset + 12:offset + 16]),
        socket.inet_ntoa(packet[offset + 16:offset + 20]),
    )


def gre_stream_markers(path):
    streams = collections.defaultdict(dict)
    for packet in pcap_packets(path.read_bytes()):
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
        payload = packet[tcp_offset + tcp_header_len:inner_offset + inner[1]]
        if payload:
            key = (inner[3], source_port, inner[4], destination_port)
            streams[key].setdefault(sequence, payload)
    combined = collections.Counter()
    for segments in streams.values():
        combined.update(markers(b"".join(segments[key] for key in sorted(segments))))
    return combined


def assert_exact(counter, expected, label):
    relevant = {key: value for key, value in counter.items() if key in expected}
    assert set(relevant) == expected, f"{label}: missing/extra markers: {relevant}"
    assert all(value == 1 for value in relevant.values()), f"{label}: duplicate markers: {relevant}"


def main(cli_name, pcapng_name, gre_name):
    cli = pathlib.Path(cli_name).read_bytes().decode("utf-8", "replace")
    observed = re.findall(
        r"L7 http (?:current|history): GET http://origin\.runner\.lab/(command-\d{2})", cli
    )
    assert observed == [f"command-{number:02d}" for number in range(12, 0, -1)] or set(observed) == EXPECTED_REQUESTS
    cli_counts = collections.Counter(observed)
    assert_exact(cli_counts, EXPECTED_REQUESTS, "CLI")

    pcap_counts = markers(pathlib.Path(pcapng_name).read_bytes())
    assert_exact(pcap_counts, EXPECTED_REQUESTS, "PCAP requests")
    assert_exact(pcap_counts, EXPECTED_RESPONSES, "PCAP responses")

    gre_counts = gre_stream_markers(pathlib.Path(gre_name))
    assert_exact(gre_counts, EXPECTED_REQUESTS, "GRE requests")
    assert_exact(gre_counts, EXPECTED_RESPONSES, "GRE responses")

    print(json.dumps({
        "cli_requests": len(EXPECTED_REQUESTS),
        "pcap_requests": len(EXPECTED_REQUESTS),
        "pcap_responses": len(EXPECTED_RESPONSES),
        "gre_requests": len(EXPECTED_REQUESTS),
        "gre_responses": len(EXPECTED_RESPONSES),
    }, sort_keys=True))


if __name__ == "__main__":
    main(*sys.argv[1:])
