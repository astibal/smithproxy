#!/usr/bin/env python3
"""Compare expected corpus streams with local PCAPNG and GRE exports."""
import collections
import hashlib
import json
import pathlib
import socket
import struct
import sys


def checksum(data):
    if len(data) & 1:
        data += b"\x00"
    total = sum(struct.unpack(f"!{len(data) // 2}H", data))
    while total >> 16:
        total = (total & 0xffff) + (total >> 16)
    return (~total) & 0xffff


def pcapng_packets(path):
    raw = path.read_bytes(); offset = 0; endian = None; packets = []; blocks = 0
    while offset < len(raw):
        if offset + 12 > len(raw):
            raise AssertionError(f"{path}: truncated pcapng block at {offset}")
        if raw[offset:offset + 4] == b"\x0a\x0d\x0d\x0a":
            bom = raw[offset + 8:offset + 12]
            endian = "<" if bom == b"\x4d\x3c\x2b\x1a" else ">" if bom == b"\x1a\x2b\x3c\x4d" else None
            if endian is None:
                raise AssertionError(f"{path}: invalid pcapng byte order")
        if endian is None:
            raise AssertionError(f"{path}: first block is not a section header")
        block_type, block_len = struct.unpack_from(endian + "II", raw, offset)
        if block_len < 12 or block_len % 4 or offset + block_len > len(raw):
            raise AssertionError(f"{path}: invalid block length {block_len} at {offset}")
        if struct.unpack_from(endian + "I", raw, offset + block_len - 4)[0] != block_len:
            raise AssertionError(f"{path}: mismatched trailing block length at {offset}")
        if block_type == 6:
            captured = struct.unpack_from(endian + "I", raw, offset + 20)[0]
            start = offset + 28
            if start + captured > offset + block_len - 4:
                raise AssertionError(f"{path}: EPB captured length exceeds block")
            packets.append(raw[start:start + captured])
        blocks += 1; offset += block_len
    return packets, blocks


def pcap_packets(path):
    raw = path.read_bytes()
    endian = {b"\xd4\xc3\xb2\xa1": "<", b"\xa1\xb2\xc3\xd4": ">"}.get(raw[:4])
    if endian is None:
        raise AssertionError(f"{path}: unsupported classic pcap magic")
    offset = 24; packets = []
    while offset < len(raw):
        if offset + 16 > len(raw):
            raise AssertionError(f"{path}: truncated packet header")
        captured = struct.unpack_from(endian + "I", raw, offset + 8)[0]; offset += 16
        if offset + captured > len(raw):
            raise AssertionError(f"{path}: truncated packet data")
        packets.append(raw[offset:offset + captured]); offset += captured
    return packets


def ipv4_at(packet, offset, issues, label):
    if offset + 20 > len(packet) or packet[offset] >> 4 != 4:
        return None
    ihl = (packet[offset] & 0x0f) * 4
    total = struct.unpack_from("!H", packet, offset + 2)[0]
    if ihl < 20 or total < ihl or offset + total > len(packet):
        raise AssertionError("invalid IPv4 header/total length")
    header = packet[offset:offset + ihl]
    if checksum(header) != 0:
        issues.append(f"{label}: invalid IPv4 header checksum")
    return packet[offset:offset + total]


def ipv6_at(packet, offset):
    if offset + 40 > len(packet) or packet[offset] >> 4 != 6:
        return None
    payload_length = struct.unpack_from("!H", packet, offset + 4)[0]
    total = 40 + payload_length
    if offset + total > len(packet):
        raise AssertionError("invalid IPv6 payload length")
    return packet[offset:offset + total]


def ip_at(packet, offset, issues, label):
    return ipv4_at(packet, offset, issues, label) or ipv6_at(packet, offset)


def local_inner(packet, issues):
    for offset in (0, 14, 16):
        inner = ip_at(packet, offset, issues, "PCAPNG")
        if inner is not None:
            return inner
    return None


def gre_inner(packet, issues):
    outer = ipv4_at(packet, 14, issues, "GRE outer")
    if outer is None or outer[9] != 47:
        return None
    ihl = (outer[0] & 0x0f) * 4
    if len(outer) < ihl + 4:
        raise AssertionError("truncated GRE header")
    flags, protocol = struct.unpack_from("!HH", outer, ihl)
    if flags != 0 or protocol not in (0x0800, 0x86DD):
        return None
    return ip_at(outer, ihl + 4, issues, "GRE inner")


def transport(inner, issues, label):
    family = inner[0] >> 4
    if family == 4:
        ihl = (inner[0] & 0x0f) * 4; protocol = inner[9]
        source = socket.inet_ntop(socket.AF_INET, inner[12:16])
        destination = socket.inet_ntop(socket.AF_INET, inner[16:20])
        segment = inner[ihl:]
        pseudo = inner[12:20] + b"\x00" + bytes((protocol,)) + len(segment).to_bytes(2, "big")
    elif family == 6:
        protocol = inner[6]
        source = socket.inet_ntop(socket.AF_INET6, inner[8:24])
        destination = socket.inet_ntop(socket.AF_INET6, inner[24:40])
        segment = inner[40:]
        pseudo = inner[8:40] + len(segment).to_bytes(4, "big") + b"\x00\x00\x00" + bytes((protocol,))
    else:
        return None
    if protocol == 6:
        if len(segment) < 20:
            raise AssertionError("truncated TCP header")
        source_port, destination_port, sequence, acknowledgment = struct.unpack_from("!HHII", segment)
        header_len = (segment[12] >> 4) * 4
        if header_len < 20 or header_len > len(segment):
            raise AssertionError("invalid TCP data offset")
        if checksum(pseudo + segment) != 0:
            issues.append(f"{label}: invalid TCP checksum")
        return {"family": family, "protocol": "tcp", "source": source, "destination": destination,
                "source_port": source_port, "destination_port": destination_port,
                "sequence": sequence, "acknowledgment": acknowledgment,
                "flags": segment[13], "payload": segment[header_len:]}
    if protocol == 17:
        if len(segment) < 8:
            raise AssertionError("truncated UDP header")
        source_port, destination_port, length, udp_sum = struct.unpack_from("!HHHH", segment)
        if length < 8 or length > len(segment):
            raise AssertionError("invalid UDP length")
        udp_pseudo = (pseudo[:10] + length.to_bytes(2, "big")) if family == 4 else \
            (inner[8:40] + length.to_bytes(4, "big") + b"\x00\x00\x00" + bytes((protocol,)))
        if udp_sum and checksum(udp_pseudo + segment[:length]) != 0:
            issues.append(f"{label}: invalid UDP checksum")
        return {"family": family, "protocol": "udp", "source": source, "destination": destination,
                "source_port": source_port, "destination_port": destination_port,
                "payload": segment[8:length]}
    return None


def connection_key(item):
    endpoints = sorted(((item["source"], item["source_port"]), (item["destination"], item["destination_port"])))
    return item["protocol"], tuple(endpoints)


def direction_key(item):
    return item["source"], item["source_port"], item["destination"], item["destination_port"]


def validate_tcp(packets, selected, issues, label):
    next_seq = {}; bases = {}; last_ack = {}; closed = set(); payloads = collections.defaultdict(dict)
    for item in packets:
        key = connection_key(item)
        if item["protocol"] != "tcp" or key not in selected:
            continue
        direction = direction_key(item); reverse = (direction[2], direction[3], direction[0], direction[1])
        seq = item["sequence"]; flags = item["flags"]; payload = item["payload"]
        syn = bool(flags & 0x02); fin = bool(flags & 0x01); rst = bool(flags & 0x04); ack_flag = bool(flags & 0x10)
        if direction in closed and (payload or syn or fin):
            issues.append(f"{label}: TCP data/control after close: {direction}")
        if direction not in next_seq:
            bases[direction] = seq
            next_seq[direction] = (seq + (1 if syn else 0)) & 0xffffffff
        elif syn:
            issues.append(f"{label}: duplicate SYN: {direction}")
        if payload or fin:
            expected = next_seq[direction]
            if seq != expected:
                issues.append(f"{label}: TCP SEQ gap/overlap {direction}: got={seq} expected={expected}")
            if payload:
                payloads[direction][seq] = payload
            next_seq[direction] = (expected + len(payload) + (1 if fin else 0)) & 0xffffffff
        elif not syn and seq != next_seq[direction]:
            issues.append(f"{label}: TCP pure ACK sequence mismatch {direction}: got={seq} expected={next_seq[direction]}")
        if ack_flag and reverse in bases:
            relative = (item["acknowledgment"] - bases[reverse]) & 0xffffffff
            produced = (next_seq[reverse] - bases[reverse]) & 0xffffffff
            previous = last_ack.get(direction, 0)
            if relative < previous or relative > produced:
                issues.append(f"{label}: TCP ACK invalid {direction}: relative={relative} previous={previous} produced={produced}")
            last_ack[direction] = relative
        if fin or rst:
            closed.add(direction)
    streams = []
    for direction, segments in payloads.items():
        base = min(segments, key=lambda seq: (seq - bases[direction]) & 0xffffffff)
        ordered = sorted(segments, key=lambda seq: (seq - base) & 0xffffffff)
        streams.append(b"".join(segments[seq] for seq in ordered))
    return streams


def collect(packet_bytes, unwrap, label, family):
    parsed = []; issues = []
    for packet in packet_bytes:
        inner = unwrap(packet, issues)
        if inner is not None:
            item = transport(inner, issues, label)
            if item is not None and item["family"] == family:
                parsed.append(item)
    selected = {connection_key(item) for item in parsed if b"CMX" in item["payload"]}
    tcp_streams = validate_tcp(parsed, selected, issues, label)
    udp_payloads = [item["payload"] for item in parsed if item["protocol"] == "udp" and b"CMX" in item["payload"]]
    return tcp_streams + udp_payloads, parsed, selected, issues


def compare(label, streams, expected):
    observed = {}; errors = []
    for entry in expected:
        marker = entry["marker"].encode()
        matches = [stream for stream in streams if marker in stream]
        if len(matches) != 1:
            errors.append(f"{label} {entry['marker']}: expected one stream, got {len(matches)}")
            continue
        stream = matches[0]
        actual = {"length": len(stream), "sha256": hashlib.sha256(stream).hexdigest()}
        wanted = {"length": entry["length"], "sha256": entry["sha256"]}
        if actual != wanted:
            errors.append(f"{label} {entry['marker']}: {actual} != {wanted}")
            continue
        observed[entry["marker"]] = actual
    return observed, errors


def main(manifest_name, data_dir_name, prefix, gre_name, family_name="4"):
    family = int(family_name)
    manifest = json.loads(pathlib.Path(manifest_name).read_text()); expected = manifest["entries"]
    files = sorted(pathlib.Path(data_dir_name).glob(f"{prefix}*.pcapng"))
    if not files:
        raise AssertionError("capture matrix: no local pcapng files")
    local_packets = []; local_blocks = 0
    for path in files:
        packets, blocks = pcapng_packets(path); local_packets.extend(packets); local_blocks += blocks
    gre_packets = pcap_packets(pathlib.Path(gre_name))
    local_streams, local_parsed, local_flows, local_issues = collect(local_packets, local_inner, "PCAPNG", family)
    gre_streams, gre_parsed, gre_flows, gre_issues = collect(gre_packets, gre_inner, "GRE", family)
    local, local_errors = compare("PCAPNG", local_streams, expected)
    gre, gre_errors = compare("GRE", gre_streams, expected)
    content_errors = local_errors + gre_errors
    if local != gre:
        content_errors.append("PCAPNG and GRE directional stream summaries differ")
    formal_counts = collections.Counter(local_issues + gre_issues)
    result = {
        "cases": len({entry["case"] for entry in expected}),
        "ip_family": family,
        "directional_streams": len(expected),
        "local_files": len(files), "local_blocks": local_blocks,
        "local_packets": len(local_parsed), "local_matrix_flows": len(local_flows),
        "gre_packets": len(gre_parsed), "gre_matrix_flows": len(gre_flows),
        "payload_sha256_equal": not content_errors,
        "tcp_formal_validation": not formal_counts,
        "content_errors": content_errors,
        "formal_errors": dict(sorted(formal_counts.items())),
    }
    print(json.dumps(result, sort_keys=True))
    if content_errors or formal_counts:
        raise SystemExit(
            f"capture matrix failed: content_errors={len(content_errors)} "
            f"formal_errors={sum(formal_counts.values())}"
        )


if __name__ == "__main__":
    main(*sys.argv[1:])
