#!/usr/bin/env python3
"""Generate a deterministic one-session PCAPNG for the Smithproxy dissector."""

import argparse
import ipaddress
import json
import struct
from pathlib import Path


PEN = 67005
DEFAULT_OUTPUT = Path(__file__).with_name("samples") / "smithproxy-reference.pcapng"


def pad4(data):
    return data + b"\0" * ((-len(data)) % 4)


def block(block_type, body):
    body = pad4(body)
    length = 12 + len(body)
    return struct.pack("<II", block_type, length) + body + struct.pack("<I", length)


def option(code, value):
    return struct.pack("<HH", code, len(value)) + pad4(value)


def interface(name, description):
    options = (option(2, name.encode()) + option(3, description.encode()) +
               option(9, b"\x06") + struct.pack("<HH", 0, 0))
    return block(1, struct.pack("<HHI", 101, 0, 65535) + options)


def custom(namespace, payload, version=1):
    envelope = struct.pack("<I4sHHI", PEN, namespace.encode("ascii"), 1, version, len(payload))
    return block(0x00000BAD, envelope + payload)


def json_custom(namespace, value):
    return custom(namespace, json.dumps(value, separators=(",", ":"), sort_keys=True).encode())


def checksum(data):
    if len(data) % 2:
        data += b"\0"
    total = sum(struct.unpack(f"!{len(data) // 2}H", data))
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)
    return (~total) & 0xFFFF


def tcp_packet(src, dst, sport, dport, seq, ack, flags, payload, ident):
    src_bytes = ipaddress.ip_address(src).packed
    dst_bytes = ipaddress.ip_address(dst).packed
    offset_flags = (5 << 12) | flags
    tcp = struct.pack("!HHIIHHHH", sport, dport, seq, ack, offset_flags, 64240, 0, 0) + payload
    pseudo = src_bytes + dst_bytes + struct.pack("!BBH", 0, 6, len(tcp))
    tcp_sum = checksum(pseudo + tcp)
    tcp = struct.pack("!HHIIHHHH", sport, dport, seq, ack, offset_flags, 64240, tcp_sum, 0) + payload
    ip = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + len(tcp), ident, 0x4000,
                     64, 6, 0, src_bytes, dst_bytes)
    ip_sum = checksum(ip)
    ip = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + len(tcp), ident, 0x4000,
                     64, 6, ip_sum, src_bytes, dst_bytes)
    return ip + tcp


def epb(interface_id, timestamp_us, packet):
    body = struct.pack("<IIIII", interface_id, timestamp_us >> 32, timestamp_us & 0xFFFFFFFF,
                       len(packet), len(packet)) + packet
    return block(6, body)


def handshake(message_type, body):
    return bytes([message_type]) + len(body).to_bytes(3, "big") + body


def tls_record(content_type, payload, legacy_version=b"\x03\x03"):
    return bytes([content_type]) + legacy_version + len(payload).to_bytes(2, "big") + payload


def tls_client_hello():
    hostname = b"example.test"
    sni_data = len(hostname) + 3
    sni = struct.pack("!HHH", 0, sni_data + 2, sni_data) + b"\0" + struct.pack("!H", len(hostname)) + hostname
    versions = struct.pack("!HH", 43, 3) + b"\x02\x03\x04"
    groups = struct.pack("!HHH", 10, 4, 2) + b"\x00\x1d"
    sigalgs = struct.pack("!HHH", 13, 4, 2) + b"\x08\x04"
    protocols = b"\x02h2\x08http/1.1"
    alpn = struct.pack("!HHH", 16, len(protocols) + 2, len(protocols)) + protocols
    extensions = sni + versions + groups + sigalgs + alpn
    body = (b"\x03\x03" + bytes(range(32)) + b"\0" + b"\x00\x02\x13\x01" +
            b"\x01\0" + struct.pack("!H", len(extensions)) + extensions)
    return tls_record(22, handshake(1, body), b"\x03\x01")


def tls_server_hello():
    versions = struct.pack("!HH", 43, 2) + b"\x03\x04"
    key_share = struct.pack("!HHH", 51, 36, 29) + struct.pack("!H", 32) + bytes(range(32, 64))
    extensions = versions + key_share
    body = (b"\x03\x03" + bytes(range(64, 96)) + b"\0" + b"\x13\x01" +
            b"\0" + struct.pack("!H", len(extensions)) + extensions)
    return tls_record(22, handshake(2, body))


def sxpp(seq, timestamp, unix_us, delta_us, session_id, session_key, side,
         component, scope, stream_id, event, status, detail=""):
    values = (timestamp, unix_us, delta_us, session_id, session_key, seq, side, component, scope,
              stream_id, event, status, detail)
    return custom("SXPP", ",".join(str(value) for value in values).encode(), version=2)


def flow(interface_id, base_us, src, dst, sport, dport, client_payload,
         server_payload, ident):
    """Emit a complete, sequence-correct TCP exchange including close."""
    cseq, sseq = 1000 + ident, 5000 + ident
    cdata = cseq + 1 + len(client_payload)
    sdata = sseq + 1 + len(server_payload)
    packets = [
        (0, src, dst, sport, dport, cseq, 0, 0x02, b""),
        (180, dst, src, dport, sport, sseq, cseq + 1, 0x12, b""),
        (230, src, dst, sport, dport, cseq + 1, sseq + 1, 0x10, b""),
        (700, src, dst, sport, dport, cseq + 1, sseq + 1, 0x18, client_payload),
        (850, dst, src, dport, sport, sseq + 1, cdata, 0x10, b""),
        (1400, dst, src, dport, sport, sseq + 1, cdata, 0x18, server_payload),
        (1650, src, dst, sport, dport, cdata, sdata, 0x10, b""),
        (2200, src, dst, sport, dport, cdata, sdata, 0x11, b""),
        (2300, dst, src, dport, sport, sdata, cdata + 1, 0x10, b""),
        (2450, dst, src, dport, sport, sdata, cdata + 1, 0x11, b""),
        (2600, src, dst, sport, dport, cdata + 1, sdata + 1, 0x10, b""),
    ]
    return [
        (base_us + offset,
         epb(interface_id, base_us + offset,
             tcp_packet(ps, pd, psp, pdp, seq, ack, flags, payload, ident + offset)))
        for offset, ps, pd, psp, pdp, seq, ack, flags, payload in packets
    ]


def generate(output):
    output.parent.mkdir(parents=True, exist_ok=True)
    session_id = "Proxy-DEADBEEF-PTR-12345678"
    session_key = "tcp_192.0.2.10:51000-198.51.100.20:443"
    base_us = 1791645001000120
    headers = [
        block(0x0A0D0D0A, struct.pack("<IHHq", 0x1A2B3C4D, 1, 0, -1)),
        interface("smithproxy-left", "client-facing plaintext leg"),
        interface("smithproxy-right", "origin-facing TLS leg"),
    ]
    timeline = [(base_us, sxpp(1, "2026-10-10T15:10:01.000120Z", base_us, 0,
                               session_id, session_key,
                               "L", "tcp", "connection", "", "ACCEPTED", "ok"))]

    http_request = (b"GET /capture-profile HTTP/1.1\r\nHost: example.test\r\n"
                    b"User-Agent: smithproxy-reference/1.0\r\n"
                    b"X-Smithproxy-Session: Proxy-DEADBEEF-PTR-12345678\r\n"
                    b"Connection: close\r\n\r\n")
    http_body = b'{"capture":"metadata","status":"ok"}\n'
    http_response = (b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: " +
                     str(len(http_body)).encode() + b"\r\nConnection: close\r\n\r\n" + http_body)
    timeline.extend(flow(0, base_us + 200, "192.0.2.10", "192.0.2.1", 51000, 8080,
                         http_request, http_response, 0x1000))
    timeline.append((base_us + 901,
                     sxpp(2, "2026-10-10T15:10:01.001021Z", base_us + 901, 901,
                          session_id, session_key,
                          "L", "http", "request", "", "FIRST_DATA", "ok",
                          "GET /capture-profile")))

    encrypted_handshake = tls_record(20, b"\x01") + tls_record(23, bytes(range(64)))
    timeline.extend(flow(1, base_us + 4000, "192.0.2.1", "198.51.100.20", 52000, 443,
                         tls_client_hello(), tls_server_hello() + encrypted_handshake, 0x2000))
    timeline.extend([
        (base_us + 4231, sxpp(3, "2026-10-10T15:10:01.004351Z", base_us + 4231, 3330,
                              session_id, session_key,
                              "R", "tls", "connection", "", "HANDSHAKE_STARTED", "pending")),
        (base_us + 5401, sxpp(4, "2026-10-10T15:10:01.005521Z", base_us + 5401, 1170,
                              session_id, session_key,
                              "R", "tls", "connection", "", "SERVER_HELLO", "ok",
                              "TLS_AES_128_GCM_SHA256")),
        (base_us + 5402, json_custom("SXTL", {
            "schema": "smithproxy.tls.v1", "session_id": session_id,
            "proxy_session_key": session_key, "transport": "tcp",
            "L": {"mode": "plain", "application": "http/1.1"},
            "R": {"version": "TLSv1.3", "cipher": "TLS_AES_128_GCM_SHA256",
                  "cipher_bits": 128, "alpn": "http/1.1", "sni": "example.test",
                  "session_reused": False,
                  "peer_certificate": {"sha256": "22" * 32, "subject_cn": "example.test",
                                       "issuer_cn": "Synthetic CA"},
                  "verify": {"performed": True, "ok": True, "openssl_code": 0,
                             "openssl_text": "ok", "origin": "openssl"}}})),
        (base_us + 5403, sxpp(5, "2026-10-10T15:10:01.005523Z", base_us + 5403, 2,
                              session_id, session_key,
                              "P", "load-balancer", "connection", "", "DECIDED", "ok",
                              "target=#3")),
        (base_us + 6610, sxpp(6, "2026-10-10T15:10:01.006730Z", base_us + 6610, 1207,
                              session_id, session_key,
                              "P", "tcp", "session", "", "CLOSED", "info")),
        (base_us + 6611, json_custom("SXME", {
            "schema": "smithproxy.metadata.v1", "session_id": session_id,
            "proxy_session_key": session_key, "started_at": 1791645001,
            "ended_at": 1791645001, "duration_seconds": 0.00661, "policy_index": 3,
            "connection": "192.0.2.10:51000+198.51.100.20:443/TCP",
            "application": "http/1.1+tls", "ja4": {"client": "t13d...synthetic",
                                                     "server": "t130...synthetic"}})),
        (base_us + 6612, json_custom("SXST", {
            "schema": "smithproxy.statistics.v1", "session_id": session_id,
            "proxy_session_key": session_key,
            "statistics": {"info": {"protocol": "http/1.1"},
                           "entropy": {"left": {"mean": 4.62}, "right": {"mean": 7.74}},
                           "flow": {"exchanges": 2, "bytes_left": len(http_request),
                                    "bytes_right": len(http_response)}}})),
    ])
    records = headers + [item for _, item in sorted(timeline, key=lambda value: value[0])]
    output.write_bytes(b"".join(records))
    return len(records)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    args = parser.parse_args()
    count = generate(args.output)
    print(f"{args.output}: {args.output.stat().st_size} bytes, {count} blocks")
