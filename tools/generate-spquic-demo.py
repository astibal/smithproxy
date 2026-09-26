#!/usr/bin/env python3
"""Generate a PCAP containing synthetic, decrypted QUIC STREAM frames."""

import argparse
import ipaddress
import struct
import time
from pathlib import Path


OUTPUT = (Path(__file__).resolve().parents[1]
          / "artifacts" / "spquic-gre-plaintext-demo.pcap")

CLIENT_IP = ipaddress.IPv4Address("198.18.10.2").packed
SERVER_IP = ipaddress.IPv4Address("198.18.20.2").packed
EXPORTER_IP = ipaddress.IPv4Address("192.0.2.10").packed
COLLECTOR_IP = ipaddress.IPv4Address("192.0.2.20").packed
CLIENT_PORT = 43880
SERVER_PORT = 443

SESSION_ID = 2
STREAM_ID = 0
SPQUIC_VERSION = b"SPQ1"
SPQUIC_HEADER_END = b">>>"
APPLICATION_PROTOCOL = b"h3"


def checksum(data: bytes) -> int:
    """Return the RFC 1071 one's-complement checksum."""
    if len(data) & 1:
        data += b"\x00"
    value = sum(struct.unpack(f"!{len(data) // 2}H", data))
    while value >> 16:
        value = (value & 0xFFFF) + (value >> 16)
    return (~value) & 0xFFFF


def quic_varint(value: int) -> bytes:
    """Encode one RFC 9000 variable-length integer."""
    if value < 0 or value >= 1 << 62:
        raise ValueError("QUIC variable-length integer is out of range")
    if value < 1 << 6:
        return bytes((value,))
    if value < 1 << 14:
        return (value | 0x4000).to_bytes(2, "big")
    if value < 1 << 30:
        return (value | 0x80000000).to_bytes(4, "big")
    return (value | 0xC000000000000000).to_bytes(8, "big")


def stream_frame(stream_id: int, offset: int, payload: bytes, fin: bool = False) -> bytes:
    """Serialize an SPQ1 STREAM frame with a visible plaintext boundary."""
    frame_type = 0x0E | int(fin)  # STREAM + OFF + LEN, optionally FIN.
    return (
        bytes((frame_type,))
        + quic_varint(stream_id)
        + quic_varint(offset)
        + quic_varint(len(payload))
        + SPQUIC_HEADER_END
        + payload
    )


def decoded_headers_frame(stream_id: int, fields: list[tuple[bytes, bytes]]) -> bytes:
    """Serialize Smithproxy's private semantic HTTP/3 HEADERS record."""
    payload = b"\x01" + quic_varint(stream_id) + quic_varint(len(fields))
    for name, value in fields:
        payload += quic_varint(len(name)) + name
        payload += quic_varint(len(value)) + value
    payload += SPQUIC_HEADER_END
    return quic_varint(0xFACE) + quic_varint(len(payload)) + payload


def synthetic_quic_packet(packet_number: int, frame: bytes) -> bytes:
    """Wrap plaintext frames in the self-identifying SPQ1 long header."""
    first_byte = 0xD3  # Long header, fixed bit, SPQ1 data type, four-byte PN.
    destination_id = SESSION_ID.to_bytes(8, "big")
    packet_number_bytes = packet_number.to_bytes(4, "big")

    # Repeat ALPN in every exported packet. Unlike a live QUIC capture, an
    # exported packet may be filtered, sampled, or received after packet loss;
    # keeping it self-contained lets Wireshark select the application dissector.
    if len(APPLICATION_PROTOCOL) > 255:
        raise ValueError("ALPN identifier is too long")
    alpn = bytes((len(APPLICATION_PROTOCOL),)) + APPLICATION_PROTOCOL
    payload_length = quic_varint(len(packet_number_bytes) + len(alpn) + len(frame))
    return (
        bytes((first_byte,))
        + SPQUIC_VERSION
        + bytes((len(destination_id),))
        + destination_id
        + b"\x00"  # No synthetic source CID.
        + payload_length
        + packet_number_bytes
        + alpn
        + frame
    )


def ipv4_packet(
    source_ip: bytes,
    destination_ip: bytes,
    protocol: int,
    payload: bytes,
    packet_id: int,
) -> bytes:
    """Create one checksum-correct IPv4 packet without an Ethernet header."""
    total_length = 20 + len(payload)
    ip_zero = struct.pack(
        "!BBHHHBBH4s4s",
        0x45,
        0,
        total_length,
        packet_id,
        0x4000,
        64,
        protocol,
        0,
        source_ip,
        destination_ip,
    )
    return ip_zero[:10] + struct.pack("!H", checksum(ip_zero)) + ip_zero[12:] + payload


def ipv4_udp_packet(
    source_ip: bytes,
    destination_ip: bytes,
    source_port: int,
    destination_port: int,
    payload: bytes,
    packet_id: int,
) -> bytes:
    """Wrap one synthetic QUIC packet in a checksum-correct IPv4/UDP packet."""
    udp_length = 8 + len(payload)
    udp_zero = struct.pack("!HHHH", source_port, destination_port, udp_length, 0)
    pseudo = source_ip + destination_ip + struct.pack("!BBH", 0, 17, udp_length)
    udp_sum = checksum(pseudo + udp_zero + payload) or 0xFFFF
    udp_header = struct.pack(
        "!HHHH", source_port, destination_port, udp_length, udp_sum
    )

    return ipv4_packet(
        source_ip, destination_ip, 17, udp_header + payload, packet_id
    )


def gre_export_packet(inner_ip: bytes, packet_id: int) -> bytes:
    """Encapsulate the captured IP packet in keyed GRE and outer Ethernet."""
    # RFC 2890 K bit, inner payload protocol IPv4, 32-bit session key.
    gre_header = struct.pack("!HHI", 0x2000, 0x0800, SESSION_ID)
    outer_ip = ipv4_packet(
        EXPORTER_IP,
        COLLECTOR_IP,
        47,
        gre_header + inner_ip,
        packet_id,
    )

    exporter_mac = bytes.fromhex("0200000000a1")
    collector_mac = bytes.fromhex("0200000000b1")
    ethernet = collector_mac + exporter_mac + struct.pack("!H", 0x0800)
    return ethernet + outer_ip


def write_demo(output_path: Path) -> None:
    """Write a deterministic SPQ1 request/response capture to output_path."""
    request = b"GET /demo HTTP/3\r\nhost: origin.runner.lab\r\n\r\n"
    response = b"HTTP/3 200\r\ncontent-length: 5\r\n\r\nhello"

    records = [
        (CLIENT_IP, SERVER_IP, CLIENT_PORT, SERVER_PORT,
         synthetic_quic_packet(1, stream_frame(STREAM_ID, 0, request)), 0x4201),
        (CLIENT_IP, SERVER_IP, CLIENT_PORT, SERVER_PORT,
         synthetic_quic_packet(2, decoded_headers_frame(STREAM_ID, [
             (b":method", b"GET"),
             (b":scheme", b"https"),
             (b":authority", b"origin.runner.lab"),
             (b":path", b"/demo"),
         ])), 0x4202),
        (SERVER_IP, CLIENT_IP, SERVER_PORT, CLIENT_PORT,
         synthetic_quic_packet(3, stream_frame(STREAM_ID, 0, response)), 0x4203),
        (SERVER_IP, CLIENT_IP, SERVER_PORT, CLIENT_PORT,
         synthetic_quic_packet(4, decoded_headers_frame(STREAM_ID, [
             (b":status", b"200"),
             (b"content-length", b"5"),
         ])), 0x4204),
        (CLIENT_IP, SERVER_IP, CLIENT_PORT, SERVER_PORT,
         synthetic_quic_packet(5, stream_frame(STREAM_ID, len(request), b"", True)), 0x4205),
        (SERVER_IP, CLIENT_IP, SERVER_PORT, CLIENT_PORT,
         synthetic_quic_packet(6, stream_frame(STREAM_ID, len(response), b"", True)), 0x4206),
    ]

    output_path.parent.mkdir(parents=True, exist_ok=True)
    started = int(time.time())
    with output_path.open("wb") as output:
        output.write(struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1))
        for index, record in enumerate(records):
            inner_ip = ipv4_udp_packet(*record)
            packet = gre_export_packet(inner_ip, 0x5200 + index)
            output.write(struct.pack("<IIII", started, index * 1000, len(packet), len(packet)))
            output.write(packet)

    print(output_path)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--output", type=Path, default=OUTPUT,
        help=f"capture path (default: {OUTPUT})",
    )
    arguments = parser.parse_args()
    write_demo(arguments.output)


if __name__ == "__main__":
    main()
