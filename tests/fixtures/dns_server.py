#!/usr/bin/env python3

"""Run a command with a tiny deterministic DNS server on loopback."""

from __future__ import annotations

import os
import socket
import socketserver
import struct
import subprocess
import sys
import threading


def encode_name(name: str) -> bytes:
    return b"".join(bytes((len(label),)) + label.encode("ascii") for label in name.split(".")) + b"\0"


def question_end(packet: bytes) -> int:
    offset = 12
    while offset < len(packet):
        size = packet[offset]
        offset += 1
        if size == 0:
            break
        if size & 0xC0 or offset + size > len(packet):
            raise ValueError("invalid qname")
        offset += size
    if offset + 4 > len(packet):
        raise ValueError("truncated question")
    return offset + 4


def qname(packet: bytes) -> str:
    labels: list[str] = []
    offset = 12
    while packet[offset]:
        size = packet[offset]
        offset += 1
        labels.append(packet[offset : offset + size].decode("ascii"))
        offset += size
    return ".".join(labels)


def response(packet: bytes) -> bytes:
    if len(packet) < 12:
        return b""
    try:
        end = question_end(packet)
        name = qname(packet)
    except (IndexError, UnicodeDecodeError, ValueError):
        return b""

    transaction_id = packet[:2]
    question = packet[12:end]
    qtype = struct.unpack("!H", packet[end - 4 : end - 2])[0]
    if name == "nxdomain.test":
        return transaction_id + struct.pack("!HHHHH", 0x8183, 1, 0, 0, 0) + question

    records = {
        1: socket.inet_aton("192.0.2.10"),
        28: socket.inet_pton(socket.AF_INET6, "2001:db8::10"),
        2: encode_name("ns1.fixture.test"),
        6: encode_name("ns1.fixture.test")
        + encode_name("hostmaster.fixture.test")
        + struct.pack("!IIIII", 1, 3600, 600, 86400, 60),
    }
    rdata = records.get(qtype)
    answer_count = int(rdata is not None)
    header = transaction_id + struct.pack("!HHHHH", 0x8180, 1, answer_count, 0, 0)
    if rdata is None:
        return header + question
    answer = b"\xc0\x0c" + struct.pack("!HHIH", qtype, 1, 60, len(rdata)) + rdata
    return header + question + answer


def recv_exact(sock: socket.socket, size: int) -> bytes:
    data = b""
    while len(data) < size:
        chunk = sock.recv(size - len(data))
        if not chunk:
            raise EOFError("DNS TCP connection closed before the full message arrived")
        data += chunk
    return data


class UDPHandler(socketserver.BaseRequestHandler):
    def handle(self) -> None:
        data, sock = self.request
        reply = response(data)
        if reply:
            sock.sendto(reply, self.client_address)


class TCPHandler(socketserver.BaseRequestHandler):
    def handle(self) -> None:
        try:
            prefix = recv_exact(self.request, 2)
            data = recv_exact(self.request, struct.unpack("!H", prefix)[0])
        except EOFError:
            return
        reply = response(data)
        if reply:
            self.request.sendall(struct.pack("!H", len(reply)) + reply)


class UDP6Server(socketserver.ThreadingUDPServer):
    address_family = socket.AF_INET6


class TCP6Server(socketserver.ThreadingTCPServer):
    address_family = socket.AF_INET6


def create_servers() -> list[socketserver.BaseServer]:
    for _ in range(20):
        udp4 = socketserver.ThreadingUDPServer(("127.0.0.1", 0), UDPHandler)
        port = udp4.server_address[1]
        servers: list[socketserver.BaseServer] = [udp4]
        try:
            servers.append(socketserver.ThreadingTCPServer(("127.0.0.1", port), TCPHandler))
            servers.append(UDP6Server(("::1", port), UDPHandler))
            servers.append(TCP6Server(("::1", port), TCPHandler))
            return servers
        except OSError:
            for server in servers:
                server.server_close()
    raise RuntimeError("cannot bind a shared UDP/TCP IPv4/IPv6 DNS port")


def self_test(port: int) -> None:
    question = encode_name("fixture.test") + struct.pack("!HH", 1, 1)
    query = b"\x12\x34" + struct.pack("!HHHHH", 0x0100, 1, 0, 0, 0) + question
    for family, host in ((socket.AF_INET, "127.0.0.1"), (socket.AF_INET6, "::1")):
        with socket.socket(family, socket.SOCK_DGRAM) as sock:
            sock.settimeout(2)
            sock.sendto(query, (host, port))
            reply = sock.recv(4096)
            assert reply[:2] == query[:2] and len(reply) > len(query)
        with socket.socket(family, socket.SOCK_STREAM) as sock:
            sock.settimeout(2)
            sock.connect((host, port))
            sock.sendall(struct.pack("!H", len(query)) + query)
            size = struct.unpack("!H", recv_exact(sock, 2))[0]
            reply = recv_exact(sock, size)
            assert reply[:2] == query[:2] and len(reply) > len(query)


def main() -> int:
    if len(sys.argv) < 2 or (sys.argv[1] != "--self-test" and sys.argv[1] != "--"):
        print(f"usage: {sys.argv[0]} --self-test | -- COMMAND [ARG ...]", file=sys.stderr)
        return 2

    servers = create_servers()
    threads = [threading.Thread(target=server.serve_forever, daemon=True) for server in servers]
    for thread in threads:
        thread.start()

    if sys.argv[1] == "--self-test":
        try:
            self_test(servers[0].server_address[1])
            return 0
        finally:
            for server in servers:
                server.shutdown()
                server.server_close()
            for thread in threads:
                thread.join()

    env = os.environ.copy()
    env["SMITHPROXY_TEST_DNS_HOST4"] = "127.0.0.1"
    env["SMITHPROXY_TEST_DNS_HOST6"] = "::1"
    env["SMITHPROXY_TEST_DNS_PORT"] = str(servers[0].server_address[1])
    try:
        return subprocess.run(sys.argv[2:], env=env, check=False).returncode
    finally:
        for server in servers:
            server.shutdown()
            server.server_close()
        for thread in threads:
            thread.join()


if __name__ == "__main__":
    raise SystemExit(main())
