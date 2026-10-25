#!/usr/bin/env python3
"""Persistent TCP, TLS and UDP echo traffic for the isolated live CLI lab."""

import argparse
import socket
import ssl
import threading
import time


def echo_connection(conn: socket.socket) -> None:
    try:
        with conn:
            while data := conn.recv(65535):
                conn.sendall(data)
    except OSError:
        pass


def stream_server(host: str, port: int, tls: bool, cert: str, key: str) -> None:
    context = None
    if tls:
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(cert, key)
    listener = socket.socket()
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listener.bind((host, port))
    listener.listen(64)
    while True:
        conn, _ = listener.accept()
        try:
            if context:
                conn = context.wrap_socket(conn, server_side=True)
        except (OSError, ssl.SSLError):
            conn.close()
            continue
        threading.Thread(target=echo_connection, args=(conn,), daemon=True).start()


def stream_client(host: str, port: int, tls: bool, payload: bytes, delay: float) -> None:
    context = ssl._create_unverified_context() if tls else None
    while True:
        try:
            conn = socket.create_connection((host, port), timeout=3)
            if context:
                conn = context.wrap_socket(conn, server_hostname="live.test")
            conn.settimeout(3)
            with conn:
                while True:
                    conn.sendall(payload)
                    received = bytearray()
                    while len(received) < len(payload):
                        part = conn.recv(len(payload) - len(received))
                        if not part:
                            raise ConnectionError("echo connection closed")
                        received.extend(part)
                    if received != payload:
                        raise RuntimeError("corrupt echo payload")
                    time.sleep(delay)
        except (OSError, ssl.SSLError):
            time.sleep(0.05)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("mode", choices=("server", "client"))
    parser.add_argument("--transport", choices=("udp", "tcp", "tls"), default="udp")
    parser.add_argument("--host", default="198.18.20.2")
    parser.add_argument("--port", type=int, default=5353)
    parser.add_argument("--cert", default="")
    parser.add_argument("--key", default="")
    parser.add_argument("--payload-size", type=int, default=4096)
    parser.add_argument("--delay", type=float, default=0.01)
    args = parser.parse_args()

    if args.transport != "udp":
        if args.mode == "server":
            stream_server(args.host, args.port, args.transport == "tls", args.cert, args.key)
        else:
            stream_client(args.host, args.port, args.transport == "tls",
                          b"S" * args.payload_size, args.delay)
        return

    if args.mode == "server":
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.bind((args.host, args.port))
        while True:
            data, peer = sock.recvfrom(65535)
            sock.sendto(data, peer)

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(1)
    payload = b"U" * args.payload_size
    while True:
        sock.sendto(payload, (args.host, args.port))
        try:
            data, _ = sock.recvfrom(65535)
            if data != payload:
                raise RuntimeError("corrupt UDP echo payload")
        except OSError:
            pass
        time.sleep(args.delay)


if __name__ == "__main__":
    main()
