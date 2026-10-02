#!/usr/bin/env python3
"""Verify that fragmented TLS-looking traffic cannot bypass TLS autodetection."""
import argparse
import json
import socket
import time


PORT = 18080
CASES = (
    ("complete", 64, 0.0),
    ("split_record_type", 1, 0.005),
    ("split_record_header", 4, 0.005),
    ("split_before_handshake", 5, 0.005),
    ("short_gap", 1, 0.001),
)


def marker(label):
    return ("SPAD-" + label).encode()[:12].ljust(12, b"X")


def malformed_hello(label):
    body = b"\x01\x00\x00\x0c" + marker(label)
    return b"\x16\x03\x03" + len(body).to_bytes(2, "big") + body


def server(args):
    family = socket.AF_INET6 if ":" in args.host else socket.AF_INET
    listener = socket.socket(family, socket.SOCK_STREAM)
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listener.bind((args.host, PORT))
    listener.listen(32)
    listener.settimeout(0.2)
    print("READY", flush=True)
    payloads = []
    deadline = time.monotonic() + 4.0
    while time.monotonic() < deadline:
        try:
            connection, peer = listener.accept()
        except socket.timeout:
            continue
        connection.settimeout(0.5)
        payload = b""
        try:
            while len(payload) < 65536:
                chunk = connection.recv(65536 - len(payload))
                if not chunk:
                    break
                payload += chunk
        except (socket.timeout, ConnectionResetError):
            pass
        finally:
            connection.close()
        payloads.append({"peer": peer[0], "payload_hex": payload.hex()})
    listener.close()
    print(json.dumps({"connections": payloads}, sort_keys=True))


def client(args):
    results = {}
    for label, cut, delay in CASES:
        payload = malformed_hello(label)
        cut = min(cut, len(payload))
        started = time.monotonic()
        outcome = "closed"
        with socket.create_connection((args.host, PORT), timeout=2) as connection:
            connection.settimeout(1)
            connection.sendall(payload[:cut])
            if delay:
                time.sleep(delay)
            connection.sendall(payload[cut:])
            connection.shutdown(socket.SHUT_WR)
            try:
                while connection.recv(4096):
                    pass
            except (socket.timeout, ConnectionResetError):
                outcome = "timeout_or_reset"
        results[label] = {
            "cut": cut,
            "delay_ms": delay * 1000,
            "elapsed_ms": round((time.monotonic() - started) * 1000, 2),
            "outcome": outcome,
        }
    print(json.dumps({"cases": results}, sort_keys=True))


def report(args):
    client_result = json.load(open(args.client_result, encoding="utf-8"))
    with open(args.server_result, encoding="utf-8") as result_file:
        lines = [line for line in result_file if line.strip() and line.strip() != "READY"]
    if not lines:
        raise RuntimeError("autodetect origin produced no result")
    server_result = json.loads(lines[-1])
    expected = {label for label, _, _ in CASES}
    if set(client_result.get("cases", {})) != expected:
        raise RuntimeError("autodetect client did not execute the complete matrix")
    origin_payloads = [bytes.fromhex(item["payload_hex"])
                       for item in server_result.get("connections", [])]
    bypassed = [label for label in expected
                if any(marker(label) in payload for payload in origin_payloads)]
    if bypassed:
        raise RuntimeError("TLS autodetect plaintext bypass: " + ", ".join(sorted(bypassed)))
    print("TLS autodetect fragmentation matrix")
    print("cases=%d origin_connections=%d plaintext_bypasses=0" %
          (len(expected), len(origin_payloads)))


parser = argparse.ArgumentParser()
parser.add_argument("mode", choices=("server", "client", "report"))
parser.add_argument("--host")
parser.add_argument("--client-result")
parser.add_argument("--server-result")
arguments = parser.parse_args()
if arguments.mode == "server":
    server(arguments)
elif arguments.mode == "client":
    client(arguments)
else:
    report(arguments)
