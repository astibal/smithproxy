#!/usr/bin/env python3

import argparse
import pathlib
import socket
import subprocess
import sys
import tempfile
import threading
import time


def free_port():
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def recv_until(sock, marker, limit=65536):
    data = bytearray()
    while marker not in data:
        chunk = sock.recv(4096)
        if not chunk:
            raise RuntimeError(f"connection closed before {marker!r}: {bytes(data)!r}")
        data.extend(chunk)
        if len(data) > limit:
            raise RuntimeError(f"input exceeded {limit} bytes")
    return bytes(data)


class EchoOrigin:
    def __init__(self):
        self.port = free_port()
        self.ready = threading.Event()
        self.finished = threading.Event()
        self.error = None
        self.request = b""
        self.thread = threading.Thread(target=self.run, daemon=True)

    def start(self):
        self.thread.start()
        if not self.ready.wait(5):
            raise RuntimeError("origin did not start")

    def run(self):
        try:
            with socket.socket() as listener:
                listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                listener.bind(("127.0.0.1", self.port))
                listener.listen(1)
                listener.settimeout(15)
                self.ready.set()
                connection, _ = listener.accept()
                with connection:
                    connection.settimeout(15)
                    self.request = recv_until(connection, b"PING\r\n")
                    connection.sendall(b"PONG\r\n")
        except Exception as exc:
            self.error = exc
        finally:
            self.finished.set()


def make_config(source, destination, worktree, runtime, listener_port, cli_port):
    config = source.read_text()
    replacements = {
        "accept_tproxy = TRUE;": "accept_tproxy = FALSE;",
        "accept_redirect = TRUE;": "accept_redirect = FALSE;",
        "accept_socks = TRUE;": "accept_socks = FALSE;",
        "accept_http_connect = FALSE;": "accept_http_connect = TRUE;",
        'http_connect_port = "3128";': f'http_connect_port = "{listener_port}";',
        "http_connect_workers = 0;": "http_connect_workers = 1;",
        'certs_path = "/etc/smithproxy/certs/default/";':
            f'certs_path = "{worktree / "etc/certs/default"}/";',
        'messages_dir = "/etc/smithproxy/msg/en/";':
            f'messages_dir = "{worktree / "etc/msg/en"}/";',
        "port = 50000;": f"port = {cli_port};",
        'log_file = "/var/log/smithproxy/messages.%s.log";':
            f'log_file = "{runtime}/messages.%s.log";',
        'sslkeylog_file = "/var/log/smithproxy/sslkeylog.%s.log";':
            f'sslkeylog_file = "{runtime}/sslkeylog.%s.log";',
        'dir = "/var/smithproxy/data"': f'dir = "{runtime}"',
        "enabled = true": "enabled = false",
    }
    for old, new in replacements.items():
        if old not in config:
            raise RuntimeError(f"configuration fixture is missing {old!r}")
        config = config.replace(old, new, 1)
    destination.write_text(config)


def wait_for_listener(process, port):
    deadline = time.monotonic() + 15
    while time.monotonic() < deadline:
        if process.poll() is not None:
            output, _ = process.communicate()
            raise RuntimeError(f"smithproxy exited early:\n{output}")
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=0.1):
                return
        except OSError:
            time.sleep(0.05)
    raise RuntimeError("HTTP CONNECT listener did not become ready")


def run(args):
    executable = args.smithproxy.resolve()
    worktree = args.source.resolve()
    with tempfile.TemporaryDirectory(prefix="smithproxy-http-connect-") as temp:
        runtime = pathlib.Path(temp)
        config = runtime / "smithproxy.cfg"
        listener_port = free_port()
        make_config(worktree / "etc/smithproxy.cfg", config, worktree, runtime,
                    listener_port, free_port())

        origin = EchoOrigin()
        origin.start()
        process = subprocess.Popen(
            [str(executable), "--config-file", str(config), "--debug"],
            cwd=worktree,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
        )
        output = ""
        try:
            wait_for_listener(process, listener_port)
            with socket.create_connection(("127.0.0.1", listener_port), timeout=10) as client:
                client.settimeout(15)
                request = (
                    f"CONNECT 127.0.0.1:{origin.port} HTTP/1.1\r\n"
                    f"Host: 127.0.0.1:{origin.port}\r\n\r\n"
                )
                client.sendall(request.encode())
                response = recv_until(client, b"\r\n\r\n")
                if not response.startswith(b"HTTP/1.1 200 Connection Established\r\n"):
                    raise RuntimeError(f"CONNECT failed: {response!r}")
                client.sendall(b"PING\r\n")
                if recv_until(client, b"PONG\r\n") != b"PONG\r\n":
                    raise RuntimeError("tunnel response mismatch")

            if not origin.finished.wait(5):
                raise RuntimeError("origin did not finish")
            if origin.error:
                raise origin.error
            if origin.request != b"PING\r\n":
                raise RuntimeError(f"unexpected tunneled request: {origin.request!r}")

            with socket.create_connection(("127.0.0.1", listener_port), timeout=10) as client:
                client.sendall(b"GET / HTTP/1.1\r\nHost: localhost\r\n\r\n")
                response = recv_until(client, b"\r\n\r\n")
                if not response.startswith(b"HTTP/1.1 400 Bad Request\r\n"):
                    raise RuntimeError(f"malformed request was accepted: {response!r}")

            unavailable_port = free_port()
            with socket.create_connection(("127.0.0.1", listener_port), timeout=10) as client:
                client.settimeout(15)
                request = (
                    f"CONNECT 127.0.0.1:{unavailable_port} HTTP/1.1\r\n"
                    f"Host: 127.0.0.1:{unavailable_port}\r\n\r\n"
                )
                client.sendall(request.encode())
                response = recv_until(client, b"\r\n\r\n")
                if not response.startswith(b"HTTP/1.1 502 Bad Gateway\r\n"):
                    raise RuntimeError(
                        f"unavailable upstream did not return 502: {response!r}")
        finally:
            process.terminate()
            try:
                output, _ = process.communicate(timeout=10)
            except subprocess.TimeoutExpired:
                process.kill()
                output, _ = process.communicate(timeout=5)
            if sys.exc_info()[0] is not None:
                print(output, file=sys.stderr)

    print("HTTP CONNECT listener integration: PASS")


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--smithproxy", type=pathlib.Path, required=True)
    parser.add_argument("--source", type=pathlib.Path,
                        default=pathlib.Path(__file__).resolve().parents[2])
    run(parser.parse_args())
