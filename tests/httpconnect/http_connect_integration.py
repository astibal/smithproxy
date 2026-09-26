#!/usr/bin/env python3

import argparse
import pathlib
import socket
import ssl
import subprocess
import sys
import tempfile
import threading
import time


def free_port(family=socket.AF_INET, address=None):
    address = address or ("::1" if family == socket.AF_INET6 else "127.0.0.1")
    with socket.socket(family) as sock:
        sock.bind((address, 0))
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


def system_nameserver():
    for line in pathlib.Path("/etc/resolv.conf").read_text().splitlines():
        fields = line.split()
        if len(fields) == 2 and fields[0] == "nameserver":
            return fields[1]
    raise RuntimeError("no nameserver found in /etc/resolv.conf")


class EchoOrigin:
    def __init__(self, family=socket.AF_INET, address=None):
        self.family = family
        self.address = address or ("::1" if family == socket.AF_INET6 else "127.0.0.1")
        self.port = free_port(family, self.address)
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
            with socket.socket(self.family) as listener:
                listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                listener.bind((self.address, self.port))
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


class TlsEchoOrigin:
    def __init__(self, cert, key):
        self.port = free_port()
        self.cert = cert
        self.key = key
        self.ready = threading.Event()
        self.finished = threading.Event()
        self.error = None
        self.request = b""
        self.thread = threading.Thread(target=self.run, daemon=True)

    def start(self):
        self.thread.start()
        if not self.ready.wait(5):
            raise RuntimeError("TLS origin did not start")
        if self.error:
            raise self.error

    def run(self):
        try:
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            context.load_cert_chain(self.cert, self.key)
            with socket.socket() as listener:
                listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                listener.bind(("127.0.0.1", self.port))
                listener.listen(1)
                listener.settimeout(15)
                self.ready.set()
                connection, _ = listener.accept()
                with context.wrap_socket(connection, server_side=True) as tls_connection:
                    tls_connection.settimeout(15)
                    self.request = recv_until(tls_connection, b"TLS-PING\r\n")
                    tls_connection.sendall(b"TLS-PONG\r\n")
        except Exception as exc:
            self.error = exc
            self.ready.set()
        finally:
            self.finished.set()


def make_config(source, destination, worktree, runtime, listener_port, cli_port,
                reject_tcp=False):
    config = source.read_text()
    replacements = {
        "accept_tproxy = TRUE;": "accept_tproxy = FALSE;",
        "accept_redirect = TRUE;": "accept_redirect = FALSE;",
        "accept_socks = TRUE;": "accept_socks = FALSE;",
        "accept_http_connect = FALSE;": "accept_http_connect = TRUE;",
        'nameservers = [ "8.8.8.8", "8.8.4.4" ];':
            f'nameservers = [ "{system_nameserver()}" ];',
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
    if reject_tcp:
        action = 'action = "accept";'
        position = config.rfind(action)
        if position < 0:
            raise RuntimeError("configuration fixture has no TCP accept policy")
        config = config[:position] + 'action = "deny";' + config[position + len(action):]
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


def check_plain_tunnel(listener_port, target, origin):
    origin.start()
    authority = f"[{target}]:{origin.port}" if ":" in target else f"{target}:{origin.port}"
    with socket.create_connection(("127.0.0.1", listener_port), timeout=10) as client:
        client.settimeout(15)
        request = (
            f"CONNECT {authority} HTTP/1.1\r\n"
            f"Host: {authority}\r\n\r\n"
        )
        client.sendall(request.encode())
        response = recv_until(client, b"\r\n\r\n")
        if not response.startswith(b"HTTP/1.1 200 Connection Established\r\n"):
            raise RuntimeError(f"CONNECT to {authority} failed: {response!r}")
        client.sendall(b"PING\r\n")
        if recv_until(client, b"PONG\r\n") != b"PONG\r\n":
            raise RuntimeError(f"tunnel response mismatch for {authority}")

    if not origin.finished.wait(5):
        raise RuntimeError(f"origin {authority} did not finish")
    if origin.error:
        raise origin.error
    if origin.request != b"PING\r\n":
        raise RuntimeError(f"unexpected tunneled request for {authority}: {origin.request!r}")


def check_fragmented_connect(listener_port):
    origin = EchoOrigin()
    origin.start()
    authority = f"127.0.0.1:{origin.port}"
    with socket.create_connection(("127.0.0.1", listener_port), timeout=10) as client:
        client.settimeout(15)
        for fragment in (
                f"CONNECT {authority} HTTP/1.1\r\n".encode(),
                f"Host: {authority}\r\n".encode(),
                b"X-Test: fragmented\r\n\r\n"):
            client.sendall(fragment)
        response = recv_until(client, b"\r\n\r\n")
        if not response.startswith(b"HTTP/1.1 200 Connection Established\r\n"):
            raise RuntimeError(f"fragmented CONNECT failed: {response!r}")
        client.sendall(b"PING\r\n")
        if recv_until(client, b"PONG\r\n") != b"PONG\r\n":
            raise RuntimeError("fragmented CONNECT tunnel response mismatch")

    if not origin.finished.wait(5):
        raise RuntimeError("fragmented CONNECT origin did not finish")
    if origin.error:
        raise origin.error


def run(args):
    executable = args.smithproxy.resolve()
    worktree = args.source.resolve()
    with tempfile.TemporaryDirectory(prefix="smithproxy-http-connect-") as temp:
        runtime = pathlib.Path(temp)
        config = runtime / "smithproxy.cfg"
        listener_port = free_port()
        make_config(worktree / "etc/smithproxy.cfg", config, worktree, runtime,
                    listener_port, free_port())

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
            check_plain_tunnel(listener_port, "127.0.0.1", EchoOrigin())
            check_plain_tunnel(listener_port, "localtest.me", EchoOrigin())
            check_fragmented_connect(listener_port)

            try:
                check_plain_tunnel(
                    listener_port, "::1", EchoOrigin(socket.AF_INET6))
                check_plain_tunnel(
                    listener_port, "ipv6.localtest.me", EchoOrigin(socket.AF_INET6))
            except OSError as exc:
                if exc.errno not in (97, 99):
                    raise
                print(f"IPv6 loopback unavailable, skipping IPv6 tunnels: {exc}")

            tls_origin = TlsEchoOrigin(
                worktree / "etc/certs/default/srv-cert.pem",
                worktree / "etc/certs/default/srv-key.pem")
            tls_origin.start()
            with socket.create_connection(("127.0.0.1", listener_port), timeout=10) as client:
                client.settimeout(15)
                client.sendall((
                    f"CONNECT 127.0.0.1:{tls_origin.port} HTTP/1.1\r\n"
                    f"Host: 127.0.0.1:{tls_origin.port}\r\n\r\n").encode())
                response = recv_until(client, b"\r\n\r\n")
                if not response.startswith(b"HTTP/1.1 200 Connection Established\r\n"):
                    raise RuntimeError(f"TLS CONNECT failed: {response!r}")

                client_context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
                client_context.check_hostname = False
                client_context.verify_mode = ssl.CERT_NONE
                with client_context.wrap_socket(
                        client, server_hostname="localhost") as tls_client:
                    tls_client.sendall(b"TLS-PING\r\n")
                    if recv_until(tls_client, b"TLS-PONG\r\n") != b"TLS-PONG\r\n":
                        raise RuntimeError("TLS tunnel response mismatch")

            if not tls_origin.finished.wait(5):
                raise RuntimeError("TLS origin did not finish")
            if tls_origin.error:
                raise tls_origin.error
            if tls_origin.request != b"TLS-PING\r\n":
                raise RuntimeError(
                    f"unexpected TLS tunneled request: {tls_origin.request!r}")

            with socket.create_connection(("127.0.0.1", listener_port), timeout=10) as client:
                client.sendall(b"GET / HTTP/1.1\r\nHost: localhost\r\n\r\n")
                response = recv_until(client, b"\r\n\r\n")
                if not response.startswith(b"HTTP/1.1 400 Bad Request\r\n"):
                    raise RuntimeError(f"malformed request was accepted: {response!r}")

            with socket.create_connection(("127.0.0.1", listener_port), timeout=10) as client:
                client.settimeout(15)
                client.sendall(
                    b"CONNECT example.test:443 HTTP/1.1\r\nX-Oversized: "
                    + b"x" * (16 * 1024))
                response = recv_until(client, b"\r\n\r\n")
                if not response.startswith(
                        b"HTTP/1.1 431 Request Header Fields Too Large\r\n"):
                    raise RuntimeError(
                        f"oversized header did not return 431: {response!r}")

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

        reject_config = runtime / "smithproxy-reject.cfg"
        reject_listener_port = free_port()
        make_config(worktree / "etc/smithproxy.cfg", reject_config, worktree, runtime,
                    reject_listener_port, free_port(), reject_tcp=True)
        reject_process = subprocess.Popen(
            [str(executable), "--config-file", str(reject_config), "--debug"],
            cwd=worktree,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
        )
        try:
            wait_for_listener(reject_process, reject_listener_port)
            with socket.create_connection(
                    ("127.0.0.1", reject_listener_port), timeout=10) as client:
                client.settimeout(15)
                client.sendall(
                    b"CONNECT 127.0.0.1:443 HTTP/1.1\r\n"
                    b"Host: 127.0.0.1:443\r\n\r\n")
                response = recv_until(client, b"\r\n\r\n")
                if not response.startswith(b"HTTP/1.1 403 Forbidden\r\n"):
                    raise RuntimeError(
                        f"rejected policy did not return 403: {response!r}")
        finally:
            reject_process.terminate()
            try:
                reject_output, _ = reject_process.communicate(timeout=10)
            except subprocess.TimeoutExpired:
                reject_process.kill()
                reject_output, _ = reject_process.communicate(timeout=5)
            if sys.exc_info()[0] is not None:
                print(reject_output, file=sys.stderr)
                for log_file in runtime.glob("messages.*.log"):
                    print(log_file.read_text(errors="replace"), file=sys.stderr)

    print("HTTP CONNECT listener integration: PASS")


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--smithproxy", type=pathlib.Path, required=True)
    parser.add_argument("--source", type=pathlib.Path,
                        default=pathlib.Path(__file__).resolve().parents[2])
    run(parser.parse_args())
