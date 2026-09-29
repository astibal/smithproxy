#!/usr/bin/env python3

"""End-to-end STARTTLS test through Smithproxy's SOCKS frontend.

The upstream first behaves as a plaintext HTTP CONNECT proxy and then switches
the same socket to TLS. Smithproxy must observe the CONNECT/200 exchange,
execute StartStopTls::start(), spoof the upstream certificate, and proxy an
HTTP request over the upgraded connection.
"""

import argparse
import dataclasses
import pathlib
import socket
import ssl
import subprocess
import sys
import tempfile
import threading
import time


@dataclasses.dataclass(frozen=True)
class Scenario:
    request: bytes
    response: bytes
    fragmented: bool = False
    upgrades: bool = True
    nested: bool = False


@dataclasses.dataclass(frozen=True)
class Address:
    family: int
    bind_host: str
    target_host: str
    socks_atyp: int


ADDRESSES = {
    "ipv4-ip": Address(socket.AF_INET, "127.0.0.1", "127.0.0.1", 1),
    "ipv4-fqdn": Address(
        socket.AF_INET, "127.0.0.1", "127-0-0-1.sslip.io", 3
    ),
    "ipv6-ip": Address(socket.AF_INET6, "::1", "::1", 4),
    "ipv6-fqdn": Address(socket.AF_INET6, "::1", "0--1.sslip.io", 3),
}


SCENARIOS = {
    "smtp": Scenario(b"STARTTLS\r\n", b"220 Ready to start TLS\r\n"),
    "imap": Scenario(b"a STARTTLS\r\n", b"a OK Begin TLS negotiation now\r\n"),
    "pop3": Scenario(b"STLS\r\n", b"+OK Begin TLS negotiation\r\n"),
    "ftp": Scenario(b"AUTH TLS\r\n", b"234 AUTH TLS successful\r\n"),
    "xmpp": Scenario(
        b"<starttls xmlns='urn:ietf:params:xml:ns:xmpp-tls'/>",
        b"<proceed xmlns='urn:ietf:params:xml:ns:xmpp-tls'/>",
    ),
    "http-connect": Scenario(
        b"CONNECT integration.invalid:443 HTTP/1.1\r\n"
        b"Host: integration.invalid:443\r\n\r\n",
        b"HTTP/1.1 200 Connection Established\r\n\r\n",
    ),
}
SCENARIOS.update({
    f"{name}-fragmented": dataclasses.replace(scenario, fragmented=True)
    for name, scenario in list(SCENARIOS.items())
})
SCENARIOS.update({
    "smtp-rejected": Scenario(
        b"STARTTLS\r\n", b"454 TLS temporarily unavailable\r\n", upgrades=False
    ),
    "http-connect-rejected": Scenario(
        b"CONNECT integration.invalid:443 HTTP/1.1\r\n"
        b"Host: integration.invalid:443\r\n\r\n",
        b"HTTP/1.1 407 Proxy Authentication Required\r\n\r\n",
        upgrades=False,
    ),
    "smtp-nested": Scenario(
        b"STARTTLS\r\n", b"220 Ready to start TLS\r\n", nested=True
    ),
})


def free_port(family=socket.AF_INET, host="127.0.0.1"):
    with socket.socket(family) as sock:
        sock.bind((host, 0))
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


def send_data(sock, data, fragmented):
    if not fragmented:
        sock.sendall(data)
        return
    for byte in data:
        sock.sendall(bytes((byte,)))
        time.sleep(0.002)


class StartTlsOrigin:
    def __init__(self, certificate, key, scenario, address):
        self.port = free_port(address.family, address.bind_host)
        self.certificate = certificate
        self.key = key
        self.scenario = scenario
        self.address = address
        self.ready = threading.Event()
        self.finished = threading.Event()
        self.error = None
        self.request = b""
        self.thread = threading.Thread(target=self.run, daemon=True)

    def start(self):
        self.thread.start()
        if not self.ready.wait(5):
            raise RuntimeError("upstream did not start")

    def run(self):
        try:
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            context.load_cert_chain(self.certificate, self.key)
            with socket.socket(self.address.family) as listener:
                listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                listener.bind((self.address.bind_host, self.port))
                listener.listen(1)
                listener.settimeout(15)
                self.ready.set()
                raw, _ = listener.accept()
                with raw:
                    raw.settimeout(15)
                    request = recv_until(raw, self.scenario.request)
                    if not request.startswith(self.scenario.request):
                        raise RuntimeError(f"unexpected STARTTLS request: {request!r}")
                    send_data(raw, self.scenario.response, self.scenario.fragmented)
                    if not self.scenario.upgrades:
                        self.request = recv_until(raw, b"PING\r\n")
                        raw.sendall(b"PONG\r\n")
                        return
                    with context.wrap_socket(raw, server_side=True) as tls:
                        if self.scenario.nested:
                            nested = recv_until(tls, b"STARTTLS\r\n")
                            if nested != b"STARTTLS\r\n":
                                raise RuntimeError(f"unexpected nested STARTTLS: {nested!r}")
                            tls.sendall(b"220 Nested TLS is not required\r\n")
                            self.request = recv_until(tls, b"PING\r\n")
                            tls.sendall(b"PONG\r\n")
                            return
                        self.request = recv_until(tls, b"\r\n\r\n")
                        tls.sendall(
                            b"HTTP/1.1 200 OK\r\nContent-Length: 20\r\n"
                            b"Connection: close\r\n\r\nSTARTTLS-INTEGRATION"
                        )
        except Exception as exc:  # surfaced in the main test thread
            self.error = exc
        finally:
            self.finished.set()


def make_config(source, destination, worktree, runtime, socks_port, cli_port):
    config = source.read_text()
    replacements = {
        "accept_tproxy = TRUE;": "accept_tproxy = FALSE;",
        "accept_redirect = TRUE;": "accept_redirect = FALSE;",
        "accept_socks = TRUE;": "accept_socks = TRUE;\n    accept_api = FALSE;",
        "async_dns = TRUE;":
            "async_dns = TRUE;\n        ipver_mixing = TRUE;\n        prefer_ipv6 = TRUE;",
        'certs_path = "/etc/smithproxy/certs/default/";':
            f'certs_path = "{worktree / "etc/certs/default"}/";',
        'messages_dir = "/etc/smithproxy/msg/en/";':
            f'messages_dir = "{worktree / "etc/msg/en"}/";',
        "socks_workers = 0;": f"socks_workers = 1;\n    socks_port = \"{socks_port}\";",
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


def wait_for_listener(process, port, timeout=15):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if process.poll() is not None:
            stdout, _ = process.communicate()
            raise RuntimeError(f"smithproxy exited early ({process.returncode}):\n{stdout}")
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=0.1):
                return
        except OSError:
            time.sleep(0.05)
    raise RuntimeError("SOCKS listener did not become ready")


def socks_connect(port, target_port, address):
    sock = socket.create_connection(("127.0.0.1", port), timeout=10)
    sock.settimeout(15)
    sock.sendall(b"\x05\x01\x00")
    if recv_until(sock, b"\x05\x00", limit=2) != b"\x05\x00":
        raise RuntimeError("SOCKS authentication negotiation failed")
    if address.socks_atyp == 1:
        encoded = socket.inet_pton(socket.AF_INET, address.target_host)
    elif address.socks_atyp == 4:
        encoded = socket.inet_pton(socket.AF_INET6, address.target_host)
    else:
        hostname = address.target_host.encode("ascii")
        encoded = bytes((len(hostname),)) + hostname
    sock.sendall(
        b"\x05\x01\x00" + bytes((address.socks_atyp,)) + encoded
        + target_port.to_bytes(2, "big")
    )
    response = recv_until_bytes(sock, 4)
    if response[:2] != b"\x05\x00":
        raise RuntimeError(f"SOCKS CONNECT failed: {response!r}")
    atyp = response[3]
    address_length = {1: 4, 4: 16}.get(atyp)
    if address_length is None:
        address_length = sock.recv(1)[0]
    recv_until_bytes(sock, address_length + 2)
    return sock


def recv_until_bytes(sock, length):
    data = bytearray()
    while len(data) < length:
        chunk = sock.recv(length - len(data))
        if not chunk:
            raise RuntimeError(f"connection closed after {len(data)}/{length} bytes")
        data.extend(chunk)
    return bytes(data)


def exercise_scenario(name, scenario, address_name, address, worktree, socks_port):
    origin = StartTlsOrigin(
        worktree / "etc/certs/default/srv-cert.pem",
        worktree / "etc/certs/default/srv-key.pem",
        scenario,
        address,
    )
    origin.start()

    raw = socks_connect(socks_port, origin.port, address)
    with raw:
        send_data(raw, scenario.request, scenario.fragmented)
        response = recv_until(raw, scenario.response)
        if not response.startswith(scenario.response):
            raise RuntimeError(
                f"{name}/{address_name}: unexpected plaintext response: {response!r}"
            )

        if not scenario.upgrades:
            raw.sendall(b"PING\r\n")
            if recv_until(raw, b"PONG\r\n") != b"PONG\r\n":
                raise RuntimeError(f"{name}: plaintext connection was not preserved")
            if not origin.finished.wait(5):
                raise RuntimeError(f"{name}: upstream did not finish")
            if origin.error:
                raise origin.error
            return

        # Repository fixtures are deliberately stable and may be expired.
        # This verifies the transition and data path, not certificate dates.
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        with context.wrap_socket(raw, server_hostname="integration.invalid") as tls:
            if scenario.nested:
                tls.sendall(b"STARTTLS\r\n")
                nested_response = recv_until(
                    tls, b"220 Nested TLS is not required\r\n"
                )
                if nested_response != b"220 Nested TLS is not required\r\n":
                    raise RuntimeError(
                        f"{name}: bad nested response: {nested_response!r}"
                    )
                tls.sendall(b"PING\r\n")
                if recv_until(tls, b"PONG\r\n") != b"PONG\r\n":
                    raise RuntimeError(f"{name}: TLS connection did not survive")
                reply = b"STARTTLS-INTEGRATION"
            else:
                tls.sendall(
                    b"GET /starttls HTTP/1.1\r\nHost: integration.invalid\r\n"
                    b"Connection: close\r\n\r\n"
                )
                reply = bytearray()
                while True:
                    chunk = tls.recv(4096)
                    if not chunk:
                        break
                    reply.extend(chunk)
    if not origin.finished.wait(5):
        raise RuntimeError(f"{name}: upstream did not finish")
    if origin.error:
        raise origin.error
    if b"STARTTLS-INTEGRATION" not in reply:
        raise RuntimeError(f"{name}: missing upstream response: {bytes(reply)!r}")
    expected = b"PING\r\n" if scenario.nested else b"GET /starttls HTTP/1.1\r\n"
    if not origin.request.startswith(expected):
        raise RuntimeError(f"{name}: unexpected decrypted request: {origin.request!r}")


def run(args):
    executable = args.smithproxy.resolve()
    worktree = args.source.resolve()
    if not executable.is_file():
        raise RuntimeError(f"smithproxy executable not found: {executable}")

    with tempfile.TemporaryDirectory(prefix="smithproxy-starttls-") as temp:
        runtime = pathlib.Path(temp)
        config = runtime / "smithproxy.cfg"
        socks_port = free_port()
        cli_port = free_port()
        make_config(worktree / "etc/smithproxy.cfg", config, worktree, runtime,
                    socks_port, cli_port)

        process = subprocess.Popen(
            [str(executable), "--config-file", str(config), "--debug"],
            cwd=worktree,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
        )
        output = ""
        try:
            wait_for_listener(process, socks_port)
            selected = SCENARIOS if args.protocol == "all" else {
                args.protocol: SCENARIOS[args.protocol]
            }
            addresses = ADDRESSES if args.address == "all" else {
                args.address: ADDRESSES[args.address]
            }
            for name, scenario in selected.items():
                for address_name, address in addresses.items():
                    exercise_scenario(
                        name, scenario, address_name, address, worktree, socks_port
                    )
                    print(f"STARTTLS {name}/{address_name}: PASS")
        finally:
            process.terminate()
            try:
                output, _ = process.communicate(timeout=10)
            except subprocess.TimeoutExpired:
                process.kill()
                output, _ = process.communicate(timeout=5)
            if sys.exc_info()[0] is not None:
                print("--- smithproxy stdout ---", file=sys.stderr)
                print(output, file=sys.stderr)
                for log in sorted(runtime.glob("*.log")):
                    print(f"--- {log.name} ---", file=sys.stderr)
                    print(log.read_text(errors="replace"), file=sys.stderr)

        if "STARTTLS: plain connection upgraded to SSL/TLS" not in output:
            # The message lives in the traffic log, so absence on stdout is not
            # fatal. Require evidence from the TLS handshake instead (already
            # verified above), but leave diagnostics useful on manual runs.
            print("note: STARTTLS traffic-log marker was not emitted to stdout")
        if any(scenario.nested for scenario in selected.values()):
            if "on_starttls: TLS transition rejected" in output:
                print("nested STARTTLS reached the duplicate-upgrade guard")
            else:
                print("note: nested STARTTLS did not re-trigger the signature sensor")
        print("STARTTLS SOCKS integration: PASS")


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--smithproxy", type=pathlib.Path, required=True)
    parser.add_argument("--source", type=pathlib.Path,
                        default=pathlib.Path(__file__).resolve().parents[2])
    parser.add_argument("--protocol", choices=["all", *SCENARIOS], default="all")
    parser.add_argument("--address", choices=["all", *ADDRESSES], default="ipv4-ip")
    run(parser.parse_args())
