#!/usr/bin/env python3

"""SOCKS5 UDP ASSOCIATE end-to-end test with a dynamically assigned port."""

import argparse
import os
import pathlib
import socket
import subprocess
import sys
import tempfile
import threading


TLS_HELPERS = pathlib.Path(__file__).resolve().parents[1] / "tls"
sys.path.insert(0, str(TLS_HELPERS))
from starttls_socks_integration import free_port, make_config, recv_until_bytes, wait_for_listener


def free_tcp_udp_port():
    """Find a port currently available to both Smithproxy listeners."""
    for _ in range(100):
        with socket.socket(socket.AF_INET6, socket.SOCK_STREAM) as tcp:
            tcp.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            tcp.bind(("::", 0))
            port = tcp.getsockname()[1]
            with socket.socket(socket.AF_INET6, socket.SOCK_DGRAM) as udp:
                udp.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                try:
                    udp.bind(("::", port))
                except OSError:
                    continue
                return port
    raise RuntimeError("could not find a TCP+UDP test port")


class UdpEcho:
    def __init__(self):
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.socket.bind(("127.0.0.1", 0))
        self.port = self.socket.getsockname()[1]
        self.error = None
        self.done = threading.Event()
        self.thread = threading.Thread(target=self.run, daemon=True)

    def start(self):
        self.thread.start()

    def run(self):
        try:
            self.socket.settimeout(10)
            payload, peer = self.socket.recvfrom(65535)
            self.socket.sendto(b"echo:" + payload, peer)
        except Exception as exc:
            self.error = exc
        finally:
            self.done.set()
            self.socket.close()


def run(args):
    executable = args.smithproxy.resolve()
    source = args.source.resolve()
    with tempfile.TemporaryDirectory(prefix="smithproxy-socks5-udp-") as temp:
        runtime = pathlib.Path(temp)
        config = runtime / "smithproxy.cfg"
        socks_port = free_tcp_udp_port()
        cli_port = free_port()
        make_config(source / "etc/smithproxy.cfg", config, source, runtime,
                    socks_port, cli_port)
        # The STARTTLS helper selects source-preserving NAT for its TCP
        # scenario.  A non-privileged UDP relay test must use normal source
        # NAT; transparent source spoofing is covered by privileged lab tests.
        config.write_text(config.read_text().replace(
            'nat = "none";', 'nat = "auto";'))

        process = subprocess.Popen(
            [str(executable), "--config-file", str(config), "--diagnose"],
            cwd=source,
            env={**os.environ,
                 "SMITHPROXY_PID_FILE": str(runtime / "smithproxy.pid")},
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
        )
        output = ""
        try:
            wait_for_listener(process, socks_port)
            echo = UdpEcho()
            echo.start()

            udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            udp.bind(("127.0.0.1", 0))
            udp.settimeout(10)
            client_port = udp.getsockname()[1]

            with socket.create_connection(("127.0.0.1", socks_port), timeout=10) as control:
                control.settimeout(10)
                control.sendall(b"\x05\x01\x00")
                if recv_until_bytes(control, 2) != b"\x05\x00":
                    raise RuntimeError("SOCKS method negotiation failed")

                control.sendall(
                    b"\x05\x03\x00\x01" + socket.inet_aton("127.0.0.1")
                    + client_port.to_bytes(2, "big"))
                reply = recv_until_bytes(control, 10)
                if reply[:4] != b"\x05\x00\x00\x01":
                    raise RuntimeError(f"UDP ASSOCIATE failed: {reply!r}")
                relay_port = int.from_bytes(reply[8:10], "big")
                if relay_port != socks_port:
                    raise RuntimeError(
                        f"UDP relay returned port {relay_port}, expected {socks_port}")

                payload = b"smithproxy-socks5-udp"
                frame = (b"\x00\x00\x00\x01" + socket.inet_aton("127.0.0.1")
                         + echo.port.to_bytes(2, "big") + payload)
                udp.sendto(frame, ("127.0.0.1", relay_port))
                try:
                    response, _ = udp.recvfrom(65535)
                except socket.timeout as exc:
                    raise RuntimeError(
                        f"UDP relay response timed out; origin_done={echo.done.is_set()} "
                        f"origin_error={echo.error!r}") from exc
                if response[:4] != b"\x00\x00\x00\x01":
                    raise RuntimeError(f"bad UDP response header: {response!r}")
                if response[10:] != b"echo:" + payload:
                    raise RuntimeError(f"bad UDP response payload: {response!r}")

            udp.close()
            if not echo.done.wait(5):
                raise RuntimeError("UDP origin did not finish")
            if echo.error:
                raise echo.error
            print("SOCKS5 UDP ASSOCIATE: PASS")
        finally:
            process.terminate()
            try:
                output, _ = process.communicate(timeout=60)
            except subprocess.TimeoutExpired:
                process.kill()
                output, _ = process.communicate(timeout=5)
            if sys.exc_info()[0] is not None:
                print("--- smithproxy stdout ---", file=sys.stderr)
                print(output, file=sys.stderr)
                for log in sorted(runtime.glob("*.log")):
                    print(f"--- {log.name} ---", file=sys.stderr)
                    print(log.read_text(errors="replace"), file=sys.stderr)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--smithproxy", type=pathlib.Path, required=True)
    parser.add_argument("--source", type=pathlib.Path, default=pathlib.Path.cwd())
    run(parser.parse_args())


if __name__ == "__main__":
    main()
