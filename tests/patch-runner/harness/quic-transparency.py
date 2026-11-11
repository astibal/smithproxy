#!/usr/bin/env python3
"""Regress transparent QUIC addressing across receiver/worker handoffs.

Use real namespaces and wire captures. One client socket targets two servers;
another targets the first server concurrently. Reuse both client ports in a
second wave, rotate CIDs, and verify origin identity and every UDP wire tuple.
"""

import argparse
import asyncio
import collections
import contextlib
import ipaddress
import json
import os
from pathlib import Path
import pwd
import re
import shutil
import signal
import socket
import subprocess
import sys
import tempfile
import time

from aioquic.asyncio import QuicConnectionProtocol
from aioquic.h3.connection import H3Connection
from aioquic.h3.events import DataReceived, HeadersReceived
from aioquic.quic.configuration import QuicConfiguration
from aioquic.quic.connection import QuicConnection
from aioquic.quic.events import ConnectionTerminated


class Client(QuicConnectionProtocol):
    """Check stream identity as well as the actual origin that answered it."""

    def __init__(self, connection, identity):
        super().__init__(connection)
        self.http = H3Connection(connection)
        self.identity = identity
        self.requests = {}

    def quic_event_received(self, event):
        if isinstance(event, ConnectionTerminated):
            for pending, _, _ in self.requests.values():
                if not pending.done():
                    pending.set_exception(ConnectionError(event.reason_phrase))
        for item in self.http.handle_event(event):
            if not isinstance(item, (HeadersReceived, DataReceived)):
                continue
            pending, headers, body = self.requests[item.stream_id]
            if isinstance(item, HeadersReceived):
                headers.update(item.headers)
            else:
                body.extend(item.data)
            if item.stream_ended and not pending.done():
                pending.set_result((headers, bytes(body)))

    async def request(self, path):
        """Return only after the response matches this stream and destination."""
        stream = self._quic.get_next_available_stream_id()
        pending = asyncio.get_running_loop().create_future()
        self.requests[stream] = (pending, {}, bytearray())
        self.http.send_headers(stream, [
            (b":method", b"GET"), (b":scheme", b"https"),
            (b":authority", b"origin.runner.lab"), (b":path", path.encode()),
        ], end_stream=True)
        self.transmit()
        headers, body = await pending
        assert headers[b":status"] == b"200", headers
        assert headers[b"x-origin-address"].decode() == self.identity, headers
        assert body == f"smithproxy-h3-origin path={path}\n".encode(), body


class SharedSocket(asyncio.DatagramProtocol):
    """Demultiplex distinct remote tuples without changing the client's port."""

    def __init__(self):
        self.clients = {}
        self.unexpected = []

    def datagram_received(self, data, address):
        key = (str(ipaddress.ip_address(address[0])), address[1])
        client = self.clients.get(key)
        if client is None:
            self.unexpected.append(key)
        else:
            client.datagram_received(data, address)


async def client_wave(args, family, wave):
    """Exercise concurrent sessions, CID rotation and exact port reuse."""
    hosts = ("198.18.20.2", "198.18.20.3") if family == 4 else ("fd00:20::2", "fd00:20::3")
    local = "198.18.10.2" if family == 4 else "fd00:10::2"
    transports, muxes, clients = [], [], []
    try:
        for port, targets in ((41001, hosts), (41002, hosts[:1])):
            mux = SharedSocket()
            transport, _ = await asyncio.get_running_loop().create_datagram_endpoint(
                lambda: mux, local_addr=(local, port),
                family=socket.AF_INET if family == 4 else socket.AF_INET6)
            transports.append(transport)
            muxes.append(mux)
            for host in targets:
                config = QuicConfiguration(is_client=True, alpn_protocols=["h3"],
                                           server_name="origin.runner.lab")
                config.load_verify_locations(cafile=str(args.root / "config/certs/ca-cert.pem"))
                client = Client(QuicConnection(configuration=config), f"{host}:443")
                mux.clients[(host, 443)] = client
                client.connection_made(transport)
                client.connect((host, 443) if family == 4 else (host, 443, 0, 0))
                clients.append(client)
        await asyncio.gather(*(client.wait_connected() for client in clients))
        for round_number in range(2):
            if round_number:
                for client in clients:
                    client.change_connection_id()
            await asyncio.gather(*(
                client.request(f"/transparent/{family}/{wave}/{index}/{round_number}/{stream}")
                for index, client in enumerate(clients) for stream in range(3)))
        assert not any(mux.unexpected for mux in muxes), [mux.unexpected for mux in muxes]
    finally:
        for client in clients:
            client.close()
        try:
            if clients:
                await asyncio.wait_for(asyncio.gather(*(c.wait_closed() for c in clients)), 5)
        finally:
            for transport in transports:
                transport.close()
        # Let asyncio release the socket before the next wave binds it again.
        await asyncio.sleep(0)


async def run_clients(args):
    for family in (4, 6):
        for wave in range(2):
            await asyncio.wait_for(client_wave(args, family, wave), 20)
        print(f"PASS{family} QUIC transparent clients: shared source port, concurrent sessions, CID rotation and tuple reuse", flush=True)


def namespace(namespace, *command, **kwargs):
    """Execute only within the disposable harness namespace."""
    return subprocess.run(["ip", "netns", "exec", namespace, *map(str, command)],
                          check=True, **kwargs)


@contextlib.contextmanager
def background(command, log, capture=False):
    """Always stop and reap a test origin or capture, including on assertion failure."""
    with log.open("w") as output:
        process = subprocess.Popen(list(map(str, command)), stdout=output, stderr=output)
        try:
            deadline = time.monotonic() + 5
            marker = "listening on" if capture else "READY h3-origin"
            while marker not in log.read_text():
                if process.poll() is not None or time.monotonic() > deadline:
                    raise RuntimeError(log.read_text())
                time.sleep(.05)
            yield
        finally:
            if process.poll() is None:
                process.send_signal(signal.SIGINT if capture else signal.SIGTERM)
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait()


def wire_tuples(capture):
    """Read network headers only; successful decryption cannot hide a bad tuple."""
    fields = ("ip.src", "ipv6.src", "udp.srcport", "ip.dst", "ipv6.dst", "udp.dstport")
    # The lab directories may be root-only; tshark drops privileges. Decode a
    # disposable readable copy under an isolated profile, as the capture suite does.
    with tempfile.TemporaryDirectory(prefix="quic-wire-") as temporary:
        staging = Path(temporary)
        staging.chmod(0o755)
        staged = staging / "wire.pcap"
        shutil.copyfile(capture, staged)
        staged.chmod(0o644)
        command = ["tshark", "-o", "tls.keylog_file:", "-r", str(staged),
                   "-Y", "udp", "-T", "fields"]
        for field in fields:
            command += ["-e", field]
        if os.geteuid() == 0:
            account = pwd.getpwnam("nobody")
            os.chown(staging, account.pw_uid, account.pw_gid)
            os.chown(staged, account.pw_uid, account.pw_gid)
            command = ["runuser", "-u", "nobody", "--", "env", f"HOME={staging}"] + command
        result = subprocess.run(command, text=True, capture_output=True)
        if result.returncode:
            raise RuntimeError(result.stderr)
    packets = []
    for line in result.stdout.splitlines():
        src4, src6, sport, dst4, dst6, dport = line.split("\t")
        packets.append((str(ipaddress.ip_address(src4 or src6)), int(sport),
                        str(ipaddress.ip_address(dst4 or dst6)), int(dport)))
    assert packets, f"empty capture: {capture}"
    return packets


def verify_wire(result):
    """Check both mirrored downstream tuples and separately terminated upstreams."""
    downstream = wire_tuples(result / "downstream.pcap")
    upstream = wire_tuples(result / "upstream.pcap")
    report = {}
    for family in (4, 6):
        client, proxy, first, second = (("198.18.10.2", "198.18.20.1", "198.18.20.2", "198.18.20.3")
                                      if family == 4 else ("fd00:10::2", "fd00:20::1", "fd00:20::2", "fd00:20::3"))
        expected = {(client, 41001, first, 443), (client, 41001, second, 443),
                    (client, 41002, first, 443)}
        reverse = {(d, dp, s, sp) for s, sp, d, dp in expected}
        observed = {row for row in downstream if client in (row[0], row[2])}
        assert observed == expected | reverse, (family, "downstream tuples", observed)
        uplink = {row for row in upstream if row[0] == proxy}
        replies = {row for row in upstream if row[2] == proxy}
        assert all(sport > 0 and dst in (first, second) and dport == 443
                   for src, sport, dst, dport in uplink), uplink
        assert replies == {(d, dp, s, sp) for s, sp, d, dp in uplink}, replies
        # There are three downstream connections per wave. An extra certificate
        # probe would create more upstream tuples, violating the A/B contract.
        counts = collections.Counter(dst for _, _, dst, _ in uplink)
        assert counts == {first: 4, second: 2}, (family, "upstream connection count", counts)
        report[str(family)] = {"downstream": sorted(observed), "upstream": sorted(uplink),
                               "upstream_replies": sorted(replies)}
        print(f"PASS{family} QUIC wire: exact original reply IP:port, isolated destinations, six A/B connections", flush=True)
    (result / "wire-tuples.json").write_text(json.dumps(report, indent=2) + "\n")


def read_cli():
    """Collect the worker counters from inside the proxy namespace."""
    with socket.create_connection(("127.0.0.1", 50000), timeout=5) as connection:
        connection.sendall(b"enable\r\ndiag proxy quic list\r\nquit\r\n")
        while data := connection.recv(65536):
            sys.stdout.buffer.write(data)


def run_lab(args):
    """Keep aliases, subprocesses and captures scoped to this single lab check."""
    result = args.root / "results/quic-transparency"
    result.mkdir(exist_ok=True)
    script = Path(__file__).resolve()
    with contextlib.ExitStack() as resources:
        for family, address in ((4, "198.18.20.3/24"), (6, "fd00:20::3/64")):
            existing = subprocess.check_output(["ip", "-n", args.server_ns, f"-{family}", "addr", "show", "dev", "eth0"], text=True)
            if address in existing:
                continue
            command = ["ip", "-n", args.server_ns, f"-{family}", "addr"]
            subprocess.run(command + ["add", address, "dev", "eth0"] + (["nodad"] if family == 6 else []), check=True)
            resources.callback(subprocess.run, command + ["del", address, "dev", "eth0"], check=True)
        resources.enter_context(background([
            "ip", "netns", "exec", args.server_ns, "python3", "-u", script.with_name("h3-origin.py"),
            "--host", "198.18.20.3", "--host6", "fd00:20::3",
            "--certificate", args.root / "config/certs/origin-cert.pem",
            "--key", args.root / "config/certs/origin-key.pem"], result / "origin.log"))
        with contextlib.ExitStack() as captures:
            for side, interface in (("downstream", args.in_if), ("upstream", args.out_if)):
                captures.enter_context(background([
                    "ip", "netns", "exec", args.data_ns, "tcpdump", "--immediate-mode",
                    "-i", interface, "-U", "-s", "0", "-w", result / f"{side}.pcap", "udp port 443"],
                    result / f"{side}-tcpdump.log", capture=True))
            namespace(args.client_ns, "python3", script, "client", "--root", args.root, timeout=90)
        verify_wire(result)
        def snapshot():
            return namespace(args.data_ns, "python3", script, "cli", capture_output=True).stdout.decode(errors="replace")

        counters = snapshot()
        (result / "workers.txt").write_text(counters)
        workers = int(os.environ.get("QUIC_WORKERS", "1"))
        entries = re.findall(r"QUIC listener\[\d+\]: udp/(.*?):\d+, sessions: \d+, accepted: (\d+).*?worker: (\d+)/(\d+), receiver queue drops: (\d+)", counters, re.S)
        assert len(entries) == 2 * workers, counters
        for family in ("0.0.0.0", "[::]"):
            group = [(int(n), int(total), int(drops), int(accepted))
                     for address, accepted, n, total, drops in entries if address == family]
            assert len(group) == workers and {n for n, _, _, _ in group} == set(range(1, workers + 1)), group
            assert all(total == workers and drops == 0 for _, total, drops, _ in group), group
            assert sum(accepted > 0 for _, _, _, accepted in group) == min(2, workers), group
        print(f"PASS QUIC workers: {workers} per family, both destination owners active, no queue drops", flush=True)
        # Closing a client is not the end of the proxy's bounded drain grace.
        # Await retirement before lab shutdown, so stop webhooks can be sent by
        # the live dispatcher rather than stranded in its shutdown queue.
        deadline = time.monotonic() + 12
        while True:
            counts = re.findall(r"sessions: (\d+), accepted: (\d+), completed: (\d+)", counters)
            if len(counts) == 2 * workers and all(int(n) == 0 and a == c for n, a, c in counts):
                break
            assert time.monotonic() < deadline, ("workers failed to retire sessions", counts)
            time.sleep(.1)
            counters = snapshot()
        (result / "workers-retired.txt").write_text(counters)
        print("PASS QUIC worker lifecycle: every accepted session retired before shutdown", flush=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("operation", choices=("run", "client", "cli"))
    parser.add_argument("--root", type=Path)
    for option in ("client-ns", "server-ns", "data-ns", "in-if", "out-if"):
        parser.add_argument("--" + option)
    args = parser.parse_args()
    if args.operation == "client":
        asyncio.run(run_clients(args))
    elif args.operation == "cli":
        read_cli()
    else:
        run_lab(args)


if __name__ == "__main__":
    main()
