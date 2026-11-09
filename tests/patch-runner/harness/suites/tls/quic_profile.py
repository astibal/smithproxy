#!/usr/bin/env python3
"""Check TLS profile enforcement on real HTTP/3 connections."""

import argparse
import asyncio
import json
import socket
import sys
import time
from pathlib import Path

from aioquic.asyncio import QuicConnectionProtocol, connect
from aioquic.h3.connection import H3Connection
from aioquic.h3.events import DataReceived, HeadersReceived
from aioquic.quic.configuration import QuicConfiguration
from aioquic.quic.events import ConnectionTerminated, HandshakeCompleted


PROFILES = ("baseline", "no_reuse", "no_pfs", "no_alpn", "old_ticket")


def enable_diagnostics():
    """Enable the existing logger in the proxy namespace before probing."""
    with socket.create_connection(("127.0.0.1", 50000), timeout=5) as cli:
        cli.settimeout(.5)
        time.sleep(.1)
        cli.recv(65536)
        for command in ("enable", "debug set com.quic 6"):
            cli.sendall(command.encode() + b"\r\n")
            time.sleep(.1)
            response = cli.recv(65536)
            if command.startswith("debug set") and b"debug level:" not in response:
                raise AssertionError("cannot enable QUIC diagnostics")


class Client(QuicConnectionProtocol):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.http = H3Connection(self._quic)
        self.result = asyncio.get_running_loop().create_future()
        self.resumed = None
        self.status = None
        self.body = bytearray()
        self.termination = None

    def quic_event_received(self, event):
        if isinstance(event, HandshakeCompleted):
            self.resumed = event.session_resumed
        if isinstance(event, ConnectionTerminated) and not self.result.done():
            self.termination = {"code": event.error_code, "reason": event.reason_phrase}
            self.result.set_exception(ConnectionError(event.reason_phrase))

        for item in self.http.handle_event(event):
            if isinstance(item, HeadersReceived):
                self.status = dict(item.headers).get(b":status")
            if isinstance(item, DataReceived):
                self.body.extend(item.data)
            if isinstance(item, (HeadersReceived, DataReceived)) and item.stream_ended:
                if not self.result.done():
                    self.result.set_result(bytes(self.body))

    async def request(self):
        stream = self._quic.get_next_available_stream_id()
        self.http.send_headers(stream, [
            (b":method", b"GET"), (b":scheme", b"https"),
            (b":authority", b"origin.runner.lab"), (b":path", b"/tls-profile"),
        ], end_stream=True)
        self.transmit()
        return await self.result


async def measure(args):
    tickets, results = [], []
    marker = "QUIC TLS profile rejects target="
    for attempt in range(3):
        before = args.proxy_log.read_text().count(marker)
        config = QuicConfiguration(is_client=True, alpn_protocols=["h3"],
                                   server_name="origin.runner.lab")
        config.load_verify_locations(cafile=args.ca_file)
        if attempt and tickets:
            # Reuse the original permissive ticket for both policy probes.
            config.session_ticket = tickets[0] if args.profile == "old_ticket" else tickets[-1]
        local_port = 23450 + attempt if args.profile == "old_ticket" else 0
        result = {"attempt": attempt, "ticket_offered": config.session_ticket is not None}

        client = None
        try:
            async with asyncio.timeout(10):
                async with connect("198.18.20.2", 443, configuration=config,
                                   create_protocol=Client, session_ticket_handler=tickets.append,
                                   local_port=local_port, wait_connected=False) as client:
                    client.transmit()
                    await client.wait_connected()
                    body = await client.request()
                    if client.status != b"200" or b"path=/tls-profile" not in body:
                        raise ValueError("missing origin response")
                    result["resumed"] = client.resumed
                    result["body"] = body.decode()
                    await asyncio.sleep(.2)
        except (OSError, ValueError) as error:
            result["error"] = type(error).__name__
            if client is not None:
                result["resumed"] = client.resumed
                result["termination"] = client.termination
                if client.result.done() and not client.result.cancelled():
                    client.result.exception()

        result["policy_rejections"] = args.proxy_log.read_text().count(marker) - before
        results.append(result)
        args.output.write_text(json.dumps(results, indent=2) + "\n")

    if args.profile in ("no_pfs", "no_alpn"):
        # OpenSSL's early QUIC rejection may be silent on the wire. A timeout
        # alone is never success: require the matching server-side policy
        # rejection for every attempt, with no completed handshake or body.
        passed = all(item.get("error") in ("ConnectionError", "TimeoutError")
                     and item["policy_rejections"] > 0 and "body" not in item
                     and item.get("resumed") is None for item in results)
    else:
        expected = [False, False, False] if args.profile == "no_reuse" else [False, True, True]
        if args.profile == "old_ticket":
            expected = [False, False, True]
        passed = all("body" in item for item in results)
        passed = passed and [item.get("resumed") for item in results] == expected
    print(f"{'PASS' if passed else 'FAIL'} QUIC TLS profile {args.profile}: {results}", flush=True)
    return 0 if passed else 1


if __name__ == "__main__":
    if sys.argv[1:] == ["--enable-diagnostics"]:
        enable_diagnostics()
        raise SystemExit(0)
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--profile", choices=PROFILES, required=True)
    parser.add_argument("--ca-file", required=True)
    parser.add_argument("--proxy-log", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    raise SystemExit(asyncio.run(measure(parser.parse_args())))
