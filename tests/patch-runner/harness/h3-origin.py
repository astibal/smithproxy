#!/usr/bin/env python3
"""Minimal aioquic HTTP/3 origin used by the optional QUIC capture lab."""

import argparse
import asyncio
import hashlib
import functools

from aioquic.asyncio import QuicConnectionProtocol, serve
from aioquic.h3.connection import H3_ALPN, H3Connection
from aioquic.h3.events import HeadersReceived, DataReceived
from aioquic.quic.configuration import QuicConfiguration
from aioquic.quic.events import ProtocolNegotiated, QuicEvent


class Http3OriginProtocol(QuicConnectionProtocol):
    """Answer every request with deterministic headers and a short body."""

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.http = None
        self.responded = set()

    def quic_event_received(self, event: QuicEvent) -> None:
        if isinstance(event, ProtocolNegotiated):
            self.http = H3Connection(self._quic)

        if self.http is None:
            return
        for http_event in self.http.handle_event(event):
            if not isinstance(http_event, HeadersReceived):
                continue
            if http_event.stream_id in self.responded:
                continue
            self.responded.add(http_event.stream_id)

            printable = " ".join(
                f"{name.decode(errors='replace')}={value.decode(errors='replace')}"
                for name, value in http_event.headers
            )
            print(f"REQUEST stream={http_event.stream_id} {printable}", flush=True)
            headers = dict(http_event.headers)
            path = headers.get(b":path", b"/")
            body = b"smithproxy-h3-origin path=" + path + b"\n"
            if path.startswith(b"/hold"):
                # A throttled client keeps this stream/session observable while
                # the runner takes CLI and packet-capture snapshots.
                body += b"H" * (64 * 1024)
            self.http.send_headers(
                stream_id=http_event.stream_id,
                headers=[
                    (b":status", b"200"),
                    (b"server", b"smithproxy-aioquic-test"),
                    (b"content-type", b"text/plain"),
                    (b"content-length", str(len(body)).encode()),
                    (b"x-smithproxy-h3", b"decoded"),
                ],
            )
            self.http.send_data(
                stream_id=http_event.stream_id, data=body, end_stream=True)
            self.transmit()


@functools.lru_cache(maxsize=16)
def zero_digest(size):
    digest = hashlib.sha256()
    while size:
        count = min(size, 65536)
        digest.update(bytes(count))
        size -= count
    return digest.digest()


class BulkOriginProtocol(QuicConnectionProtocol):
    """Benchmark origin with bounded send queues and checked upload payloads."""
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.http = None
        self.downloads = {}
        self.uploads = {}

    def reply(self, stream, status, size=0):
        self.http.send_headers(stream, [(b":status", str(status).encode()),
                                       (b"content-length", str(size).encode())],
                               end_stream=size == 0)

    def quic_event_received(self, event):
        if isinstance(event, ProtocolNegotiated):
            self.http = H3Connection(self._quic)
        if self.http is None:
            return
        for item in self.http.handle_event(event):
            if isinstance(item, HeadersReceived):
                headers = dict(item.headers)
                try:
                    path = headers[b":path"].split(b"?", 1)[0]
                    if not path.startswith(b"/bulk/"):
                        raise ValueError("not a bulk request")
                    size = int(path[6:])
                    if not 0 < size <= 1024 ** 3:
                        raise ValueError("invalid size")
                except (ValueError, KeyError):
                    self.reply(item.stream_id, 400)
                    continue
                if headers.get(b":method") == b"POST":
                    self.uploads[item.stream_id] = [size, 0, hashlib.sha256()]
                    if item.stream_ended:
                        self.finish_upload(item.stream_id)
                elif headers.get(b":method") == b"GET":
                    self.reply(item.stream_id, 200, size)
                    self.downloads[item.stream_id] = size
                else:
                    self.reply(item.stream_id, 405)
            elif isinstance(item, DataReceived) and item.stream_id in self.uploads:
                state = self.uploads[item.stream_id]
                state[1] += len(item.data)
                state[2].update(item.data)
                if item.stream_ended:
                    self.finish_upload(item.stream_id)

    def finish_upload(self, stream):
        expected, received, digest = self.uploads.pop(stream)
        valid = received == expected and digest.digest() == zero_digest(expected)
        self.reply(stream, 200 if valid else 400)

    def datagram_received(self, data, addr):
        super().datagram_received(data, addr)
        # aioquic has no public H3 drain API. This test-runtime adapter bounds
        # unacknowledged application data; ACK reception refills it without a
        # pacing sleep. Keep the dependency explicit so API changes fail loudly.
        for stream, remaining in list(self.downloads.items()):
            sender = self._quic._streams[stream].sender
            if sender.is_finished:
                del self.downloads[stream]
                continue
            while remaining and len(sender._buffer) < 256 * 1024:
                # Reserve room for the H3 DATA frame header as well.
                available = 256 * 1024 - len(sender._buffer) - 16
                if available <= 0:
                    break
                count = min(remaining, 64 * 1024, available)
                remaining -= count
                self.http.send_data(stream, bytes(count), end_stream=remaining == 0)
            if remaining:
                self.downloads[stream] = remaining
            else:
                del self.downloads[stream]
        self.transmit()


async def run(arguments: argparse.Namespace) -> None:
    configuration = QuicConfiguration(
        is_client=False,
        alpn_protocols=H3_ALPN,
    )
    configuration.load_cert_chain(arguments.certificate, arguments.key)
    servers = []
    try:
        for host in (arguments.host, arguments.host6):
            if not host:
                continue
            servers.append(await serve(host, arguments.port, configuration=configuration,
                                       create_protocol=BulkOriginProtocol if arguments.bulk else Http3OriginProtocol))
        print(f"READY h3-origin {arguments.host}:{arguments.port} ipv6={arguments.host6}", flush=True)
        await asyncio.Future()
    finally:
        for server in servers:
            server.close()


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--bulk", action="store_true")
    parser.add_argument("--host", default="198.18.20.2")
    parser.add_argument("--host6")
    parser.add_argument("--port", type=int, default=443)
    parser.add_argument("--certificate", required=True)
    parser.add_argument("--key", required=True)
    asyncio.run(run(parser.parse_args()))


if __name__ == "__main__":
    main()
