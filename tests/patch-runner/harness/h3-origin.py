#!/usr/bin/env python3
"""Minimal aioquic HTTP/3 origin used by the optional QUIC capture lab."""

import argparse
import asyncio

from aioquic.asyncio import QuicConnectionProtocol, serve
from aioquic.h3.connection import H3_ALPN, H3Connection
from aioquic.h3.events import HeadersReceived
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


async def run(arguments: argparse.Namespace) -> None:
    configuration = QuicConfiguration(
        is_client=False,
        alpn_protocols=H3_ALPN,
    )
    configuration.load_cert_chain(arguments.certificate, arguments.key)
    server = await serve(
        arguments.host,
        arguments.port,
        configuration=configuration,
        create_protocol=Http3OriginProtocol,
    )
    print(f"READY h3-origin {arguments.host}:{arguments.port}", flush=True)
    try:
        await asyncio.Future()
    finally:
        server.close()


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--host", default="198.18.20.2")
    parser.add_argument("--port", type=int, default=443)
    parser.add_argument("--certificate", required=True)
    parser.add_argument("--key", required=True)
    asyncio.run(run(parser.parse_args()))


if __name__ == "__main__":
    main()
