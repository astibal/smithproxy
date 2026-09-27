#!/usr/bin/env python3
"""Exercise every configured STARTTLS signature through the transparent proxy."""
import argparse
import json
import socket
import ssl


CASES = (
    "smtp/starttls",
    "imap/starttls",
    "pop3/starttls",
    "ftp/starttls",
    "xmpp/starttls",
    "http-proxy/starttls",
)


def read_line(stream):
    value = stream.readline()
    if not value:
        raise RuntimeError("unexpected EOF")
    return value


def server_dialog(name, stream):
    if name == "smtp/starttls":
        stream.write(b"220 origin.runner.lab ESMTP ready\r\n")
        assert read_line(stream).startswith(b"EHLO ")
        stream.write(b"250-origin.runner.lab\r\n250 STARTTLS\r\n")
        assert read_line(stream) == b"STARTTLS\r\n"
        stream.write(b"220 Ready to start TLS\r\n")
    elif name == "imap/starttls":
        stream.write(b"* OK IMAP4rev1 ready\r\n")
        assert read_line(stream) == b"a001 STARTTLS\r\n"
        stream.write(b"a001 OK Begin TLS negotiation\r\n")
    elif name == "pop3/starttls":
        stream.write(b"+OK POP3 ready\r\n")
        assert read_line(stream) == b"STLS\r\n"
        stream.write(b"+OK Begin TLS negotiation\r\n")
    elif name == "ftp/starttls":
        stream.write(b"220 FTP ready\r\n")
        assert read_line(stream) == b"AUTH TLS\r\n"
        stream.write(b"234 AUTH TLS successful\r\n")
    elif name == "xmpp/starttls":
        assert read_line(stream) == b"<starttls xmlns='urn:ietf:params:xml:ns:xmpp-tls'/>\r\n"
        stream.write(b"<proceed xmlns='urn:ietf:params:xml:ns:xmpp-tls'/>\r\n")
    elif name == "http-proxy/starttls":
        assert read_line(stream) == b"CONNECT origin.runner.lab:443 HTTP/1.1\r\n"
        assert read_line(stream) == b"Host: origin.runner.lab:443\r\n"
        assert read_line(stream) == b"\r\n"
        stream.write(b"HTTP/1.1 200 Connection established\r\n\r\n")
    else:
        raise AssertionError(name)


def client_dialog(name, stream):
    if name == "smtp/starttls":
        assert read_line(stream).startswith(b"220 ")
        stream.write(b"EHLO client.runner.lab\r\n")
        assert read_line(stream).startswith(b"250-")
        assert read_line(stream) == b"250 STARTTLS\r\n"
        stream.write(b"STARTTLS\r\n")
        assert read_line(stream).startswith(b"220 ")
    elif name == "imap/starttls":
        assert read_line(stream).startswith(b"* OK ")
        stream.write(b"a001 STARTTLS\r\n")
        assert read_line(stream).startswith(b"a001 OK")
    elif name == "pop3/starttls":
        assert read_line(stream).startswith(b"+OK ")
        stream.write(b"STLS\r\n")
        assert read_line(stream).startswith(b"+OK ")
    elif name == "ftp/starttls":
        assert read_line(stream).startswith(b"220 ")
        stream.write(b"AUTH TLS\r\n")
        assert read_line(stream).startswith(b"234 AUTH")
    elif name == "xmpp/starttls":
        stream.write(b"<starttls xmlns='urn:ietf:params:xml:ns:xmpp-tls'/>\r\n")
        assert read_line(stream).startswith(b"<proceed ")
    elif name == "http-proxy/starttls":
        stream.write(
            b"CONNECT origin.runner.lab:443 HTTP/1.1\r\n"
            b"Host: origin.runner.lab:443\r\n\r\n"
        )
        assert read_line(stream).startswith(b"HTTP/1.1 200 ")
        assert read_line(stream) == b"\r\n"
    else:
        raise AssertionError(name)


def serve(args):
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(args.cert, args.key)
    results = []
    with socket.create_server((args.host, args.port), reuse_port=True) as listener:
        for name in CASES:
            conn, peer = listener.accept()
            with conn:
                stream = conn.makefile("rwb", buffering=0)
                server_dialog(name, stream)
                with context.wrap_socket(conn, server_side=True) as tls:
                    tls_stream = tls.makefile("rwb", buffering=0)
                    assert read_line(tls_stream) == b"PING " + name.encode() + b"\r\n"
                    tls_stream.write(b"PONG " + name.encode() + b"\r\n")
                    results.append({"case": name, "peer": peer[0], "version": tls.version()})
    print(json.dumps(results))


def common_name(entries):
    for relative_name in entries:
        for key, value in relative_name:
            if key == "commonName":
                return value
    return None


def run_client(args):
    context = ssl.create_default_context(cafile=args.ca)
    results = []
    for name in CASES:
        with socket.create_connection((args.host, args.port), timeout=10) as conn:
            stream = conn.makefile("rwb", buffering=0)
            client_dialog(name, stream)
            with context.wrap_socket(conn, server_hostname="origin.runner.lab") as tls:
                certificate = tls.getpeercert()
                assert common_name(certificate.get("subject", ())) == "origin.runner.lab"
                assert common_name(certificate.get("issuer", ())) == "Runner Test CA"
                tls_stream = tls.makefile("rwb", buffering=0)
                tls_stream.write(b"PING " + name.encode() + b"\r\n")
                assert read_line(tls_stream) == b"PONG " + name.encode() + b"\r\n"
                results.append({
                    "case": name,
                    "version": tls.version(),
                    "cipher": tls.cipher()[0],
                    "issuer": "Runner Test CA",
                })
    assert tuple(item["case"] for item in results) == CASES
    print(json.dumps(results))


parser = argparse.ArgumentParser()
parser.add_argument("mode", choices=("server", "client"))
parser.add_argument("--host", required=True)
parser.add_argument("--port", type=int, default=2525)
parser.add_argument("--cert")
parser.add_argument("--key")
parser.add_argument("--ca")
arguments = parser.parse_args()
serve(arguments) if arguments.mode == "server" else run_client(arguments)
