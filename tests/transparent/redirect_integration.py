#!/usr/bin/env python3
"""Exercise the real redirect MitmProxy and replacement paths without host firewall changes."""

from __future__ import annotations

import argparse
import html
import http.server
import os
from pathlib import Path
import re
import shutil
import socket
import ssl
import subprocess
import sys
import tempfile
import threading
import time
import urllib.parse

REQUEST = (b"GET /redirect HTTP/1.1\r\n"
           b"Host: redirect.invalid\r\nConnection: close\r\n\r\n")
RESPONSE = (b"HTTP/1.1 200 OK\r\nContent-Length: 14\r\n"
            b"Connection: close\r\n\r\nredirect reply")
H2_PREFACE = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"


def h2_frame(frame_type: int, flags: int, stream_id: int, payload: bytes = b"") -> bytes:
    return (len(payload).to_bytes(3, "big") + bytes((frame_type, flags))
            + (stream_id & 0x7fffffff).to_bytes(4, "big") + payload)


def h2_request_headers(stream_id: int, head: bool = False) -> bytes:
    # Static :method GET (or a literal HEAD) and :scheme https plus literal
    # :authority and :path.
    authority = b"redirect.invalid"
    path = b"/redirect"
    method = b"\x02\x04HEAD" if head else b"\x82"
    block = (method + b"\x87\x01" + bytes((len(authority),)) + authority
             + b"\x04" + bytes((len(path),)) + path)
    return h2_frame(1, 0x05, stream_id, block)


def h2_request(head: bool = False, multi_stream: bool = False) -> bytes:
    frames = H2_PREFACE + h2_frame(4, 0, 0)
    if multi_stream:
        frames += h2_request_headers(1, False)
        frames += h2_request_headers(3, head)
        return frames
    return frames + h2_request_headers(1, head)


def validate_h2_replacement(response: bytes, allow_goaway_only: bool = False,
                            head: bool = False, expected_stream: int = 1) -> None:
    if response.startswith(b"HTTP/"):
        raise AssertionError("HTTP/1 replacement was sent on an h2 connection")
    offset = 0
    types: list[int] = []
    body = bytearray()
    ended = False
    goaway_error: int | None = None
    while offset < len(response):
        if len(response) - offset < 9:
            raise AssertionError(f"truncated h2 replacement frame: {response[offset:]!r}")
        length = int.from_bytes(response[offset:offset + 3], "big")
        frame_type = response[offset + 3]
        flags = response[offset + 4]
        stream_id = int.from_bytes(response[offset + 5:offset + 9], "big") & 0x7fffffff
        end = offset + 9 + length
        if end > len(response):
            raise AssertionError("declared h2 replacement frame exceeds received bytes")
        payload = response[offset + 9:end]
        types.append(frame_type)
        if frame_type in (0, 1) and stream_id != expected_stream:
            raise AssertionError(f"replacement used wrong stream {stream_id}")
        if frame_type == 1 and not flags & 0x04:
            raise AssertionError("replacement HEADERS did not terminate its HPACK block")
        if frame_type == 1:
            ended = ended or bool(flags & 0x01)
        if frame_type == 0:
            body.extend(payload)
            ended = ended or bool(flags & 0x01)
        if frame_type == 7:
            if stream_id != 0 or len(payload) < 8:
                raise AssertionError("malformed replacement GOAWAY")
            goaway_error = int.from_bytes(payload[4:8], "big")
        offset = end
    if allow_goaway_only and types == [4, 4, 7]:
        if goaway_error != 0x0c:
            raise AssertionError(f"unexpected early replacement GOAWAY error {goaway_error}")
        return
    if len(types) < 3 or types[:3] != [4, 4, 1] or 7 not in types:
        raise AssertionError(f"incomplete h2 replacement frame sequence: {types}")
    if head:
        if 0 in types:
            raise AssertionError("HEAD replacement incorrectly contained DATA")
        if not ended:
            raise AssertionError("HEAD replacement HEADERS did not set END_STREAM")
    elif 0 not in types or not ended:
        raise AssertionError("replacement DATA did not set END_STREAM")
    if not head and b"/SM/IT/HP/RO/XY/warning" not in body:
        raise AssertionError(f"unexpected h2 replacement body: {bytes(body[:200])!r}")


class WebhookHandler(http.server.BaseHTTPRequestHandler):
    requests = 0

    def do_POST(self) -> None:
        self.rfile.read(int(self.headers.get("Content-Length", "0")))
        self.__class__.requests += 1
        body = b'{"access-response":"accept"}'
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        try:
            self.wfile.write(body)
        except BrokenPipeError:
            pass

    def log_message(self, format: str, *args: object) -> None:
        pass


def free_port() -> int:
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        return probe.getsockname()[1]


def replace_setting(text: str, name: str, value: str) -> str:
    result, count = re.subn(
        rf"(?m)^(\s*{re.escape(name)}\s*=\s*).*$", rf"\g<1>{value}", text, count=1)
    if count != 1:
        raise AssertionError(f"setting not found: {name}")
    return result


def tls_http_request(port: int, sni: str | None, target: str,
                     host: str | None = None,
                     client: socket.socket | None = None) -> bytes:
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    raw = client or socket.create_connection(("127.0.0.1", port), timeout=10)
    with raw:
        with context.wrap_socket(raw, server_hostname=sni) as stream:
            stream.settimeout(10)
            stream.sendall((f"GET {target} HTTP/1.1\r\nHost: {host or sni or 'nosni.invalid'}\r\n"
                            "Connection: close\r\n\r\n").encode())
            response = bytearray()
            while True:
                chunk = stream.recv(4096)
                if not chunk:
                    return bytes(response)
                response.extend(chunk)


class EchoOrigin:
    def __init__(self, source: Path, tls: bool, certificate: Path | None = None,
                 key: Path | None = None, expect_forward: bool | list[bool] = True,
                 response_delay: float = 0, alpn: str | None = None,
                 early_h2_settings: bool = False,
                 early_origin_data: bool = False):
        self.listener = socket.socket()
        self.listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.listener.bind(("127.0.0.1", 0))
        self.listener.listen(4)
        self.listener.settimeout(15)
        self.port = self.listener.getsockname()[1]
        self.tls = tls
        self.source = source
        self.certificate = certificate or source / "etc/certs/default/srv-cert.pem"
        self.key = key or source / "etc/certs/default/srv-key.pem"
        self.expect_forward = ([expect_forward] if isinstance(expect_forward, bool)
                               else list(expect_forward))
        self.response_delay = response_delay
        self.alpn = alpn
        self.early_h2_settings = early_h2_settings
        self.early_origin_data = early_origin_data
        self.error: Exception | None = None
        self.thread = threading.Thread(target=self.run, daemon=True)

    def start(self) -> None:
        self.thread.start()

    def run(self) -> None:
        try:
            for expect_forward in self.expect_forward:
                connection, _ = self.listener.accept()
                with connection:
                    self._serve_connection(connection, expect_forward)
        except Exception as exception:
            self.error = exception

    def _serve_connection(self, connection: socket.socket,
                          expect_forward: bool) -> None:
                stream: socket.socket = connection
                if self.tls:
                    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
                    context.load_cert_chain(self.certificate, self.key)
                    if self.alpn:
                        context.set_alpn_protocols([self.alpn])
                    stream = context.wrap_socket(connection, server_side=True)
                with stream:
                    if not expect_forward:
                        if self.early_h2_settings:
                            stream.sendall(h2_frame(4, 0, 0))
                        elif self.early_origin_data:
                            stream.sendall(b"early-origin-data")
                        stream.settimeout(3)
                        try:
                            forwarded = stream.recv(4096)
                        except TimeoutError:
                            forwarded = b""
                        if forwarded:
                            raise AssertionError(
                                f"rejected TLS request reached origin: {forwarded!r}")
                        return
                    request = bytearray()
                    while b"\r\n\r\n" not in request:
                        chunk = stream.recv(4096)
                        if not chunk:
                            break
                        request.extend(chunk)
                    if bytes(request) != REQUEST:
                        raise AssertionError(f"unexpected origin payload: {request!r}")
                    if self.response_delay:
                        time.sleep(self.response_delay)
                    stream.sendall(RESPONSE)

    def close(self) -> None:
        self.listener.close()
        self.thread.join(timeout=5)
        if self.error is not None:
            raise self.error


def run_case(binary: Path, source: Path, runtime: Path, tls: bool,
             webhook_port: int, reject_certificate: bool = False,
             listener_tls: bool | None = None, half_close: bool = False,
             http2: bool = False, early_h2_settings: bool = False,
             raw_tls: bool = False, early_origin_data: bool = False,
             head: bool = False, multi_stream: bool = False,
             offered_h2_without_negotiation: bool = False,
             override_scope: bool = False) -> None:
    if listener_tls is None:
        listener_tls = tls
    certificate = key = None
    if reject_certificate:
        certificate = runtime / "untrusted-cert.pem"
        key = runtime / "untrusted-key.pem"
        subprocess.run(
            ["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
             "-days", "1", "-subj", "/CN=untrusted.invalid",
             "-keyout", str(key), "-out", str(certificate)],
            check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    origin = EchoOrigin(source, tls, certificate, key,
                        expect_forward=([False] * 7 + [True]
                                        if override_scope else not reject_certificate),
                        response_delay=.25 if half_close else 0,
                        alpn="h2" if http2 else None,
                        early_h2_settings=early_h2_settings,
                        early_origin_data=early_origin_data)
    origin.start()
    redirect_port = free_port()
    base_port = redirect_port - 1000
    if base_port <= 1024:
        raise AssertionError(f"unsuitable generated redirect port: {redirect_port}")

    if override_scope:
        case_name = "tls-override-sni-scope"
    elif reject_certificate:
        if offered_h2_without_negotiation:
            case_name = ("tls-reject-http1-unselected-h2-early"
                         if early_origin_data else "tls-reject-http1-unselected-h2")
        elif raw_tls:
            case_name = "tls-reject-raw"
        elif early_origin_data:
            case_name = "tls-reject-http1-early"
        else:
            case_name = (("tls-reject-h2-early" if early_h2_settings else "tls-reject-h2")
                         if http2 else "tls-reject")
            if head:
                case_name += "-head"
            if multi_stream:
                case_name += "-multi"
    elif tls and not listener_tls:
        case_name = "tls-autodetect"
    elif half_close:
        case_name = "plain-half-close"
    else:
        case_name = "tls" if tls else "plain"
    config = runtime / f"redirect-{case_name}.cfg"
    runtime_log = runtime / f"redirect-{case_name}.log"
    capture_dir = runtime / f"capture-{case_name}"
    capture_dir.mkdir()
    shutil.copyfile(source / "etc/smithproxy.cfg", config)
    text = config.read_text()
    for name, value in (
        ("accept_tproxy", "FALSE;"),
        ("accept_redirect", "TRUE;"),
        ("accept_socks", "FALSE;"),
        ("accept_http_connect", "FALSE;"),
        ("log_level", "8;" if early_h2_settings else "6;"),
        ("plaintext_port", f'"{base_port}";'),
        ("ssl_port", f'"{base_port}";'),
        ("udp_port", f'"{base_port}";'),
        ("plaintext_workers", "-1;" if listener_tls else "1;"),
        ("ssl_workers", "1;" if listener_tls else "-1;"),
        ("udp_workers", "-1;"),
        ("socks_workers", "-1;"),
        ("http_connect_workers", "-1;"),
        ("certs_path", f'"{source / "etc/certs/default"}/";'),
        ("messages_dir", f'"{source / "etc/msg/en"}/";'),
        ("write_payload_dir", f'"{capture_dir}";'),
        ("log_file", f'"{runtime_log}";'),
        ("log_console", "TRUE;"),
        ("allow_untrusted_issuers", "FALSE;" if reject_certificate else "TRUE;"),
        ("allow_invalid_certs", "FALSE;" if reject_certificate else "TRUE;"),
        ("allow_self_signed", "FALSE;" if reject_certificate else "TRUE;"),
        ("failed_certcheck_override", "TRUE;" if override_scope else "FALSE;"),
    ):
        text = replace_setting(text, name, value)
    text = text.replace('dir = "/var/smithproxy/data"', f'dir = "{capture_dir}"', 1)
    text = text.replace("write_payload = FALSE;", "write_payload = TRUE;", 1)
    text, content_count = re.subn(
        r"(content_profiles\s*=\s*\{\s*default\s*=\s*\{)",
        r'\1\n        webhook_enable = true; webhook_lock_traffic = true;\n'
        r'        content_rules = ( { match = "redirect reply"; '
        r'replace = "modified reply"; } );',
        text, count=1)
    if content_count != 1:
        raise AssertionError("default content profile not found")
    text = text.replace(
        "settings = {",
        "settings = {\n    accept_api = FALSE;\n"
        "    webhook = { enabled = true; "
        f'url = "http://127.0.0.1:{webhook_port}/events"; '
        "tls_verify = false; };",
        1)
    text = text.replace(
        "address_objects = {",
        "address_objects = {\n"
        "    redirect_origin = { type = 0; cidr = \"127.0.0.1/32\"; };",
        1)
    text = text.replace(
        "port_objects = {",
        "port_objects = {\n"
        f"    redirect_origin = {{ start = {origin.port}; end = {origin.port}; }};",
        1)
    text, count = re.subn(
        r"routing\s*=\s*\{\s*\}",
        "routing = { redirect_test = { "
        "dnat_address = [ \"redirect_origin\" ]; "
        "dnat_port = [ \"redirect_origin\" ]; "
        "dnat_lb_method = \"round-robin\"; "
        "rewrite_sni = \"\"; rewrite_sni_to = \"\"; }; }",
        text, count=1)
    if count != 1:
        raise AssertionError("empty routing section not found")
    marker = 'routing = "none";'
    position = text.rfind(marker)
    if position < 0:
        raise AssertionError("TCP policy routing marker not found")
    text = (text[:position]
            + 'features = [ "access-request" ]; routing = "redirect_test";'
            + text[position + len(marker):])
    config.write_text(text)

    env = {**os.environ, "SMITHPROXY_PID_FILE": str(runtime / f"redirect-{case_name}.pid")}
    process = subprocess.Popen(
        [str(binary), "--dump", "--config-file", str(config)], env=env,
        stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
    try:
        deadline = time.monotonic() + 20
        client: socket.socket | None = None
        while time.monotonic() < deadline:
            if process.poll() is not None:
                output, _ = process.communicate()
                raise AssertionError(f"smithproxy exited early:\n{output}")
            try:
                client = socket.create_connection(("127.0.0.1", redirect_port), timeout=.2)
                break
            except OSError:
                time.sleep(.1)
        if client is None:
            raise AssertionError("redirect listener did not open")
        if override_scope:
            first = tls_http_request(
                redirect_port, "alpha.invalid", "/protected?x=1", client=client)
            warning_match = re.search(rb'top\.location\.href="([^"]+)"', first)
            if not warning_match:
                raise AssertionError(f"override warning redirect missing: {first[:300]!r}")
            warning_url = warning_match.group(1).decode()

            def override_action(page: bytes) -> str:
                action_match = re.search(rb'<form action="([^"]+)"', page)
                if not action_match:
                    raise AssertionError(f"override action missing: {page[:300]!r}")
                hidden = {
                    name.decode(): html.unescape(value.decode())
                    for name, value in re.findall(
                        rb'<input type="hidden" name="([^"]+)" value="([^"]*)">', page)
                }
                action_path = html.unescape(action_match.group(1).decode())
                if not re.fullmatch(
                        r"/SM/IT/HP/RO/XY/override/[0-9a-f]{32}", action_path):
                    raise AssertionError("override form omitted its opaque path token")
                query = urllib.parse.urlencode(hidden)
                return action_path + ("?" + query if query else "")

            attacked_action = override_action(tls_http_request(
                redirect_port, "alpha.invalid", warning_url))
            action = override_action(tls_http_request(
                redirect_port, "alpha.invalid", warning_url))
            beta_token = tls_http_request(
                redirect_port, "beta.invalid", attacked_action)
            if b"invalid or expired" not in beta_token:
                raise AssertionError("alpha override token was accepted for beta SNI")
            accepted = tls_http_request(redirect_port, "alpha.invalid", action)
            if b"applied, redirecting" not in accepted:
                raise AssertionError(
                    f"alpha override was not accepted; attacked={attacked_action!r}, "
                    f"selected={action!r}: {accepted[:300]!r}")
            if b'url=/protected?x=1' not in accepted:
                raise AssertionError(
                    f"override lost return target from {warning_url!r}; "
                    f"selected={action!r}: {accepted[:500]!r}")
            beta = tls_http_request(redirect_port, "beta.invalid", "/redirect")
            if b"/SM/IT/HP/RO/XY/warning" not in beta:
                raise AssertionError("beta SNI inherited alpha override")
            no_sni = tls_http_request(redirect_port, None, "/redirect")
            if b"/SM/IT/HP/RO/XY/warning" not in no_sni:
                raise AssertionError("no-SNI connection inherited alpha override")
            alpha = tls_http_request(
                redirect_port, "alpha.invalid", "/redirect", "redirect.invalid")
            if b"modified reply" not in alpha or b"redirect reply" in alpha:
                raise AssertionError(f"alpha SNI did not retain override: {alpha[:300]!r}")
            return
        with client:
            stream: socket.socket = client
            if tls:
                context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
                context.check_hostname = False
                context.verify_mode = ssl.CERT_NONE
                if http2:
                    context.set_alpn_protocols(["h2"])
                elif offered_h2_without_negotiation:
                    context.set_alpn_protocols(["h2", "http/1.1"])
                stream = context.wrap_socket(client, server_hostname="redirect.invalid")
            with stream:
                stream.settimeout(10)
                if http2 and stream.selected_alpn_protocol() != "h2":
                    raise AssertionError(
                        f"h2 replacement test negotiated {stream.selected_alpn_protocol()!r}")
                if offered_h2_without_negotiation and stream.selected_alpn_protocol() is not None:
                    raise AssertionError(
                        "origin unexpectedly negotiated ALPN in the unselected-offer case")
                response = bytearray()
                early_closed = False
                if early_h2_settings or early_origin_data:
                    time.sleep(.25)
                    stream.settimeout(.1)
                    try:
                        first = stream.recv(4096)
                        response.extend(first)
                        early_closed = not first
                    except TimeoutError:
                        pass
                    stream.settimeout(10)
                if not response and not early_closed:
                    try:
                        request = b"\x00\xffraw-tls-protocol" if raw_tls else (
                            h2_request(head, multi_stream) if http2 else
                            (REQUEST.replace(b"GET ", b"HEAD ", 1) if head else REQUEST))
                        stream.sendall(request)
                    except (BrokenPipeError, ssl.SSLError):
                        if not early_h2_settings and not early_origin_data:
                            raise
                if half_close:
                    stream.shutdown(socket.SHUT_WR)
                while not early_closed and b"redirect reply" not in response:
                    chunk = stream.recv(4096)
                    if not chunk:
                        break
                    response.extend(chunk)
                    if http2 and len(response) >= 9 and response.count(b"TLS certificate rejected"):
                        break
                if reject_certificate:
                    if raw_tls:
                        if response:
                            raise AssertionError(
                                f"non-HTTP TLS received a synthetic response: {bytes(response)!r}")
                    elif http2:
                        validate_h2_replacement(
                            bytes(response), early_h2_settings, head,
                            3 if multi_stream else 1)
                    elif (not response.startswith(b"HTTP/1.1 403 Forbidden\r\n") or
                          b"modified reply" in response or
                          (head and response.partition(b"\r\n\r\n")[2])):
                        raise AssertionError(
                            f"certificate rejection page missing: {bytes(response[:200])!r}")
                elif b"modified reply" not in response or b"redirect reply" in response:
                    raise AssertionError(f"content replacement mismatch: {bytes(response)!r}")
    finally:
        failed = sys.exc_info()[0] is not None
        process.terminate()
        try:
            process.wait(timeout=10)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=5)
        if failed and process.stdout:
            print(process.stdout.read()[-12000:], file=sys.stderr)
        if failed and runtime_log.exists():
            print(runtime_log.read_text(errors="replace")[-30000:], file=sys.stderr)
        origin.close()
        if process.returncode not in (0, -15):
            output = process.stdout.read() if process.stdout else ""
            raise AssertionError(f"smithproxy shutdown failed ({process.returncode}):\n{output[-4000:]}")
    captures = [path for path in capture_dir.iterdir()
                if path.is_file() and path.stat().st_size > 0]
    if not captures:
        raise AssertionError("enabled per-session capture produced no data")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--smithproxy", required=True, type=Path)
    parser.add_argument("--source", required=True, type=Path)
    args = parser.parse_args()
    webhook = http.server.ThreadingHTTPServer(("127.0.0.1", 0), WebhookHandler)
    webhook_thread = threading.Thread(target=webhook.serve_forever, daemon=True)
    webhook_thread.start()
    try:
        with tempfile.TemporaryDirectory(prefix="smithproxy-redirect-e2e-") as temp:
            port = webhook.server_address[1]
            if os.getenv("REDIRECT_OVERRIDE_ONLY"):
                run_case(args.smithproxy.resolve(), args.source.resolve(), Path(temp), True,
                         port, True, override_scope=True)
                print("PASS: SNI-scoped TLS override lifecycle")
                return
            run_case(args.smithproxy.resolve(), args.source.resolve(), Path(temp), False, port)
            run_case(args.smithproxy.resolve(), args.source.resolve(), Path(temp), True, port)
            run_case(args.smithproxy.resolve(), args.source.resolve(), Path(temp), True, port, True)
            run_case(args.smithproxy.resolve(), args.source.resolve(), Path(temp), True, port, True,
                     http2=True)
            run_case(args.smithproxy.resolve(), args.source.resolve(), Path(temp), True, port, True,
                     http2=True, early_h2_settings=True)
            run_case(args.smithproxy.resolve(), args.source.resolve(), Path(temp), True, port, True,
                     raw_tls=True)
            run_case(args.smithproxy.resolve(), args.source.resolve(), Path(temp), True, port, True,
                     early_origin_data=True)
            run_case(args.smithproxy.resolve(), args.source.resolve(), Path(temp), True, port, True,
                     offered_h2_without_negotiation=True)
            run_case(args.smithproxy.resolve(), args.source.resolve(), Path(temp), True, port, True,
                     offered_h2_without_negotiation=True, early_origin_data=True)
            run_case(args.smithproxy.resolve(), args.source.resolve(), Path(temp), True, port, True,
                     head=True)
            run_case(args.smithproxy.resolve(), args.source.resolve(), Path(temp), True, port, True,
                     http2=True, head=True)
            run_case(args.smithproxy.resolve(), args.source.resolve(), Path(temp), True, port, True,
                     http2=True, head=True, multi_stream=True)
            run_case(args.smithproxy.resolve(), args.source.resolve(), Path(temp), True, port,
                     listener_tls=False)
            run_case(args.smithproxy.resolve(), args.source.resolve(), Path(temp), False, port,
                     half_close=True)
            run_case(args.smithproxy.resolve(), args.source.resolve(), Path(temp), True, port, True,
                     override_scope=True)
        if WebhookHandler.requests == 0:
            raise AssertionError("enabled content webhook received no requests")
    finally:
        webhook.shutdown()
        webhook.server_close()
        webhook_thread.join(timeout=5)
    print("PASS: plaintext, TLS, autodetect, half-close, raw-TLS rejection and HTTP/1+HTTP/2 rejected-certificate "
          "redirect MitmProxy lifecycle")


if __name__ == "__main__":
    main()
