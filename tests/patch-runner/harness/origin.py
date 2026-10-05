#!/usr/bin/env python3
import http.server, socket, socketserver, ssl, threading, pathlib, sys, os
certs = pathlib.Path(sys.argv[1])
class Handler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path.startswith('/bulk/'):
            size = int(self.path.split('?', 1)[0].removeprefix('/bulk/'))
            if size < 0 or size > 1024 * 1024 * 1024:
                self.send_error(400)
                return
            self.send_response(200)
            self.send_header('Content-Type', 'application/octet-stream')
            self.send_header('Content-Length', str(size))
            self.end_headers()
            chunk = b'x' * (64 * 1024)
            while size:
                current = min(size, len(chunk))
                self.wfile.write(chunk[:current])
                size -= current
            return
        body = ('runner-origin-ok peer=' + self.client_address[0] + '\n').encode()
        self.send_response(200)
        self.send_header('Content-Length', str(len(body)))
        self.end_headers()
        self.wfile.write(body)
    def do_POST(self):
        if not self.path.startswith('/bulk/'):
            self.send_error(404)
            return
        expected = int(self.path.split('?', 1)[0].removeprefix('/bulk/'))
        remaining = int(self.headers.get('Content-Length', '-1'))
        if remaining != expected or remaining < 0 or remaining > 1024 * 1024 * 1024:
            self.send_error(400)
            return
        while remaining:
            data = self.rfile.read(min(remaining, 64 * 1024))
            if not data:
                self.send_error(400)
                return
            remaining -= len(data)
        body = b'upload-ok\n'
        self.send_response(200)
        self.send_header('Content-Length', str(len(body)))
        self.end_headers()
        self.wfile.write(body)
    def log_message(self, fmt, *args):
        print(fmt % args, flush=True)
class HTTPServer(http.server.ThreadingHTTPServer):
    # Transfer and churn suites intentionally release large connection waves.
    # socketserver defaults to a listen backlog of just five, which drops SYNs
    # before Smithproxy can exercise its TLS state machine.
    request_queue_size = 128

class HTTPServer6(HTTPServer):
    address_family = socket.AF_INET6

def serve_http(address, family, port):
    cls = HTTPServer6 if family == socket.AF_INET6 else HTTPServer
    server = cls((address, port), Handler)
    if port == 443:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        tls_version = os.environ.get('TLS_TEST_VERSION')
        if tls_version:
            version = {'1.2': ssl.TLSVersion.TLSv1_2,
                       '1.3': ssl.TLSVersion.TLSv1_3}[tls_version]
            ctx.minimum_version = version
            ctx.maximum_version = version
        tls_cipher = os.environ.get('TLS_TEST_CIPHER')
        if tls_cipher and tls_version != '1.3':
            ctx.set_ciphers(tls_cipher)
        ctx.set_alpn_protocols(['http/1.1'])
        ctx.load_cert_chain(certs/'origin-cert.pem',certs/'origin-key.pem')
        server.socket = ctx.wrap_socket(server.socket,server_side=True)
    threading.Thread(target=server.serve_forever,daemon=True).start()

for address, family in [('198.18.20.2', socket.AF_INET), ('fd00:20::2', socket.AF_INET6)]:
    for port in (8080, 443):
        serve_http(address, family, port)

class EchoHandler(socketserver.BaseRequestHandler):
    def handle(self):
        while True:
            payload = self.request.recv(65535)
            if not payload:
                return
            self.request.sendall(payload)

class EchoServer(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    request_queue_size = 128
class EchoServer6(EchoServer):
    address_family = socket.AF_INET6

for address, cls in [('198.18.20.2', EchoServer), ('fd00:20::2', EchoServer6)]:
    for port in range(9989, 9999):
        server = cls((address, port), EchoHandler)
        threading.Thread(target=server.serve_forever, daemon=True).start()

def udp_loop(family, address):
    udp = socket.socket(family, socket.SOCK_DGRAM)
    udp.bind((address, 9999))
    while True:
        payload, addr = udp.recvfrom(65535)
        udp.sendto(payload + b' peer=' + addr[0].encode() + b' sport=' + str(addr[1]).encode(), addr)

threading.Thread(target=udp_loop, args=(socket.AF_INET, '198.18.20.2'), daemon=True).start()
udp_loop(socket.AF_INET6, 'fd00:20::2')
