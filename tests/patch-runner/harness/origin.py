#!/usr/bin/env python3
import http.server, socket, socketserver, ssl, threading, pathlib, sys
certs = pathlib.Path(sys.argv[1])
class Handler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        body = ('runner-origin-ok peer=' + self.client_address[0] + '\n').encode()
        self.send_response(200)
        self.send_header('Content-Length', str(len(body)))
        self.end_headers()
        self.wfile.write(body)
    def log_message(self, fmt, *args):
        print(fmt % args, flush=True)
class HTTPServer6(http.server.ThreadingHTTPServer):
    address_family = socket.AF_INET6

def serve_http(address, family, port):
    cls = HTTPServer6 if family == socket.AF_INET6 else http.server.ThreadingHTTPServer
    server = cls((address, port), Handler)
    if port == 443:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
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
    for port in (9995, 9996, 9997, 9998):
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
