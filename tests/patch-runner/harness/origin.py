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
for port in (8080, 443):
    server = http.server.ThreadingHTTPServer(('198.18.20.2',port),Handler)
    if port == 443:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.set_alpn_protocols(['http/1.1'])
        ctx.load_cert_chain(certs/'origin-cert.pem',certs/'origin-key.pem')
        server.socket = ctx.wrap_socket(server.socket,server_side=True)
    threading.Thread(target=server.serve_forever,daemon=True).start()

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

echo = EchoServer(('198.18.20.2', 9998), EchoHandler)
threading.Thread(target=echo.serve_forever, daemon=True).start()
for port in (9995, 9996, 9997):
    server = EchoServer(('198.18.20.2', port), EchoHandler)
    threading.Thread(target=server.serve_forever, daemon=True).start()

udp = socket.socket(socket.AF_INET,socket.SOCK_DGRAM)
udp.bind(('198.18.20.2',9999))
while True:
    payload, addr = udp.recvfrom(65535)
    udp.sendto(payload + b' peer=' + addr[0].encode() + b' sport=' + str(addr[1]).encode(),addr)
