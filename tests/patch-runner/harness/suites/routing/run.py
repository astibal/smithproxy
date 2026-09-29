#!/usr/bin/env python3
"""End-to-end routing profile/DNAT test server and client."""

import argparse
import ipaddress
import json
import socket
import socketserver
import ssl
import struct
import threading


BACKEND_PORTS = (18080, 18081, 19080)
TLS_BACKEND_PORT = 18443


def recv_until(sock, marker, limit=65536):
    data = b""
    while marker not in data:
        chunk = sock.recv(4096)
        if not chunk:
            break
        data += chunk
        if len(data) > limit:
            raise RuntimeError("request exceeded limit")
    return data


def recv_exact(sock, size):
    data = b""
    while len(data) < size:
        chunk = sock.recv(size - len(data))
        if not chunk:
            raise EOFError(f"connection closed with {size - len(data)} bytes missing")
        data += chunk
    return data


class Handler(socketserver.BaseRequestHandler):
    def handle(self):
        request = recv_until(self.request, b"\n")
        if request.startswith(b"CONNECT ") and b"\r\n\r\n" not in request:
            request += recv_until(self.request, b"\r\n\r\n")
        local_host, local_port = self.request.getsockname()[:2]
        peer_host, peer_port = self.request.getpeername()[:2]
        result = json.dumps({
            "local_host": str(ipaddress.ip_address(local_host)),
            "local_port": local_port,
            "peer_host": str(ipaddress.ip_address(peer_host)),
            "peer_port": peer_port,
            "request": request.decode("ascii", "replace").strip(),
            "sni": getattr(self.request, "received_sni", None),
        }, sort_keys=True).encode() + b"\n"
        if request.startswith(b"CONNECT "):
            self.request.sendall(b"HTTP/1.1 200 Connection Established\r\n\r\n" + result)
            tunnel_payload = recv_until(self.request, b"\n")
            self.request.sendall(tunnel_payload)
        else:
            self.request.sendall(result)


class TCP6Server(socketserver.ThreadingTCPServer):
    address_family = socket.AF_INET6
    allow_reuse_address = True


class TCP4Server(socketserver.ThreadingTCPServer):
    allow_reuse_address = True


class TLSServerMixin:
    def __init__(self, server_address, handler, context):
        self.tls_context = context
        super().__init__(server_address, handler)

    def get_request(self):
        sock, address = super().get_request()
        return self.tls_context.wrap_socket(sock, server_side=True), address


class TLS4Server(TLSServerMixin, TCP4Server):
    pass


class TLS6Server(TLSServerMixin, TCP6Server):
    pass


def run_server(cert, key):
    tls_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    tls_context.load_cert_chain(cert, key)

    def capture_sni(tls_socket, server_name, _context):
        tls_socket.received_sni = server_name

    tls_context.set_servername_callback(capture_sni)
    servers = []
    for family, cls, tls_cls, hosts in (
        (socket.AF_INET, TCP4Server, TLS4Server, ("198.18.20.2", "198.18.20.3")),
        (socket.AF_INET6, TCP6Server, TLS6Server, ("fd00:20::2", "fd00:20::3")),
    ):
        for host in hosts:
            for port in BACKEND_PORTS:
                try:
                    servers.append(cls((host, port), Handler))
                except OSError as exc:
                    raise RuntimeError(f"cannot listen on {host}:{port}: {exc}") from exc
            try:
                servers.append(tls_cls((host, TLS_BACKEND_PORT), Handler, tls_context))
            except OSError as exc:
                raise RuntimeError(f"cannot listen on {host}:{TLS_BACKEND_PORT}: {exc}") from exc
    threads = [threading.Thread(target=server.serve_forever, daemon=True) for server in servers]
    for thread in threads:
        thread.start()
    print("READY", flush=True)
    try:
        for thread in threads:
            thread.join()
    finally:
        for server in servers:
            server.shutdown()
            server.server_close()


def read_json_line(sock):
    return json.loads(recv_until(sock, b"\n").decode())


def direct_request(family, host, port, payload="routing-test"):
    with socket.socket(family, socket.SOCK_STREAM) as sock:
        sock.settimeout(10)
        sock.connect((host, port))
        sock.sendall(payload.encode() + b"\n")
        return read_json_line(sock)


def socks_request(family, proxy_host, target_host, target_port):
    with socket.socket(family, socket.SOCK_STREAM) as sock:
        sock.settimeout(10)
        sock.connect((proxy_host, 1080))
        sock.sendall(b"\x05\x01\x00")
        assert recv_exact(sock, 2) == b"\x05\x00"
        packed = socket.inet_pton(family, target_host)
        atyp = b"\x01" if family == socket.AF_INET else b"\x04"
        sock.sendall(b"\x05\x01\x00" + atyp + packed + struct.pack("!H", target_port))
        reply = recv_exact(sock, 4)
        assert len(reply) == 4 and reply[:2] == b"\x05\x00", reply
        bound_size = {1: 4, 4: 16}[reply[3]]
        recv_exact(sock, bound_size + 2)
        sock.sendall(b"socks5-dnat\n")
        return read_json_line(sock)


def connect_request(family, host):
    with socket.socket(family, socket.SOCK_STREAM) as sock:
        sock.settimeout(10)
        sock.connect((host, 19300))
        sock.sendall(b"CONNECT service.example:443 HTTP/1.1\r\nHost: service.example:443\r\n\r\n")
        response = recv_until(sock, b"\r\n\r\n")
        head, body = response.split(b"\r\n\r\n", 1)
        assert head.startswith(b"HTTP/1.1 200"), head
        while b"\n" not in body:
            body += sock.recv(4096)
        result = json.loads(body.split(b"\n", 1)[0].decode())
        sock.sendall(b"connect-tunnel\n")
        assert recv_exact(sock, len(b"connect-tunnel\n")) == b"connect-tunnel\n"
        return result


def tls_request(family, host, server_name):
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    with socket.socket(family, socket.SOCK_STREAM) as raw_sock:
        raw_sock.settimeout(10)
        with context.wrap_socket(raw_sock, server_hostname=server_name) as sock:
            sock.connect((host, 19443))
            sock.sendall(b"sni-rewrite\n")
            return read_json_line(sock)


def test_family(family):
    v6 = family == socket.AF_INET6
    decoy = "fd00:20::9" if v6 else "198.18.20.9"
    backend_a = "fd00:20::2" if v6 else "198.18.20.2"
    backend_b = "fd00:20::3" if v6 else "198.18.20.3"
    proxy = "fd00:10::1" if v6 else "198.18.10.1"

    address = direct_request(family, decoy, 19080, "address-dnat")
    assert (address["local_host"], address["local_port"]) == (backend_a, 19080), address

    port = direct_request(family, backend_a, 19081, "port-dnat")
    assert (port["local_host"], port["local_port"]) == (backend_a, 18080), port

    rr = [direct_request(family, decoy, 19082, f"rr-{i}") for i in range(4)]
    rr_hosts = [item["local_host"] for item in rr]
    assert set(rr_hosts) == {backend_a, backend_b}, rr_hosts
    assert all(rr_hosts[i] != rr_hosts[i - 1] for i in range(1, len(rr_hosts))), rr_hosts

    l3 = [direct_request(family, decoy, 19083, f"l3-{i}") for i in range(4)]
    assert len({item["local_host"] for item in l3}) == 1, l3

    l4 = {port: direct_request(family, decoy, port, f"l4-{port}")["local_host"]
          for port in range(19100, 19116)}
    assert set(l4.values()) == {backend_a, backend_b}, l4
    for requested_port, selected_host in l4.items():
        repeat = direct_request(family, decoy, requested_port, "l4-repeat")
        assert repeat["local_host"] == selected_host, (l4, repeat)

    socks = socks_request(family, proxy, decoy, 19200)
    assert (socks["local_host"], socks["local_port"], socks["request"]) == \
           (backend_a, 18080, "socks5-dnat"), socks

    connect = connect_request(family, decoy)
    assert (connect["local_host"], connect["local_port"]) == (backend_a, 18081), connect
    assert connect["request"].startswith("CONNECT service.example:443 HTTP/1.1"), connect

    rewritten_sni = tls_request(family, decoy, "client.example")
    assert (rewritten_sni["local_host"], rewritten_sni["local_port"], rewritten_sni["sni"]) == \
           (backend_a, TLS_BACKEND_PORT, "origin.internal"), rewritten_sni
    unchanged_sni = tls_request(family, decoy, "other.example")
    assert unchanged_sni["sni"] == "other.example", unchanged_sni

    return {
        "family": 6 if v6 else 4,
        "address_dnat": address,
        "port_dnat": port,
        "round_robin": rr_hosts,
        "sticky_l3": l3[0]["local_host"],
        "sticky_l4": l4,
        "socks5_dnat": socks,
        "opaque_connect_tunnel": connect,
        "rewritten_sni": rewritten_sni,
        "unchanged_sni": unchanged_sni,
    }


def main():
    parser = argparse.ArgumentParser()
    sub = parser.add_subparsers(dest="mode", required=True)
    server = sub.add_parser("server")
    server.add_argument("--cert", required=True)
    server.add_argument("--key", required=True)
    client = sub.add_parser("client")
    client.add_argument("--family", type=int, choices=(4, 6), required=True)
    args = parser.parse_args()
    if args.mode == "server":
        run_server(args.cert, args.key)
    else:
        family = socket.AF_INET if args.family == 4 else socket.AF_INET6
        print(json.dumps(test_family(family), indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
