"""Real TLS 1.2/1.3 exchanges with deterministic decrypted capture bytes."""
import socket
import ssl
import sys


def cases():
    for number, version in ((30, '1.2'), (31, '1.3')):
        client = f'CMX{number}C'.encode()
        server = f'CMX{number}S'.encode()
        request = (b'GET /capture-matrix/' + str(number).encode()
                   + b' HTTP/1.1\r\nHost: origin.runner.lab\r\nX-Matrix: '
                   + client + b'\r\nConnection: close\r\n\r\n')
        response = (b'HTTP/1.1 200 OK\r\nContent-Length: '
                    + str(len(server)).encode() + b'\r\nConnection: close\r\n\r\n' + server)
        yield number, version, request, response


def run(host, ca_file):
    for number, version, request, expected in cases():
        context = ssl.create_default_context(cafile=ca_file)
        selected = ssl.TLSVersion.TLSv1_2 if version == '1.2' else ssl.TLSVersion.TLSv1_3
        context.minimum_version = context.maximum_version = selected
        with socket.create_connection((host, 443), timeout=10) as raw:
            with context.wrap_socket(raw, server_hostname='origin.runner.lab') as conn:
                assert conn.version() == 'TLSv' + version
                conn.sendall(request)
                received = bytearray()
                while True:
                    chunk = conn.recv(65536)
                    if not chunk:
                        break
                    received.extend(chunk)
                assert received == expected, f'TLS {version}: response differs'
        print(f'PASS capture case {number}: HTTPS TLS {version}')


if __name__ == '__main__':
    run(*sys.argv[1:])
