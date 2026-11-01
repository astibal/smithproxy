"""Exercise real CONNECT/SOCKS listeners against a temporary PAM broker."""
import base64
import grp
import os
from pathlib import Path
import pwd
import socket
import struct
import subprocess
import sys
import tempfile
import time

PROXY, BROKER, MODULE = [str(Path(value).resolve()) for value in sys.argv[1:4]]
SOURCE = Path(__file__).resolve().parents[4]
sys.path.insert(0, str(SOURCE / 'tests/httpconnect'))
from http_connect_integration import free_port, make_config, process_env, wait_for_listener

USER = pwd.getpwuid(os.getuid()).pw_name
GROUP = grp.getgrgid(pwd.getpwuid(os.getuid()).pw_gid).gr_name
PASSWORD = 'test-only-password'


def receive(client, size):
    result = b''
    while len(result) < size:
        part = client.recv(size - len(result))
        assert part, result
        result += part
    return result


def http_request(port, target, password=PASSWORD, expected=200, fragment=False):
    header = b''
    if password is not None:
        value = base64.b64encode(f'{USER}:{password}'.encode())
        header = b'Proxy-Authorization: Basic ' + value + b'\r\n'
    request = f'CONNECT 127.0.0.1:{target} HTTP/1.1\r\nHost: localhost\r\n'.encode() + header + b'\r\n'
    client = socket.create_connection(('127.0.0.1', port), timeout=5)
    if fragment:
        client.sendall(request[:-5])
        time.sleep(0.03)
        client.sendall(request[-5:])
    else:
        client.sendall(request)
    response = b''
    while not response.endswith(b'\r\n\r\n'):
        response += receive(client, 1)
    assert response.startswith(f'HTTP/1.1 {expected} '.encode()), response
    if expected == 407:
        assert b'Proxy-Authenticate: Basic ' in response, response
    return client


def socks_request(port, target, password=PASSWORD, accepted=True, fragment=False, pipeline=False, command=1):
    client = socket.create_connection(('127.0.0.1', port), timeout=5)
    user, secret = USER.encode(), password.encode()
    auth = bytes([1, len(user)]) + user + bytes([len(secret)]) + secret
    request = bytes([5, command, 0, 1, 127, 0, 0, 1]) + struct.pack('!H', target)
    client.sendall(b'\x05\x02\x00\x02' + (auth + request if pipeline else b''))
    assert receive(client, 2) == b'\x05\x02'
    if not pipeline:
        if fragment:
            for byte in auth:
                client.sendall(bytes([byte]))
                time.sleep(0.002)
        else:
            client.sendall(auth)
    reply = receive(client, 2)
    assert reply == bytes([1, 0 if accepted else 1]), reply
    if accepted:
        if not pipeline:
            client.sendall(request)
        reply = receive(client, 4)
        assert reply[:3] == b'\x05\x00\x00', reply
        receive(client, 6 if reply[3] == 1 else 18)
    return client


def roundtrip(client, origin):
    with client, origin.accept()[0] as server:
        server.settimeout(5)
        client.sendall(b'PING\r\n')
        assert receive(server, 6) == b'PING\r\n'
        server.sendall(b'PONG\r\n')
        assert receive(client, 6) == b'PONG\r\n'


def no_target(origin):
    origin.settimeout(0.15)
    try:
        connection, _ = origin.accept()
    except socket.timeout:
        return
    connection.close()
    raise AssertionError('authentication failure opened the target')


def udp_authentication(socks_port):
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as origin:
        origin.bind(('127.0.0.1', 0))
        frame = b'\x00\x00\x00\x01\x7f\x00\x00\x01' + struct.pack('!H', origin.getsockname()[1]) + b'UDP-PING'
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as anonymous:
            anonymous.sendto(frame, ('127.0.0.1', socks_port))
            origin.settimeout(0.2)
            try:
                origin.recvfrom(1024)
            except socket.timeout:
                pass
            else:
                raise AssertionError('anonymous UDP reached the target')
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as client:
            client.bind(('127.0.0.1', 0))
            client.settimeout(5)
            with socks_request(socks_port, client.getsockname()[1], command=3):
                origin.settimeout(5)
                client.sendto(frame, ('127.0.0.1', socks_port))
                data, peer = origin.recvfrom(1024)
                assert data == b'UDP-PING', data
                origin.sendto(b'UDP-PONG', peer)
                response, _ = client.recvfrom(1024)
                assert response[10:] == b'UDP-PONG', response


with tempfile.TemporaryDirectory(prefix='sx-auth-proxy-') as directory:
    root = Path(directory)
    path = root / 'auth.sock'
    (root / 'test-auth').write_text(f'auth required {MODULE}\naccount required {MODULE}\n')
    broker_config = root / 'broker.cfg'
    broker_config.write_text(f'socket="{path}"; pam={{service="test-auth"; allowed_group="{GROUP}"; config_directory="{root}";}};')
    http_port, socks_port = free_port(), free_port()
    config = root / 'proxy.cfg'
    make_config(SOURCE / 'etc/smithproxy.cfg', config, SOURCE, root, http_port, free_port())
    content = config.read_text().replace('accept_socks = FALSE;', 'accept_socks = TRUE;')
    content = content.replace('socks_workers = 0;', f'socks_workers = 1;\n socks_port = "{socks_port}";')
    config.write_text(content)
    with (root / 'broker.log').open('w') as broker_log, (root / 'proxy.log').open('w+') as proxy_log:
        broker = subprocess.Popen([BROKER, '--config', str(broker_config)], stdout=broker_log, stderr=broker_log)
        proxy = subprocess.Popen([PROXY, '--config-file', str(config), '--debug', '--comm-auth', str(path)],
                                 cwd=SOURCE, env=process_env(root), stdout=proxy_log, stderr=proxy_log)
        try:
            deadline = time.monotonic() + 5
            while not path.exists():
                assert broker.poll() is None
                assert time.monotonic() < deadline
                time.sleep(0.01)
            wait_for_listener(proxy, http_port)
            wait_for_listener(proxy, socks_port)
            with socket.socket() as origin:
                origin.bind(('127.0.0.1', 0))
                origin.listen(10)
                origin.settimeout(5)
                target = origin.getsockname()[1]
                http_request(http_port, target, password=None, expected=407).close()
                http_request(http_port, target, password='wrong', expected=407).close()
                socks_request(socks_port, target, password='wrong', accepted=False, pipeline=True).close()
                with socket.create_connection(('127.0.0.1', socks_port), timeout=5) as client:
                    client.sendall(b'\x05\x01\x00')
                    assert receive(client, 2) == b'\x05\xff'
                with socket.create_connection(('127.0.0.1', socks_port), timeout=5) as client:
                    client.sendall(b'\x04\x01' + struct.pack('!H', target) + b'\x7f\x00\x00\x01\x00')
                    try:
                        assert client.recv(1) == b''
                    except ConnectionResetError:
                        pass
                no_target(origin)
                origin.settimeout(5)
                roundtrip(http_request(http_port, target, fragment=True), origin)
                roundtrip(socks_request(socks_port, target, fragment=True), origin)
                roundtrip(socks_request(socks_port, target, pipeline=True), origin)
                udp_authentication(socks_port)
                broker.terminate()
                broker.wait(timeout=5)
                http_request(http_port, target, expected=503).close()
                socks_request(socks_port, target, accepted=False).close()
                no_target(origin)
        except Exception:
            proxy_log.flush()
            proxy_log.seek(0)
            print(proxy_log.read()[-12000:], file=sys.stderr)
            for log in root.glob('messages.*.log'):
                print(log.read_text(errors='replace')[-24000:], file=sys.stderr)
            raise
        finally:
            for process in (proxy, broker):
                if process.poll() is None:
                    process.terminate()
                try:
                    process.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait()
print('PASS: CONNECT and SOCKS5 PAM auth, fragmentation, pipelining, no downgrade and fail closed')
