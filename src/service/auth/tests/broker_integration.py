"""Real Unix HTTP, Linux PAM conversation/account policy and group checks.

A temporary PAM configuration loads a test-only module. No system PAM files,
accounts, passwords or group memberships are modified.
"""
import concurrent.futures
import grp
import http.client
import json
import os
from pathlib import Path
import pwd
import socket
import subprocess
import sys
import tempfile
import threading
import time

BROKER, CLIENT, MODULE = map(lambda value: str(Path(value).resolve()), sys.argv[1:4])
USER = pwd.getpwuid(os.getuid()).pw_name
GROUP = grp.getgrgid(pwd.getpwuid(os.getuid()).pw_gid).gr_name


def check(path, password='test-only-password', username=USER):
    return subprocess.run([CLIENT, str(path), username], input=password + '\n',
                          text=True, capture_output=True, timeout=5)


def request(path, body):
    with socket.socket(socket.AF_UNIX) as connection:
        connection.settimeout(5)
        connection.connect(str(path))
        header = f'POST /v1/pap HTTP/1.1\r\nHost: localhost\r\nContent-Length: {len(body)}\r\nConnection: close\r\n\r\n'
        connection.sendall(header.encode() + body)
        response = http.client.HTTPResponse(connection)
        response.begin()
        return response.status, response.read()


def run_case(root, *, group=GROUP, account='', service='test-auth'):
    path = root / 'auth.sock'
    (root / 'test-auth').write_text(f'auth required {MODULE}\naccount required {MODULE} {account}\n')
    config = root / 'broker.cfg'
    config.write_text(
        f'socket = "{path}";\npam = {{ service = "{service}"; '
        f'allowed_group = "{group}"; config_directory = "{root}"; }};\n')
    process = subprocess.Popen([BROKER, '--config', str(config)], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    try:
        deadline = time.monotonic() + 5
        while not path.exists():
            assert process.poll() is None, process.communicate()
            assert time.monotonic() < deadline, 'broker did not bind'
            time.sleep(0.01)
        assert path.stat().st_mode & 0o777 == 0o700, oct(path.stat().st_mode)
        if group == GROUP and not account and service == 'test-auth':
            good = check(path)
            assert good.returncode == 0 and f'accepted {USER}' in good.stdout, good
            assert f'group {GROUP}' in good.stdout, good
            bad = check(path, 'wrong')
            assert bad.returncode == 1 and bad.stdout == 'rejected\n', bad
            assert check(path, username='no-such-smithproxy-user').returncode == 1
            assert request(path, b'not json')[0] == 400
            assert request(path, b'x' * 4097)[0] == 413
            assert request(path, b'{"version":2,"username":"x","password":"y"}')[0] == 400

            with concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool:
                results = list(pool.map(lambda _: check(path), range(16)))
            assert all(result.returncode == 0 for result in results), results

            # A second daemon must neither replace nor remove a live socket.
            inode = path.stat().st_ino
            duplicate = subprocess.run([BROKER, '--config', str(config)], capture_output=True, timeout=5)
            assert duplicate.returncode != 0 and path.stat().st_ino == inode
        else:
            result = check(path)
            assert result.returncode == 1, result
    finally:
        process.terminate()
        stdout, stderr = process.communicate(timeout=5)
        assert process.returncode == 0, (stdout, stderr)
    assert not path.exists(), 'broker did not remove its own socket'
    assert check(path).stdout == 'unavailable\n'


def malformed_broker_replies(root):
    path = root / 'fake.sock'
    accepted = {'version': 1, 'status': 'accepted', 'identity': USER, 'groups': [GROUP]}
    cases = [
        (200, b'not json', 0),
        (200, b'{}', 0),
        (200, json.dumps({**accepted, 'version': 2}).encode(), 0),
        (200, json.dumps({**accepted, 'identity': ''}).encode(), 0),
        (200, json.dumps({**accepted, 'groups': ['']}).encode(), 0),
        (200, json.dumps({**accepted, 'status': 'unknown'}).encode(), 0),
        (503, json.dumps(accepted).encode(), 0),
        (302, json.dumps(accepted).encode(), 0),
        (200, b'x' * 16385, 0),
        (200, json.dumps(accepted).encode(), 2),
    ]
    for status, body, delay in cases:
        with socket.socket(socket.AF_UNIX) as listener:
            listener.bind(str(path))
            listener.listen(1)
            listener.settimeout(5)
            def serve():
                connection, _ = listener.accept()
                with connection:
                    connection.settimeout(5)
                    incoming = b''
                    while b'\r\n\r\n' not in incoming:
                        incoming += connection.recv(4096)
                    time.sleep(delay)
                    try:
                        header = f'HTTP/1.1 {status} Test\r\nContent-Length: {len(body)}\r\nConnection: close\r\n\r\n'
                        connection.sendall(header.encode() + body)
                    except BrokenPipeError:
                        pass
            worker = threading.Thread(target=serve)
            worker.start()
            try:
                result = check(path)
                assert result.returncode == 1 and result.stdout == 'unavailable\n', result
            finally:
                worker.join(timeout=6)
                assert not worker.is_alive()
        path.unlink()


with tempfile.TemporaryDirectory(prefix='smithproxy-auth-test-') as directory:
    root = Path(directory)
    malformed_broker_replies(root)
    run_case(root)
    run_case(root, group='no-such-smithproxy-group')
    run_case(root, account='deny')
    run_case(root, service='missing-pam-service')

    # Refuse non-socket paths without changing their content.
    path = root / 'auth.sock'
    path.write_text('preserve this file')
    result = subprocess.run([BROKER, '--config', str(root / 'broker.cfg')], capture_output=True, timeout=5)
    assert result.returncode != 0 and path.read_text() == 'preserve this file'
print('PASS: Unix transport, PAM password/account/group policy, concurrency and unavailable broker')
