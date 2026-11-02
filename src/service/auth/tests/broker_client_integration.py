"""Validate the Smithproxy client against malformed Unix HTTP replies."""
import json
import os
from pathlib import Path
import pwd
import grp
import socket
import subprocess
import sys
import tempfile
import threading
import time

CLIENT = str(Path(sys.argv[1]).resolve())
USER = pwd.getpwuid(os.getuid()).pw_name
GROUP = grp.getgrgid(pwd.getpwuid(os.getuid()).pw_gid).gr_name

def check(path, password='test-only-password', username=USER):
    return subprocess.run([CLIENT, str(path), username], input=password + '\n',
                          text=True, capture_output=True, timeout=5)


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


with tempfile.TemporaryDirectory(prefix='sx-auth-client-') as directory:
    malformed_broker_replies(Path(directory))
print('PASS: malformed replies and unavailable broker remain fail closed')
