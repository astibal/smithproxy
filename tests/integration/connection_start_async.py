#!/usr/bin/env python3
"""Real SOCKS/TLS regression. Run in an empty network namespace on a test host.
Usage: unshare -n python3 connection_start_async.py BINARY ARTIFACT_DIRECTORY
The webhook deliberately withholds its reply until application data succeeds.
"""
import http.server
import json
import pathlib
import re
import socket
import ssl
import struct
import subprocess
import sys
import threading
import time


def run(*args):
    return subprocess.check_output(args, text=True, stderr=subprocess.STDOUT)


assert len(json.loads(run('ip', '-j', 'link'))) == 1, 'requires empty net namespace'
run('ip', 'link', 'set', 'lo', 'up')
binary = pathlib.Path(sys.argv[1]).resolve()
root = pathlib.Path(sys.argv[2]).resolve()
inspection = '--inspection' in sys.argv[3:]
root.mkdir(parents=True, exist_ok=True)
source = pathlib.Path(__file__).resolve().parents[2]
(root / 'src').symlink_to(source, target_is_directory=True)
subprocess.run([sys.executable, str(source / 'tests/patch-runner/harness/prepare.py'),
                str(root)], check=True)


class Hooks(http.server.BaseHTTPRequestHandler):
    entered = threading.Event()
    release = threading.Event()
    replied = threading.Event()
    unexpected_inspection = threading.Event()
    response = b'{"action":"drop"}'

    def log_message(self, *_):
        pass

    def do_POST(self):
        event = json.loads(self.rfile.read(int(self.headers['Content-Length'])))
        if not inspection and event.get('action') == 'inspection-start':
            self.unexpected_inspection.set()
        start = event.get('action') == ('inspection-start' if inspection else 'connection-start')
        if start:
            self.entered.set()
            self.release.wait(8)
        body = self.response if start else b'{}'
        try:
            self.send_response(200)
            self.send_header('Content-Length', str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        except OSError:
            pass
        if start:
            self.replied.set()


hooks = http.server.ThreadingHTTPServer(('127.0.0.1', 18081), Hooks)
threading.Thread(target=hooks.serve_forever, daemon=True).start()
listeners = []
context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
context.load_cert_chain(root / 'config/certs/origin-cert.pem', root / 'config/certs/origin-key.pem')


def origin(port, tls):
    listener = socket.socket()
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listener.bind(('127.0.0.1', port))
    listener.listen()
    listeners.append(listener)

    def handle(peer):
        try:
            if tls:
                peer = context.wrap_socket(peer, server_side=True)
            with peer:
                while data := peer.recv(4096):
                    peer.sendall(data)
        except OSError:
            peer.close()

    def accept():
        while True:
            try:
                peer, _ = listener.accept()
            except OSError:
                return
            threading.Thread(target=handle, args=(peer,), daemon=True).start()

    threading.Thread(target=accept, daemon=True).start()


origin(18080, False)
origin(18443, True)
config = root / 'config/smithproxy.cfg'
text = config.read_text().replace('accept_socks = FALSE', 'accept_socks = TRUE')
text = text.replace('accept_tproxy = TRUE', 'accept_tproxy = FALSE')
text = text.replace('extended_local_destination_protection = TRUE',
                    'extended_local_destination_protection = FALSE')
text = text.replace('settings = {', '''settings = {
    socks_port = "1080";
    webhook = { enabled = true; url = "http://127.0.0.1:18081/";
                tls_verify = false; sift = false; };
''', 1)
text = re.sub(r'(socks_workers|plaintext_workers|ssl_workers|udp_workers|dtls_workers) = \d+',
              r'\1 = 1', text)
start = text.index('policy = (')
end = text.index('\n)', start) + len('\n)')
text = text[:start] + '''policy = (
 { name = "async-start"; proto = "tcp"; src = ["any", "any6"]; sport = ["all"];
   dst = ["any", "any6"]; dport = ["all"]; action = "accept"; nat = "auto";
   tls_profile = "default"; }
)''' + text[end:]
config.write_text(text)
proxy = None
try:
    with (root / 'proxy.log').open('w') as log:
        proxy = subprocess.Popen([str(binary), '--no-pidfile', '--diagnose', '-c', str(config)],
                                 stdout=log, stderr=subprocess.STDOUT)
        deadline = time.monotonic() + 30
        while True:
            assert proxy.poll() is None, 'proxy exited; inspect proxy.log'
            try:
                socket.create_connection(('127.0.0.1', 1080), .2).close()
                break
            except OSError:
                assert time.monotonic() < deadline, 'proxy startup timeout'
                time.sleep(.1)

        for tls in (False, True):
            for response in ((b'{"action":"accept"}', b'{"action":"drop"}', b'not-json')
                             if inspection else (b'{"action":"drop"}', b'not-json')):
                Hooks.entered.clear(); Hooks.release.clear(); Hooks.replied.clear()
                Hooks.response = response
                started = time.monotonic()
                peer = socket.create_connection(('127.0.0.1', 1080), 2)
                peer.settimeout(2)
                with peer:
                    peer.sendall(b'\x05\x01\x00')
                    assert peer.recv(2) == b'\x05\x00'
                    peer.sendall(b'\x05\x01\x00\x01' + socket.inet_aton('127.0.0.1')
                                 + struct.pack('!H', 18443 if tls else 18080))
                    if inspection:
                        assert Hooks.entered.wait(2), 'inspection request not delivered'
                        peer.settimeout(.2)
                        try:
                            premature = peer.recv(10)
                        except socket.timeout:
                            pass
                        else:
                            raise AssertionError(('inspection did not wait', premature))
                        Hooks.release.set()
                        assert Hooks.replied.wait(2)
                        peer.settimeout(2)
                    reply = peer.recv(10)
                    if inspection and response == b'{"action":"drop"}':
                        assert reply[:2] != b'\x05\x00', 'drop allowed connection'
                        print(f'PASS inspection-start tls={tls} drop rejected', flush=True)
                        continue
                    assert reply[:2] == b'\x05\x00', (reply, Hooks.entered.is_set())
                    if tls:
                        client = ssl.create_default_context(cafile=str(root / 'config/certs/ca-cert.pem'))
                        client.load_verify_locations(cafile=str(root / 'config/certs/origin-ca.pem'))
                        peer = client.wrap_socket(peer, server_hostname='origin.runner.lab')
                    with peer:
                        peer.sendall(b'first\n')
                        assert peer.recv(64) == b'first\n'
                        elapsed = time.monotonic() - started
                        assert Hooks.entered.wait(2), 'notification was not delivered'
                        if not inspection:
                            assert not Hooks.replied.is_set(), 'backend already replied'
                        Hooks.release.set()
                        assert Hooks.replied.wait(2)
                        time.sleep(.1)
                        peer.sendall(b'after-reply\n')
                        assert peer.recv(64) == b'after-reply\n'
                        print(f'PASS inspection={inspection} tls={tls} reply={response!r} data_before_reply={elapsed:.3f}s', flush=True)
        assert not Hooks.unexpected_inspection.is_set(), 'normal setup invoked inspection'
finally:
    Hooks.release.set()
    if proxy:
        proxy.terminate()
        proxy.wait(timeout=15)
    hooks.shutdown()
    for listener in listeners:
        listener.close()
