#!/usr/bin/env python3
"""Real idle SOCKS sessions and route/role changes, in disposable namespaces.
Run: unshare -Urn python3 tests/integration/master_policy_revalidation.py BINARY ARTIFACT_DIR
QUIC gate (requires aioquic on PYTHONPATH and OpenSSL 3.5+):
  REVALIDATION_CASES=quic-policy-drop unshare -Urn python3 <this file> BINARY ARTIFACT_DIR
Never run the driver in the host network namespace. It refuses that topology.
"""
import http.server
import json
import os
import pathlib
import re
import signal
import socket
import ssl
import struct
import subprocess
import sys
import threading
import time
import urllib.request


def run(*args):
    return subprocess.check_output(args, text=True, stderr=subprocess.STDOUT)


def eventually(check, timeout=12):
    end = time.monotonic() + timeout
    last = None
    while time.monotonic() < end:
        try:
            value = check()
            if value:
                return value
        except (OSError, ValueError, AssertionError) as error:
            last = error
        time.sleep(.15)
    raise AssertionError(f'timeout: {last}')


def echo(connection):
    with connection:
        try:
            while data := connection.recv(4096):
                connection.sendall(data)
        except OSError:
            pass


if len(sys.argv) >= 2 and sys.argv[1] == 'origin':
    print(os.getpid(), flush=True)
    sys.stdin.readline()
    run('ip', 'link', 'set', 'lo', 'up')
    for name, address in [('rv-ap', '192.0.2.2/30'), ('rv-bp', '198.51.100.2/30')]:
        run('ip', 'link', 'set', name, 'up')
        run('ip', 'addr', 'add', address, 'dev', name)
    run('ip', 'addr', 'add', '203.0.113.10/32', 'dev', 'lo')
    run('ip', '-6', 'addr', 'add', '2001:db8:ff::10/128', 'dev', 'lo', 'nodad')
    run('ip', '-6', 'addr', 'add', '2001:db8:1::2/64', 'dev', 'rv-ap', 'nodad')
    run('ip', '-6', 'addr', 'add', '2001:db8:2::2/64', 'dev', 'rv-bp', 'nodad')
    if 'quic-policy-drop' in os.environ.get('REVALIDATION_CASES', ''):
        quic = subprocess.Popen([sys.executable, str(pathlib.Path(__file__).with_name('quic_revalidation_peer.py')),
                                 'origin', sys.argv[2]], stdout=subprocess.PIPE, text=True)
        assert quic.stdout.readline().strip() == 'ready'
        def stop_origin(*_):
            quic.terminate(); quic.wait(timeout=5)
            raise SystemExit(0)
        signal.signal(signal.SIGTERM, stop_origin)
    def udp_echo():
        udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        udp.bind(('203.0.113.10', 18080))
        while True:
            data, peer = udp.recvfrom(65535)
            udp.sendto(data, peer)
    threading.Thread(target=udp_echo, daemon=True).start()
    def tls_echo():
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        certs = pathlib.Path(sys.argv[2]) / 'config/certs'
        context.load_cert_chain(certs / 'origin-cert.pem', certs / 'origin-key.pem')
        with socket.create_server(('203.0.113.10', 443)) as server:
            while True:
                peer, _ = server.accept()
                def handle(peer):
                    try:
                        echo(context.wrap_socket(peer, server_side=True))
                    except OSError:
                        peer.close()
                threading.Thread(target=handle, args=(peer,), daemon=True).start()
    threading.Thread(target=tls_echo, daemon=True).start()
    listener = socket.socket(socket.AF_INET6)
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listener.bind(('::', 18080))
    listener.listen()
    print('ready', flush=True)
    while True:
        connection, _ = listener.accept()
        threading.Thread(target=echo, args=(connection,), daemon=True).start()

# Observe actual asynchronous notifications, not just the client's EOF.
class Hooks(http.server.BaseHTTPRequestHandler):
    events = []
    lock = threading.Lock()

    def log_message(self, *_):
        pass

    def do_POST(self):
        event = json.loads(self.rfile.read(int(self.headers['Content-Length'])))
        with self.lock:
            self.events.append(event)
        result = {'action': 'unchanged', 'control': {'server_lifecycle': 1, 'tls_lifecycle': 1}}
        if event.get('action') == 'server-lifecycle':
            result = {'action': 'server-lifecycle', 'id': event['id'],
                      'envelope': event['details']['server']['envelope']}
        if event.get('action') == 'tls-lifecycle':
            result = {'action': 'tls-lifecycle', 'id': event['id'], 'proceed': True,
                      'envelope': event['details']['tls']['envelope']}
        reply = json.dumps(result).encode()
        self.send_response(200)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Content-Length', str(len(reply)))
        self.end_headers()
        self.wfile.write(reply)

    @classmethod
    def snapshot(cls):
        with cls.lock:
            return list(cls.events)

assert json.loads(run('ip', '-j', 'link'))[0]['ifname'] == 'lo'
assert len(json.loads(run('ip', '-j', 'link'))) == 1, 'use an empty network namespace'
binary = pathlib.Path(sys.argv[1]).resolve()
root = pathlib.Path(sys.argv[2]).resolve()
root.mkdir(parents=True, exist_ok=True)
source = pathlib.Path(__file__).resolve().parents[2]
if not (root / 'src').exists():
    (root / 'src').symlink_to(source, target_is_directory=True)
subprocess.run([sys.executable, str(source / 'tests/patch-runner/harness/prepare.py'), str(root)], check=True)
base = (root / 'config/smithproxy.cfg').read_text()
run('ip', 'link', 'set', 'lo', 'up')
hooks = http.server.ThreadingHTTPServer(('127.0.0.1', 18081), Hooks)
threading.Thread(target=hooks.serve_forever, daemon=True).start()
origin = subprocess.Popen(['unshare', '-n', sys.executable, __file__, 'origin', str(root)],
                          stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True)
proxy = None
try:
    pid = int(origin.stdout.readline())
    for name, peer, address in [('rv-a', 'rv-ap', '192.0.2.1/30'), ('rv-b', 'rv-bp', '198.51.100.1/30')]:
        run('ip', 'link', 'add', name, 'type', 'veth', 'peer', 'name', peer)
        run('ip', 'link', 'set', peer, 'netns', str(pid))
        run('ip', 'link', 'set', name, 'up')
        run('ip', 'addr', 'add', address, 'dev', name)
    for name, address in [('rv-a', '2001:db8:1::1/64'), ('rv-b', '2001:db8:2::1/64')]:
        run('ip', '-6', 'addr', 'add', address, 'dev', name, 'nodad')
    origin.stdin.write('go\n'); origin.stdin.flush()
    assert origin.stdout.readline().strip() == 'ready'
    key = (root / 'config/api.key').read_text().strip()
    context = ssl._create_unverified_context()
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), urllib.request.HTTPSHandler(context=context))
    def api(path):
        request = urllib.request.Request('https://127.0.0.1:55555/api/' + path, headers={'X-API-Key': key})
        with opener.open(request, timeout=2) as response:
            return json.load(response)
    def sessions():
        return api('diag/proxy/session/list')
    def cli(command):
        with socket.create_connection(('127.0.0.1', 50000), timeout=5) as connection:
            def prompt():
                data = b''
                while True:
                    data += connection.recv(65536)
                    plain = re.sub(rb"\x1b\[[0-?]*[ -/]*[@-~]", b"", data)
                    if re.search(rb"smithpr[^\r\n]*[>#] $", plain):
                        return plain.decode(errors='replace')
            prompt()
            connection.sendall(b'enable\r\n'); prompt()
            result = ''
            for line in command.splitlines():
                connection.sendall(line.encode() + b'\r\n')
                result += prompt()
            return result
    def route(family, dev, unknown=False):
        target, gateway = ('203.0.113.10/32', '192.0.2.2' if dev == 'rv-a' else '198.51.100.2') if family == 4 else (
            '2001:db8:ff::10/128', '2001:db8:1::2' if dev == 'rv-a' else '2001:db8:2::2')
        run('ip', f'-{family}', 'route', 'replace', *(['unreachable', target] if unknown else [target, 'via', gateway, 'dev', dev]))
    def connect(family, http=False, tls=False):
        if http:
            connection = socket.create_connection(('127.0.0.1', 3128), timeout=5)
            connection.sendall(b'CONNECT 203.0.113.10:18080 HTTP/1.1\r\nHost: 203.0.113.10:18080\r\n\r\n')
            assert b'200' in connection.recv(4096)
            connection.sendall(b'first\n')
            assert connection.recv(64) == b'first\n'
            return connection
        connection = socket.create_connection(('127.0.0.1', 1080), timeout=5)
        connection.sendall(b'\x05\x01\x00')
        assert connection.recv(2) == b'\x05\x00'
        address = socket.inet_pton(socket.AF_INET if family == 4 else socket.AF_INET6,
                                  '203.0.113.10' if family == 4 else '2001:db8:ff::10')
        connection.sendall(b'\x05\x01\x00' + bytes([1 if family == 4 else 4]) + address + struct.pack('!H', 443 if tls else 18080))
        reply = connection.recv(64)
        assert reply[:2] == b'\x05\x00', reply
        if tls:
            context = ssl.create_default_context(cafile=str(root / 'config/certs/ca-cert.pem'))
            connection = context.wrap_socket(connection, server_hostname='origin.runner.lab')
        connection.sendall(b'first\n')
        assert connection.recv(64) == b'first\n'
        return connection
    results = []
    cases = [('route-drop', False, False, 4),
             ('route-other-policy', True, False, 4),
             ('multiple-drop', False, False, 4),
             ('role-drop', False, True, 4),
             ('unknown-keep', False, False, 4),
             ('ipv6-route-drop', False, False, 6),
             ('http-connect-drop', False, False, 4),
             ('role-reload-drop', False, False, 4),
             ('policy-reload-drop', False, False, 4),
             ('settings-fail-open-drop', False, False, 4),
             ('tls-policy-reload-drop', False, False, 4),
             ('udp-drop', False, False, 4),
             ('quic-policy-drop', False, False, 4)]
    selected_cases = os.environ.get('REVALIDATION_CASES', '').split(',')
    for label, allow_other, role_change, family in cases:
        if selected_cases != [''] and label not in selected_cases: continue
        if label.startswith('quic') and selected_cases == ['']: continue
        route(4, 'rv-a'); route(6, 'rv-a')
        run('ip', 'route', 'replace', 'default', 'via', '192.0.2.2', 'dev', 'rv-a')
        text = base.replace('accept_socks = FALSE', 'accept_socks = TRUE').replace('accept_http_connect = FALSE', 'accept_http_connect = TRUE')
        text = text.replace('extended_local_destination_protection = TRUE', 'extended_local_destination_protection = FALSE')
        text = text.replace('settings = {', f'''settings = {{
    interfaces = ( {{ match = {{ if_name = "lo"; }}; role = "Office"; }} {'' if role_change else ', { match = { if_name = "rv-a"; }; role = "Outside"; }, { match = { if_name = "rv-b"; }; role = "Guest"; }'} );
    socks_port = "1080";
''', 1)
        text = re.sub(r'(socks_workers|plaintext_workers|ssl_workers|udp_workers|dtls_workers) = \d+', r'\1 = 1', text)
        # Keep the test's ordered policy list independent of shipped examples.
        start = text.index('policy = (')
        end = text.index('\n)', start) + len('\n)')
        rule = lambda name, role, action: '{ name = "' + name + '"; proto = "tcp"; src = ["any", "any6"]; sport = ["all"]; dst = ["any", "any6"]; dport = ["all"]; ingress_role = "Office"; egress_role = "' + role + '"; action = "' + action + '"; nat = "auto"; tls_profile = "default"; }'
        text = text[:start] + 'policy = (\n' + rule('outside', 'Outside', 'accept') + ',\n' + rule('other', 'Guest', 'accept' if allow_other else 'deny') + '\n);' + text[end:]
        if label == 'settings-fail-open-drop':
            begin = text.index('policy = (')
            end = text.index('\n);', begin) + len('\n);')
            text = text[:begin] + 'policy = ();' + text[end:]
            text = text.replace('policy_fail_open = FALSE', 'policy_fail_open = TRUE', 1)
        if label.startswith(('udp', 'quic')):
            text = text.replace('proto = "tcp";', 'proto = "udp";')
        text = text.replace('settings = {', 'settings = {\n'
            '    webhook = { enabled = true; url = "http://127.0.0.1:18081/"; '
            'tls_verify = false; sift = false; };', 1)
        if label.startswith('quic'):
            text = text.replace('quic_workers = -1', 'quic_workers = 1')
            text = text.replace('interfaces = (', 'interfaces = ( { match = { if_name = "rv-c"; }; role = "Office"; },', 1)
        with Hooks.lock:
            Hooks.events.clear()
        cfg = root / 'config/smithproxy.cfg'; cfg.write_text(text)
        with (root / f'{label}.log').open('w') as log:
            proxy = subprocess.Popen([str(binary), '--no-pidfile', '--diagnose', '-c', str(cfg)], stdout=log, stderr=subprocess.STDOUT)
            eventually(lambda: api('status/ping'))
            if label.startswith('quic'):
                from quic_revalidation_peer import run_case
                run_case(root, proxy, Hooks, cfg, eventually, run, sessions, cli)
                proxy.terminate(); proxy.wait(timeout=15); proxy = None
                results.append({'case': label, 'result': 'PASS'})
                (root / 'results.json').write_text(json.dumps(results, indent=2))
                print(label, 'PASS', flush=True)
                continue
            udp = None
            if label.startswith('udp'):
                udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                udp.bind(('127.0.0.1', 0)); udp.settimeout(5)
                connection = socket.create_connection(('127.0.0.1', 1080), timeout=5)
                connection.sendall(b'\x05\x01\x00'); assert connection.recv(2) == b'\x05\x00'
                connection.sendall(b'\x05\x03\x00\x01' + socket.inet_aton('127.0.0.1') + struct.pack('!H', udp.getsockname()[1]))
                assert connection.recv(64)[:2] == b'\x05\x00'
                frame = b'\x00\x00\x00\x01' + socket.inet_aton('203.0.113.10') + struct.pack('!H', 18080)
                udp.sendto(frame + b'first', ('127.0.0.1', 1080))
                try:
                    assert udp.recv(4096)[10:] == b'first'
                except OSError:
                    (root / f'{label}-failure.json').write_text(json.dumps(sessions(), indent=2))
                    raise
            else:
                connection = connect(family, label.startswith('http'), label.startswith('tls'))
            extra = [connect(family) for _ in range(3)] if label == 'multiple-drop' else []
            rows = eventually(lambda: sessions())
            (root / f'{label}-before.json').write_text(json.dumps(rows, indent=2))
            original_oids = {r['oid'] for r in rows}
            starts = [e for e in Hooks.snapshot() if e.get('action') == 'connection-start']
            assert len(starts) == 1 + len(extra), starts
            started_ids = {e['id'] for e in starts}
            assert not [e for e in Hooks.snapshot() if e.get('action') == 'connection-stop']
            if label == 'settings-fail-open-drop':
                response = cli('configure terminal\nedit settings\nset policy_fail_open false\nend')
                (root / 'settings-apply.txt').write_text(response)
            elif label in ('role-reload-drop', 'policy-reload-drop', 'tls-policy-reload-drop'):
                changed = text.replace('}; role = "Outside";', '}; role = "Blocked";') if label.startswith('role') else text.replace('action = "accept";', 'action = "deny";')
                assert changed != text
                cfg.write_text(changed)
                proxy.send_signal(signal.SIGUSR1)
            elif label.startswith('unknown'):
                route(family, 'rv-a', True)
            elif role_change:
                run('ip', 'route', 'replace', 'default', 'via', '198.51.100.2', 'dev', 'rv-b')
            else:
                route(family, 'rv-b')
            killed = label.endswith('-drop')
            if killed:
                # No client traffic after the route event: idle timer must close it.
                if udp:
                    # The association control connection is separate. The idle
                    # UDP flow must disappear without another client datagram.
                    eventually(lambda: len(sessions()) < len(rows))
                else:
                    connection.settimeout(12)
                    assert connection.recv(64) == b''
                    for other in extra:
                        other.settimeout(12)
                        assert other.recv(64) == b''
                        other.close()
                    eventually(lambda: not sessions())
            else:
                time.sleep(3)  # allow multiple worker ticks without client traffic
                current = sessions()
                assert any(r['oid'] in original_oids for r in current), current
                (root / f'{label}-after.json').write_text(json.dumps(current, indent=2))
                if allow_other:
                    assert current[0]['policy'] == rows[0]['policy']  # profiles are not reapplied
                if label == 'unknown-keep':
                    before = cli('show event list').count('Policy revalidation checks:')
                    assert before > 0
                    time.sleep(2.2)
                    assert cli('show event list').count('Policy revalidation checks:') == before, 'unchanged retries flooded event trail'
                    route(family, 'rv-a')
                    time.sleep(2)
                if udp:
                    udp.sendto(frame + b'still-alive', ('127.0.0.1', 1080))
                    assert udp.recv(4096)[10:] == b'still-alive'
                else:
                    connection.sendall(b'still-alive\n')
                    assert connection.recv(64) == b'still-alive\n'
            if killed:
                eventually(lambda: started_ids <= {e['id'] for e in Hooks.snapshot()
                    if e.get('action') == 'connection-stop'})
                # Leave several more timer ticks for retirement: shutdown plus
                # destruction must still produce only one terminal notification.
                time.sleep(2.2)
                events = Hooks.snapshot()
                stops = [e for e in events if e.get('action') == 'connection-stop']
                assert len(stops) == len(started_ids), stops
                for stop in stops:
                    assert stop['id'] in started_ids
                    info = stop['details']['info']
                    assert info['bytes_up'] > 0 and info['bytes_down'] > 0, info
                    assert info['session'] and info['policy'] == (65500 if label == 'settings-fail-open-drop' else 0), info
                    if not udp:
                        lifecycle = [e for e in events if e.get('id') == stop['id']
                            and e.get('action') == 'server-lifecycle']
                        assert [e['details']['server']['envelope']['event'] for e in lifecycle] == [
                            'connect', 'connected', 'disconnected'], lifecycle
                        terminal = lifecycle[-1]
                        assert terminal['details']['server']['session_ending'] is True
                        assert terminal['details']['server']['peername'], terminal
                        assert events.index(terminal) < events.index(stop)
                    if label.startswith('tls'):
                        tls_events = [e for e in events if e.get('id') == stop['id']
                            and e.get('action') == 'tls-lifecycle']
                        assert len(tls_events) == 2, tls_events
                        assert {e['details']['tls']['envelope']['side'] for e in tls_events} == {'server', 'client'}
                        assert all(e['details']['tls']['envelope']['event'] == 'established' for e in tls_events)
                        assert all(events.index(e) < events.index(stop) for e in tls_events)
                        assert info['tls']['sni'] == 'origin.runner.lab', info
                        (root / 'tls-terminal-events.json').write_text(json.dumps(tls_events, indent=2))
                assert proxy.poll() is None, 'worker crash after retirement'
            else:
                assert not [e for e in Hooks.snapshot() if e.get('action') == 'connection-stop']
            (root / f'{label}-webhooks.json').write_text(json.dumps(Hooks.snapshot(), indent=2))
            trail = cli('show event list')
            (root / f'{label}-event-trail.txt').write_text(trail)
            summaries = re.findall(r'Policy revalidation checks: allowed=(\d+) terminated=(\d+) deferred=(\d+) superseded_passes=(\d+)', trail)
            assert summaries, 'missing revalidation summary in event trail'
            if killed:
                assert sum(int(item[1]) for item in summaries) == len(started_ids), summaries
            else:
                assert all(int(item[1]) == 0 for item in summaries), summaries
            connection.close()
            if udp: udp.close()
            proxy.terminate(); proxy.wait(timeout=15); proxy = None
        results.append({'case': label, 'result': 'PASS'})
        print(label, 'PASS', flush=True)
        (root / 'results.json').write_text(json.dumps(results, indent=2))
finally:
    if proxy:
        (root / f'{label}-failure-webhooks.json').write_text(json.dumps(Hooks.snapshot(), indent=2))
        proxy.terminate()
        try: proxy.wait(timeout=10)
        except subprocess.TimeoutExpired: proxy.kill(); proxy.wait()
    origin.terminate(); origin.wait(timeout=5)
