#!/usr/bin/env python3
"""Real HTTP/3 peers for the isolated master revalidation integration test."""
import asyncio
import json
import os
import re
from pathlib import Path
import signal
import subprocess
import sys
import time


def run_case(root, proxy, hooks, config, eventually, run, sessions, cli):
    """Keep two HTTP/3 responses open, revoke policy, observe all lifetimes."""
    for name in ('quic-ready', 'quic-closed'):
        (root / name).unlink(missing_ok=True)
    peer = subprocess.Popen(['unshare', '-n', sys.executable, __file__, 'client', str(root)],
                            stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True)
    try:
        pid = int(peer.stdout.readline())
        run('ip', 'link', 'add', 'rv-c', 'type', 'veth', 'peer', 'name', 'rv-cp')
        run('ip', 'link', 'set', 'rv-cp', 'netns', str(pid))
        run('ip', 'link', 'set', 'rv-c', 'up')
        run('ip', 'addr', 'add', '198.18.10.1/24', 'dev', 'rv-c')
        run('ip', 'rule', 'add', 'fwmark', '1', 'lookup', '100')
        run('ip', 'route', 'add', 'local', '0.0.0.0/0', 'dev', 'lo', 'table', '100')
        run('iptables', '-t', 'mangle', '-A', 'PREROUTING', '-i', 'rv-c', '-p', 'udp',
            '--dport', '443', '-j', 'TPROXY', '--on-port', '443', '--tproxy-mark', '1')
        peer.stdin.write('go\n'); peer.stdin.flush()
        eventually(lambda: (root / 'quic-ready').exists(), timeout=20)
        time.sleep(1)
        events = hooks.snapshot()
        starts = [e for e in events if e.get('action') == 'connection-start']
        parents = {e['id'] for e in starts if e['details']['info'].get('scope') == 'transport'}
        streams = {e['id']: e['details']['info'] for e in starts
                   if e['details']['info'].get('scope') == 'stream'}
        assert len(parents) == 1 and len(streams) >= 2, starts
        assert sum(info['stream_id'] % 4 == 0 for info in streams.values()) >= 2, streams
        assert all(info['parent_id'] in parents for info in streams.values())
        assert not [e for e in events if e.get('action') == 'connection-stop'], events
        assert not (root / 'quic-closed').exists()
        # Startup retires the legacy file; revoke the active native config.
        original = subprocess.check_output(
            [str(Path(proxy.args[0]).with_name('smithproxy-cftar')), 'get',
             str(config.with_suffix('.cftar')), 'smithproxy.cfg'], text=True)
        if os.environ.get('QUIC_REVALIDATION_TRIGGER') == 'role':
            # Change the interface map, not the policy's ingress_role criterion.
            revoked = re.sub(r'(?<!_)role = "Office"', 'role = "Blocked"', original)
        else:
            revoked = original.replace('action = "accept"', 'action = "deny"')
        assert revoked != original, 'policy revocation did not change configuration'
        config.write_text(revoked)
        from cftar_fixture import publish_config
        publish_config(Path(proxy.args[0]), config)
        proxy.send_signal(signal.SIGUSR1)
        eventually(lambda: (root / 'quic-closed').exists(), timeout=15)
        eventually(lambda: set(streams) <= {e['id'] for e in hooks.snapshot()
                   if e.get('action') == 'connection-stop'}, timeout=15)
        time.sleep(2.2)
        events = hooks.snapshot()
        for identity, info in streams.items():
            stops = [e for e in events if e.get('action') == 'connection-stop' and e.get('id') == identity]
            assert len(stops) == 1, stops
            final = stops[0]['details']['info']
            assert final['parent_id'] == info['parent_id'] and final['stream_id'] == info['stream_id'], final
            assert final['policy'] == 0 and final['session'], final
            if info['stream_id'] % 4 == 0:
                assert final['bytes_up'] > 0 and final['bytes_down'] > 0, final
        trail = cli('show event list')
        (root / 'quic-policy-drop-event-trail.txt').write_text(trail)
        terminated = re.findall(r'Policy revalidation checks: allowed=\d+ terminated=(\d+)', trail)
        assert sum(map(int, terminated)) == len(streams), terminated
        peer.stdin.write('close\n'); peer.stdin.flush()
        assert peer.wait(timeout=10) == 0
        eventually(lambda: parents <= {e['id'] for e in hooks.snapshot()
                   if e.get('action') == 'connection-stop'}, timeout=15)
        assert proxy.poll() is None
        eventually(lambda: not sessions(), timeout=15)
        events = hooks.snapshot()
        for identity in parents:
            assert sum(e.get('id') == identity and e.get('action') == 'connection-stop' for e in events) == 1
        stopped = set()
        for event in events:
            identity = event.get('id')
            if identity not in streams and identity not in parents:
                continue
            assert identity not in stopped, 'session callback arrived after connection-stop'
            if event.get('action') == 'connection-stop':
                stopped.add(identity)
        (root / 'quic-policy-drop-webhooks.json').write_text(json.dumps(events, indent=2))
    finally:
        if peer.poll() is None:
            peer.terminate(); peer.wait(timeout=5)
        (root / 'quic-failure-events.json').write_text(json.dumps(hooks.snapshot(), indent=2))


async def main(mode, root):
    from aioquic.asyncio import QuicConnectionProtocol, connect, serve
    from aioquic.h3.connection import H3Connection
    from aioquic.h3.events import HeadersReceived, DataReceived
    from aioquic.quic.configuration import QuicConfiguration
    from aioquic.quic.logger import QuicFileLogger
    from aioquic.quic.events import ConnectionTerminated, StreamReset

    class Peer(QuicConnectionProtocol):
        def __init__(self, *args, **kwargs):
            super().__init__(*args, **kwargs)
            self.http = H3Connection(self._quic)
            self.received, self.ended = set(), set()
            self.ready = asyncio.Event()
            self.closed = asyncio.Event()

        def quic_event_received(self, event):
            if isinstance(event, ConnectionTerminated):
                self.closed.set()
            if isinstance(event, StreamReset):
                self.ended.add(event.stream_id)
            for item in self.http.handle_event(event):
                if mode == 'origin' and isinstance(item, HeadersReceived):
                    self.http.send_headers(item.stream_id, [(b':status', b'200')])
                    # Deliberately no FIN: only revalidation may end this stream.
                    self.http.send_data(item.stream_id, b'held-response', end_stream=False)
                    self.transmit()
                if mode == 'client' and isinstance(item, DataReceived):
                    if item.data:
                        self.received.add(item.stream_id)
                    if item.stream_ended:
                        self.ended.add(item.stream_id)
            if len(self.received) == 2:
                self.ready.set()
            if {0, 4} <= self.ended:
                self.closed.set()

    certs = root / 'config/certs'
    config = QuicConfiguration(is_client=mode == 'client', alpn_protocols=['h3'])
    # Preserve transport resets and their error codes when readiness fails.
    qlog = root / f'quic-{mode}-qlog'
    qlog.mkdir(exist_ok=True)
    config.quic_logger = QuicFileLogger(str(qlog))
    if mode == 'origin':
        config.load_cert_chain(certs / 'origin-cert.pem', certs / 'origin-key.pem')
        server = await serve('203.0.113.10', 443, configuration=config, create_protocol=Peer)
        print('ready', flush=True)
        try:
            await asyncio.Future()
        finally:
            server.close()
    else:
        print(os.getpid(), flush=True)
        sys.stdin.readline()
        for args in [('link', 'set', 'lo', 'up'), ('link', 'set', 'rv-cp', 'up'),
                     ('addr', 'add', '198.18.10.2/24', 'dev', 'rv-cp'),
                     ('route', 'add', 'default', 'via', '198.18.10.1')]:
            subprocess.run(['ip', *args], check=True)
        config.server_name = 'origin.runner.lab'
        config.load_verify_locations(cafile=str(certs / 'ca-cert.pem'))
        async with connect('203.0.113.10', 443, configuration=config, create_protocol=Peer) as client:
            for _ in range(2):
                sid = client._quic.get_next_available_stream_id()
                client.http.send_headers(sid, [(b':method', b'GET'), (b':scheme', b'https'),
                    (b':authority', b'origin.runner.lab'), (b':path', b'/hold')], end_stream=True)
            client.transmit()
            await asyncio.wait_for(client.ready.wait(), 15)
            (root / 'quic-ready').touch()
            await asyncio.wait_for(client.closed.wait(), 20)
            (root / 'quic-closed').touch()
            await asyncio.to_thread(sys.stdin.readline)


if __name__ == '__main__':
    asyncio.run(main(sys.argv[1], Path(sys.argv[2])))
