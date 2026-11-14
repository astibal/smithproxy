#!/usr/bin/env python3
"""Real H3 warning -> challenge -> reconnect -> TTL expiry, with verified TLS.

Invoked by master_policy_revalidation.py in disposable network namespaces.
The origin intentionally has the wrong hostname; neither client nor proxy
verification is disabled. Only synthetic request counts are saved.
"""
import asyncio
import os
from pathlib import Path
import re
import subprocess
import sys


def run_case(root, proxy, hooks, config, eventually, run, sessions, cli):
    peer = subprocess.Popen(['unshare', '-n', sys.executable, __file__, 'client', str(root)],
                            stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True)
    try:
        pid = int(peer.stdout.readline())
        for args in [('link', 'add', 'rv-c', 'type', 'veth', 'peer', 'name', 'rv-cp'),
                     ('link', 'set', 'rv-cp', 'netns', str(pid)),
                     ('link', 'set', 'rv-c', 'up'),
                     ('addr', 'add', '198.18.10.1/24', 'dev', 'rv-c'),
                     ('rule', 'add', 'fwmark', '1', 'lookup', '100'),
                     ('route', 'add', 'local', '0.0.0.0/0', 'dev', 'lo', 'table', '100')]:
            run('ip', *args)
        run('iptables', '-t', 'mangle', '-A', 'PREROUTING', '-i', 'rv-c', '-p', 'udp',
            '--dport', '443', '-j', 'TPROXY', '--on-port', '443', '--tproxy-mark', '1')
        peer.stdin.write('go\n'); peer.stdin.flush()
        assert peer.wait(timeout=30) == 0, 'H3 replacement client failed'
        assert proxy.poll() is None
    finally:
        if peer.poll() is None:
            peer.terminate()
            peer.wait(timeout=5)


async def main(mode, root):
    from aioquic.asyncio import QuicConnectionProtocol, connect, serve
    from aioquic.h3.connection import H3Connection
    from aioquic.h3.events import HeadersReceived, DataReceived
    from aioquic.quic.configuration import QuicConfiguration

    class Peer(QuicConnectionProtocol):
        def __init__(self, *args, **kwargs):
            super().__init__(*args, **kwargs)
            self.http = H3Connection(self._quic)
            self.requests = {}

        def quic_event_received(self, event):
            for item in self.http.handle_event(event):
                if mode == 'origin' and isinstance(item, HeadersReceived):
                    with (root / 'replacement-origin-count.txt').open('a') as log:
                        log.write('request\n')
                    self.http.send_headers(item.stream_id, [(b':status', b'200')])
                    self.http.send_data(item.stream_id, b'origin accepted', end_stream=True)
                    self.transmit()
                elif item.stream_id in self.requests:
                    record = self.requests[item.stream_id]
                    if isinstance(item, HeadersReceived):
                        record[1] = int(dict(item.headers).get(b':status', record[1]))
                    elif isinstance(item, DataReceived):
                        record[2].extend(item.data)
                    if item.stream_ended and not record[0].done():
                        record[0].set_result((record[1], bytes(record[2])))

        async def get(self, path):
            stream = self._quic.get_next_available_stream_id()
            done = asyncio.get_running_loop().create_future()
            self.requests[stream] = [done, 0, bytearray()]
            self.http.send_headers(stream, [(b':method', b'GET'), (b':scheme', b'https'),
                (b':authority', b'wrong.example'), (b':path', path.encode())], end_stream=True)
            self.transmit()
            return await asyncio.wait_for(done, 5)

    certs = root / 'config/certs'
    config = QuicConfiguration(is_client=mode == 'client', alpn_protocols=['h3'])
    if mode == 'origin':
        config.load_cert_chain(certs / 'origin-cert.pem', certs / 'origin-key.pem')
        server = await serve('203.0.113.10', 443, configuration=config, create_protocol=Peer)
        print('ready', flush=True)
        try:
            await asyncio.Future()
        finally:
            server.close()
        return

    print(os.getpid(), flush=True)
    sys.stdin.readline()
    for args in [('link', 'set', 'lo', 'up'), ('link', 'set', 'rv-cp', 'up'),
                 ('addr', 'add', '198.18.10.2/24', 'dev', 'rv-cp'),
                 ('route', 'add', 'default', 'via', '198.18.10.1')]:
        subprocess.run(['ip', *args], check=True)
    config.server_name = 'wrong.example'
    config.load_verify_locations(cafile=str(certs / 'ca-cert.pem'))
    count_file = root / 'replacement-origin-count.txt'
    enabled = os.environ.get('H3_REPLACEMENT_OVERRIDE', '1') == '1'
    async with connect('203.0.113.10', 443, configuration=config, create_protocol=Peer) as client:
        status, body = await client.get('/SM/IT/HP/RO/XY/warning?orig_url=%2Fprivate')
        assert status == 403 and b'TLS security warning' in body
        assert not count_file.exists(), 'request leaked before override'
        token = re.search(rb'/SM/IT/HP/RO/XY/override/([a-f0-9]{32})', body)
        if not enabled:
            assert token is None, 'disabled override was offered'
            return
        assert token, 'missing challenge'
        action = '/SM/IT/HP/RO/XY/override/' + token[1].decode()
        status, _ = await client.get(action + '?orig_url=%2Fprivate')
        assert status == 200
        assert not count_file.exists(), 'override action leaked to origin'
    async with connect('203.0.113.10', 443, configuration=config, create_protocol=Peer) as client:
        status, body = await client.get('/private')
        assert status == 200 and body == b'origin accepted'
    assert count_file.read_text().splitlines() == ['request']
    await asyncio.sleep(3)  # Test profile uses a two-second, hard-expiry grant.
    async with connect('203.0.113.10', 443, configuration=config, create_protocol=Peer) as client:
        status, body = await client.get(action)
        assert status == 403 and b'invalid or expired' in body
        status, body = await client.get('/SM/IT/HP/RO/XY/warning')
        assert status == 403 and b'TLS security warning' in body
    assert count_file.read_text().splitlines() == ['request'], 'expired grant forwarded data'


if __name__ == '__main__':
    asyncio.run(main(sys.argv[1], Path(sys.argv[2])))
