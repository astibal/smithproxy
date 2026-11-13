#!/usr/bin/env python3
"""H3 endpoint metadata and late rewrite through real QUIC and content hooks.

Run with aioquic/pylsqpack on PYTHONPATH:
  REVALIDATION_CASES=quic-engine-views unshare -Urn python3 \
    tests/integration/master_policy_revalidation.py BINARY ARTIFACT_DIR
The driver owns disposable network namespaces and a temporary configuration.
"""
import asyncio
import base64
import json
import os
from pathlib import Path
import subprocess
import sys


pending = bytearray()
dynamic = os.environ.get('H3_VIEWS_CASE', 'static').startswith('dynamic')
artifact_root = None


def request_frame(stream, method=b'GET'):
    import pylsqpack
    from aioquic.buffer import encode_uint_var
    encoder = pylsqpack.Encoder()
    instructions, fields = encoder.encode(stream, [
        (b':method', method), (b':scheme', b'https'),
        (b':authority', b'origin.runner.lab'), (b':path', f'/views/{stream}'.encode()),
    ])
    assert not instructions  # Deliberately static: the rewrite changes no QPACK table.
    return b'\x01' + encode_uint_var(len(fields)) + fields


def decode_event(raw, path):
    if raw.startswith(b'SXBN001:'):
        metadata_size = int(raw[8:16], 16)
        payload_size = int(raw[17:25], 16)
        assert len(raw) == 25 + metadata_size + payload_size
        event = json.loads(raw[25:25 + metadata_size])
        event['details']['info']['content'] = base64.b64encode(raw[25 + metadata_size:]).decode()
    else:
        event = json.loads(raw)
    event['_test_receiver'] = 'sift' if path == '/sift' else 'spider'
    return event


def webhook_reply(event, default):
    if dynamic:
        from quic_engine_dynamic import reply
        return reply(event, default, artifact_root)
    if event['_test_receiver'] == 'sift':
        return {'action': 'unchanged'}
    info = event.get('details', {}).get('info', {})
    if info.get('scope') != 'stream' or info.get('stream_id') != 4:
        return default
    if event['action'] == 'connection-start':
        # Stream 0 has already completed. Reserve rewrite only now to exercise
        # replay of the shared session state before admitting stream 4.
        return {'action': 'accept', 'control': {'rewrite': True}}
    if event['action'] != 'connection-content':
        return default
    data = base64.b64decode(info['content'], validate=True)
    if info['side'] == 'L':
        pending.extend(data)
        expected = request_frame(4)
        assert expected.startswith(pending), (expected, pending)
        if len(pending) < len(expected):
            return {'action': 'need-more'}
        pending.clear()
        return {'action': 'replace', 'content': base64.b64encode(request_frame(4, b'POST')).decode()}
    return default


def run_case(root, proxy, hooks, config, eventually, run, sessions, cli):
    global artifact_root
    artifact_root = root
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
        if not dynamic:
            eventually(lambda: (root / 'diagnostics-ready').exists())
            def h3_snapshots(value):
                if isinstance(value, dict):
                    if 'http3' in value:
                        yield value['http3']
                    for child in value.values():
                        yield from h3_snapshots(child)
                elif isinstance(value, list):
                    for child in value:
                        yield from h3_snapshots(child)
            api_snapshot = eventually(lambda: next((item for item in h3_snapshots(sessions())
                if item['stream_id'] == 4 and item['split']), None))
            assert api_snapshot['client']['request']['flow.http3.method'] == 'GET'
            assert api_snapshot['server']['request']['flow.http3.method'] == 'POST'
            assert api_snapshot['server']['response']['flow.http3.decode']['state'] == 'decoded'
            def http_records(value):
                if isinstance(value, dict):
                    if 'http' in value and value.get('stream_id') == 4:
                        yield value
                    for child in value.values():
                        yield from http_records(child)
                elif isinstance(value, list):
                    for child in value:
                        yield from http_records(child)
            record = eventually(lambda: next(http_records(sessions(verbose=True, tlsinfo=True)), None))
            views = record['http']['views']
            assert views['client']['current']['method'] == 'GET', record
            assert views['server']['current']['method'] == 'POST', record
            assert views['server']['current']['url'].endswith('/views/4'), record
            assert views['server']['streams'][0]['response']['header_sections'], record
            assert record['left'][0]['buffers']['read']['size'] >= 0, record
            assert record['tlsinfo']['source'] == 'quic parent', record
            assert record['tlsinfo']['right']['alpn'] == 'h3', record
            assert record['tlsinfo']['right']['established'], record
            text7 = cli('diag proxy session list 7')
            assert 'HTTP protocol: "http3"' in text7, text7
            assert 'current: "GET" "https://origin.runner.lab/views/4"' in text7, text7
            assert 'current: "POST" "https://origin.runner.lab/views/4"' in text7, text7
            assert 'L7_engine: none' not in text7, text7
            assert 'client -> server: control, open' in text7, text7
            assert 'server -> client: control, open' in text7, text7
            assert 'decode={' not in text7, text7
            assert 'QUIC errors: process-lifetime' not in text7, text7
            (root / 'http-diagnostics-api.json').write_text(json.dumps(record, indent=2))
            (root / 'http-diagnostics-cli-7.txt').write_text(text7)
            text = cli('diag proxy session list 99')
            cli_snapshots = [json.loads(line.split('H3: ', 1)[1]) for line in text.splitlines()
                             if 'H3: ' in line]
            assert api_snapshot in cli_snapshots, (api_snapshot, text)
            (root / 'diagnostics-api.json').write_text(json.dumps(api_snapshot, indent=2))
            (root / 'diagnostics-cli.txt').write_text(text)
            (root / 'diagnostics-release').touch()
        assert peer.wait(timeout=30) == 0
        # Metadata uses asynchronous connection-info delivery. Wait for the
        # final stream's header observation at both sinks before comparing.
        final_stream = 12 if dynamic else 8
        def delivered():
            observed = hooks.snapshot()
            if not all(any(e.get('action') == 'connection-info'
                           and e.get('_test_receiver') == sink
                           and e.get('details', {}).get('info', {}).get('stream_id') == final_stream
                           and e['details']['info'].get('protocol_event') == 'headers'
                           and e['details']['info'].get('side') == 'R'
                           for e in observed) for sink in ('spider', 'sift')):
                return False
            envelopes = [[json.dumps(e['details']['info'], sort_keys=True)
                          for e in observed if e.get('action') == 'connection-info'
                          and e.get('_test_receiver') == sink
                          and e.get('details', {}).get('info', {}).get('payload_layer') == 'http3.metadata']
                         for sink in ('spider', 'sift')]
            return observed if sorted(envelopes[0]) == sorted(envelopes[1]) else False
        events = eventually(delivered)
        metadata = [e['details']['info'] for e in events if e.get('action') == 'connection-info'
                    and e['details'].get('info', {}).get('payload_layer') == 'http3.metadata'
                    and e['_test_receiver'] == 'spider']
        sift_metadata = [e['details']['info'] for e in events if e.get('action') == 'connection-info'
                         and e['details'].get('info', {}).get('payload_layer') == 'http3.metadata'
                         and e['_test_receiver'] == 'sift']
        # Dispatch is asynchronous, so compare complete envelopes without
        # relying on cross-sink delivery order.
        assert sorted(map(lambda x: json.dumps(x, sort_keys=True), metadata)) == sorted(
            map(lambda x: json.dumps(x, sort_keys=True), sift_metadata))
        metadata.sort(key=lambda i: i['protocol_sequence'])
        assert len({i['protocol_sequence'] for i in metadata}) == len(metadata)
        assert metadata and any(i['protocol_event'] == 'fin' for i in metadata)
        for info in metadata:
            assert info['scope'] == 'stream' and info['parent_id']
            assert info['protocol_metadata_version'] == 1
            assert info['protocol_endpoint'] in ('client', 'server')
            assert 'content' not in info
            if info['protocol_event'] == 'headers':
                assert info['flow.http3.headers']
                assert info['flow.http3.header_section'] in ('request', 'interim', 'response', 'trailers')
        spider = [e['details']['info'] for e in events if e.get('action') == 'connection-content'
                  and e['_test_receiver'] == 'spider']
        sift = [e['details']['info'] for e in events if e.get('action') == 'connection-content'
                and e['_test_receiver'] == 'sift']
        assert spider and sift, 'missing Spider or SIFT content'
        keys = ('stream_id', 'side', 'content', 'content_annotations', 'L7_payload_start',
                'L7_payload_end', 'L7_encoding', 'flow.http3.method', 'flow.http3.authority',
                'flow.http3.path', 'flow.http3.url', 'flow.http3.decode')
        assert [[i.get(k) for k in keys] for i in spider] == [[i.get(k) for k in keys] for i in sift]
        content = spider
        assert content, 'no H3 content callbacks'
        for info in content:
            assert 'protocol_fork_error' not in info, info
            payload = base64.b64decode(info['content'], validate=True)
            cursor = 0
            for start, end, kind, attributes in info['content_annotations']:
                assert start == cursor and start < end <= len(payload), info
                assert kind.startswith('h3.') and attributes['stream_id'] == info['stream_id'], info
                cursor = end
            assert cursor == len(payload), info
        if dynamic:
            from quic_engine_dynamic import verify
            verify(content, metadata)
        else:
            for stream in (0, 4, 8):
                sections = [i for i in metadata if i['stream_id'] == stream and i['side'] == 'R'
                            and i['protocol_event'] == 'headers']
                assert [i['flow.http3.header_section'] for i in sections] == ['response', 'trailers']
                assert sections[0]['flow.http3.headers'][1] == ['x-raw', {'encoding': 'base64', 'data': '/w=='}]
                assert sections[0]['flow.http3.headers'][-2:] == [['set-cookie', 'a=1'], ['set-cookie', 'b=2']]
                assert sections[1]['flow.http3.headers'] == [['x-trailer', 'done']]
                body_chunks = [i for i in content if i['stream_id'] == stream and i['side'] == 'R'
                               and any(end > start for start, end in zip(i['L7_payload_start'], i['L7_payload_end']))]
                assert body_chunks
                assert all(i['flow.http3.decode']['encoding_known'] and
                           all(encoding == '' for encoding in i['L7_encoding']) for i in body_chunks)
            for stream in (0, 4, 8):
                for side in ('L', 'R'):
                    observations = [i for i in content if i['stream_id'] == stream and i['side'] == side
                                    and i.get('flow.http3')]
                    assert observations, (stream, side, content)
                    for info in observations:
                        assert info['flow.http3.method'] == ('POST' if stream == 4 and side == 'R' else 'GET'), info
                        assert info['flow.http3.authority'] == 'origin.runner.lab', info
                        assert info['flow.http3.path'] == f'/views/{stream}', info
                        assert info['flow.http3.url'] == f'https://origin.runner.lab/views/{stream}', info
        assert proxy.poll() is None
        (root / 'quic-engine-views-webhooks.json').write_text(json.dumps(events, indent=2))
        print(f'PASS H3 views ({"dynamic" if dynamic else "static"}): late split, {len(content)} annotated input callbacks', flush=True)
    finally:
        if peer.poll() is None:
            peer.terminate(); peer.wait(timeout=5)
        (root / 'quic-engine-views-events.json').write_text(json.dumps(hooks.snapshot(), indent=2))


async def main(mode, root):
    from aioquic.asyncio import QuicConnectionProtocol, connect, serve
    from aioquic.h3.connection import H3Connection
    from aioquic.h3.events import HeadersReceived, DataReceived
    from aioquic.quic.configuration import QuicConfiguration

    class Peer(QuicConnectionProtocol):
        def __init__(self, *args, **kwargs):
            super().__init__(*args, **kwargs)
            self.http = H3Connection(self._quic)
            self.responses = {}
            self.bodies = {}

        def quic_event_received(self, event):
            for item in self.http.handle_event(event):
                if mode == 'origin' and isinstance(item, HeadersReceived):
                    fields = dict(item.headers)
                    if dynamic:
                        with (root / 'dynamic-origin.jsonl').open('a') as log:
                            log.write(json.dumps({'stream': item.stream_id, 'method': fields[b':method'].decode()}) + '\n')
                    body = fields[b':method'] + b' ' + fields[b':path']
                    self.http.send_headers(item.stream_id, [(b':status', b'200'), (b'x-raw', b'\xff'),
                        (b'set-cookie', b'a=1'), (b'set-cookie', b'b=2')])
                    self.http.send_data(item.stream_id, body, end_stream=dynamic)
                    if not dynamic:
                        self.http.send_headers(item.stream_id, [(b'x-trailer', b'done')], end_stream=True)
                    self.transmit()
                elif mode == 'client' and isinstance(item, HeadersReceived) and item.stream_ended:
                    self.responses[item.stream_id].set_result(bytes(self.bodies[item.stream_id]))
                elif mode == 'client' and isinstance(item, DataReceived):
                    self.bodies[item.stream_id].extend(item.data)
                    if item.stream_ended:
                        self.responses[item.stream_id].set_result(bytes(self.bodies[item.stream_id]))

    config = QuicConfiguration(is_client=mode == 'client', alpn_protocols=['h3'])
    certs = root / 'config/certs'
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
            if dynamic:
                from quic_engine_dynamic import run_client
                await run_client(client, root)
                return
            for stream in (0, 4, 8):
                assert client._quic.get_next_available_stream_id() == stream
                client.responses[stream] = asyncio.get_running_loop().create_future()
                client.bodies[stream] = bytearray()
                client._quic.send_stream_data(stream, request_frame(stream), end_stream=stream != 4)
                client.transmit()
                body = await asyncio.wait_for(client.responses[stream], 10)
                expected = (b'POST' if stream == 4 else b'GET') + f' /views/{stream}'.encode()
                assert body == expected, (body, expected)
                if stream == 4:
                    # Keep this child alive while CLI/API inspect both rewrite views.
                    (root / 'diagnostics-ready').touch()
                    deadline = asyncio.get_running_loop().time() + 20
                    while not (root / 'diagnostics-release').exists():
                        assert asyncio.get_running_loop().time() < deadline
                        await asyncio.sleep(0.02)
                    client._quic.send_stream_data(stream, b'', end_stream=True)
                    client.transmit()


if __name__ == '__main__':
    asyncio.run(main(sys.argv[1], Path(sys.argv[2])))
