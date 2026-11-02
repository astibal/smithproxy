#!/usr/bin/env python3
"""Record real QUIC webhook envelopes and verify transport/stream lifetimes."""
import json
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
import sys


def serve(path):
    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *_args):
            pass

        def do_POST(self):
            event = json.loads(self.rfile.read(int(self.headers['Content-Length'])))
            with path.open('a') as output:
                output.write(json.dumps(event) + '\n')
            action = event.get('action')
            reply = {'action': 'accept'}
            if action == 'info':
                reply = {'action': 'info-response', 'protocols': {}}
            elif action == 'access-request':
                reply = {'access-response': 'accept'}
            body = json.dumps(reply).encode()
            self.send_response(200)
            self.send_header('Content-Type', 'application/json')
            self.send_header('Content-Length', str(len(body)))
            self.end_headers()
            self.wfile.write(body)

    server = HTTPServer(('127.0.0.1', 59090), Handler)
    path.with_suffix('.ready').touch()
    server.serve_forever()


def verify(path):
    events = [json.loads(line) for line in path.read_text().splitlines()]
    parents, streams, stopped, content = {}, {}, set(), set()
    for event in events:
        info = event.get('details', {}).get('info', {})
        scope = info.get('scope')
        if scope not in ('transport', 'stream'):
            continue
        identity, action = event['id'], event['action']
        if action == 'connection-start':
            assert identity not in parents and identity not in streams, 'duplicate setup'
            if scope == 'transport':
                assert info['protocol'] == 'quic'
                assert '+' in info['session'], 'parent lost the endpoint display label'
                parents[identity] = info
            else:
                assert info['parent_id'] in parents, 'stream preceded its parent setup'
                assert type(info['stream_id']) is int
                streams[identity] = info
        elif action in ('connection-content', 'connection-stop'):
            owners = parents if scope == 'transport' else streams
            assert identity in owners, 'event preceded setup'
            assert identity not in stopped, 'event followed stop'
            if scope == 'stream':
                assert info['parent_id'] == owners[identity]['parent_id']
                assert info['stream_id'] == owners[identity]['stream_id']
            if action == 'connection-content':
                assert scope == 'stream', 'physical parent must not deliver stream content'
                content.add(identity)
            else:
                stopped.add(identity)
    assert parents, 'no physical QUIC setup received'
    assert len(streams) >= 4, 'missing independent stream setups'
    assert content, 'no logical stream content received'
    assert set(streams) <= stopped, 'logical streams did not retire'
    assert set(parents) <= stopped, 'physical parents did not retire'
    print(f'PASS QUIC webhook contract: {len(parents)} parents, {len(streams)} streams')


if __name__ == '__main__':
    operation, filename = sys.argv[1:]
    (serve if operation == 'serve' else verify)(Path(filename))
