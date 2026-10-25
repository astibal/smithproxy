"""Scenarios for need_more_integration.py --h2-views.

Uses real SOCKS forwarding and HTTP content callbacks. Native tests inspect
internal HPACK/SETTINGS state; these check byte delivery and webhook annotations.
Neither test runs Spider: the deterministic webhook is its protocol stand-in.
"""
import base64

from need_more_integration import receive, silent


def frame(kind, flags=0, stream=0, payload=b''):
    return len(payload).to_bytes(3, 'big') + bytes((kind, flags)) + stream.to_bytes(4, 'big') + payload


def run(connection, send, set_reply, server):
    preface = b'PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n'
    request = b'\x83\x87\x84\x01\x0cexample.test'  # POST https /, authority
    scenarios = 0

    def forward(sender, receiver, data, output=None):
        expected = data if output is None else output
        pending = bytearray()

        def reply(chunk):
            if output is None:
                return 200, {'action': 'unchanged'}
            pending.extend(chunk)
            assert data.startswith(pending), 'Unexpected input while collecting replacement'
            if len(pending) < len(data):
                return 200, {'action': 'need-more'}
            return 200, {'action': 'replace', 'content': base64.b64encode(output).decode()}

        set_reply(reply)
        start = len(server.received)
        observed = send(sender, data)
        if expected:
            assert receive(receiver, len(expected)) == expected
        else:
            silent(receiver)
        # Give spurious output-side callbacks an opportunity to surface.
        silent(receiver)
        assert len(server.received) == start + len(observed), 'Output invoked the webhook again'
        return server.metadata[start:]

    for first_sender in ('client', 'server'):
        with connection(warmup=False) as (client, origin):
            forward(client, origin, preface + frame(4))
            forward(origin, client, frame(4))
            forward(client, origin, frame(4, 1))
            forward(origin, client, frame(4, 1))

            # First mutation on either side, then a reply and another request.
            original = frame(1, 4, 1, request)
            if first_sender == 'client':
                metadata = forward(client, origin, original, frame(1, 4, 1, b'\x82' + request[1:]))
                assert metadata[-1].get('flow.http2.method') == 'POST', metadata
                metadata = forward(origin, client, frame(1, 4, 1, b'\x88'))
                # The response must be annotated using what the SERVER saw,
                # not the original POST retained by the client-side view.
                assert metadata[-1].get('flow.http2.method') == 'GET', metadata
            else:
                forward(client, origin, original)
                forward(origin, client, frame(1, 4, 1, b'\x88'), frame(1, 4, 1, b'\x8d'))

            metadata = forward(client, origin, frame(1, 4, 3, request))
            assert metadata[-1].get('flow.http2.method') == 'POST', metadata
            forward(origin, client, frame(1, 4, 3, b'\x88'))

            # Both sides can independently rewrite and then continue framing.
            for sender, receiver in ((client, origin), (origin, client)):
                metadata = forward(sender, receiver, frame(0, 0, 3, b'abc'),
                                   frame(0, 0, 3, b'longer body'))
                assert any(a[2] == 'h2.data' for info in metadata
                           for a in info['content_annotations']), metadata
                body = frame(0, 0, 3, b'hello')
                forward(sender, receiver, body[:11], b'')
                metadata = forward(sender, receiver, body[11:], frame(0, 0, 3, b'held and rewritten'))
                # The input is the remaining three DATA bytes, NOT a frame header.
                assert metadata[-1]['L7_payload_start'] == [0], metadata
                assert metadata[-1]['L7_payload_end'] == [3], metadata

            forward(client, origin, frame(6, payload=b'12345678'))
            forward(origin, client, frame(6, 1, payload=b'12345678'))
            forward(client, origin, frame(1, 4, 5, request))
            forward(origin, client, frame(1, 4, 5, b'\x88'))
            scenarios += 1

    # Split on the very first callback, before the receiver has seen a preface.
    with connection(warmup=False) as (client, origin):
        initial = preface + frame(4)
        forward(client, origin, initial, b'')
        first_request = frame(1, 4, 1, request)
        forward(client, origin, first_request, initial + first_request)
        forward(origin, client, frame(4))
        forward(origin, client, frame(4, 1))
        forward(client, origin, frame(4, 1))
        forward(origin, client, frame(1, 4, 1, b'\x88'))
        forward(client, origin, frame(6, payload=b'abcdefgh'))
        forward(origin, client, frame(6, 1, payload=b'abcdefgh'))
        scenarios += 1

    # Plaintext detection may become available only after the second read.
    with connection(warmup=False) as (client, origin):
        forward(client, origin, preface[:12])
        forward(client, origin, preface[12:] + frame(4))
        forward(origin, client, frame(4))
        forward(origin, client, frame(4, 1))
        forward(client, origin, frame(4, 1))
        metadata = forward(client, origin, frame(1, 4, 1, request),
                           frame(1, 4, 1, b'\x82' + request[1:]))
        assert metadata[-1].get('flow.http2.method') == 'POST', metadata
        forward(origin, client, frame(1, 4, 1, b'\x88'))
        scenarios += 1

    # Split an in-progress HEADERS block, then verify that the opposite input
    # uses the rewritten request's context. Neither view loses CONTINUATION.
    with connection(warmup=False) as (client, origin):
        forward(client, origin, preface + frame(4))
        forward(origin, client, frame(4))
        forward(client, origin, frame(4, 1))
        forward(origin, client, frame(4, 1))
        forward(client, origin, frame(1, 0, 1, request[:3]))
        tail = request[3:]
        changed = b'\x01\x0cchanged.test'
        forward(client, origin, frame(9, 4, 1, tail), frame(9, 4, 1, changed))
        metadata = forward(origin, client, frame(1, 4, 1, b'\x88'))
        assert metadata[-1].get('flow.http2.method') == 'POST', metadata
        forward(client, origin, frame(0, stream=1, payload=b'body'))
        forward(origin, client, frame(0, stream=1, payload=b'reply'))
        scenarios += 1

    # Hold a partial frame while the other direction continues. Releasing the
    # first direction must not replay, lose or misattribute the intervening data.
    with connection(warmup=False) as (client, origin):
        forward(client, origin, preface + frame(4))
        forward(origin, client, frame(4))
        forward(client, origin, frame(4, 1))
        forward(origin, client, frame(4, 1))
        forward(client, origin, frame(1, 4, 1, request))
        forward(origin, client, frame(1, 4, 1, b'\x88'))
        data = frame(0, stream=1, payload=b'held')
        forward(client, origin, data[:7], b'')
        metadata = forward(origin, client, frame(0, stream=1, payload=b'opposite'))
        assert any(a[2] == 'h2.data' for info in metadata
                   for a in info['content_annotations']), metadata
        forward(client, origin, data[7:], frame(0, stream=1, payload=b'released'))
        forward(client, origin, frame(6, payload=b'abcdefgh'))
        forward(origin, client, frame(6, 1, payload=b'abcdefgh'))
        scenarios += 1

    assert not server.errors, server.errors
    print(f'PASS H2 endpoint views: {scenarios} bidirectional scenarios; '
          f'{len(server.received)} input callbacks; no output callbacks', flush=True)
