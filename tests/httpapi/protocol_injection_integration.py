"""Real proxy + HTTP/SXBN webhook + sockets; no Spider or fake write buffers."""
import base64

from need_more_integration import receive, silent
from protocol_views_integration import frame


def reply(forward, reverse):
    return 200, {'action': 'replace', 'content': base64.b64encode(forward).decode(),
                 'content-reverse': base64.b64encode(reverse).decode()}


def closed(sock):
    sock.settimeout(5)
    try:
        assert sock.recv(1) == b'', 'Rejected directional output leaked bytes'
    except ConnectionResetError:
        pass


def run(connection, send, set_reply, server):
    preface = b'PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n'
    request = b'\x83\x87\x84\x01\x0cexample.test'
    count = 0

    def forward(sender, receiver, wire):
        set_reply(lambda data: (200, {'action': 'unchanged'}))
        send(sender, wire)
        assert receive(receiver, len(wire)) == wire

    def setup(client, origin):
        forward(client, origin, preface + frame(4))
        forward(origin, client, frame(4))
        forward(client, origin, frame(4, 1))
        forward(origin, client, frame(4, 1))
        forward(client, origin, frame(1, 4, 1, request))
        forward(origin, client, frame(1, 4, 1, b'\x88'))

    for reverse_direction in (False, True):
        for reverse_size in (0, 3, 32768):
            with connection(warmup=False) as (client, origin):
                setup(client, origin)
                sender, receiver = (origin, client) if reverse_direction else (client, origin)
                previous = frame(0, stream=1, payload=b'previous')
                set_reply(lambda data: (200, {'action': 'unchanged'}))
                send(receiver, previous)  # Leave preceding output unread at sender.

                source = frame(0, stream=1, payload=b'input')
                output = frame(0, stream=1, payload=b'changed')
                backward = b''.join(frame(0, stream=1, payload=b'r' * min(16384, reverse_size - pos))
                                    for pos in range(0, reverse_size, 16384))
                pending = bytearray()

                def replacement(data):
                    pending.extend(data)
                    assert source.startswith(pending)
                    if len(pending) < len(source):
                        return 200, {'action': 'need-more'}
                    return reply(output, backward)

                set_reply(replacement)
                start = len(server.received)
                seen = send(sender, source)
                assert receive(receiver, len(output)) == output
                assert receive(sender, len(previous + backward)) == previous + backward
                silent(receiver)
                silent(sender)
                assert len(server.received) == start + len(seen), 'Injection triggered another webhook'
                assert server.metadata[-1]['webhook_control']['content-reverse'] is True
                assert any(a[2] == 'h2.data' for info in server.metadata[start:]
                           for a in info['content_annotations'])

                # Subsequent native input still has the correct frame boundaries.
                forward(sender, receiver, frame(0, stream=1, payload=b'next'))
                forward(receiver, sender, frame(0, stream=1, payload=b'reply'))
                count += 1

        with connection(warmup=False) as (client, origin):
            setup(client, origin)
            sender, receiver = (origin, client) if reverse_direction else (client, origin)
            settings = frame(4, payload=b'\x00\x01\x00\x00\x00\x00')
            source = frame(0, stream=1, payload=b'held')
            set_reply(lambda data: (200, {'action': 'need-more'}))
            send(sender, source[:7])  # Split even the nine-byte frame header.
            silent(sender)
            silent(receiver)
            set_reply(lambda data: reply(b'', settings))
            send(sender, source[7:])
            assert receive(sender, len(settings)) == settings
            silent(receiver)  # No new reverse read was needed to trigger write.

            set_reply(lambda data: reply(b'', b''))
            send(sender, frame(4, 1))  # Consume ACK belonging to our injection.
            silent(receiver)
            forward(client, origin, frame(1, 4, 3, request))
            forward(origin, client, frame(1, 4, 3, b'\x88'))
            count += 1

    # Both directions must remain empty even if one field is perfectly valid.
    for bad in (
        {'action': 'replace', 'content': 'YQ==', 'content-reverse': '!bad'},
        {'action': 'replace', 'content': '!bad', 'content-reverse': 'YQ=='},
        {'action': 'need-more', 'content': '', 'content-reverse': 'YQ=='},
        {'content': '', 'content-reverse': 'YQ=='},
        {'action': 'replace', 'content': '', 'content-reverse': None},
        {'action': 'replace', 'content': '', 'content-reverse': 'A' * 1398108},
    ):
        with connection(warmup=False) as (client, origin):
            setup(client, origin)
            set_reply(lambda data, bad=bad: (200, bad))
            send(client, frame(0, stream=1, payload=b'must-not-pass'))
            closed(client)
            closed(origin)
            count += 1

    # No same-size escape hatch for reverse output without setup permission.
    saved = server.start_reply
    server.start_reply = lambda event: (200, {'action': 'accept', 'control': {'rewrite': False}})
    try:
        with connection(warmup=False) as (client, origin):
            setup(client, origin)
            set_reply(lambda data: reply(data, frame(6, payload=b'12345678')))
            send(client, frame(0, stream=1, payload=b'data'))
            assert server.metadata[-1]['webhook_control']['content-reverse'] is False
            closed(client)
            closed(origin)
            count += 1
    finally:
        server.start_reply = saved

    with connection() as (client, origin):
        # Rewrite permission alone is insufficient before an adapter is known.
        set_reply(lambda data: reply(data, b'reverse'))
        send(client, b'opaque input')
        assert server.metadata[-1]['webhook_control']['content-reverse'] is False
        closed(client)
        closed(origin)
        count += 1

    assert not server.errors, server.errors
    print(f'PASS directional injection: {count} socket scenarios; no recursive webhook', flush=True)
