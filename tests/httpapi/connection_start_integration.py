"""Setup decisions through the real SOCKS/TLS proxy, not a mock datapath."""
import ssl
import threading
import base64

from need_more_integration import TLS_HOSTNAME, receive, silent


REQUEST = b'GET /setup HTTP/1.1\r\nHost: example.test\r\n\r\n'


def closed(sock):
    sock.settimeout(5)
    try:
        assert sock.recv(1) == b'', 'Setup drop leaked application bytes'
    except ConnectionResetError:
        pass


def run(connection, send, set_reply, server, source, tls=False):
    scenarios = 0

    def set_start(status=200, body=None):
        server.start_reply = lambda event: (status, {} if body is None else body)

    # A held setup reply is a deterministic ordering probe. Neither the origin
    # nor the content webhook may receive the waiting application bytes.
    for server_first in (False, True):
        entered, release = threading.Event(), threading.Event()

        def delayed(event):
            entered.set()
            assert release.wait(5), 'Test did not release setup gate'
            return 200, {'action': 'accept'}

        server.start_reply = delayed
        with connection(warmup=False) as (client, origin):
            before_starts, before_content = len(server.starts), len(server.received)
            sender, receiver = (origin, client) if server_first else (client, origin)
            data = b'220 setup server greeting\r\n' if server_first else REQUEST
            try:
                sender.sendall(data)
                assert entered.wait(5), 'Missing connection-start'
                silent(receiver)
                assert len(server.received) == before_content, 'Content raced ahead of setup'
                event = server.starts[-1]
                info = event['details']['info']
                assert info['phase'] == 'setup'
                assert info['source']['host'] == '127.0.0.1'
                assert int(info['destination']['port']) == origin.getsockname()[1]
                assert isinstance(info['policy'], int)
                assert info['transport'] == 'tcp'
                assert info['webhook_control']['sequence'] == 0
                assert 'content' not in info
            finally:
                release.set()

            assert receive(receiver, len(data)) == data
            send(sender, b'next')
            assert receive(receiver, 4) == b'next'
            assert len(server.starts) == before_starts + 1, 'Duplicate setup'
            assert server.received[-1][0] == event['id'], 'Setup/content identity mismatch'
        scenarios += 1

    # An unavailable receiver remains fail-open before strict was negotiated.
    server.start_reply = lambda event: (200, None)
    with connection(warmup=False) as (client, origin):
        send(client, REQUEST)
        assert receive(origin, len(REQUEST)) == REQUEST
    scenarios += 1

    # Legacy replies, non-success responses and malformed replies preserve the
    # regular-mode fail-open contract. Content-only actions never rewrite data.
    for status, body in (
        (200, {}), (204, b''), (202, {'action': 'unchanged'}),
        (200, {'action': 'accept'}), (503, {'action': 'drop'}),
        (200, b'not-json'), (200, {'action': 'discard'}),
        (200, {'action': 'replace', 'content': 'RVZJTA=='}),
    ):
        set_start(status, body)
        with connection(warmup=False) as (client, origin):
            send(client, REQUEST)
            assert receive(origin, len(REQUEST)) == REQUEST
        scenarios += 1

    for server_first in (False, True):
        set_start(body={'action': 'drop'})
        with connection(warmup=False) as (client, origin):
            before = len(server.received)
            sender, receiver = (origin, client) if server_first else (client, origin)
            sender.sendall(b'220 dropped\r\n' if server_first else REQUEST)
            closed(receiver)
            closed(sender)
            assert len(server.received) == before, 'Drop still invoked content webhook'
        scenarios += 1

    set_start(body={'action': 'not-interested'})
    with connection(warmup=False) as (client, origin):
        before = len(server.received)
        client.sendall(REQUEST)
        assert receive(origin, len(REQUEST)) == REQUEST
        origin.sendall(b'reply')
        assert receive(client, 5) == b'reply'
        assert len(server.received) == before, 'not-interested still delivered content'
    scenarios += 1

    set_start(body={'action': 'replace', 'control': {'mode': 'strict'}})
    with connection(warmup=False) as (client, origin):
        before = len(server.received)
        client.sendall(REQUEST)
        closed(origin)
        assert len(server.received) == before, 'Invalid strict setup leaked content'
    scenarios += 1

    # Control must be applied before the very first content callback.
    set_start(body={'action': 'accept', 'control': {'mode': 'strict'}})
    with connection(warmup=False) as (client, origin):
        send(client, REQUEST)
        assert receive(origin, len(REQUEST)) == REQUEST
        control = server.metadata[-1]['webhook_control']
        assert control['mode'] == 'strict' and control['sequence'] == 1
    scenarios += 1

    set_start(body={'action': 'not-interested', 'control': {'mode': 'strict'}})
    with connection(warmup=False) as (client, origin):
        before = len(server.received)
        client.sendall(REQUEST)
        closed(origin)
        assert len(server.received) == before
    scenarios += 1

    # Length changes and holding still need setup, never a retroactive opt-in.
    # No original or replacement bytes may leak on failure.
    for body in ({}, {'control': {'rewrite': False}}, {'control': {'rewrite': 'yes'}}):
        for action in ('replace', 'need-more', 'discard'):
            set_start(body=body)
            with connection(warmup=False) as (client, origin):
                response = {'action': action, 'control': {'rewrite': True}}
                if action == 'replace':
                    response['content'] = base64.b64encode(b'changed').decode()
                set_reply(lambda data, response=response: (200, response))
                send(client, REQUEST)
                closed(origin)
                closed(client)
                assert server.metadata[-1]['webhook_control']['rewrite'] is False
            scenarios += 1

    # Same-size replacements are deliberately allowed without a reservation,
    # including arbitrary bytes, either direction and strict delivery mode.
    # Subsequent callbacks must still advertise rewrite=false: no late upgrade.
    for reservation in (None, False, 'yes'):
        for strict in (False, True):
            if reservation == 'yes' and strict:
                continue  # Invalid strict setup must close before content.

            control = {'mode': 'strict' if strict else 'regular'}
            if reservation is not None:
                control['rewrite'] = reservation

            for server_first in (False, True):
                set_start(body={'control': control})
                with connection(warmup=False) as (client, origin):
                    sender, receiver = (origin, client) if server_first else (client, origin)
                    set_reply(lambda data: (200, {'action': 'replace',
                        'content': base64.b64encode(bytes(value ^ 0x20 for value in data)).decode()}))

                    for data in (REQUEST, bytes(range(256))):
                        send(sender, data)
                        expected = bytes(value ^ 0x20 for value in data)
                        assert receive(receiver, len(expected)) == expected
                        assert server.metadata[-1]['webhook_control']['rewrite'] is False
                        assert server.metadata[-1]['webhook_control']['mode'] == control['mode']
                scenarios += 1

    # Check decoded byte counts, not base64 lengths (both envelopes are equal
    # length in these cases). Reject shrinking and growing in either direction.
    for original, replacement in ((b'abc', b'ab'), (b'abcd', b'abcde')):
        assert len(base64.b64encode(original)) == len(base64.b64encode(replacement))
        for server_first in (False, True):
            set_start()
            with connection(warmup=False) as (client, origin):
                sender, receiver = (origin, client) if server_first else (client, origin)
                set_reply(lambda data, replacement=replacement: (200, {'action': 'replace',
                    'content': base64.b64encode(replacement).decode()}))
                send(sender, original)
                closed(receiver)
                closed(sender)
            scenarios += 1

    # Supplying equal-size content must not disguise a hold/discard as replace.
    for action in ('need-more', 'discard', 'accept'):
        set_start()
        with connection(warmup=False) as (client, origin):
            set_reply(lambda data, action=action: (200, {'action': action,
                'content': base64.b64encode(data).decode()}))
            send(client, REQUEST)
            closed(origin)
            closed(client)
        scenarios += 1

    for server_first in (False, True):
        set_start(body={'control': {'rewrite': True}})
        with connection(warmup=False) as (client, origin):
            sender, receiver = (origin, client) if server_first else (client, origin)
            set_reply(lambda data: (200, {'action': 'replace',
                'content': base64.b64encode(b'changed').decode()}))
            send(sender, REQUEST)
            assert receive(receiver, 7) == b'changed'
            assert server.metadata[-1]['webhook_control']['rewrite'] is True
        scenarios += 1

    # Dropping the connection is a decision, not a content rewrite.
    set_start()
    with connection(warmup=False) as (client, origin):
        set_reply(lambda data: (200, {'action': 'drop'}))
        send(client, REQUEST)
        closed(origin)
        closed(client)
    scenarios += 1

    # TLS metadata must be available at setup, not merely at connection-stop.
    # Certificate trust is intentionally disabled in this private lab fixture.
    if not tls:
        assert not server.errors, server.errors
        if server.binary_enabled:
            assert server.binary_count > 0, 'Binary content transport was not exercised'
        print(f'COMPLETED connection-start: {scenarios} scenarios; '
              'TLS omitted (requires --setup-tls in a private namespace)', flush=True)
        return

    set_start(body={'action': 'accept'})
    server_tls = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    server_tls.load_cert_chain(source / 'etc/certs/default/srv-cert.pem',
                               source / 'etc/certs/default/srv-key.pem')
    server_tls.set_alpn_protocols(['http/1.1'])
    client_tls = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    client_tls.check_hostname = False
    client_tls.verify_mode = ssl.CERT_NONE
    client_tls.set_alpn_protocols(['http/1.1'])
    with connection(warmup=False, target_port=443, tls=(client_tls, server_tls)) as (client, origin):
        before = len(server.starts)
        send(client, REQUEST)
        assert receive(origin, len(REQUEST)) == REQUEST
        assert len(server.starts) == before + 1
        metadata = server.starts[-1]['details']['info']['tls']
        assert any(leg.get('sni') == TLS_HOSTNAME for leg in metadata.values()), metadata
        assert metadata['server']['alpn'] == 'http/1.1', metadata
    scenarios += 1

    assert not server.errors, server.errors
    print(f'COMPLETED connection-start: {scenarios} scenarios', flush=True)
