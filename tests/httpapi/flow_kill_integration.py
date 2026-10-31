"""Exercise callback-local HTTP/1 connection termination through real sockets."""

from need_more_integration import receive


def closed(sock):
    sock.settimeout(5)
    try:
        assert sock.recv(1) == b'', 'Connection-close callback leaked request bytes'
    except ConnectionResetError:
        pass


def run(connection, send, set_reply, server):
    request = b'GET /kill HTTP/1.1\r\nHost: example.test\r\n\r\n'
    exact_close = {
        'action': 'close',
        'control': {'mode': 'strict'},
        'reason': 'Connection killed.',
    }

    with connection(warmup=False) as (client, origin):
        set_reply(lambda data: (200, exact_close))
        send(client, request)
        assert server.metadata[-1]['webhook_control']['connection-close'] is True
        closed(client)
        closed(origin)

    # A close is scoped to one connection. A fresh flow remains usable.
    with connection(warmup=False) as (client, origin):
        set_reply(lambda data: (200, {'action': 'unchanged'}))
        send(client, request)
        assert receive(origin, len(request)) == request

    # Ambiguous close-shaped replies fail closed without forwarding bytes.
    invalid = [
        {**exact_close, 'content': ''},
        {**exact_close, 'control': {'mode': 'regular'}},
        {**exact_close, 'reason': ''},
        {**exact_close, 'reason': 'bad\nreason'},
        {**exact_close, 'reason': 'x' * 1025},
    ]
    for reply in invalid:
        with connection(warmup=False) as (client, origin):
            set_reply(lambda data, reply=reply: (200, reply))
            send(client, request)
            closed(client)
            closed(origin)

    assert not server.errors, server.errors
    print(f'PASS HTTP/1 flow.kill: 1 exact close, 1 scoped survivor, '
          f'{len(invalid)} fail-closed replies', flush=True)
