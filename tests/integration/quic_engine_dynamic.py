"""Deterministic dynamic-QPACK fixture for the real H3 integration driver.

The fixture deliberately delays encoder instructions. Local pylsqpack decoding
proves blocking independently of network timing; origin observations prove that
the blocked streams did not reach the HTTP handler before those instructions.
"""
import asyncio
import base64
import json
import os


def fields(method=b'GET'):
    return [(b':method', method), (b':scheme', b'https'),
            (b':authority', b'origin.runner.lab'), (b':path', b'/dynamic'),
            (b'x-shared', b'repeated-dynamic-value')]


def fixture():
    import pylsqpack
    from aioquic.buffer import encode_uint_var
    encoder = pylsqpack.Encoder()
    capacity = encoder.apply_settings(4096, 16)
    frames, instructions, blocks = {}, {}, {}
    for stream in (0, 4, 8, 12):
        instructions[stream], blocks[stream] = encoder.encode(stream, fields())
        frames[stream] = b'\x01' + encode_uint_var(len(blocks[stream])) + blocks[stream]
    assert instructions[4] and not instructions[0]
    assert not instructions[8] and not instructions[12]
    assert blocks[8][2] == 0xd1  # Static :method GET follows the two-byte prefix.
    decoder = pylsqpack.Decoder(4096, 16)
    decoder.feed_encoder(capacity)
    decoder.feed_header(0, blocks[0])
    for stream in (4, 8):
        try:
            decoder.feed_header(stream, blocks[stream])
        except pylsqpack.StreamBlocked:
            pass
        else:
            raise AssertionError('fixture must require missing dynamic entries')
    assert set(decoder.feed_encoder(instructions[4])) == {4, 8}
    for stream in (4, 8):
        _, decoded = decoder.resume_header(stream)
        assert decoded == fields()
    return encoder, capacity, frames, instructions


_pending = bytearray()


def reply(event, default, root):
    info = event.get('details', {}).get('info', {})
    stream = info.get('stream_id')
    if event['_test_receiver'] == 'sift':
        return {'action': 'unchanged'}
    if event['action'] == 'connection-start' and stream == 8:
        return {'action': 'accept', 'control': {'rewrite': True}}
    if event['action'] != 'connection-content' or info.get('side') != 'L':
        return default
    data = base64.b64decode(info['content'], validate=True)
    if stream in (4, 8) and not info.get('flow.http3'):
        if stream == 4:
            (root / 'dynamic-blocked-4').touch()
            return default
        _pending.extend(data)
        _, _, frames, _ = fixture()
        expected = frames[8]
        assert expected.startswith(_pending), (expected, _pending)
        if len(_pending) < len(expected):
            return {'action': 'need-more'}
        # Change only the static method index, preserving all dynamic refs.
        rewritten = bytearray(expected)
        assert len(expected) < 64 and rewritten[4] == 0xd1
        rewritten[4] = 0xd4  # POST, same static table and encoded length.
        _pending.clear()
        (root / 'dynamic-blocked-8').touch()
        return {'action': 'replace', 'content': base64.b64encode(rewritten).decode()}
    return default


async def wait_for(check, timeout=10):
    async with asyncio.timeout(timeout):
        while not check():
            await asyncio.sleep(.01)


async def run_client(client, root):
    await wait_for(lambda: client.http.received_settings is not None)
    encoder, capacity, frames, instructions = fixture()
    # Use this encoder for feedback too: the peer's decoder acknowledgements
    # must refer to the same header sections as our deliberately ordered bytes.
    client.http._encoder = encoder
    client._quic.send_stream_data(client.http._local_encoder_stream_id, capacity)

    async def send(stream, fin=True):
        assert client._quic.get_next_available_stream_id() == stream
        client.responses[stream] = asyncio.get_running_loop().create_future()
        client.bodies[stream] = bytearray()
        wire = frames[stream]
        fragmented = os.environ.get('H3_VIEWS_CASE') == 'dynamic-fragmented' and stream in (4, 8)
        chunk_size = 1 if fragmented else len(wire)
        for offset in range(0, len(wire), chunk_size):
            end = min(len(wire), offset + chunk_size)
            client._quic.send_stream_data(stream, wire[offset:end], end_stream=fin and end == len(wire))
            client.transmit()
            if fragmented:
                await asyncio.sleep(.02)

    await send(0)
    assert await asyncio.wait_for(client.responses[0], 10) == b'GET /dynamic'
    await send(4, False)
    await wait_for(lambda: (root / 'dynamic-blocked-4').exists())
    await send(8, False)  # Late split while stream 4 is still blocked.
    await wait_for(lambda: (root / 'dynamic-blocked-8').exists())
    seen = [json.loads(line) for line in (root / 'dynamic-origin.jsonl').read_text().splitlines()]
    assert not any(item['stream'] in (4, 8) for item in seen), seen
    assert not client.responses[4].done() and not client.responses[8].done()

    # Fragment encoder instructions independently of the blocked field sections.
    wire = instructions[4]
    for start in range(0, len(wire), 3):
        client._quic.send_stream_data(client.http._local_encoder_stream_id, wire[start:start + 3])
        client.transmit()
        await asyncio.sleep(.02)
    for stream, method in ((4, b'GET'), (8, b'POST')):
        body = await asyncio.wait_for(client.responses[stream], 10)
        assert body == method + b' /dynamic', body
        # No extra DATA to trigger metadata publication: the encoder-stream
        # callback must already have announced the newly decoded request.
        client._quic.send_stream_data(stream, b'', end_stream=True)
    client.transmit()
    await send(12)
    assert await asyncio.wait_for(client.responses[12], 10) == b'GET /dynamic'


def verify(content, metadata):
    for stream in (0, 4, 8, 12):
        for side in ('L', 'R'):
            observed = [i for i in content + metadata if i['stream_id'] == stream and i['side'] == side
                        and i.get('flow.http3.method')]
            assert observed, (stream, side, content)
            for info in observed:
                assert info['flow.http3.method'] == ('POST' if stream == 8 and side == 'R' else 'GET'), info
                assert info['flow.http3.authority'] == 'origin.runner.lab', info
                assert info['flow.http3.path'] == '/dynamic', info
                assert info['flow.http3.url'] == 'https://origin.runner.lab/dynamic', info
    for stream in (4, 8):
        first = next(i for i in content if i['stream_id'] == stream and i['side'] == 'L')
        assert 'flow.http3.method' not in first, 'blocked headers must not invent metadata'

    if os.environ.get('H3_VIEWS_CASE') == 'dynamic-fragmented':
        fragments = [i for i in content if i['stream_id'] == 8 and i['side'] == 'L'
                     and not i.get('flow.http3')]
        assert len(fragments) > 1, 'network run did not exercise need-more across callbacks'
