#!/usr/bin/env python3
"""Exercise real proxy forwarding with a loopback HTTP content webhook.

No live configuration is touched. Temporary SOCKS, origin and webhook listeners
use ephemeral ports. This tests consumption, not a persistent proxy-side hold.
"""
import argparse
import base64
import contextlib
import concurrent.futures
import http.server
import json
import os
import pathlib
import socket
import subprocess
import sys
import tempfile
import threading
import time

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / 'tls'))
from starttls_socks_integration import ADDRESSES, free_port, make_config, socks_connect


# Match the repository certificate's SAN. Allowing an expired/self-signed
# certificate does not waive hostname checks in the proxy.
TLS_HOSTNAME = 'Smithproxy-Server-Certificate'


class Hook(http.server.BaseHTTPRequestHandler):
    def log_message(self, *_):
        pass

    def do_POST(self):
        raw = self.rfile.read(int(self.headers['Content-Length']))
        try:
            binary = raw.startswith(b'SXBN001:')
            if binary:
                metadata_size = int(raw[8:16], 16)
                payload_size = int(raw[17:25], 16)
                assert len(raw) == 25 + metadata_size + payload_size
                event = json.loads(raw[25:25 + metadata_size])
                payload = raw[25 + metadata_size:]
                self.server.binary_count += 1
            else:
                event = json.loads(raw)
            self.server.actions.append(event.get('action'))
            result = {'action': 'unchanged'}
            status = 200
            if event.get('action') == 'connection-start':
                with self.server.condition:
                    self.server.starts.append(event)
                    self.server.condition.notify_all()
                status, result = self.server.start_reply(event)
            if event.get('action') == 'info' and self.server.binary_enabled:
                result = {'action': 'info-response',
                          'protocols': {'connection-content': ['sxbn-001']}}

            if event.get('action') == 'connection-content':
                info = event['details']['info']
                data = payload if binary else base64.b64decode(info['content'], validate=True)
                with self.server.condition:
                    if self.server.verify_control:
                        control = info['webhook_control']
                        assert control['version'] == 1
                        previous = self.server.sequences.get(event['id'], 0)
                        assert control['sequence'] == previous + 1
                        self.server.sequences[event['id']] = control['sequence']
                        assert control['mode'] in ('regular', 'strict')
                    self.server.received.append((event['id'], info['side'], data))
                    self.server.metadata.append(info)
                    status, result = self.server.reply(data)
                    self.server.condition.notify_all()

            # A test-only missing response exercises the transport error path,
            # rather than merely returning a non-2xx HTTP status.
            if result is None:
                self.close_connection = True
                self.connection.shutdown(socket.SHUT_RDWR)
                return

            response = result if isinstance(result, bytes) else json.dumps(result).encode()
            self.send_response(status)
            self.send_header('Content-Type', 'application/json')
            self.send_header('Content-Length', str(len(response)))
            self.end_headers()
            self.wfile.write(response)
        except (BrokenPipeError, ConnectionResetError):
            # Shutdown may close an asynchronous notification connection.
            pass
        except Exception as error:
            with self.server.condition:
                self.server.errors.append(repr(error))
                self.server.condition.notify_all()
            self.send_error(500)


def receive(sock, size):
    data = bytearray()
    sock.settimeout(5)
    while len(data) < size:
        chunk = sock.recv(size - len(data))
        if not chunk:
            raise AssertionError(f'EOF after {len(data)}/{size} bytes')
        data.extend(chunk)
    return bytes(data)


def silent(sock):
    sock.settimeout(0.15)
    try:
        data = sock.recv(1)
    except socket.timeout:
        return
    raise AssertionError(f'Expected an open silent socket, received {data!r}')


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--smithproxy', type=pathlib.Path, required=True)
    parser.add_argument('--source', type=pathlib.Path, required=True)
    parser.add_argument('--binary', action='store_true')
    parser.add_argument('--control-only', action='store_true')
    parser.add_argument('--replace-only', action='store_true', help='Reproduce resize handling without need-more')
    parser.add_argument('--h2-views', action='store_true', help='Exercise lazy endpoint views through real forwarding')
    parser.add_argument('--setup-only', action='store_true', help='Verify synchronous connection setup decisions')
    parser.add_argument('--setup-tls', action='store_true', help='Also bind TLS origin port 443 (use isolated network namespace)')
    args = parser.parse_args()
    source = args.source.resolve()
    with tempfile.TemporaryDirectory(prefix='need-more-') as directory:
        runtime = pathlib.Path(directory)
        server = http.server.ThreadingHTTPServer(('127.0.0.1', 0), Hook)
        server.condition = threading.Condition()
        server.received, server.errors = [], []
        server.metadata = []
        server.actions = []
        server.starts = []
        server.start_reply = lambda event: (200, {'action': 'accept', 'control': {'rewrite': True}})
        server.binary_enabled, server.binary_count = args.binary, 0
        server.verify_control, server.sequences = args.control_only, {}
        server.reply = lambda data: (200, {'action': 'unchanged'})
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        port = free_port()
        config = runtime / 'smithproxy.cfg'
        make_config(source / 'etc/smithproxy.cfg', config, source, runtime, port, free_port())
        text = config.read_text().replace('settings = {',
            'settings = {\n webhook = { enabled = true; tls_verify = false; '
            f'url = "http://127.0.0.1:{server.server_port}/"; }};', 1)
        text = text.replace('        write_payload = FALSE;',
                            '        write_payload = FALSE; webhook_enable = TRUE; webhook_lock_traffic = FALSE;', 1)
        if args.setup_only:
            # Both plain TCP and implicit TLS use an ordinary local origin;
            # transparent source-address spoofing is not part of this fixture.
            text = text.replace('nat = "auto";', 'nat = "none";')
            for name in ('allow_invalid_certs', 'allow_untrusted_issuers', 'allow_self_signed'):
                text = text.replace(f'{name} = FALSE;', f'{name} = TRUE;')
            text = text.replace('inspect = TRUE;', 'inspect = TRUE; ct_enable = FALSE;', 1)
        config.write_text(text)
        log = open(runtime / 'stdout.log', 'w+')
        process = subprocess.Popen([str(args.smithproxy.resolve()), '--config-file', str(config), '--diagnose'],
            cwd=source, stdout=log, stderr=subprocess.STDOUT,
            env={**os.environ, 'SMITHPROXY_PID_FILE': str(runtime / 'proxy.pid')})

        def set_reply(reply):
            with server.condition:
                server.reply = reply

        def send(sender, data):
            with server.condition:
                before = len(server.received)
                sender.sendall(data)
                ok = server.condition.wait_for(
                    lambda: sum(len(item[2]) for item in server.received[before:]) >= len(data)
                    or server.errors, timeout=10)
                assert ok, 'No content callback'
                assert not server.errors, server.errors
                observed = server.received[before:]
                actual = b''.join(item[2] for item in observed)
                assert actual == data, f'Callback mismatch: expected={data[:100]!r}, actual={actual[:100]!r}'
                return observed

        @contextlib.contextmanager
        def connection(warmup=True, target_port=0, tls=None):
            with socket.socket() as listener:
                listener.bind(('127.0.0.1', target_port))
                listener.listen()
                listener.settimeout(5)
                if tls:
                    client_context, origin_context = tls

                    def tls_accept():
                        peer, _ = listener.accept()
                        peer.settimeout(10)
                        return origin_context.wrap_socket(peer, server_side=True)

                    # The origin must handshake concurrently with SOCKS setup;
                    # waiting for CONNECT success before serving TLS deadlocks.
                    with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
                        accepted = pool.submit(tls_accept)
                        try:
                            with socks_connect(port, target_port, ADDRESSES['ipv4-ip']) as raw:
                                with client_context.wrap_socket(raw, server_hostname=TLS_HOSTNAME) as client:
                                    with accepted.result(timeout=10) as origin:
                                        set_reply(lambda data: (200, {'action': 'unchanged'}))
                                        yield client, origin
                        except Exception:
                            try:
                                accepted.result(timeout=12)
                            except Exception as error:
                                print(f'TLS origin: {error!r}', file=sys.stderr)
                            raise
                    return

                with socks_connect(port, listener.getsockname()[1], ADDRESSES['ipv4-ip']) as client:
                    origin, _ = listener.accept()
                    with origin:
                        # Complete protocol sniffing before testing one-byte chunks
                        # or a server-first content callback.
                        set_reply(lambda data: (200, {'action': 'unchanged'}))
                        if warmup:
                            send(client, b'WARMUP PLAINTEXT\r\n')
                            assert receive(origin, 18) == b'WARMUP PLAINTEXT\r\n'
                        yield client, origin

        count = 0
        failures = []
        try:
            deadline = time.monotonic() + 20
            while True:
                assert process.poll() is None, 'Proxy exited during startup'
                try:
                    with socket.create_connection(('127.0.0.1', port), timeout=.1):
                        break
                except OSError:
                    if time.monotonic() > deadline:
                        raise AssertionError('SOCKS startup timeout')
                    time.sleep(.05)

            if args.binary:
                deadline = time.monotonic() + 20
                while 'info' not in server.actions:
                    assert time.monotonic() < deadline, 'No protocol negotiation'
                    time.sleep(.05)
                time.sleep(.1)

            if args.setup_only:
                from connection_start_integration import run
                run(connection, send, set_reply, server, source, tls=args.setup_tls)
                return

            if args.h2_views:
                from protocol_views_integration import run
                run(connection, send, set_reply, server)
                return

            if args.control_only:
                for failure in ((503, {'control': {'mode': 'regular'}}),
                                (200, b'invalid-json'), (200, [])):
                    with connection() as (client, origin):
                        set_reply(lambda data: (200, {'control': {'mode': 'strict'}}))
                        send(client, b'ARM')
                        assert receive(origin, 3) == b'ARM'
                        set_reply(lambda data: (200, {'control': {'mode': 'unknown'}}))
                        send(client, b'KEEP')
                        assert receive(origin, 4) == b'KEEP'
                        set_reply(lambda data: failure)
                        send(client, b'MUST-NOT-PASS')
                        origin.settimeout(5)
                        try:
                            assert origin.recv(1) == b'', 'Strict content leaked'
                        except ConnectionResetError:
                            pass

                with connection() as (client, origin):
                    for mode in ('strict', 'regular'):
                        set_reply(lambda data, mode=mode: (200, {'control': {'mode': mode}}))
                        send(client, b'MODE')
                        assert receive(origin, 4) == b'MODE'
                    set_reply(lambda data: (503, {}))
                    send(client, b'FAIL-OPEN')
                    assert receive(origin, 9) == b'FAIL-OPEN'

                with connection() as (client, origin):
                    set_reply(lambda data: (200, {'action': 'not-interested',
                                                  'control': {'mode': 'strict'}}))
                    send(client, b'ARM')
                    assert receive(origin, 3) == b'ARM'
                    set_reply(lambda data: (200, {'action': 'unchanged'}))
                    send(client, b'STILL-CALLING')
                    assert receive(origin, 13) == b'STILL-CALLING'
                print('PASS control strict/regular, failure closure and not-interested guard', flush=True)
                return

            if args.replace_only:
                with connection() as (client, origin):
                    set_reply(lambda data: (200, {'action': 'replace',
                        'content': base64.b64encode(b'longer replacement').decode()}))
                    send(client, b'!')
                    assert receive(origin, 18) == b'longer replacement'
                    silent(origin)
                    set_reply(lambda data: (200, {'action': 'unchanged'}))
                    send(client, b'NEXT')
                    assert receive(origin, 4) == b'NEXT'
                return

            # Exercise the copying path and the zero-copy path independently.
            # A replacement must never become input to the following callback,
            # whether it grows, shrinks, keeps its size or becomes empty.
            for reverse in (False, True):
                for warm_size in (0, 32768):
                    for output_size in (0, 3, 16, 128, 65536):
                        with connection() as (client, origin):
                            sender, receiver = (origin, client) if reverse else (client, origin)
                            if warm_size:
                                send(sender, b'W' * warm_size)
                                assert receive(receiver, warm_size) == b'W' * warm_size

                            replacement = bytes(i % 256 for i in range(output_size))
                            set_reply(lambda data: (200, {'action': 'replace',
                                'content': base64.b64encode(replacement).decode()}))
                            send(sender, b'0123456789abcdef')
                            assert receive(receiver, output_size) == replacement
                            silent(receiver)
                            set_reply(lambda data: (200, {'action': 'unchanged'}))
                            send(sender, b'NEXT')
                            assert receive(receiver, 4) == b'NEXT'
                            silent(receiver)
                            count += 1
            print('PASS 20 resize/copy/fastlane/direction combinations', flush=True)

            # Repeated need-more, binary payloads, both directions and replacement
            # length changes. A peer socket must remain silent after every hold.
            for reverse in (False, True):
                for size in (1, 17, 4096, 65536):
                    with connection() as (client, origin):
                        sender, receiver = (origin, client) if reverse else (client, origin)
                        held = bytearray()
                        def hold(data):
                            held.extend(data)
                            reply = {'action': 'need-more'}
                            if size > 1:
                                reply['content'] = base64.b64encode(b'MUST NOT LEAK').decode()
                            return 200, reply
                        set_reply(hold)
                        for _ in range(3):
                            send(sender, bytes(i % 256 for i in range(size)))
                            silent(receiver)
                        result = b'REASSEMBLED:' + bytes(held) + b':END'
                        set_reply(lambda data: (200, {'action': 'replace', 'content': base64.b64encode(result).decode()}))
                        send(sender, b'!')
                        assert receive(receiver, len(result)) == result
                        silent(receiver)
                        set_reply(lambda data: (200, {'action': 'unchanged'}))
                        try:
                            send(sender, b'NEXT')
                            assert receive(receiver, 4) == b'NEXT'
                        except AssertionError as error:
                            failures.append(f'direction={reverse} chunk={size}: {error}')
                        count += 1
                        print(f'PASS repeated hold/release direction={reverse} chunk={size}', flush=True)

            # HTTP/1 body assembly with a different final Content-Length.
            with connection() as (client, origin):
                set_reply(lambda data: (200, {'action': 'need-more'}))
                send(client, b'POST / HTTP/1.1\r\nHost: test\r\nContent-Length: 6\r\n\r\nab')
                silent(origin)
                send(client, b'cd')
                silent(origin)
                replacement = b'POST / HTTP/1.1\r\nHost: test\r\nContent-Length: 12\r\n\r\nHello world!'
                set_reply(lambda data: (200, {'action': 'replace', 'content': base64.b64encode(replacement).decode()}))
                send(client, b'ef')
                assert receive(origin, len(replacement)) == replacement
                silent(origin)
                count += 1

            for action in ('discard', 'unchanged', 'replace', 'unknown'):
                with connection() as (client, origin):
                    reply = {'action': action}
                    if action == 'replace':
                        reply['content'] = base64.b64encode(b'longer replacement').decode()
                    set_reply(lambda data: (200, reply))
                    send(client, b'abc')
                    if action == 'discard':
                        silent(origin)
                    else:
                        expected = b'longer replacement' if action == 'replace' else b'abc'
                        assert receive(origin, len(expected)) == expected
                        silent(origin)
                    count += 1

            # Document current fail-open semantics, not a fail-closed promise:
            # after a hold, a failing callback passes ONLY its current fragment.
            for status, reply in ((500, {}), (200, b'not-json')):
                with connection() as (client, origin):
                    set_reply(lambda data: (200, {'action': 'need-more'}))
                    send(client, b'HELD')
                    silent(origin)
                    set_reply(lambda data: (status, reply))
                    send(client, b'CURRENT')
                    assert receive(origin, 7) == b'CURRENT'
                    silent(origin)
                    count += 1
                    print(f'PASS observed fail-open after hold: status={status}', flush=True)

            with connection() as (client, origin):
                set_reply(lambda data: (200, {'action': 'not-interested'}))
                send(client, b'first')
                assert receive(origin, 5) == b'first'
                with server.condition:
                    before = len(server.received)
                client.sendall(b'second')
                assert receive(origin, 6) == b'second'
                silent(origin)
                assert len(server.received) == before
                count += 1

            if args.binary:
                assert server.binary_count > 0, 'Binary transport was not exercised'
            print(f'COMPLETED {count} scenarios; {len(failures)} continuation failures; '
                  f'{len(server.received)} content callbacks; '
                  f'{server.binary_count} binary callbacks', flush=True)
            for failure in failures:
                print(f'FAIL subsequent callback: {failure}', flush=True)
            assert not failures, f'{len(failures)} post-replacement regressions'
        except Exception:
            log.flush()
            log.seek(0)
            print(log.read()[-12000:], file=sys.stderr)
            print('Webhook actions:', server.actions, file=sys.stderr)
            for logfile in runtime.glob('messages*'):
                print(logfile.read_text(errors='replace')[-15000:], file=sys.stderr)
            raise
        finally:
            process.terminate()
            try:
                process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait()
            log.close()
            server.shutdown()
            server.server_close()
            thread.join()


if __name__ == '__main__':
    main()
