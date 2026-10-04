#!/usr/bin/env python3
"""Exercise timing and failure transitions across both legs of a TLS MITM."""
import argparse, json, os, select, socket, ssl, struct, threading, time

BASE_PORT = 14443
MODES = ('server_drip', 'upstream_drip', 'bidirectional_stall',
         'upstream_eof', 'partial_server_rst', 'upstream_fatal_alert')

def chunks(payload, size):
    for offset in range(0, len(payload), size):
        yield payload[offset:offset + size]

def linger_rst(sock):
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, struct.pack('ii', 1, 0))

def relay_connection(client, target, mode):
    origin = socket.create_connection(target, timeout=4)
    client.settimeout(4); origin.settimeout(4)
    try:
        if mode == 'upstream_eof':
            client.recv(16384)
            return
        if mode == 'upstream_fatal_alert':
            client.recv(16384)
            client.sendall(b'\x15\x03\x03\x00\x02\x02\x28')
            return
        if mode == 'partial_server_rst':
            origin.sendall(client.recv(16384))
            reply = origin.recv(16384)
            client.sendall(reply[:9])
            linger_rst(client)
            return

        peers = {client: origin, origin: client}
        while peers:
            readable, _, _ = select.select(list(peers), [], [], 4)
            if not readable:
                raise TimeoutError(mode + ' relay stalled')
            for source in readable:
                payload = source.recv(16384)
                if not payload:
                    return
                destination = peers[source]
                drip = ((mode == 'server_drip' and source is origin) or
                        (mode == 'upstream_drip' and source is client) or
                        mode == 'bidirectional_stall')
                if drip:
                    for part in chunks(payload, 7):
                        destination.sendall(part)
                        time.sleep(0.002)
                    if mode == 'bidirectional_stall':
                        time.sleep(0.025)
                else:
                    destination.sendall(payload)
    finally:
        origin.close()
        client.close()

def server(args):
    family = socket.AF_INET6 if ':' in args.host else socket.AF_INET
    target = (args.host, 443)
    listeners = []
    for index, mode in enumerate(MODES):
        listener = socket.socket(family, socket.SOCK_STREAM)
        listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        listener.bind((args.host, BASE_PORT + index)); listener.listen(1)
        listeners.append((listener, mode))
    print('READY', flush=True)
    results = {}
    def accept_one(listener, mode):
        try:
            connection, _ = listener.accept()
            relay_connection(connection, target, mode)
            results[mode] = 'handled'
        except Exception as exc:
            results[mode] = type(exc).__name__ + ': ' + str(exc)
        finally:
            listener.close()
    workers = [threading.Thread(target=accept_one, args=item) for item in listeners]
    for worker in workers: worker.start()
    for worker in workers: worker.join()
    print(json.dumps(results, sort_keys=True))

def tls_context(ca_file, version=None):
    context = ssl.create_default_context(cafile=ca_file)
    context.set_alpn_protocols(['http/1.1'])
    if version:
        context.minimum_version = context.maximum_version = version
    return context

def memory_handshake(host, port, ca_file, send_size=16384, send_delay=0,
                     receive_size=16384, flight_delay=0, version=None):
    incoming, outgoing = ssl.MemoryBIO(), ssl.MemoryBIO()
    tls = tls_context(ca_file, version).wrap_bio(
        incoming, outgoing, server_side=False, server_hostname='origin.runner.lab')
    with socket.create_connection((host, port), timeout=6) as raw:
        raw.settimeout(6)
        flights = 0
        while True:
            try:
                tls.do_handshake()
                break
            except (ssl.SSLWantReadError, ssl.SSLWantWriteError):
                pending = outgoing.read()
                if pending:
                    flights += 1
                    for part in chunks(pending, send_size):
                        raw.sendall(part)
                        if send_delay: time.sleep(send_delay)
                    if flight_delay: time.sleep(flight_delay)
                try:
                    received = raw.recv(receive_size)
                except socket.timeout:
                    raise TimeoutError('TLS handshake stalled')
                if not received:
                    raise ConnectionError('TLS peer closed during handshake')
                incoming.write(received)
        pending = outgoing.read()
        if pending: raw.sendall(pending)
        tls.write(b'GET / HTTP/1.1\r\nHost: origin.runner.lab\r\nConnection: close\r\n\r\n')
        raw.sendall(outgoing.read())
        response = b''
        while b'runner-origin-ok' not in response:
            try:
                response += tls.read(16384)
                continue
            except ssl.SSLWantReadError:
                received = raw.recv(receive_size)
                if not received: break
                incoming.write(received)
        if b'runner-origin-ok' not in response:
            raise RuntimeError('application data did not traverse the MITM')
        return {'result': 'completed', 'version': tls.version(),
                'alpn': tls.selected_alpn_protocol(), 'client_flights': flights}

def expected_failure(host, port, ca_file):
    started = time.monotonic()
    try:
        memory_handshake(host, port, ca_file)
    except (ssl.SSLError, ConnectionError, ConnectionResetError, BrokenPipeError,
            TimeoutError, OSError) as exc:
        elapsed = time.monotonic() - started
        if elapsed >= 5:
            raise RuntimeError('failure was delayed until timeout') from exc
        return {'result': 'failed_closed', 'elapsed_ms': round(elapsed * 1000, 1),
                'error': type(exc).__name__}
    raise RuntimeError('invalid upstream handshake unexpectedly completed')

def abort_client(host, ca_file, mode):
    context = tls_context(ca_file)
    incoming, outgoing = ssl.MemoryBIO(), ssl.MemoryBIO()
    tls = context.wrap_bio(incoming, outgoing, server_side=False,
                           server_hostname='origin.runner.lab')
    try: tls.do_handshake()
    except ssl.SSLWantReadError: pass
    hello = outgoing.read()
    raw = socket.create_connection((host, 443), timeout=3)
    if mode == 'partial_eof':
        raw.sendall(hello[:4]); raw.shutdown(socket.SHUT_WR); raw.close()
    elif mode == 'partial_rst':
        raw.sendall(hello[:17]); linger_rst(raw); raw.close()
    else:
        raw.sendall(hello[:9] + b'\x15\x03\x03\x00\x02\x02\x28'); raw.close()
    time.sleep(0.05)
    # A fresh verified handshake proves that the aborted state did not poison
    # the listener or turn subsequent traffic into a bypass path.
    recovery = memory_handshake(host, 443, ca_file)
    return {'result': 'failed_closed', 'recovery': recovery['result']}

def client(args):
    cases = {
        'downstream_all_flights_drip_tls12': memory_handshake(
            args.host, 443, args.ca_file, send_size=3, send_delay=0.001,
            flight_delay=0.04, version=ssl.TLSVersion.TLSv1_2),
        'downstream_all_flights_drip_tls13': memory_handshake(
            args.host, 443, args.ca_file, send_size=3, send_delay=0.001,
            flight_delay=0.04, version=ssl.TLSVersion.TLSv1_3),
        'downstream_receive_drip': memory_handshake(
            args.host, 443, args.ca_file, receive_size=5,
            version=ssl.TLSVersion.TLSv1_2),
        'upstream_server_drip': memory_handshake(args.host, BASE_PORT, args.ca_file),
        'upstream_client_drip': memory_handshake(args.host, BASE_PORT + 1, args.ca_file),
        'both_legs_stalled': memory_handshake(args.host, BASE_PORT + 2, args.ca_file,
                                              send_size=11, send_delay=0.001),
        'upstream_eof': expected_failure(args.host, BASE_PORT + 3, args.ca_file),
        'upstream_partial_server_rst': expected_failure(
            args.host, BASE_PORT + 4, args.ca_file),
        'upstream_fatal_alert': expected_failure(args.host, BASE_PORT + 5, args.ca_file),
        'downstream_partial_eof': abort_client(args.host, args.ca_file, 'partial_eof'),
        'downstream_partial_rst': abort_client(args.host, args.ca_file, 'partial_rst'),
        'downstream_fatal_alert': abort_client(args.host, args.ca_file, 'fatal_alert'),
    }
    print(json.dumps({'cases': cases, 'passed': len(cases)}, sort_keys=True))

parser = argparse.ArgumentParser()
parser.add_argument('role', choices=('server', 'client'))
parser.add_argument('--host', required=True)
parser.add_argument('--ca-file')
args = parser.parse_args()
if args.role == 'server': server(args)
else:
    if not args.ca_file: parser.error('--ca-file is required for client')
    client(args)
