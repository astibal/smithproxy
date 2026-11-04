#!/usr/bin/env python3
"""Opt-in real proxy/CPU monitor integration on an explicitly local target.

Run in a disposable network namespace (see CPU_MONITOR.md). No public traffic.
Reports and proxy logs persist in a new --output directory.
"""
import argparse
from concurrent.futures import ThreadPoolExecutor
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import socket
import signal
import ssl
import struct
import subprocess
import tempfile
import threading
import time
import traceback

from cpu_monitor import Client

HERE = Path(__file__).resolve().parent
SPEC = importlib.util.spec_from_file_location('connect_fixture', HERE.parent / 'httpconnect/http_connect_integration.py')
fixture = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(fixture)


def tunnel(port, destination):
    client = socket.create_connection(('127.0.0.1', port), timeout=5)
    try:
        client.settimeout(5)
        authority = f'127.0.0.1:{destination}'
        client.sendall(f'CONNECT {authority} HTTP/1.1\r\nHost: {authority}\r\n\r\n'.encode())
        response = fixture.recv_until(client, b'\r\n\r\n')
        if not response.startswith(b'HTTP/1.1 200 '):
            raise AssertionError(f'CONNECT failed: {response!r}')
        return client
    except BaseException:
        client.close()
        raise


def tls_transfer(port, source):
    origin = fixture.TlsEchoOrigin(source / 'etc/certs/default/portal-cert.pem',
                                  source / 'etc/certs/default/portal-key.pem')
    origin.start()
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE  # Disposable fixture CA, never public traffic.
    with tunnel(port, origin.port) as client:
        with context.wrap_socket(client, server_hostname='localhost') as tls:
            tls.sendall(b'TLS-PING\r\n')
            assert fixture.recv_until(tls, b'TLS-PONG\r\n') == b'TLS-PONG\r\n'
    assert origin.finished.wait(5), 'TLS origin did not finish'
    if origin.error:
        raise origin.error
    assert origin.request == b'TLS-PING\r\n'


def half_close(port, evidence):
    errors = []
    state = dict(origin_bytes=0, origin_eof=False, response_sent=False, direct=port is None)
    payload = b'half-close-payload-' * 4096
    listener = socket.socket()
    listener.bind(('127.0.0.1', 0))
    listener.listen(1)
    listener.settimeout(5)

    def origin():
        try:
            with listener:
                connection, _ = listener.accept()
                with connection:
                    connection.settimeout(8)
                    data = bytearray()
                    while True:
                        chunk = connection.recv(65536)
                        if not chunk:
                            break
                        data.extend(chunk)
                        state['origin_bytes'] = len(data)
                    state['origin_eof'] = True
                    state['origin_eof_time'] = time.monotonic()
                    assert data == payload, f'partial upload: {len(data)} bytes'
                    time.sleep(.1)
                    connection.sendall(b'AFTER-FIN\r\n')
                    state['response_sent'] = True
                    state['response_sent_time'] = time.monotonic()
        except BaseException as error:
            errors.append(str(error))

    thread = threading.Thread(target=origin, daemon=True)
    thread.start()
    try:
        destination = listener.getsockname()[1]
        connection = (socket.create_connection(('127.0.0.1', destination), timeout=5)
                      if port is None else tunnel(port, destination))
        with connection as client:
            client.sendall(payload)
            client.shutdown(socket.SHUT_WR)
            state['client_fin_sent'] = True
            state['client_fin_time'] = time.monotonic()
            try:
                assert fixture.recv_until(client, b'AFTER-FIN\r\n') == b'AFTER-FIN\r\n'
                state['client_response_time'] = time.monotonic()
            except Exception as error:
                state['client_read_error'] = str(error)
                state['client_read_error_time'] = time.monotonic()
                state['origin_eof_at_client_error'] = state['origin_eof']
                raise
    finally:
        state['client_socket_closed_time'] = time.monotonic()
        thread.join(timeout=9)
        listener.close()
        state['origin_errors'] = errors
        state['expected_bytes'] = len(payload)
        evidence.write_text(json.dumps(state, indent=2))
    assert not thread.is_alive(), 'half-close origin did not finish'
    assert not errors, errors


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--local', action='store_true', required=True)
    parser.add_argument('--smithproxy', type=Path, required=True)
    parser.add_argument('--monitor', type=Path, required=True)
    parser.add_argument('--source', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    output, source = args.output.resolve(), args.source.resolve()
    binary, monitor_binary = args.smithproxy.resolve(), args.monitor.resolve()
    output.mkdir(parents=True, exist_ok=False)
    config = output / 'smithproxy.cfg'
    port = fixture.free_port()
    fixture.make_config(source / 'etc/smithproxy.cfg', config, source, output,
                        port, fixture.free_port())
    # Only this ephemeral profile trusts the local TLS origin fixture.
    config.write_text(config.read_text().replace('allow_invalid_certs = FALSE', 'allow_invalid_certs = TRUE')
                      .replace('allow_self_signed = FALSE', 'allow_self_signed = TRUE'))
    result = dict(functional='ERROR', phases=[], target='local',
                  proxy_binary=str(binary), proxy_sha256=hashlib.sha256(binary.read_bytes()).hexdigest(),
                  monitor_binary=str(monitor_binary),
                  monitor_sha256=hashlib.sha256(monitor_binary.read_bytes()).hexdigest(),
                  network_namespace=os.readlink('/proc/self/ns/net'),
                  monitoring_scope='proxy core PID and its threads; helper child processes excluded')
    processes = []
    proxy = None
    client = None
    active = False

    try:
        with tempfile.TemporaryDirectory(prefix='cpu-real-') as sockets, \
             (output / 'proxy.log').open('w') as proxy_log, \
             (output / 'monitor.log').open('w') as monitor_log:
            monitor = subprocess.Popen([str(monitor_binary), '--socket', sockets + '/control.sock',
                                        '--output', str(output / 'cpu'), '--control-timeout', '60'],
                                       stdout=monitor_log, stderr=subprocess.STDOUT)
            processes.append(monitor)
            client = Client(sockets + '/control.sock')
            env = fixture.process_env(output)
            env.pop('SMITHPROXY_RUN_AS', None)
            proxy = subprocess.Popen([str(binary), '--config-file', str(config)], cwd=source,
                                     env=env, stdout=proxy_log, stderr=subprocess.STDOUT, start_new_session=True)
            processes.append(proxy)
            result['proxy_pid'] = proxy.pid
            client.request('ATTACH', pid=proxy.pid)

            def phase(name, operation, mode='observe', minimum=.65):
                nonlocal active
                client.request('BEGIN', name=name, mode=mode)
                active = True
                started = time.monotonic()
                item = dict(name=name, functional='PASS')
                try:
                    operation()
                except Exception:
                    item.update(functional='FAIL', error=traceback.format_exc())
                elapsed = time.monotonic() - started
                if elapsed < minimum:
                    time.sleep(minimum - elapsed)
                client.request('END', result=item['functional'])
                active = False
                item['seconds'] = time.monotonic() - started
                result['phases'].append(item)
                print(name, item['functional'], flush=True)
                (output / 'result.json').write_text(json.dumps(result, indent=2))
                return item['functional'] == 'PASS'

            if not phase('startup', lambda: fixture.wait_for_listener(proxy, port)):
                raise RuntimeError('proxy startup failed; see proxy.log')
            children = Path(f'/proc/{proxy.pid}/task/{proxy.pid}/children')
            result['helper_pids_after_startup'] = children.read_text().split()
            phase('idle-before', lambda: time.sleep(2), mode='idle')

            def traffic():
                with ThreadPoolExecutor(max_workers=4) as pool:
                    list(pool.map(lambda _: fixture.check_plain_tunnel(port, '127.0.0.1', fixture.EchoOrigin()), range(40)))
            phase('connect-40-transfers', traffic)
            phase('idle-after-plain', lambda: time.sleep(2), mode='idle')
            phase('tls-10-transfers', lambda: [tls_transfer(port, source) for _ in range(10)])
            phase('idle-after-tls', lambda: time.sleep(2), mode='idle')
            phase('half-close-direct-control', lambda: half_close(None, output / 'half-close-direct.json'))
            phase('half-close-delayed-response', lambda: half_close(port, output / 'half-close-proxy.json'))

            def resets():
                for _ in range(100):
                    with socket.create_connection(('127.0.0.1', port), timeout=3) as connection:
                        connection.sendall(b'CONNECT 127.0.0.1:9 HTTP/1.1\r\nHost:')
                        connection.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, struct.pack('ii', 1, 0))
            phase('100-partial-connect-resets', resets)
            phase('idle-after-lifecycle', lambda: time.sleep(5), mode='idle')
            reply = client.request('FINISH')
            monitor.wait(timeout=5)
            report = json.loads((output / 'cpu/report.json').read_text())
            assert reply['verdict'] == report['verdict']
            assert report['implementation'] == 'cpp'
            assert monitor.returncode == (0 if report['verdict'] == 'PASS' else 1)
            result['cpu'] = report['verdict']
            result['functional'] = 'PASS' if all(p['functional'] == 'PASS' for p in result['phases']) else 'FAIL'
            result['proxy_alive_at_finish'] = proxy.poll() is None
            assert result['proxy_alive_at_finish']
    except Exception:
        result['error'] = traceback.format_exc()
        if client and active:
            try:
                client.request('END', result='FAIL')
                client.request('FINISH')
            except Exception:
                pass
    finally:
        if client:
            client.close()
        for process in reversed(processes):
            if process.poll() is None:
                process.terminate()
                try:
                    process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait(timeout=5)
        if proxy is not None:
            # The proxy owns a separate process group, including its helpers.
            # Normal core shutdown stops them; this also bounds abnormal cleanup.
            try:
                os.killpg(proxy.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
        result['direct_children_reaped'] = all(p.poll() is not None for p in processes)
        (output / 'result.json').write_text(json.dumps(result, indent=2))
    print(json.dumps(result, indent=2), flush=True)
    return 0 if result['functional'] == result.get('cpu') == 'PASS' else 1


if __name__ == '__main__':
    raise SystemExit(main())
