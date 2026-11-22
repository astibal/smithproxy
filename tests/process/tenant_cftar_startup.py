#!/usr/bin/env python3
"""Exercise tenant selection and migration with private /etc and network namespaces."""
import os
from pathlib import Path
import signal
import socket
import subprocess
import sys
import tarfile
import tempfile
import time

SOURCE = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(SOURCE / 'tests/cli'))
from libcli2_process_e2e import replace_or_add_setting


def inside(build, root):
    etc = root / 'etc'
    binary = build / 'smithproxy'
    tool = build / 'smithproxy-cftar'
    with tarfile.open(build / 'defaults/smithproxy.cftar') as archive:
        payload = {m.name: archive.extractfile(m).read() for m in archive.getmembers() if m.isfile()}
    (etc / 'smithproxy.tenants.cfg').write_text('3;blue;192.0.2.0/24;2001:db8::/64\n')
    certs = root / 'certs'
    certs.mkdir()
    for name, data in payload.items():
        if name.startswith('pki/ca/default/'):
            (certs / Path(name).name).write_bytes(data)
    with socket.socket() as available:
        available.bind(('127.0.0.1', 0))
        port = available.getsockname()[1]
    base = payload['smithproxy.cfg'].decode()
    for key, value in {
        'accept_tproxy': 'FALSE;', 'accept_redirect': 'FALSE;', 'accept_socks': 'FALSE;',
        'accept_http_connect': 'FALSE;', 'accept_api': 'FALSE;', 'port': f'{port};',
        'log_file': '"";', 'log_console': 'TRUE;', 'certs_path': f'"{certs}/";',
        'sslkeylog_file': f'"{root}/sslkeylog.%s";', 'write_payload_dir': f'"{root}/payload";',
    }.items():
        base = replace_or_add_setting(base, key, value)
    base = base.replace('/var/smithproxy/data', str(root / 'data'))
    startup = '# tenant migration marker\nSMITH_TCP_PORTS="8080"\n'
    (etc / 'smithproxy.startup.cfg').write_text(startup)
    tenant = etc / 'smithproxy.blue.cftar'
    legacy = etc / 'smithproxy.blue.cfg'
    (etc / 'smithproxy.cfg').write_text('invalid default must not be selected')

    def pack(destination):
        (root / 'main').write_text(base)
        args = [tool, 'create', '--config', root / 'main', '--startup', etc / 'smithproxy.startup.cfg',
                '--output', root / 'packed-next']
        for index, (name, data) in enumerate(payload.items()):
            if name in {'manifest.json', 'smithproxy.cfg', 'smithproxy.startup.cfg'}:
                continue
            path = root / f'resource-{index}'
            path.write_bytes(data)
            args.extend(['--file', f'{name}={path}'])
        result = subprocess.run(args, capture_output=True, text=True)
        assert result.returncode == 0, result.stdout + result.stderr
        (root / 'packed-next').replace(destination)

    def check(extra=(), success=True):
        result = subprocess.run([binary, '-o', '--tenant-name', 'blue', *extra],
                                cwd=root, capture_output=True, text=True, timeout=30)
        assert (result.returncode == 0) == success, result.stdout + result.stderr

    def boot(label, tenant_name='blue'):
        with (root / f'{label}.log').open('w+') as log:
            process = subprocess.Popen([binary, '--no-pidfile', '--tenant-name', tenant_name],
                cwd=root, stdout=log, stderr=subprocess.STDOUT, start_new_session=True,
                env={**os.environ, 'SMITHPROXY_PID_FILE': str(root / 'proxy.pid')})
            try:
                target_port = port + (3 if tenant_name == 'blue' else 0)
                for _ in range(150):
                    if process.poll() is not None:
                        break
                    try:
                        with socket.create_connection(('127.0.0.1', target_port), timeout=.1):
                            return
                    except OSError:
                        time.sleep(.1)
                log.seek(0)
                raise AssertionError(label + ': no CLI readiness\n' + log.read())
            finally:
                if process.poll() is None:
                    os.killpg(process.pid, signal.SIGTERM)
                    try:
                        process.wait(timeout=10)
                    except subprocess.TimeoutExpired:
                        os.killpg(process.pid, signal.SIGKILL)
                        process.wait()

    pack(tenant)
    check()
    boot('native-only')
    assert not legacy.exists()
    print('PASS native-only named tenant starts with offset CLI port', flush=True)
    legacy.write_text('invalid stale tenant configuration')
    check()
    boot('retire-stale')
    assert not legacy.exists() and Path(str(legacy) + '.old').exists()
    pack(etc / 'smithproxy.cftar')
    tenant.write_text('corrupt archive')
    check(success=False)
    tenant.unlink()
    check(success=False)
    tenant.symlink_to(root / 'missing')
    check(success=False)
    tenant.unlink()
    print('PASS corrupt, missing-after-retirement and dangling archives never fall back', flush=True)
    explicit = root / 'literal%s.cftar'
    pack(explicit)
    check(('-c', str(explicit)))
    print('PASS explicit archive path stays literal', flush=True)

    legacy.write_text(base)
    boot('migration')
    assert tenant.exists() and not legacy.exists()
    with tarfile.open(tenant) as archive:
        assert archive.extractfile('smithproxy.startup.cfg').read().decode() == startup
    boot('migration-restart')
    print('PASS tenant migration carries shared startup and restarts without .cfg', flush=True)

    preserved = {p: p.read_bytes() for p in (tenant, etc / 'smithproxy.tenants.cfg',
                                            etc / 'smithproxy.startup.cfg')}
    boot('default-with-tenants', 'default')
    assert all(p.read_bytes() == data for p, data in preserved.items())
    boot('tenant-after-default')
    print('PASS default startup preserves tenant registry, archive and shared resources', flush=True)
    pack(etc / 'smithproxy.default.cftar')
    (etc / 'smithproxy.cftar').write_text('invalid shared default')
    boot('named-default-native', 'default')
    print('PASS named default archive needs no .cfg sibling', flush=True)
    (etc / 'smithproxy.default.cftar').unlink()
    pack(etc / 'smithproxy.cftar')
    for path in etc.glob('smithproxy.blue.*'):
        path.rename(root / path.name)
    boot('shared-default-native')
    check(('-c', str(root / 'does-not-exist.cftar')), success=False)
    unknown = subprocess.run([binary, '-o', '--tenant-name', 'unknown'], cwd=root,
                             capture_output=True, timeout=30)
    assert unknown.returncode != 0
    print('PASS legacy shared-default selection, missing explicit archive, unknown tenant', flush=True)


if __name__ == '__main__':
    build = Path(sys.argv[1]).resolve()
    if len(sys.argv) == 4 and sys.argv[2] == '--inside':
        inside(build, Path(sys.argv[3]))
    else:
        with tempfile.TemporaryDirectory(prefix='tenant-cftar-startup-') as directory:
            root = Path(directory)
            (root / 'etc').mkdir()
            result = subprocess.run(['unshare', '--user', '--map-root-user', '--net', 'sh', '-c',
                'ip link set lo up && exec "$@"', 'fixture', 'bwrap', '--unshare-pid',
                '--die-with-parent', '--ro-bind', '/', '/', '--tmpfs', '/tmp', '--bind', str(root), str(root),
                '--tmpfs', '/etc', '--ro-bind', '/etc/ssl', '/etc/ssl',
                '--ro-bind', '/etc/passwd', '/etc/passwd', '--ro-bind', '/etc/group', '/etc/group',
                '--ro-bind', '/etc/nsswitch.conf', '/etc/nsswitch.conf',
                '--bind', str(root / 'etc'), '/etc/smithproxy', '--proc', '/proc', '--dev', '/dev',
                sys.executable, __file__, str(build), '--inside', str(root)])
            raise SystemExit(result.returncode)
