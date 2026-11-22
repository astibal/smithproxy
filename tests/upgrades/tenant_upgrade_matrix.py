#!/usr/bin/env python3
"""Compare default upgrades and exercise tenant migrations in private namespaces.

The baseline binary differs only in the two hotfix translation units. Firewall
commands are recorded by stubs; proxy processes, CFtar migration and installation
are real. This suite does not claim to exercise a running systemd manager.
"""
import argparse
import hashlib
import json
import os
import re
from pathlib import Path
import shutil
import signal
import socket
import subprocess
import sys
import tarfile
import time

SOURCE = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(SOURCE / 'tests/cli'))
from libcli2_process_e2e import Cli, replace_or_add_setting, socks_connect
sys.path.insert(0, str(SOURCE / 'tests/install'))
from cftar_install import install


def contents(path):
    with tarfile.open(path) as archive:
        return {m.name: archive.extractfile(m).read() for m in archive.getmembers() if m.isfile()}


def snapshot(root):
    return {str(p.relative_to(root)): (p.stat().st_mode & 0o777, hashlib.sha256(p.read_bytes()).hexdigest())
            for p in sorted(root.rglob('*')) if p.is_file()}


def run_inside(args):
    root = args.output
    etc = Path('/etc/smithproxy')
    payload = contents(args.build / 'defaults/smithproxy.cftar')
    results = []
    port = 25100
    socks = 25200
    certs = root / 'certs'
    certs.mkdir(exist_ok=True)
    templates = root / 'templates'
    templates.mkdir(exist_ok=True)
    for name, data in payload.items():
        if name.startswith('pki/ca/default/'):
            (certs / Path(name).name).write_bytes(data)
        if name.startswith('templates/replacement/en/'):
            (templates / Path(name).name).write_bytes(data)
    base = Path(args.legacy_config).read_text() if args.legacy_config else payload['smithproxy.cfg'].decode()
    for key, value in {
        'accept_tproxy': 'FALSE;', 'accept_redirect': 'FALSE;', 'accept_socks': 'TRUE;',
        'accept_http_connect': 'FALSE;', 'accept_api': 'FALSE;', 'socks_workers': '1;',
        'socks_port': f'"{socks}";', 'port': f'{port};',
        'enable_password': '"upgrade-matrix";',
        'certs_path': '"/etc/smithproxy/certs/default/";',
        'messages_dir': '"/etc/smithproxy/msg/en/";',
        'log_file': '"";', 'log_console': 'TRUE;',
        'sslkeylog_file': f'"{root}/sslkeylog.%s";',
        'write_payload_dir': f'"{root}/payload";',
        'extended_local_destination_protection': 'FALSE;',
    }.items():
        base = replace_or_add_setting(base, key, value)
    if not re.search(r'\bhttp_api\s*[:=]\s*\{', base):
        base = re.sub(r'(settings\s*[:=]\s*\{)', r'\1 http_api = { keys = [ "upgrade-matrix-test-only" ]; };', base, count=1)
    else:
        base, replaced = re.subn(r'(http_api\s*[:=]\s*\{[\s\S]*?\bkeys\s*=\s*)\[[^\]]*\]', r'\1[ "upgrade-matrix-test-only" ]', base, count=1)
        assert replaced == 1, 'fixture must declare deterministic API keys'
    base = base.replace('/var/smithproxy/data', str(root / 'data'))
    (root / 'input.cfg').write_text(base)
    startup = 'SMITH_TCP_PORTS="80 8080"\nSMITH_UDP_PORTS="53"\n'
    stubs = root / 'stubs'
    stubs.mkdir(exist_ok=True)
    for name in ('iptables', 'ip6tables', 'ip', 'sysctl'):
        p = stubs / name
        p.write_text('#!/bin/sh\nprintf "%s %s\\n" "${0##*/}" "$*" >> "$COMMAND_LOG"\nexit 0\n')
        p.chmod(0o755)

    def reset(tenants=False, own_startup=False):
        for p in etc.iterdir():
            if p.is_dir(): shutil.rmtree(p)
            else: p.unlink()
        shutil.copytree(certs, etc / 'certs/default')
        shutil.copytree(templates, etc / 'msg/en')
        (etc / 'smithproxy.cfg').write_text(base)
        (etc / 'smithproxy.cfg').chmod(0o600)
        (etc / 'smithproxy.startup.cfg').write_text(startup)
        if tenants:
            (etc / 'smithproxy.tenants.cfg').write_text('3;blue;192.0.2.0/24;2001:db8::/64\n7;green;198.51.100.0/24;2001:db8:1::/64\n')
            for tenant in ('blue', 'green'):
                tenant_config = replace_or_add_setting(base, 'enable_password', f'"upgrade-matrix-{tenant}";')
                (etc / f'smithproxy.{tenant}.cfg').write_text(tenant_config)
                if own_startup:
                    (etc / f'smithproxy.{tenant}.startup.cfg').write_text(startup + f'# {tenant}\n')

    def network(script, action, tenant='default'):
        log = root / 'commands.log'
        log.write_text('')
        env = {**os.environ, 'SMITHPROXY_ETC_DIR': str(etc),
               'SMITHPROXY_RUN_DIR': str(root / 'run'),
               'SMITHPROXY_NETWORK_LOG': str(root / 'network.log'),
               'SMITHPROXY_CFTAR_CMD': str(args.build / 'smithproxy-cftar'),
               'COMMAND_LOG': str(log)}
        for name in ('iptables', 'ip6tables', 'ip', 'sysctl'):
            env[name.upper() + '_CMD'] = str(stubs / name)
        result = subprocess.run(['bash', str(script), action, tenant], env=env,
                                capture_output=True, text=True, timeout=30)
        assert result.returncode == 0, result.stdout + result.stderr
        return log.read_text()

    counter = 0
    def boot(binary, tenant='default', save=False, implicit=False):
        nonlocal counter
        counter += 1
        offset = {'default': 0, 'blue': 3, 'green': 7}[tenant]
        sequence = counter
        logpath = root / f'boot-{sequence:03}-{tenant}.log'
        with logpath.open('w') as log:
            command = [str(binary), '--no-pidfile']
            if not implicit: command += ['--tenant-name', tenant]
            p = subprocess.Popen(command, stdout=log, stderr=subprocess.STDOUT,
                                 start_new_session=True, cwd=root,
                                 env={**os.environ, 'SMITHPROXY_PID_FILE': str(root / 'proxy.pid')})
            cli = None
            try:
                deadline = time.monotonic() + 20
                while p.poll() is None and time.monotonic() < deadline:
                    try:
                        cli = Cli(port + offset)
                        break
                    except OSError: time.sleep(.1)
                assert cli is not None, logpath.read_text()
                cli.command('enable')
                password = 'upgrade-matrix' + (f'-{tenant}' if tenant != 'default' else '')
                assert '#' in cli.command(password), 'wrong tenant configuration/password'
                settings = cli.command_ok('show config settings')
                # A live SOCKS session must carry bytes after each migration/restart.
                import threading
                with socket.socket() as origin:
                    origin.bind(('127.0.0.1', 0)); origin.listen(1); origin.settimeout(5)
                    failures = []
                    def echo():
                        try:
                            conn, _ = origin.accept()
                            with conn:
                                conn.settimeout(5)
                                conn.sendall(conn.recv(64))
                        except Exception as error: failures.append(str(error))
                    worker = threading.Thread(target=echo); worker.start()
                    try:
                        with socks_connect(socks + offset, origin.getsockname()[1]) as client:
                            client.settimeout(5); client.sendall(b'upgrade-matrix')
                            assert client.recv(64) == b'upgrade-matrix'
                    finally: worker.join(timeout=6)
                    assert not failures, failures
                if save:
                    assert 'config saved successfully' in cli.command_ok('save config')
                return settings
            finally:
                if cli:
                    (root / f'cli-{sequence:03}.txt').write_bytes(cli.transcript)
                    cli.sock.close()
                if p.poll() is None:
                    os.killpg(p.pid, signal.SIGTERM)
                    try: p.wait(timeout=10)
                    except subprocess.TimeoutExpired:
                        os.killpg(p.pid, signal.SIGKILL); p.wait()

    def case(name, callback):
        if args.only and args.only != name: return
        try:
            detail = callback()
            results.append({'name': name, 'status': 'PASS', 'detail': detail})
        except Exception as error:
            import traceback
            results.append({'name': name, 'status': 'FAIL', 'error': str(error)})
            (root / f'{name}-failure.txt').write_text(traceback.format_exc())
        (root / 'results.json').write_text(json.dumps(results, indent=2))
        print(name, results[-1]['status'], results[-1].get('error', '')[:300], flush=True)

    def default_compare():
        states = []
        for binary, script in ((args.baseline / 'smithproxy', args.baseline / 'smithproxy.startup.sh'),
                               (args.build / 'smithproxy', SOURCE / 'etc/smithproxy.startup.sh')):
            reset()
            before = network(script, 'start')
            settings = boot(binary)
            archive = contents(etc / 'smithproxy.cftar')
            assert archive['smithproxy.cfg'] == (etc / 'smithproxy.cfg.old').read_bytes()
            assert archive['smithproxy.startup.cfg'] == startup.encode()
            persistent = snapshot(etc)
            assert not (etc / 'smithproxy.cfg').exists()
            for _ in range(2):
                assert boot(binary) == settings
                assert snapshot(etc) == persistent
            after = network(script, 'start')
            (root / ('comparison-' + str(len(states)) + '.json')).write_text(json.dumps({'settings': settings, 'payloads': {k: v.decode(errors='replace') for k,v in archive.items() if k != 'manifest.json'}, 'files': sorted(p.name for p in etc.iterdir()), 'before': before, 'after': after}, indent=2))
            states.append((settings, {k:v for k,v in archive.items() if k != 'manifest.json'},
                           sorted(p.name for p in etc.iterdir()), before, after))
        assert states[0] == states[1], 'default before/after hotfix differs; see comparison JSON files'
        return 'Identical effective settings, archive payloads, cleanup names and sx_network commands; two cold restarts each.'
    case('default-before-after-comparison', default_compare)

    def implicit_default():
        reset()
        first = boot(args.build / 'smithproxy', implicit=True)
        assert boot(args.build / 'smithproxy', implicit=True) == first
        assert not (etc / 'smithproxy.cfg').exists()
    case('default-without-tenant-option', implicit_default)

    def tenant_order(order, own_startup=False):
        reset(True, own_startup)
        registry = (etc / 'smithproxy.tenants.cfg').read_bytes()
        originals = {t: (etc / f'smithproxy.{t}.cfg').read_bytes() for t in ('blue', 'green')}
        for tenant in order:
            boot(args.build / 'smithproxy', tenant)
            assert (etc / 'smithproxy.tenants.cfg').read_bytes() == registry
        for tenant in ('blue', 'green'):
            archive = contents(etc / f'smithproxy.{tenant}.cftar')
            assert archive['smithproxy.cfg'] == (etc / f'smithproxy.{tenant}.cfg.old').read_bytes()
            expected = startup + (f'# {tenant}\n' if own_startup else '')
            assert archive['smithproxy.startup.cfg'] == expected.encode()
            assert not (etc / f'smithproxy.{tenant}.cfg').exists()
        before = snapshot(etc)
        for tenant in ('default', 'green', 'blue', 'default', 'blue', 'green'):
            network(SOURCE / 'etc/smithproxy.startup.sh', 'start', tenant)
            boot(args.build / 'smithproxy', tenant)
        assert snapshot(etc) == before, 'cold restarts changed persisted configuration'
        # Saving one tenant must not change any other tenant or the default.
        other = {p: p.read_bytes() for p in (etc / 'smithproxy.cftar', etc / 'smithproxy.green.cftar')}
        boot(args.build / 'smithproxy', 'blue', save=True)
        assert all(p.read_bytes() == data for p,data in other.items())
        boot(args.build / 'smithproxy', 'blue')
    case('default-first-two-tenants', lambda: tenant_order(('default','blue','green')))
    case('tenant-first-two-tenants', lambda: tenant_order(('blue','green','default')))
    case('tenant-specific-startup', lambda: tenant_order(('green','default','blue'), True))

    def concurrent_tenants():
        from concurrent.futures import ThreadPoolExecutor
        reset(True)
        resources = snapshot(etc / 'certs')
        with ThreadPoolExecutor(max_workers=3) as workers:
            tasks = [workers.submit(boot, args.build / 'smithproxy', tenant)
                     for tenant in ('default', 'blue', 'green')]
            for task in tasks: task.result()
        assert snapshot(etc / 'certs') == resources
        for tenant in ('default', 'blue', 'green'):
            boot(args.build / 'smithproxy', tenant)
    case('simultaneous-default-and-two-tenants', concurrent_tenants)

    def install_upgrade(tenants, native):
        reset(tenants)
        if native:
            for tenant in (('default','blue','green') if tenants else ('default',)):
                boot(args.build / 'smithproxy', tenant)
        stage = root / ('install-' + str(tenants) + '-' + str(native))
        shutil.copytree(etc, stage / 'etc/smithproxy')
        before = snapshot(stage / 'etc/smithproxy')
        install(args.build, stage)
        assert snapshot(stage / 'etc/smithproxy') == before, 'installation altered existing configuration'
        # Run the installed artifacts, with the same arguments as sx-core@.service.
        binary = stage / 'usr/bin/smithproxy'
        assert binary.is_file()
        for tenant in (('default','blue','green') if tenants else ('default',)):
            network(stage / 'usr/bin/sx_network', 'start', tenant)
            boot(binary, tenant)
            boot(binary, tenant)
        return 'DESTDIR installation preserved config; installed proxy and sx_network started and restarted.'
    for tenants in (False, True):
        for native in (False, True):
            case(f'install-upgrade-tenants-{tenants}-native-{native}',
                 lambda t=tenants,n=native: install_upgrade(t,n))
    return int(any(r['status'] != 'PASS' for r in results))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--build', type=Path, required=True)
    parser.add_argument('--baseline', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--inside', action='store_true')
    parser.add_argument('--only', default='')
    parser.add_argument('--legacy-config', default='')
    args = parser.parse_args()
    args.build=args.build.resolve(); args.baseline=args.baseline.resolve(); args.output=args.output.resolve()
    if args.legacy_config: args.legacy_config = str(Path(args.legacy_config).resolve())
    if args.inside: return run_inside(args)
    args.output.mkdir(parents=True, exist_ok=False)
    (args.output / 'etc').mkdir()
    command = ['unshare', '--user', '--map-root-user', '--net', 'sh', '-c',
               'ip link set lo up && exec "$@"', 'fixture', 'bwrap', '--unshare-pid', '--die-with-parent',
               '--ro-bind', '/', '/', '--tmpfs', '/tmp', '--bind', str(args.output), str(args.output),
               '--bind', str(args.build / 'install_manifest.txt'), str(args.build / 'install_manifest.txt'),
               '--tmpfs', '/etc', '--ro-bind', '/etc/ssl', '/etc/ssl',
               '--ro-bind', '/etc/passwd', '/etc/passwd', '--ro-bind', '/etc/group', '/etc/group',
               '--ro-bind', '/etc/nsswitch.conf', '/etc/nsswitch.conf',
               '--bind', str(args.output / 'etc'), '/etc/smithproxy', '--proc', '/proc', '--dev', '/dev',
               sys.executable, str(Path(__file__).resolve()), '--build', str(args.build),
               '--baseline', str(args.baseline), '--output', str(args.output), '--inside', '--only', args.only, '--legacy-config', args.legacy_config]
    return subprocess.call(command)


if __name__ == '__main__':
    raise SystemExit(main())
