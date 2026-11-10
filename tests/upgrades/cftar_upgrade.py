#!/usr/bin/env python3
"""Process-level master -> CFtar upgrade gate, isolated in mount/network namespaces."""
import argparse
from contextlib import contextmanager
import hashlib
import errno
import json
import os
from pathlib import Path
import shutil
import signal
import socket
import subprocess
import sys
import time
import traceback
import threading

SOURCE = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(SOURCE / 'tests/cli'))
from libcli2_process_e2e import Cli, replace_or_add_setting, socks_connect


def run(*args):
    return subprocess.run(list(map(str, args)), check=True, capture_output=True, text=True).stdout


def native_path(path):
    return path.with_suffix('.cftar') if path.suffix == '.cfg' else Path(str(path) + '.cftar')


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def snapshot(directory):
    result = {}
    for path in sorted(directory.rglob('*')):
        state = path.lstat()
        row = {'mode': oct(state.st_mode & 0o7777), 'size': state.st_size}
        if path.is_symlink():
            row['link'] = os.readlink(path)
        elif path.is_file():
            row['sha256'] = digest(path)
        result[str(path.relative_to(directory))] = row
    return result


def free_port():
    with socket.socket() as sock:
        sock.bind(('127.0.0.1', 0))
        return sock.getsockname()[1]


class Gate:
    def __init__(self, args):
        self.args = args
        self.root = args.output.resolve()
        self.root.mkdir(parents=True, exist_ok=False)
        self.port = free_port()
        self.socks = free_port()
        self.results = []
        self.sequence = 0
        self.seed = self.root / 'master-seed'
        self.seed.mkdir()
        self.base = ''

    def fixture(self, name, filename='smithproxy.cfg'):
        case = self.root / name
        case.mkdir()
        (case / 'config').mkdir()
        (case / 'runtime').mkdir()
        shutil.copytree(self.args.master_source / 'etc/certs/default', case / 'certs')
        shutil.copytree(self.args.master_source / 'etc/msg/en', case / 'templates')
        cfg = case / 'config' / filename
        text = self.base or (self.args.master_source / 'etc/smithproxy.cfg').read_text()
        values = {
            'accept_tproxy': 'FALSE;', 'accept_redirect': 'FALSE;',
            'accept_socks': 'TRUE;', 'accept_http_connect': 'FALSE;',
            'accept_api': 'FALSE;', 'socks_workers': '1;',
            'socks_port': f'"{self.socks}";', 'port': f'{self.port};',
            'enable_password': '"upgrade-test-only";',
            'certs_path': f'"{case / "certs"}/";',
            'messages_dir': f'"{case / "templates"}/";',
            'log_file': '"";', 'log_console': 'TRUE;',
            'sslkeylog_file': f'"{case / "runtime"}/sslkeylog.%s.log";',
            'write_payload_dir': f'"{case / "runtime"}/payload";',
            'extended_local_destination_protection': 'FALSE;',
        }
        for key, value in values.items():
            text = replace_or_add_setting(text, key, value)
        # Neighbor snapshots and capture state must never use the host's /var directory.
        text = text.replace('/var/smithproxy/data', str(case / 'runtime'))
        cfg.write_text(text)
        cfg.chmod(0o600)
        return case, cfg

    @contextmanager
    def process(self, binary, case, cfg, expect_running=True, default_config=False):
        self.sequence += 1
        label = f'{self.sequence:02d}-{Path(binary).parent.name}'
        log = (case / f'{label}.log').open('w')
        env = dict(os.environ, SMITHPROXY_PID_FILE=str(case / 'runtime/proxy.pid'))
        command = [str(binary), '--no-pidfile']
        if not default_config:
            command += ['-c', str(cfg)]
        process = subprocess.Popen(command,
                                   stdout=log, stderr=subprocess.STDOUT, env=env,
                                   start_new_session=True)
        cli = None
        self.active_pid = process.pid
        try:
            deadline = time.monotonic() + 15
            while time.monotonic() < deadline and process.poll() is None:
                try:
                    cli = Cli(self.port)
                    break
                except OSError:
                    time.sleep(.1)
            if cli is None:
                assert expect_running is not True, f'proxy not ready; exit={process.poll()}, log={label}'
                assert process.wait(timeout=5) > 0, 'invalid config did not exit cleanly with an error'
            else:
                assert expect_running is not False, 'unexpected CLI admission with invalid native state'
                assert process.poll() is None, 'proxy exited after opening CLI'
                cli.command('enable')
                response = cli.command('upgrade-test-only')
                assert '#' in response, f'CLI login failed: {response}'
            yield cli
        finally:
            if cli:
                if process.poll() is None:
                    try:
                        (case / f'{label}.events.txt').write_text(cli.command('show event list'))
                    except OSError as error:
                        (case / f'{label}.events-error.txt').write_text(str(error))
                (case / f'{label}.cli.txt').write_bytes(cli.transcript)
                cli.sock.close()
            if process.poll() is None:
                process.terminate()
                try:
                    process.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait(timeout=5)
            # Reap/terminate helpers even when the parent exited unexpectedly.
            try:
                os.killpg(process.pid, signal.SIGTERM)
            except ProcessLookupError:
                pass
            log.close()
            (case / f'{label}.exit.json').write_text(json.dumps({'returncode': process.returncode}))

    def marker(self, cli):
        text = cli.command_ok('show config address_objects')
        assert 'upgrade_marker' in text and '192.0.2.0/24' in text, 'saved master object lost'
        # Validate live forwarding, not merely successful configuration parsing.
        with socket.socket() as origin:
            origin.bind(('127.0.0.1', 0))
            origin.listen(1)
            origin.settimeout(5)
            errors = []
            def respond():
                try:
                    peer, _ = origin.accept()
                    with peer:
                        peer.settimeout(5)
                        assert peer.recv(64) == b'upgrade-probe'
                        peer.sendall(b'upgrade-ok')
                except Exception as error:
                    errors.append(str(error))
            worker = threading.Thread(target=respond, daemon=True)
            worker.start()
            try:
                with socks_connect(self.socks, origin.getsockname()[1]) as client:
                    client.settimeout(5)
                    client.sendall(b'upgrade-probe')
                    assert client.recv(64) == b'upgrade-ok'
            finally:
                worker.join(timeout=6)
            assert not errors, errors

    def seed_master(self):
        case, cfg = self.fixture('master-save')
        before = cfg.read_bytes()
        with self.process(self.args.master, case, cfg) as cli:
            for cmd in ['configure terminal', 'edit address_objects', 'add upgrade_marker',
                        'edit upgrade_marker', 'set type cidr', 'set value 192.0.2.0/24',
                        'end', 'end', 'end']:
                cli.command_ok(cmd)
            self.marker(cli)
            assert 'config saved successfully' in cli.command_ok('save config')
        assert cfg.exists() and cfg.read_bytes() != before
        assert 'upgrade_marker' in cfg.read_text()
        self.base = cfg.read_text()
        (self.seed / 'saved-by-master.cfg').write_text(self.base)
        (self.seed / 'state.json').write_text(json.dumps(snapshot(case / 'config'), indent=2))

    def native(self, case, cfg):
        with self.process(self.args.tlc, case, cfg) as cli:
            self.marker(cli)
        archive = native_path(cfg)
        run(self.args.cftar, 'verify', archive)
        assert not cfg.exists(), 'legacy configuration was not retired'
        assert cfg.with_name(cfg.name + '.old').is_file(), 'backup missing'
        return archive

    @contextmanager
    def readonly(self, directory):
        run('mount', '--bind', directory, directory)
        try:
            run('mount', '-o', 'remount,bind,ro', directory)
            yield
        finally:
            run('umount', directory)

    def check_log(self, case, message):
        assert any(message in p.read_text() for p in case.glob('*.log')), f'missing diagnostic: {message}'

    def case(self, name, callback, filename='smithproxy.cfg'):
        case, cfg = self.fixture(name, filename)
        record = {'name': name, 'status': 'FAIL', 'started': time.time()}
        (case / 'before.json').write_text(json.dumps(snapshot(case / 'config'), indent=2))
        try:
            callback(case, cfg)
            record['status'] = 'PASS'
        except Exception as error:
            record['error'] = str(error)
            (case / 'failure.txt').write_text(traceback.format_exc())
        record['elapsed_seconds'] = round(time.time() - record['started'], 3)
        (case / 'after.json').write_text(json.dumps(snapshot(case / 'config'), indent=2))
        self.results.append(record)
        (self.root / 'results.json').write_text(json.dumps(self.results, indent=2))
        print(name, record['status'], record.get('error', ''), flush=True)

    def run_cases(self):
        self.seed_master()

        def happy(case, cfg):
            archive = self.native(case, cfg)
            saved = run(self.args.cftar, 'get', archive, 'smithproxy.cfg')
            assert saved == cfg.with_name(cfg.name + '.old').read_text()
            assert cfg.with_name(cfg.name + '.old').stat().st_mode & 0o777 == 0o600
            before = snapshot(case / 'config')
            for _ in range(2):
                with self.process(self.args.tlc, case, cfg) as cli:
                    self.marker(cli)
            assert snapshot(case / 'config') == before, 'restart changed persistent configuration'
        self.case('migration-and-two-restarts', happy)
        self.case('custom-config-path', happy, 'tenant-office.cfg')
        self.case('extensionless-config-path', happy, 'tenant-office')
        self.case('alternative-config-suffix', happy, 'tenant-office.conf')

        def collision(case, cfg):
            old = cfg.with_name(cfg.name + '.old')
            old.write_text('previous backup')
            with self.process(self.args.tlc, case, cfg) as cli:
                self.marker(cli)
            assert old.read_text() == 'previous backup'
            assert cfg.with_name(cfg.name + '.old.1').is_file()
            assert not cfg.exists()
        self.case('existing-backup', collision)

        def directory_backup(case, cfg):
            cfg.with_name(cfg.name + '.old').mkdir()
            with self.process(self.args.tlc, case, cfg) as cli:
                self.marker(cli)
            assert cfg.with_name(cfg.name + '.old.1').is_file()
        self.case('backup-name-is-directory', directory_backup)

        def readonly_retirement(case, cfg):
            archive = self.native(case, cfg)
            cfg.write_text('stale configuration must not be used')
            before = digest(archive)
            with self.readonly(cfg.parent):
                with self.process(self.args.tlc, case, cfg) as cli:
                    self.marker(cli)
                assert cfg.exists() and digest(archive) == before
            self.check_log(case, 'legacy configuration retirement failed')
            with self.process(self.args.tlc, case, cfg) as cli:
                self.marker(cli)
            assert not cfg.exists(), 'retry did not finish retirement'
        self.case('readonly-retirement-and-retry', readonly_retirement)

        def readonly_migration(case, cfg):
            before = snapshot(cfg.parent)
            with self.readonly(cfg.parent):
                with self.process(self.args.tlc, case, cfg) as cli:
                    self.marker(cli)
                assert snapshot(cfg.parent) == before
            self.check_log(case, 'cannot create native configuration archive')
            self.native(case, cfg)
        self.case('readonly-migration-and-retry', readonly_migration)

        def corrupt_archive(case, cfg):
            archive = native_path(cfg)
            archive.write_bytes(b'not a CFtar archive')
            before = snapshot(cfg.parent)
            with self.process(self.args.tlc, case, cfg, False):
                pass
            assert snapshot(cfg.parent) == before
        self.case('corrupt-archive-no-legacy-fallback', corrupt_archive)

        def missing_archive(case, cfg):
            archive = self.native(case, cfg)
            archive.unlink()
            backup = cfg.with_name(cfg.name + '.old')
            before = digest(backup)
            with self.process(self.args.tlc, case, cfg, False):
                pass
            assert digest(backup) == before and not cfg.exists() and not archive.exists()
        self.case('missing-archive-no-old-fallback', missing_archive)

        def broken_pki(case, cfg):
            archive = self.native(case, cfg)
            cfg.write_text('stale legacy')
            invalid = case / 'bad-cert.pem'
            invalid.write_text('not a certificate')
            run(self.args.cftar, 'resource', 'import', archive,
                'pki/ca/default/ca-cert.pem', invalid)
            before = snapshot(cfg.parent)
            with self.process(self.args.tlc, case, cfg, False):
                pass
            assert snapshot(cfg.parent) == before, 'failed native resources retired legacy input'
        self.case('invalid-native-certificate-keeps-legacy', broken_pki)

        def reload(case, cfg):
            self.native(case, cfg)
            with self.process(self.args.tlc, case, cfg) as cli:
                cfg.write_text('not a valid configuration')
                assert 'Configuration file reloaded' in cli.command_ok('execute reload')
                self.marker(cli)
                assert cfg.read_text() == 'not a valid configuration', 'reload retired the legacy file'
        self.case('reload-native-only-no-retirement', reload)

        def check_only(case, cfg):
            self.native(case, cfg)
            cfg.write_text('stale legacy')
            before = snapshot(cfg.parent)
            result = subprocess.run([str(self.args.tlc), '-o', '-c', str(cfg)],
                                    capture_output=True, text=True, timeout=20)
            (case / 'check.log').write_text(result.stdout + result.stderr)
            assert result.returncode == 0
            assert snapshot(cfg.parent) == before
        self.case('config-check-is-read-only', check_only)

        def archive_directory(case, cfg):
            native_path(cfg).mkdir()
            before = snapshot(cfg.parent)
            with self.process(self.args.tlc, case, cfg, False):
                pass
            assert snapshot(cfg.parent) == before
        self.case('archive-path-is-directory', archive_directory)

        def symlink(case, cfg):
            self.native(case, cfg)
            target = case / 'external.cfg'
            target.write_text('must survive')
            cfg.symlink_to(target)
            with self.process(self.args.tlc, case, cfg) as cli:
                self.marker(cli)
            assert cfg.is_symlink() and target.read_text() == 'must survive'
            self.check_log(case, 'legacy configuration retirement failed')
        self.case('legacy-symlink-is-not-followed', symlink)

        def no_source(case, cfg):
            cfg.unlink()
            with self.process(self.args.tlc, case, cfg, False):
                pass
            assert not native_path(cfg).exists()
        self.case('no-source-fails-cleanly', no_source)

        def explicit(case, cfg):
            archive = self.native(case, cfg)
            cfg.write_text('stale config')
            with self.process(self.args.tlc, case, archive) as cli:
                self.marker(cli)
            assert not cfg.exists()
        self.case('explicit-cftar-path', explicit)

        def crash_restart(case, cfg):
            archive = self.native(case, cfg)
            before = snapshot(cfg.parent)
            with self.process(self.args.tlc, case, cfg) as cli:
                self.marker(cli)
                # Kill only this scenario's proxy; its context cleans up helpers.
                pid = self.active_pid
                os.kill(pid, signal.SIGKILL)
            with self.process(self.args.tlc, case, cfg) as cli:
                self.marker(cli)
            assert snapshot(cfg.parent) == before
        self.case('kill-after-activation-and-restart', crash_restart)

        def missing_template(case, cfg):
            (case / 'templates/test.txt').unlink()
            # Missing legacy resources may keep the old runtime usable or
            # reject startup cleanly. Never accept a signal crash or swallow a
            # forwarding assertion from a process that did become ready.
            with self.process(self.args.tlc, case, cfg, expect_running=None) as cli:
                if cli is not None:
                    self.marker(cli)
            self.check_log(case, 'cannot create native configuration archive')
            assert cfg.is_file() and not native_path(cfg).exists()
            assert not cfg.with_name(cfg.name + '.old').exists()
            shutil.copyfile(self.args.master_source / 'etc/msg/en/test.txt', case / 'templates/test.txt')
            self.native(case, cfg)
        self.case('missing-migration-resource-and-retry', missing_template)

        def backup_symlink(case, cfg):
            target = case / 'protected-backup'
            target.write_text('untouched')
            cfg.with_name(cfg.name + '.old').symlink_to(target)
            with self.process(self.args.tlc, case, cfg) as cli:
                self.marker(cli)
            assert target.read_text() == 'untouched'
            assert cfg.with_name(cfg.name + '.old').is_symlink()
            assert cfg.with_name(cfg.name + '.old.1').is_file()
        self.case('backup-symlink-never-overwritten', backup_symlink)

        def full_disk(case, cfg):
            disk = case / 'full-filesystem'
            disk.mkdir()
            run('mount', '-t', 'tmpfs', '-o', 'size=1m,mode=0700', 'tmpfs', disk)
            try:
                active = disk / 'smithproxy.cfg'
                active.write_bytes(cfg.read_bytes())
                filler = disk / 'fill'
                with filler.open('wb', buffering=0) as output:
                    try:
                        while True:
                            output.write(b'x' * 4096)
                    except OSError as error:
                        assert error.errno == errno.ENOSPC, error
                before = active.read_bytes()
                with self.process(self.args.tlc, case, active) as cli:
                    self.marker(cli)
                assert active.read_bytes() == before, 'ENOSPC changed the only legacy config'
                assert not native_path(active).exists(), 'ENOSPC published an incomplete archive'
                assert not active.with_name(active.name + '.old').exists()
                self.check_log(case, 'cannot create native configuration archive')
                (case / 'enospc-state.json').write_text(json.dumps(snapshot(disk), indent=2))
                filler.unlink()
                self.native(case, active)
                shutil.copytree(disk, case / 'recovered-filesystem')
            finally:
                run('umount', disk)
        self.case('disk-full-migration-and-retry', full_disk)

        def broken_template(case, cfg):
            archive = self.native(case, cfg)
            cfg.write_text('legacy must survive failed activation')
            run(self.args.cftar, 'resource', 'remove', archive, 'templates/replacement/en/test.txt')
            before = snapshot(cfg.parent)
            with self.process(self.args.tlc, case, cfg, False):
                pass
            assert snapshot(cfg.parent) == before
        self.case('missing-native-template-keeps-legacy', broken_template)


        def default_layout(case, cfg):
            etc = case / 'isolated-etc'
            etc.mkdir()
            # Only public OS lookup/trust inputs are needed; never copy shadow,
            # host service configurations or private keys from the host /etc.
            for name in ('passwd', 'group', 'nsswitch.conf', 'hosts', 'resolv.conf'):
                original = Path('/etc') / name
                if original.is_file():
                    shutil.copyfile(original, etc / name)
            (etc / 'ssl').mkdir()
            shutil.copytree('/etc/ssl/certs', etc / 'ssl/certs', symlinks=True)
            product = etc / 'smithproxy'
            product.mkdir()
            shutil.copytree(case / 'certs', product / 'certs/default')
            shutil.copytree(case / 'templates', product / 'msg/en')
            text = replace_or_add_setting(cfg.read_text(), 'certs_path',
                                          '"/etc/smithproxy/certs/default/";')
            text = replace_or_add_setting(text, 'messages_dir',
                                          '"/etc/smithproxy/msg/en/";')
            (product / 'smithproxy.cfg').write_text(text)
            run('mount', '--bind', etc, '/etc')
            try:
                selected = Path('/etc/smithproxy/smithproxy.cfg')
                with self.process(self.args.tlc, case, selected, default_config=True) as cli:
                    self.marker(cli)
                assert not selected.exists()
                assert (product / 'smithproxy.cfg.old').is_file()
                assert (product / 'smithproxy.pre-cftar.tar').is_file()
                assert not (product / 'certs').exists() and not (product / 'msg').exists()
                run(self.args.cftar, 'verify', product / 'smithproxy.cftar')
                before = snapshot(product)
                with self.process(self.args.tlc, case, selected, default_config=True) as cli:
                    self.marker(cli)
                assert snapshot(product) == before
                (case / 'default-layout-state.json').write_text(json.dumps(before, indent=2))
            finally:
                run('umount', '/etc')
        self.case('default-etc-layout-and-restart', default_layout)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('master', 'master-source', 'tlc', 'cftar', 'output'):
        parser.add_argument('--' + name, type=Path, required=True)
    parser.add_argument('--master-revision', required=True)
    parser.add_argument('--tlc-revision', required=True)
    parser.add_argument('--isolated', action='store_true', help=argparse.SUPPRESS)
    args = parser.parse_args()
    if not args.isolated:
        if os.geteuid() != 0:
            parser.error('root is required for isolated network and readonly mount tests')
        return subprocess.call(['unshare', '--mount', '--net', '--pid', '--fork', '--mount-proc',
                                sys.executable, str(Path(__file__).resolve()),
                                *sys.argv[1:], '--isolated'])
    run('mount', '--make-rprivate', '/')
    if args.output.resolve().is_relative_to('/tmp'):
        parser.error('output must be outside /tmp, which is isolated for runtime scratch files')
    run('mount', '-t', 'tmpfs', '-o', 'mode=1777,size=128m', 'tmpfs', '/tmp')
    run('ip', 'link', 'set', 'lo', 'up')
    for attr in ('master', 'master_source', 'tlc', 'cftar'):
        setattr(args, attr, getattr(args, attr).resolve())
    gate = Gate(args)
    (gate.root / 'builds.json').write_text(json.dumps({
        'master': {'revision': args.master_revision, 'binary': str(args.master), 'sha256': digest(args.master)},
        'tlc': {'revision': args.tlc_revision, 'binary': str(args.tlc), 'sha256': digest(args.tlc)},
        'cftar': {'binary': str(args.cftar), 'sha256': digest(args.cftar)},
        'suite_sha256': digest(Path(__file__)),
    }, indent=2))
    gate.run_cases()
    lines = ['# CFtar upgrade gate', '',
             f'Master: `{args.master_revision}`; TLC: `{args.tlc_revision}`.', '',
             '| Scenario | Result | Seconds | Detail |', '|---|---|---:|---|']
    for result in gate.results:
        detail = result.get('error', '').replace('|', r'\|').replace('\n', ' ')
        lines.append(f"| {result['name']} | {result['status']} | {result['elapsed_seconds']} | {detail} |")
    lines += ['', 'Each scenario includes file snapshots, process logs, CLI transcripts and exit codes.',
              'Read-only retirement intentionally continues using native configuration with a logged error.',
              'SIGKILL coverage starts after activation; power-loss durability and package scripts are not covered.']
    (gate.root / 'summary.md').write_text('\n'.join(lines) + '\n')
    failures = [r for r in gate.results if r['status'] != 'PASS']
    print(f'{len(gate.results)-len(failures)}/{len(gate.results)} PASS', flush=True)
    return bool(failures)


if __name__ == '__main__':
    sys.exit(main())
