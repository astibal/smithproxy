#!/usr/bin/env python3
"""Old native archives upgrade resources atomically, without legacy files."""
import argparse
import os
from pathlib import Path
import re
import signal
import socket
import subprocess
import sys
import tarfile
import tempfile
import time

SOURCE = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(SOURCE / 'tests/cli'))
from libcli2_process_e2e import Cli, require, replace_or_add_setting

PREFIX = 'templates/replacement/en/'


def contents(archive):
    with tarfile.open(archive) as tar:
        return {m.name: tar.extractfile(m).read() for m in tar.getmembers() if m.isfile()}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('binary', type=Path)
    parser.add_argument('--native-archive', required=True, type=Path)
    parser.add_argument('--schema', '--from-schema', dest='schema', type=int, default=1050)
    args = parser.parse_args()
    binary = args.binary.resolve()
    tool = binary.with_name('smithproxy-cftar')
    with tempfile.TemporaryDirectory(prefix='cftar-schema-upgrade-') as temporary:
        root = Path(temporary)
        archive = root / 'old.cftar'
        payload = contents(args.native_archive)
        defaults = {name[len(PREFIX):]: value for name, value in payload.items() if name.startswith(PREFIX)}
        NEW = set(defaults)
        with socket.socket() as sock:
            sock.bind(('127.0.0.1', 0))
            port = sock.getsockname()[1]
        config = payload['smithproxy.cfg'].decode()
        config = re.sub(r'\*_internal_\*\s*[:=]\s*\{[^}]*\}\s*;?', '', config)
        config += '\n*_internal_* : { schema = %d; version = "schema-upgrade-test"; };\n' % args.schema
        for name, value in {
            'accept_tproxy': 'FALSE;', 'accept_redirect': 'FALSE;',
            'accept_socks': 'FALSE;', 'accept_http_connect': 'FALSE;', 'accept_api': 'FALSE;',
            'custom_cert_fallback_dir': f'"{root}/external";',
            'enable_password': '"template-test-password";',
            'port': f'{port};', 'log_file': '"";', 'log_console': 'TRUE;',
            'sslkeylog_file': f'"{root}/sslkeylog.%s.log";',
            'write_payload_dir': f'"{root}/payload";',
        }.items():
            config = replace_or_add_setting(config, name, value)
        config = config.replace('/var/smithproxy/data', str(root / 'data'))
        # Preserve an explicit opt-in, while migration supplies the absent flags.
        capture_options = r'(captures\s*[:=]\s*\{.*?options\s*[:=]\s*\{)(.*?)(\})'
        config, changed = re.subn(capture_options,
            lambda m: m[1] + ' metadata = TRUE; ' + m[3], config, count=1, flags=re.S)
        assert changed == 1, 'fixture has no captures.options group'
        (root / 'config').write_text(config)
        (root / 'startup').write_bytes(payload['smithproxy.startup.cfg'])
        command = [str(tool), 'create', '--config', str(root / 'config'),
                   '--startup', str(root / 'startup'), '--output', str(archive)]
        for index, (name, value) in enumerate(payload.items()):
            if name in {'manifest.json', 'smithproxy.cfg', 'smithproxy.startup.cfg'}:
                continue
            if name.startswith(PREFIX) and name[len(PREFIX):] in NEW:
                # Preserve one already customized fragment during upgrade.
                if name != PREFIX + 'tls_reason.txt':
                    continue
                value = b'<p>custom reason {{ message }}</p>'
            path = root / f'resource-{index}'
            path.write_bytes(value)
            command += ['--file', f'{name}={path}']
        subprocess.run(command, check=True, capture_output=True)
        external = root / 'external/sni/external.test'
        external.mkdir(parents=True)
        (external / 'cert.pem').write_bytes(payload['pki/ca/default/srv-cert.pem'])
        (external / 'key.pem').write_bytes(payload['pki/ca/default/srv-key.pem'])
        before = archive.read_bytes()
        previous = contents(archive)
        env = {**os.environ, 'SMITHPROXY_PID_FILE': str(root / 'proxy.pid')}
        check = [str(binary), '-o', '-c', str(archive)]
        result = subprocess.run(check, cwd=root, env=env, capture_output=True, text=True, timeout=30)
        assert result.returncode == 0, result.stdout + result.stderr
        assert archive.read_bytes() == before, 'check-only wrote schema/resources'

        def boot(label, action=None):
            with (root / f'{label}.log').open('w+') as log:
                process = subprocess.Popen([str(binary), '--no-pidfile', '-c', str(archive)],
                                           cwd=root, env=env, stdout=log, stderr=subprocess.STDOUT,
                                           start_new_session=True)
                try:
                    deadline = time.monotonic() + 20
                    while process.poll() is None and time.monotonic() < deadline:
                        try:
                            with socket.create_connection(('127.0.0.1', port), timeout=.2):
                                pass
                            if action:
                                action()
                            return
                        except OSError:
                            time.sleep(.1)
                    log.seek(0)
                    raise AssertionError('daemon did not reach CLI readiness:\n' + log.read())
                finally:
                    if process.poll() is None:
                        os.killpg(process.pid, signal.SIGTERM)
                        try:
                            process.wait(timeout=10)
                        except subprocess.TimeoutExpired:
                            os.killpg(process.pid, signal.SIGKILL)
                            process.wait()

        boot('upgrade')
        upgraded = contents(archive)
        assert re.search(rb'schema\s*=\s*1054', upgraded['smithproxy.cfg'])
        options = re.search(rb'captures\s*[:=]\s*\{.*?options\s*[:=]\s*\{([^}]*)',
                            upgraded['smithproxy.cfg'], re.S)
        assert options, 'capture options were not saved'
        for name, value in [('metadata', 'true'), ('statistics', 'false'),
                            ('transport', 'false'), ('protocol_events', 'false')]:
            assert re.search(name.encode() + rb'\s*=\s*' + value.encode(),
                             options[1], re.I), name

        assert str(root / 'external').encode() in upgraded['smithproxy.cfg']
        assert not any('external.test' in name for name in upgraded), 'fallback identity was imported'
        assert (external / 'cert.pem').exists(), 'external identity was retired'
        for name in NEW:
            assert PREFIX + name in upgraded, name
        for name, value in previous.items():
            if name != 'smithproxy.cfg':
                assert upgraded[name] == value, f'overwritten existing resource: {name}'
        saved = archive.read_bytes()
        boot('restart')
        assert archive.read_bytes() == saved, 'second boot rewrote the archive'

        def maintenance():
            cli = Cli(port)
            try:
                original = archive.read_bytes()
                cli.command("maintenance template fix-missing")
                assert archive.read_bytes() == original, 'unprivileged command wrote archive'
                require(cli.command("enable"), "Password:")
                require(cli.command("template-test-password"), "#")
                require(cli.command_ok("maintenance template fix-missing"), "archive unchanged")
                require(cli.command("maintenance template rollback"), "including custom edits")
                require(cli.command("n"), "Command cancelled")
                assert archive.read_bytes() == original, 'cancelled rollback wrote archive'
                require(cli.command("maintenance template rollback"), "including custom edits")
                require(cli.command_ok("y"), "Restart to activate")
                restored = contents(archive)
                for name in NEW:
                    assert restored[PREFIX + name] == defaults[name]
                for name, value in contents_before_maintenance.items():
                    if not name.startswith(PREFIX):
                        assert restored[name] == value, name
                require(cli.command_failed("maintenance template fix-missing"), "restart first")
            finally:
                cli.sock.close()

        contents_before_maintenance = contents(archive)
        boot('maintenance', maintenance)
        restored_bytes = archive.read_bytes()
        boot('maintenance-restart')
        assert archive.read_bytes() == restored_bytes, 'rollback did not survive restart'

        def transfer():
            cli = Cli(port)
            directory = root / 'exported-templates'
            try:
                require(cli.command("enable"), "Password:")
                require(cli.command("template-test-password"), "#")
                require(cli.command_ok(f"maintenance template export {directory}"), "Templates exported")
                require(cli.command_failed(f"maintenance template export {directory}"), "cannot create")
                assert {p.name for p in (directory / 'en').iterdir()} == NEW
                original = archive.read_bytes()
                require(cli.command_ok(f"maintenance template import {directory}"), "archive unchanged")
                reason = directory / 'en/tls_reason.txt'
                reason.unlink()
                require(cli.command_failed(f"maintenance template import {directory}"), "complete exported English set")
                assert archive.read_bytes() == original
                reason.write_text('<p>imported reason</p>')
                require(cli.command_ok(f"maintenance template import {directory}"), "Restart to activate")
                assert contents(archive)[PREFIX + 'tls_reason.txt'] == b'<p>imported reason</p>'
            finally:
                cli.sock.close()

        boot('transfer', transfer)
        imported_bytes = archive.read_bytes()
        boot('transfer-restart')
        assert archive.read_bytes() == imported_bytes

        # A current-schema archive missing a required resource remains invalid:
        # migration defaults are not a permanent runtime fallback.
        subprocess.run([str(tool), 'resource', 'remove', str(archive), PREFIX + 'tls_redirect.txt'],
                       check=True, capture_output=True)
        damaged = archive.read_bytes()
        result = subprocess.run(check, cwd=root, env=env, capture_output=True, text=True, timeout=30)
        assert result.returncode != 0, 'current-schema corruption was silently repaired'
        assert archive.read_bytes() == damaged
    print(f'PASS: {args.schema} -> 1054 resource upgrade and external custom certificate persistence, read-only check, custom templates, restart, maintenance CLI and strict current schema')


if __name__ == '__main__':
    main()
