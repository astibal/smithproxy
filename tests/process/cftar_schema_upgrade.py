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
from libcli2_process_e2e import replace_or_add_setting

NEW = {'tls_override_form.txt', 'tls_reason.txt', 'tls_certificate_field.txt',
       'tls_certificate_details.txt', 'tls_replacement_error.txt',
       'tls_redirect.txt', 'tls_redirect_top.txt'}
PREFIX = 'templates/replacement/en/'


def contents(archive):
    with tarfile.open(archive) as tar:
        return {m.name: tar.extractfile(m).read() for m in tar.getmembers() if m.isfile()}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('binary', type=Path)
    parser.add_argument('--native-archive', required=True, type=Path)
    args = parser.parse_args()
    binary = args.binary.resolve()
    tool = binary.with_name('smithproxy-cftar')
    with tempfile.TemporaryDirectory(prefix='cftar-schema-upgrade-') as temporary:
        root = Path(temporary)
        archive = root / 'old.cftar'
        payload = contents(args.native_archive)
        with socket.socket() as sock:
            sock.bind(('127.0.0.1', 0))
            port = sock.getsockname()[1]
        config = payload['smithproxy.cfg'].decode()
        config = re.sub(r'\*_internal_\*\s*[:=]\s*\{[^}]*\}\s*;?', '', config)
        config += '\n*_internal_* : { schema = 1050; version = "schema-upgrade-test"; };\n'
        for name, value in {
            'accept_tproxy': 'FALSE;', 'accept_redirect': 'FALSE;',
            'accept_socks': 'FALSE;', 'accept_http_connect': 'FALSE;', 'accept_api': 'FALSE;',
            'port': f'{port};', 'log_file': '"";', 'log_console': 'TRUE;',
            'sslkeylog_file': f'"{root}/sslkeylog.%s.log";',
            'write_payload_dir': f'"{root}/payload";',
        }.items():
            config = replace_or_add_setting(config, name, value)
        config = config.replace('/var/smithproxy/data', str(root / 'data'))
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
        before = archive.read_bytes()
        previous = contents(archive)
        env = {**os.environ, 'SMITHPROXY_PID_FILE': str(root / 'proxy.pid')}
        check = [str(binary), '-o', '-c', str(archive)]
        result = subprocess.run(check, cwd=root, env=env, capture_output=True, text=True, timeout=30)
        assert result.returncode == 0, result.stdout + result.stderr
        assert archive.read_bytes() == before, 'check-only wrote schema/resources'

        def boot(label):
            with (root / f'{label}.log').open('w+') as log:
                process = subprocess.Popen([str(binary), '--no-pidfile', '-c', str(archive)],
                                           cwd=root, env=env, stdout=log, stderr=subprocess.STDOUT,
                                           start_new_session=True)
                try:
                    deadline = time.monotonic() + 20
                    while process.poll() is None and time.monotonic() < deadline:
                        try:
                            with socket.create_connection(('127.0.0.1', port), timeout=.2):
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
        assert re.search(rb'schema\s*=\s*1051', upgraded['smithproxy.cfg'])
        for name in NEW:
            assert PREFIX + name in upgraded, name
        for name, value in previous.items():
            if name != 'smithproxy.cfg':
                assert upgraded[name] == value, f'overwritten existing resource: {name}'
        saved = archive.read_bytes()
        boot('restart')
        assert archive.read_bytes() == saved, 'second boot rewrote the archive'

        # A current-schema archive missing a required resource remains invalid:
        # migration defaults are not a permanent runtime fallback.
        subprocess.run([str(tool), 'resource', 'remove', str(archive), PREFIX + 'tls_redirect.txt'],
                       check=True, capture_output=True)
        damaged = archive.read_bytes()
        result = subprocess.run(check, cwd=root, env=env, capture_output=True, text=True, timeout=30)
        assert result.returncode != 0, 'current-schema corruption was silently repaired'
        assert archive.read_bytes() == damaged
    print('PASS: 1050 -> 1051 resource upgrade, read-only check, custom templates, restart and strict current schema')


if __name__ == '__main__':
    main()
