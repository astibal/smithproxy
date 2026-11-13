#!/usr/bin/env python3
"""Build and run the H3 engine, decoder and namespace-isolated webhook suite."""
import argparse
import json
import os
import signal
from pathlib import Path
import subprocess
import sys
import tempfile
import time


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--build', type=Path, required=True, help='Configured CMake build directory')
    parser.add_argument('--output', type=Path, help='New artifact directory; defaults to a temporary directory')
    parser.add_argument('--python-path', type=Path, help='Directory containing aioquic and pylsqpack')
    parser.add_argument('--jobs', type=int, default=2)
    parser.add_argument('--repeat', type=int, default=1, help='Repeat each real-network case')
    parser.add_argument('--unit-only', action='store_true', help='Run without network namespaces or Python QUIC dependencies')
    args = parser.parse_args()
    if args.jobs < 1 or args.repeat < 1:
        parser.error('--jobs and --repeat must be positive')
    source = Path(__file__).resolve().parents[2]
    build = args.build.resolve()
    output = args.output.resolve() if args.output else Path(tempfile.mkdtemp(prefix='h3-suite-'))
    if args.output:
        output.mkdir(parents=True, exist_ok=False)
    environment = dict(os.environ)
    if args.python_path:
        environment['PYTHONPATH'] = os.pathsep.join(filter(None, [str(args.python_path.resolve()),
                                                                environment.get('PYTHONPATH')]))
    results = []
    print(f'Artifacts: {output}', flush=True)

    def stage(name, command, timeout, extra_env=None):
        log = output / f'{name}.log'
        started = time.monotonic()
        status = 'FAIL'
        code = None
        try:
            with log.open('w') as stream:
                process = subprocess.Popen(command, cwd=source,
                                           env={**environment, **(extra_env or {})},
                                           stdout=stream, stderr=subprocess.STDOUT,
                                           start_new_session=True)
                try:
                    code = process.wait(timeout=timeout)
                except (subprocess.TimeoutExpired, KeyboardInterrupt):
                    # Stop the whole namespace/process tree, not just the driver.
                    os.killpg(process.pid, signal.SIGTERM)
                    try:
                        process.wait(timeout=5)
                    except subprocess.TimeoutExpired:
                        pass
                    try:
                        os.killpg(process.pid, signal.SIGKILL)
                    except ProcessLookupError:
                        pass
                    process.wait()
                    raise
            status = 'PASS' if code == 0 else 'FAIL'
        except (OSError, subprocess.TimeoutExpired) as error:
            with log.open('a') as stream:
                stream.write(f'\nRunner failure: {error}\n')
        finally:
            results.append({'stage': name, 'status': status, 'exit_code': code,
                            'seconds': round(time.monotonic() - started, 3),
                            'command': [str(item) for item in command], 'log': str(log)})
            (output / 'results.json').write_text(json.dumps(results, indent=2) + '\n')
        print(f'{status}: {name}', flush=True)
        if status != 'PASS':
            print('\n'.join(log.read_text(errors='replace').splitlines()[-40:]), file=sys.stderr)
            raise RuntimeError(f'{name} failed; see {log}')

    targets = ['sx_gtests_http1', 'quic_testbed']
    if not args.unit_only:
        stage('dependencies', [sys.executable, '-c', 'import aioquic, pylsqpack'], 30)
        targets += ['smithproxy', 'smithproxy-cftar']
    stage('build', ['cmake', '--build', str(build), '--target', *targets, '-j', str(args.jobs)], 1800)
    stage('units', ['ctest', '--test-dir', str(build), '--output-on-failure',
                    '-R', r'^unit\.(http3|http3_capture|protocol_views)$'], 180)
    if not args.unit_only:
        driver = source / 'tests/integration/master_policy_revalidation.py'
        for iteration in range(1, args.repeat + 1):
            for case in ('static', 'dynamic', 'dynamic-fragmented'):
                name = f'{case}-{iteration}'
                stage(name, ['unshare', '-Urn', sys.executable, str(driver),
                             str(build / 'smithproxy'), str(output / name)], 90,
                      {'REVALIDATION_CASES': 'quic-engine-views', 'H3_VIEWS_CASE': case})
    return 0


if __name__ == '__main__':
    try:
        sys.exit(main())
    except (RuntimeError, FileExistsError) as error:
        print(error, file=sys.stderr)
        sys.exit(1)
