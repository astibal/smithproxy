#!/usr/bin/env python3
"""CTest entry point: isolate networking and fail clearly on missing prerequisites."""
import argparse
import os
from pathlib import Path
import shutil
import subprocess
import sys

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('binary', type=Path)
parser.add_argument('artifacts', type=Path)
parser.add_argument('--quic', action='store_true')
parser.add_argument('--trigger', choices=('policy', 'role'), default='policy')
args = parser.parse_args()
for tool in ('unshare', 'ip', 'openssl', *(['iptables'] if args.quic else [])):
    if not shutil.which(tool):
        parser.error(f'missing integration prerequisite: {tool}')
probe = subprocess.run(['unshare', '-Urn', 'true'], capture_output=True, text=True)
if probe.returncode:
    parser.error('network/user namespaces unavailable: ' + probe.stderr.strip())
env = os.environ.copy()
# Avoid inherited case filters accidentally turning a gate into a partial run.
env.pop('REVALIDATION_CASES', None)
if args.quic:
    runtime = Path(__file__).resolve().parents[3] / 'quic-python'
    if runtime.is_dir():
        env['PYTHONPATH'] = str(runtime) + os.pathsep + env.get('PYTHONPATH', '')
    probe = subprocess.run([sys.executable, '-c', 'import aioquic'], env=env, capture_output=True)
    if probe.returncode:
        parser.error('aioquic unavailable; run tests/patch-runner/prepare-quic-runtime.sh or set PYTHONPATH')
    env['REVALIDATION_CASES'] = 'quic-policy-drop'
    env['QUIC_REVALIDATION_TRIGGER'] = args.trigger
args.artifacts.mkdir(parents=True, exist_ok=True)
command = ['unshare', '-Urn', sys.executable,
           str(Path(__file__).with_name('master_policy_revalidation.py')),
           str(args.binary.resolve()), str(args.artifacts.resolve())]
raise SystemExit(subprocess.call(command, env=env))
