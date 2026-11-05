#!/usr/bin/env python3
"""Adversarial protocol, filesystem and process-boundary checks."""
import argparse
import importlib.util
import json
import os
import resource
import signal
from pathlib import Path
import socket
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from unittest import mock

import cpu_monitor
from cpu_monitor import monitor_command

HERE = Path(__file__).resolve().parent
SPEC = importlib.util.spec_from_file_location('diagnostic_helpers', HERE / 'test-cpu-monitor-diagnostics.py')
HELPERS = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(HELPERS)


class FaultTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix='cpu-faults-')
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.counter = 0

    def lab(self, **kwargs):
        self.counter += 1
        lab = HELPERS.Lab(self.root / str(self.counter), **kwargs)
        self.addCleanup(lab.close)
        return lab

    def assert_error(self, lab, packet):
        lab.client.sock.sendall(packet)
        reply = json.loads(lab.client.sock.recv(65536))
        self.assertFalse(reply['ok'], reply)
        self.assertEqual(lab.monitor.wait(timeout=3), 2)
        report = json.loads((lab.output / 'monitor/report.json').read_text())
        self.assertEqual(report['verdict'], 'ERROR', report)

    def test_malformed_packets(self):
        for packet in (b'{', b'null', b'[]', b'42', b'"BEGIN"', b'\xff',
                       b'{}', b'{"op":"unknown"}', b'x' * 65537):
            with self.subTest(packet=packet[:80]):
                self.assert_error(self.lab(), packet)

    def test_invalid_phase_arguments(self):
        for fields in ({'name': ''}, {'name': []}, {'name': 'x', 'mode': []},
                       {'name': 'x', 'limit': None}, {'name': 'x', 'limit': float('nan')},
                       {'name': 'x', 'limit': -1}, {'name': 'x', 'limit': True}):
            with self.subTest(fields=fields):
                packet = json.dumps(dict(op='BEGIN', **fields)).encode()
                self.assert_error(self.lab(), packet)

    def test_pid_is_an_integer_not_a_coercible_value(self):
        for kind in ('float', 'string'):
            lab = self.lab(attach=False)
            pid = lab.target.pid + .5 if kind == 'float' else str(lab.target.pid)
            self.assert_error(lab, json.dumps(dict(op='ATTACH', pid=pid)).encode())

    def test_wrong_command_order(self):
        for op in ('PHASE', 'END', 'FINISH', 'ATTACH'):
            with self.subTest(op=op):
                lab = self.lab()
                self.assert_error(lab, json.dumps(dict(op=op, name='x', pid=lab.target.pid)).encode())
        lab = self.lab()
        lab.client.request('BEGIN', name='active')
        self.assert_error(lab, b'{"op":"BEGIN","name":"again"}')

    def test_existing_socket_is_not_removed(self):
        path = self.root / 'occupied.sock'
        listener = socket.socket(socket.AF_UNIX, socket.SOCK_SEQPACKET)
        self.addCleanup(listener.close)
        listener.bind(str(path))
        result = subprocess.run([
            *monitor_command(), '--socket', str(path),
            '--output', str(self.root / 'blocked'),
        ], capture_output=True, timeout=5)
        self.assertEqual(result.returncode, 2)
        self.assertTrue(path.exists())
        report = json.loads((self.root / 'blocked/report.json').read_text())
        self.assertEqual(report['verdict'], 'ERROR')

    def test_replaced_socket_is_not_removed_by_old_monitor(self):
        lab = self.lab()
        path = Path(lab.socket_dir.name) / 'control.sock'
        path.unlink()
        replacement = socket.socket(socket.AF_UNIX, socket.SOCK_SEQPACKET)
        self.addCleanup(replacement.close)
        replacement.bind(str(path))
        lab.client.request('BEGIN', name='original-connection')
        lab.client.request('END', result='PASS')
        lab.finish()
        self.assertTrue(path.exists(), 'old monitor unlinked a replacement socket')

    def test_removed_socket_does_not_break_existing_session(self):
        lab = self.lab()
        (Path(lab.socket_dir.name) / 'control.sock').unlink()
        lab.client.request('BEGIN', name='unlinked-connection')
        lab.client.request('END', result='PASS')
        lab.finish()

    def test_existing_results_are_preserved(self):
        output = self.root / 'existing'
        output.mkdir()
        sentinel = output / 'report.json'
        sentinel.write_text('previous evidence')
        result = subprocess.run([
            *monitor_command(),
            '--socket', str(self.root / 'unused.sock'), '--output', str(output),
        ], capture_output=True, timeout=5)
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(sentinel.read_text(), 'previous evidence')
        self.assertFalse((self.root / 'unused.sock').exists())

    def test_real_file_size_limit_never_returns_pass(self):
        original_spawn = HELPERS.Lab.spawn

        def limited_spawn(lab, argv, **kwargs):
            if '--socket' in argv:
                def limit_output():
                    signal.signal(signal.SIGXFSZ, signal.SIG_IGN)
                    resource.setrlimit(resource.RLIMIT_FSIZE, (512, 512))
                kwargs['preexec_fn'] = limit_output
            return original_spawn(lab, argv, **kwargs)

        with mock.patch.object(HELPERS.Lab, 'spawn', limited_spawn):
            lab = self.lab()
        # Force the buffered sample stream to flush against a real kernel
        # file-size limit. Only the child monitor receives that resource limit.
        with self.assertRaises(cpu_monitor.MonitorError):
            lab.client.request('BEGIN', name='limited-output')
            for index in range(40):
                lab.client.request('PHASE', name=f'marker-{index}')
            lab.client.request('END', result='PASS')
            lab.client.request('FINISH')
        self.assertNotEqual(lab.monitor.wait(timeout=3), 0)
        report = lab.output / 'monitor/report.json'
        if report.exists():
            self.assertNotEqual(json.loads(report.read_text())['verdict'], 'PASS')

    def test_report_publish_failure_never_returns_pass(self):
        lab = self.lab()
        lab.client.request('BEGIN', name='short-observe')
        lab.client.request('END', result='PASS')
        (lab.output / 'monitor/report.json').mkdir()
        lab.client.sock.sendall(b'{"op":"FINISH"}')
        reply = json.loads(lab.client.sock.recv(65536))
        self.assertFalse(reply['ok'])
        self.assertEqual(lab.monitor.wait(timeout=3), 2)
        self.assertFalse((lab.output / 'monitor/report.json').is_file())

    @unittest.skipIf(os.environ.get('CPU_MONITOR_BINARY'), 'Python injection; native core fault tests cover this')
    def test_slow_proc_read_produces_error_report(self):
        original = cpu_monitor.snapshot
        for delayed_call in (1, 2):
            with self.subTest(delayed_call=delayed_call):
                args = argparse.Namespace(
                    interval_ms=50, window_ms=500, suspect_percent=80,
                    control_timeout=3, socket=str(self.root / f'slow-{delayed_call}.sock'),
                    output=str(self.root / f'slow-{delayed_call}'))
                calls = 0
                outcome = []

                def delayed_snapshot(*arguments):
                    nonlocal calls
                    calls += 1
                    values = original(*arguments)
                    if calls == delayed_call:
                        time.sleep(.08)
                    return values

                with mock.patch('cpu_monitor.snapshot', side_effect=delayed_snapshot):
                    thread = threading.Thread(
                        target=lambda: outcome.append(cpu_monitor.serve(args)), daemon=True)
                    thread.start()
                    client = cpu_monitor.Client(args.socket)
                    try:
                        if delayed_call == 2:
                            client.request('ATTACH', pid=os.getpid())
                            operation = ('BEGIN', {'name': 'slow-read'})
                        else:
                            operation = ('ATTACH', {'pid': os.getpid()})
                        with self.assertRaises(cpu_monitor.MonitorError):
                            client.request(operation[0], **operation[1])
                    finally:
                        client.close()
                        thread.join(timeout=5)
                    self.assertFalse(thread.is_alive())
                self.assertEqual(outcome, [2])
                report = json.loads((Path(args.output) / 'report.json').read_text())
                self.assertEqual(report['verdict'], 'ERROR')
                self.assertIn('snapshot', report['error'])
                self.assertGreater(report['max_snapshot_duration'], .05)

    @unittest.skipIf(os.environ.get('CPU_MONITOR_BINARY'), 'Python injection; native core fault tests cover this')
    def test_sample_write_failure_is_reported(self):
        # Fault injection at the actual writer; the real server/protocol still
        # runs so this checks its error path, not a duplicate test implementation.
        args = argparse.Namespace(interval_ms=50, window_ms=500, suspect_percent=80,
                                  control_timeout=3, socket=str(self.root / 'control.sock'),
                                  output=str(self.root / 'failed-write'))
        outcome = []
        def run():
            outcome.append(cpu_monitor.serve(args))
        with mock.patch.object(cpu_monitor.Recorder, '_write_sample',
                               side_effect=OSError(28, 'injected no space')):
            thread = threading.Thread(target=run, daemon=True)
            thread.start()
            client = cpu_monitor.Client(args.socket)
            try:
                client.request('ATTACH', pid=os.getpid())
                with self.assertRaises(cpu_monitor.MonitorError):
                    client.request('BEGIN', name='write-failure')
            finally:
                client.close()
                thread.join(timeout=5)
            self.assertFalse(thread.is_alive())
        self.assertEqual(outcome, [2])
        report = json.loads((Path(args.output) / 'report.json').read_text())
        self.assertEqual(report['verdict'], 'ERROR')
        self.assertIn('no space', report['error'])


if __name__ == '__main__':
    unittest.main()
