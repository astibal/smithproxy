#!/usr/bin/env python3
"""Exercise the real monitor with controlled processes, without a proxy or root."""
import json
import os
import signal
from pathlib import Path
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from unittest import mock

from cpu_monitor import monitor_command, Client, MonitorError, snapshot, stat

HERE = Path(__file__).resolve().parent
TARGET = '''
import sys, time, threading
print('ready', flush=True)
for line in sys.stdin:
    duration = float(line)
    def work():
        end = time.monotonic() + duration
        while time.monotonic() < end:
            pass
    thread = threading.Thread(target=work)
    thread.start()
    thread.join()
    print('done', flush=True)
'''


class MonitorTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='cpu-mon-')
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.count = 0

    def process(self, argv, **kwargs):
        process = subprocess.Popen(argv, **kwargs)
        def cleanup():
            if process.poll() is None:
                process.terminate()
                try:
                    process.wait(timeout=3)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait(timeout=3)
            for stream in (process.stdin, process.stdout, process.stderr):
                if stream:
                    stream.close()
        self.addCleanup(cleanup)
        return process

    def target(self):
        target = self.process([sys.executable, '-u', '-c', TARGET],
                              stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True)
        self.assertEqual(target.stdout.readline().strip(), 'ready')
        return target

    def monitor(self, target, timeout=5):
        self.count += 1
        output = self.root / str(self.count)
        path = self.root / f'{self.count}.sock'
        process = self.process([*monitor_command(),
                                '--socket', str(path), '--output', str(output),
                                '--control-timeout', str(timeout)], stderr=subprocess.PIPE)
        client = Client(path)
        self.addCleanup(client.close)
        client.request('ATTACH', pid=target.pid)
        return client, process, output

    def finish(self, client, process, output):
        client.request('END', result='PASS')
        reply = client.request('FINISH')
        rc = process.wait(timeout=3)
        report = json.loads((output / 'report.json').read_text())
        self.assertEqual(reply['verdict'], report['verdict'])
        self.assertEqual(rc, 0 if report['verdict'] == 'PASS' else 1)
        return report

    def test_sleep_and_overhead(self):
        target = self.target()
        client, process, output = self.monitor(target)
        client.request('BEGIN', name='sleep', mode='idle')
        time.sleep(1.1)
        report = self.finish(client, process, output)
        self.assertEqual(report['verdict'], 'PASS')
        self.assertEqual(report['events'], [])
        self.assertGreaterEqual(report['samples'], 15)
        print(f"sleep: monitor CPU={report['monitor_cpu_seconds']:.4f}s, "
              f"samples={report['samples']}, max gap={report['max_sample_gap']:.4f}s")

    def test_half_second_loop_and_parallel_isolation(self):
        busy, sleeping = self.target(), self.target()
        first = self.monitor(busy)
        second = self.monitor(sleeping)
        for client, _, _ in (first, second):
            client.request('BEGIN', name='parallel', mode='idle')
        time.sleep(.15)
        busy.stdin.write('0.5\n')
        busy.stdin.flush()
        self.assertEqual(busy.stdout.readline().strip(), 'done')
        time.sleep(.2)
        hot = self.finish(*first)
        cold = self.finish(*second)
        self.assertEqual(hot['verdict'], 'FAIL')
        self.assertEqual(cold['verdict'], 'PASS')
        suspects = [e for e in hot['events'] if e['suspect']]
        self.assertTrue(suspects, hot)
        self.assertTrue(any(e['subject'].startswith('thread:') for e in suspects), hot)
        print(f"500ms loop: peak={max(e['cpu'] for e in suspects):.1f}% of one core; "
              f"parallel sleeping target={cold['verdict']}")

    def test_short_pulse_observe_and_phase_boundary(self):
        target = self.target()
        client, process, output = self.monitor(target)
        client.request('BEGIN', name='short-pulse', mode='observe')
        target.stdin.write('0.05\n')
        target.stdin.flush()
        self.assertEqual(target.stdout.readline().strip(), 'done')
        time.sleep(.55)
        client.request('PHASE', name='idle', mode='idle')
        time.sleep(.6)
        report = self.finish(client, process, output)
        self.assertEqual(report['verdict'], 'PASS')
        self.assertFalse(any(e['suspect'] for e in report['events']))
        self.assertEqual(len(report['phases']), 2)

    def test_observe_records_loop_without_failing(self):
        target = self.target()
        client, process, output = self.monitor(target)
        client.request('BEGIN', name='benchmark', mode='observe')
        target.stdin.write('0.6\n')
        target.stdin.flush()
        self.assertEqual(target.stdout.readline().strip(), 'done')
        time.sleep(.1)
        report = self.finish(client, process, output)
        self.assertEqual(report['verdict'], 'PASS')
        self.assertTrue(any(e['suspect'] for e in report['events']))
        self.assertFalse(any(e['violation'] for e in report['events']))

    def test_disconnect_is_incomplete(self):
        client, process, output = self.monitor(self.target())
        client.request('BEGIN', name='unfinished')
        client.close()
        self.assertEqual(process.wait(timeout=3), 2)
        report = json.loads((output / 'report.json').read_text())
        self.assertEqual(report['verdict'], 'ERROR')
        self.assertIn('disconnected', report['error'])

    def test_target_exit_is_incomplete(self):
        target = self.target()
        client, process, output = self.monitor(target)
        client.request('BEGIN', name='exit')
        target.terminate()
        target.wait(timeout=3)
        self.assertEqual(process.wait(timeout=3), 2)
        self.assertEqual(json.loads((output / 'report.json').read_text())['verdict'], 'ERROR')

    def test_control_deadline_and_monitor_death(self):
        client, process, output = self.monitor(self.target(), timeout=.2)
        self.assertEqual(process.wait(timeout=3), 2)
        self.assertIn('deadline', json.loads((output / 'report.json').read_text())['error'])
        client, process, _ = self.monitor(self.target())
        process.kill()
        process.wait(timeout=3)
        with self.assertRaises((OSError, MonitorError)):
            client.request('BEGIN', name='dead')

    def test_invalid_order_and_sampling_gap(self):
        client, process, output = self.monitor(self.target())
        with self.assertRaises(MonitorError):
            client.request('END')
        self.assertEqual(process.wait(timeout=3), 2)
        self.assertEqual(json.loads((output / 'report.json').read_text())['verdict'], 'ERROR')
        client, process, output = self.monitor(self.target())
        client.request('BEGIN', name='interrupted', mode='idle')
        process.send_signal(signal.SIGSTOP)
        try:
            time.sleep(.65)
        finally:
            process.send_signal(signal.SIGCONT)
        self.assertEqual(process.wait(timeout=3), 2)
        self.assertIn('sampling gap', json.loads((output / 'report.json').read_text())['error'])

    def test_many_thread_sampling_overhead(self):
        source = TARGET.replace("print('ready', flush=True)", """
for _ in range(32):
    threading.Thread(target=lambda: time.sleep(30), daemon=True).start()
print('ready', flush=True)
""")
        target = self.process([sys.executable, '-u', '-c', source],
                              stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True)
        self.assertEqual(target.stdout.readline().strip(), 'ready')
        client, process, output = self.monitor(target)
        client.request('BEGIN', name='32-idle-threads', mode='idle')
        time.sleep(1.1)
        report = self.finish(client, process, output)
        self.assertEqual(report['verdict'], 'PASS')
        self.assertGreaterEqual(len(report['phases'][0]['peak_window_cpu']), 33)
        print(f"32 idle threads: monitor CPU={report['monitor_cpu_seconds']:.4f}s "
              f"over {report['elapsed']:.3f}s, max gap={report['max_sample_gap']:.4f}s")

    @unittest.skipIf(os.environ.get('CPU_MONITOR_BINARY'), 'Python reader injection; native proc tests cover this')
    def test_thread_exit_during_stat_read(self):
        # Open the real proc file while the thread lives, then let it exit
        # before read(). Linux returns ESRCH here, rather than ENOENT.
        ready = threading.Event()
        release = threading.Event()
        tids = []

        def worker():
            tids.append(threading.get_native_id())
            ready.set()
            release.wait(timeout=5)

        thread = threading.Thread(target=worker)
        thread.start()

        def cleanup():
            release.set()
            thread.join(timeout=5)

        self.addCleanup(cleanup)
        self.assertTrue(ready.wait(timeout=3))
        pid = os.getpid()
        victim_path = Path(f'/proc/{pid}/task/{tids[0]}/stat')
        original_read = Path.read_text
        interrupted = []

        def read_after_exit(path, *args, **kwargs):
            if path != victim_path:
                return original_read(path, *args, **kwargs)
            with path.open() as stream:
                release.set()
                thread.join(timeout=3)
                self.assertFalse(thread.is_alive())
                interrupted.append(True)
                time.sleep(.02)
                return stream.read()

        identity = stat(f'/proc/{pid}/stat')[0]
        with mock.patch.object(Path, 'read_text', read_after_exit):
            values = snapshot(pid, identity)
        self.assertTrue(interrupted)
        self.assertIn('process', values)
        self.assertNotIn(f'thread:{tids[0]}', values)

    @unittest.skipIf(os.environ.get('CPU_MONITOR_BINARY'), 'Python reader injection; native proc tests cover this')
    def test_dead_threads_are_skipped_but_access_errors_are_not(self):
        pid = os.getpid()
        identity = stat(f'/proc/{pid}/stat')[0]
        original_stat = stat

        def dead_thread(path):
            if '/task/' in str(path):
                return (identity, 0, 'X')
            return original_stat(path)

        with mock.patch('cpu_monitor.stat', dead_thread):
            self.assertEqual(set(snapshot(pid, identity)), {'process'})

        def inaccessible_thread(path):
            if '/task/' in str(path):
                raise PermissionError('test: access denied')
            return original_stat(path)

        with mock.patch('cpu_monitor.stat', inaccessible_thread):
            with self.assertRaises(PermissionError):
                snapshot(pid, identity)

    def test_reused_pid_and_short_required_phase(self):
        target = self.target()
        identity = stat(f'/proc/{target.pid}/stat')[0]
        with self.assertRaises(MonitorError):
            snapshot(target.pid, identity + 1)
        client, process, output = self.monitor(target)
        client.request('BEGIN', name='too-short', mode='idle')
        report = self.finish(client, process, output)
        self.assertEqual(report['verdict'], 'ERROR')


if __name__ == '__main__':
    unittest.main()
