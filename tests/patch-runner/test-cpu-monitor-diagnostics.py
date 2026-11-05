#!/usr/bin/env python3
"""Extended real-process measurements; preserve artifacts with --output DIR."""
import argparse
import json
import os
from pathlib import Path
import selectors
import signal
import subprocess
import sys
import tempfile
import time
import unittest

from cpu_monitor import monitor_command, Client

HERE = Path(__file__).resolve().parent
ARTIFACT_ROOT = None
SOAK_SECONDS = 180


def read_reply(process, timeout):
    """Never let a failed diagnostic workload hang the test driver."""
    with selectors.DefaultSelector() as selector:
        selector.register(process.stdout, selectors.EVENT_READ)
        if not selector.select(timeout):
            raise TimeoutError('workload response deadline expired')
    line = process.stdout.readline()
    if not line:
        raise RuntimeError(f'workload exited: rc={process.poll()}')
    return json.loads(line)


def memory_kib(pid):
    for line in Path(f'/proc/{pid}/status').read_text().splitlines():
        if line.startswith('VmRSS:'):
            return int(line.split()[1])
    raise RuntimeError('monitor has no resident-memory counter')


class Lab:
    """Own only this diagnostic's processes, socket and report directory."""
    def __init__(self, output, attach=True):
        self.output = output
        output.mkdir(parents=True)
        self.socket_dir = tempfile.TemporaryDirectory(prefix='cpu-diag-')
        self.processes = []
        self.streams = []
        self.client = None
        try:
            self.target = self.spawn(
                [sys.executable, '-u', str(HERE / 'cpu_monitor_workload.py')],
                stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True,
            )
            assert read_reply(self.target, 5) == {'ready': True}
            stderr = (output / 'monitor-stderr.log').open('w')
            self.streams.append(stderr)
            socket_path = Path(self.socket_dir.name) / 'control.sock'
            self.monitor = self.spawn([
                *monitor_command(),
                '--socket', str(socket_path), '--output', str(output / 'monitor'),
                '--control-timeout', str(max(300, SOAK_SECONDS + 30)),
            ], stderr=stderr)
            self.client = Client(socket_path)
            if attach:
                self.client.request('ATTACH', pid=self.target.pid)
        except BaseException:
            self.close()
            raise

    def spawn(self, argv, **kwargs):
        process = subprocess.Popen(argv, **kwargs)
        self.processes.append(process)
        return process

    def start(self, command):
        self.target.stdin.write(json.dumps(command) + '\n')
        self.target.stdin.flush()

    def finish(self):
        reply = self.client.request('FINISH')
        self.monitor.wait(timeout=5)
        report = json.loads((self.output / 'monitor/report.json').read_text())
        assert reply['verdict'] == report['verdict']
        assert self.monitor.returncode == (0 if report['verdict'] == 'PASS' else 1)
        return report

    def close(self):
        if self.client:
            self.client.close()
        for process in reversed(self.processes):
            if process.poll() is None:
                process.send_signal(signal.SIGCONT)
                process.terminate()
                try:
                    process.wait(timeout=3)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait(timeout=3)
            for stream in (process.stdin, process.stdout):
                if stream:
                    stream.close()
        for stream in self.streams:
            stream.close()
        self.socket_dir.cleanup()


class Diagnostics(unittest.TestCase):
    def setUp(self):
        if ARTIFACT_ROOT:
            self.root = ARTIFACT_ROOT / self._testMethodName
            self.root.mkdir(parents=True)
        else:
            temporary = tempfile.TemporaryDirectory(prefix='cpu-diag-results-')
            self.addCleanup(temporary.cleanup)
            self.root = Path(temporary.name)

    def lab(self, name):
        lab = Lab(self.root / name)
        self.addCleanup(lab.close)
        return lab

    def assert_cpu_reference(self, lab, references):
        """Integrate measured process percentages; compare with high-res CPU time."""
        measured = {phase: 0.0 for phase in references}
        thread_measured = {phase: 0.0 for phase in references}
        for line in (lab.output / 'monitor/samples.jsonl').read_text().splitlines():
            sample = json.loads(line)
            phase = sample['phase']
            if phase in measured:
                measured[phase] += sample['cpu'].get('process', 0) * sample['gap'] / 100
                tid = references[phase].get('tid')
                if tid:
                    thread_measured[phase] += sample['cpu'].get(f'thread:{tid}', 0) * sample['gap'] / 100

        errors = []
        for phase, reference in references.items():
            difference = measured[phase] - reference['cpu_seconds']
            errors.append(dict(phase=phase, measured=measured[phase],
                               reference=reference['cpu_seconds'], error=difference))
            # /proc exports user/system time in clock ticks; phase boundaries
            # also include the tiny request/response overhead of the workload.
            tolerance = 3 / os.sysconf('SC_CLK_TCK') + .005
            self.assertLessEqual(abs(difference), tolerance, errors[-1])
            if 'thread_cpu_seconds' in reference:
                thread_error = thread_measured[phase] - reference['thread_cpu_seconds']
                errors[-1].update(thread_measured=thread_measured[phase],
                                  thread_reference=reference['thread_cpu_seconds'],
                                  thread_error=thread_error)
                # Short-lived threads lose their first/last partial intervals
                # in the per-interval series; the process total retains them.
                self.assertLessEqual(thread_error, tolerance, errors[-1])
                self.assertGreaterEqual(thread_error, -.1 - tolerance, errors[-1])
        (lab.output / 'cpu-reference.json').write_text(json.dumps(errors, indent=2))
        return errors

    def test_pulse_offsets_and_reference(self):
        lab = self.lab('matrix')
        references = {}
        cases = []
        phase = 0
        # Both persistent and short-lived workers; five offsets in one 50ms cycle.
        for threaded in (False, True):
            for duration in (.25, .5, .75):
                for offset in (0, .01, .025, .04, .049):
                    name = f'pulse-{duration}-offset-{offset}-thread-{threaded}'
                    lab.client.request('BEGIN', name=name, mode='observe')
                    lab.start(dict(op='pulse', duration=duration, offset=offset, thread=threaded))
                    references[phase] = read_reply(lab.target, 5)
                    time.sleep(.55)  # Include a complete post-pulse window.
                    lab.client.request('END', result='PASS')
                    cases.append(dict(phase=phase, duration=duration, offset=offset,
                                      threaded=threaded, reference=references[phase]))
                    phase += 1

        report = lab.finish()
        (self.root / 'cases.json').write_text(json.dumps(cases, indent=2))
        errors = self.assert_cpu_reference(lab, references)
        self.assertEqual(report['verdict'], 'PASS')
        for case in cases:
            events = [e for e in report['events'] if e['phase'] == case['phase'] and e['suspect']]
            if case['duration'] == .25:
                self.assertFalse(events, case)
            else:
                # Check delivered CPU as well as wall duration before judging
                # the detector: a descheduled workload cannot saturate a core.
                self.assertGreater(case['reference']['cpu_seconds'], .42, case)
                self.assertTrue(events, case)
        print('30 pulse cases: max CPU reference error =',
              max(abs(e['error']) for e in errors), flush=True)

    def test_eight_parallel_monitors(self):
        labs = [self.lab(str(index)) for index in range(8)]
        references = []
        for index, lab in enumerate(labs):
            lab.client.request('BEGIN', name=f'parallel-{index}', mode='idle')
        for index, lab in enumerate(labs):
            lab.start(dict(op='pulse' if index < 2 else 'sleep', duration=1.0))
        for lab in labs:
            references.append(read_reply(lab.target, 5))
        time.sleep(.1)
        for index, lab in enumerate(labs):
            lab.client.request('END', result='PASS')
            report = lab.finish()
            self.assert_cpu_reference(lab, {0: references[index]})
            self.assertEqual(report['verdict'], 'FAIL' if index < 2 else 'PASS')
        print('8 parallel monitors: two busy targets detected, six idle targets clean', flush=True)

    def test_multicore_process_accounting(self):
        lab = self.lab('multicore')
        lab.client.request('BEGIN', name='two-active-threads', mode='observe')
        lab.start(dict(op='multicore', workers=2, duration=1.5))
        reference = read_reply(lab.target, 10)
        time.sleep(.1)
        lab.client.request('END', result='PASS')
        report = lab.finish()
        (self.root / 'workload.json').write_text(json.dumps(reference, indent=2))
        self.assert_cpu_reference(lab, {0: reference})
        self.assertEqual(report['verdict'], 'PASS')
        delivered_percent = 100 * reference['cpu_seconds'] / reference['wall_seconds']
        self.assertGreater(delivered_percent, 140, reference)
        self.assertGreater(report['phases'][0]['peak_window_cpu']['process'], 140)
        self.assertEqual(len(reference['thread_references']), 2)
        print(f'multicore process: {delivered_percent:.1f}% of one core, process accounting matches', flush=True)

    def test_real_loop_crossing_phase_boundary(self):
        lab = self.lab('cross-phase')
        lab.client.request('BEGIN', name='first-half', mode='observe')
        lab.start(dict(op='pulse', duration=.5))
        time.sleep(.25)
        lab.client.request('PHASE', name='second-half', mode='observe')
        reference = read_reply(lab.target, 5)
        time.sleep(.55)
        lab.client.request('END', result='PASS')
        report = lab.finish()
        self.assertEqual(report['verdict'], 'PASS')
        self.assertGreater(reference['cpu_seconds'], .42)
        self.assertTrue(any(e['suspect'] and 0 in e.get('phase_ids', [])
                            and 1 in e.get('phase_ids', []) for e in report['events']))

    def test_same_process_observed_by_two_monitors(self):
        first = self.lab('first')
        self_counter = self.root / 'second'
        second = Lab(self_counter, attach=False)
        self.addCleanup(second.close)
        second.client.request('ATTACH', pid=first.target.pid)
        for lab in (first, second):
            lab.client.request('BEGIN', name='same-target', mode='observe')
        first.start(dict(op='pulse', duration=.75))
        reference = read_reply(first.target, 5)
        time.sleep(.1)
        for lab in (first, second):
            lab.client.request('END', result='PASS')
            report = lab.finish()
            self.assertEqual(report['verdict'], 'PASS')
            self.assertTrue(any(e['suspect'] for e in report['events']))
            self.assert_cpu_reference(lab, {0: reference})

    def test_256_idle_threads_snapshot_cost(self):
        lab = Lab(self.root / 'many-threads', attach=False)
        self.addCleanup(lab.close)
        source = (
            "import json, threading\n"
            "stop = threading.Event()\n"
            "for _ in range(256):\n"
            "    threading.Thread(target=stop.wait, daemon=True).start()\n"
            "print(json.dumps({'ready': True}), flush=True)\n"
            "input()\n"
        )
        target = lab.spawn([sys.executable, '-u', '-c', source],
                           stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True)
        self.assertEqual(read_reply(target, 10), {'ready': True})
        lab.client.request('ATTACH', pid=target.pid)
        lab.client.request('BEGIN', name='256-idle-threads', mode='idle')
        time.sleep(2)
        lab.client.request('END', result='PASS')
        report = lab.finish()
        self.assertEqual(report['verdict'], 'PASS')
        self.assertGreaterEqual(len(report['phases'][0]['peak_window_cpu']), 258)
        self.assertLessEqual(report['max_snapshot_duration'], .05)
        print(f"256 threads: snapshot max={report['max_snapshot_duration']:.6f}s, "
              f"monitor CPU={report['monitor_cpu_seconds']:.4f}s", flush=True)

    def test_sampling_stall_fails_closed(self):
        lab = self.lab('stalled-monitor')
        lab.client.request('BEGIN', name='stalled', mode='idle')
        lab.monitor.send_signal(signal.SIGSTOP)
        try:
            time.sleep(.22)
        finally:
            lab.monitor.send_signal(signal.SIGCONT)
        self.assertEqual(lab.monitor.wait(timeout=5), 2)
        report = json.loads((lab.output / 'monitor/report.json').read_text())
        self.assertEqual(report['verdict'], 'ERROR')
        self.assertIn('sampling gap', report['error'])

    def test_steady_cpu_soak(self):
        lab = self.lab('steady-cpu')
        duration = min(SOAK_SECONDS, 60)
        lab.client.request('BEGIN', name='steady-cpu', mode='observe')
        lab.start(dict(op='pulse', duration=duration))
        memory = []
        started = time.monotonic()
        while time.monotonic() - started < duration:
            memory.append(dict(seconds=time.monotonic() - started,
                               rss_kib=memory_kib(lab.monitor.pid)))
            time.sleep(min(5, max(.01, duration - (time.monotonic() - started))))
        reference = read_reply(lab.target, 10)
        lab.client.request('END', result='PASS')
        report = lab.finish()
        (self.root / 'memory.json').write_text(json.dumps(memory, indent=2))
        self.assert_cpu_reference(lab, {0: reference})
        self.assertEqual(report['verdict'], 'PASS')
        self.assertTrue(report['events'])
        self.assertLess(memory[-1]['rss_kib'] - memory[0]['rss_kib'], 8 * 1024)
        print(f'steady CPU: {reference}, {len(report["events"])} suspicious windows recorded', flush=True)

    def test_thread_churn_soak(self):
        lab = self.lab('churn')
        lab.client.request('BEGIN', name='continuous-thread-churn', mode='observe')
        lab.start(dict(op='churn', duration=SOAK_SECONDS))
        memory = []
        started = time.monotonic()
        while time.monotonic() - started < SOAK_SECONDS:
            memory.append(dict(seconds=time.monotonic() - started,
                               rss_kib=memory_kib(lab.monitor.pid)))
            if len(memory) % 3 == 0:
                print(f'churn soak: {memory[-1]}', flush=True)
            time.sleep(min(5, max(.01, SOAK_SECONDS - (time.monotonic() - started))))
        reference = read_reply(lab.target, 10)
        lab.client.request('END', result='PASS')
        report = lab.finish()
        (self.root / 'memory.json').write_text(json.dumps(memory, indent=2))
        (self.root / 'workload.json').write_text(json.dumps(reference, indent=2))
        self.assert_cpu_reference(lab, {0: reference})
        self.assertEqual(report['verdict'], 'PASS')
        # After warm-up, thread churn must not retain an unbounded inventory.
        warm = memory[min(3, len(memory) - 1)]['rss_kib']
        growth = memory[-1]['rss_kib'] - warm
        print(f'churn soak: {reference}, memory growth after warmup={growth} KiB', flush=True)
        self.assertLess(growth, 8 * 1024, memory)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path)
    parser.add_argument('--soak-seconds', type=float, default=180)
    options, remaining = parser.parse_known_args()
    ARTIFACT_ROOT = options.output
    SOAK_SECONDS = options.soak_seconds
    if ARTIFACT_ROOT:
        ARTIFACT_ROOT.mkdir(parents=True, exist_ok=False)
        print('Artifacts:', ARTIFACT_ROOT, flush=True)
    unittest.main(argv=[sys.argv[0], *remaining])
