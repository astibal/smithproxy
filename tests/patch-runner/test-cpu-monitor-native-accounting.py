#!/usr/bin/env python3
"""Differential test of the compiled C++ core against the Python reference."""
import json
import math
import os
from pathlib import Path
import random
import subprocess
import tempfile
from unittest import mock

import cpu_monitor as reference


def step(time, ticks, command=None, **extra):
    result = dict(time=time, counters={'process': [1, ticks]}, **extra)
    if command is not None:
        result['command'] = command
    return result


def series(duration, offset, gaps, boundary=None):
    steps = [step(0, 0, dict(op='ATTACH', pid=1)),
             step(0, 0, dict(op='BEGIN', name='first', mode='observe'))]
    elapsed = 0
    changed = False
    for gap in gaps:
        elapsed += gap
        ticks = int(100 * min(duration, max(0, elapsed - offset)))
        command = None
        if boundary and elapsed >= boundary and not changed:
            command = dict(op='PHASE', name='second', mode='observe')
            changed = True
        steps.append(step(elapsed, ticks, command))
    steps.append(step(elapsed, ticks, dict(op='END', result='PASS')))
    steps.append(step(elapsed, ticks, dict(op='FINISH')))
    return dict(steps=steps)


def oracle(case, directory):
    now = [0.0]
    values = [{'process': (1, 0)}]
    records = []
    with mock.patch.object(reference.time, 'monotonic', lambda: now[0]), \
         mock.patch.object(reference.time, 'process_time', lambda: 0), \
         mock.patch.object(reference, 'snapshot', lambda *_: values[0]), \
         mock.patch.object(reference, 'stat', return_value=(1, 0, 'S')):
        recorder = reference.Recorder(directory, .05, .5, 80)
        try:
            for item in case['steps']:
                now[0] = item['time']
                values[0] = {name: tuple(value) for name, value in item['counters'].items()}
                if 'command' in item:
                    recorder.command(item['command'])
                else:
                    recorder.sample()
            report = recorder.finish()
            records = [json.loads(line) for line in (directory / 'samples.jsonl').read_text().splitlines()]
        finally:
            recorder.log.close()
            (directory / 'samples.jsonl').unlink()
    return dict(report=report, samples=records)


def normalized(result):
    report = result['report']
    report.pop('implementation', None)
    report.pop('attribution', None)
    for event in report['events']:
        event.pop('attribution', None)
        if event['scope'] == 'monitor':
            # Native reporting intentionally removes the misleading single
            # owner on crossing windows. Compare the complete overlapping set.
            event['phase'] = event['phase_ids'][0] if len(event['phase_ids']) == 1 else None
    report['events'].sort(key=lambda e: (e['start'], e['end'], e['scope'], e['subject']))
    return result


def equal(left, right, path='root'):
    if isinstance(left, dict):
        assert left.keys() == right.keys(), (path, left.keys(), right.keys())
        for key in left:
            equal(left[key], right[key], path + '.' + key)
    elif isinstance(left, list):
        assert len(left) == len(right), (path, len(left), len(right))
        for index, (a, b) in enumerate(zip(left, right)):
            equal(a, b, f'{path}[{index}]')
    elif isinstance(left, (int, float)) and not isinstance(left, bool):
        assert math.isclose(left, right, rel_tol=1e-10, abs_tol=1e-9), (path, left, right)
    else:
        assert left == right, (path, left, right)


def main():
    binary = os.environ['CPU_MONITOR_REPLAY']
    rng = random.Random(20261105)
    cases = [series(duration, offset / 1000, [.05] * 30)
             for duration in (.25, .5, .75) for offset in range(0, 50, 5)]
    for index in range(2000):
        duration = rng.choice((.25, .5, .75))
        gaps = [rng.uniform(.005, .099) for _ in range(40)]
        cases.append(series(duration, rng.uniform(.1, .3), gaps,
                            boundary=.4 if index % 2 else None))

    # Changing policies must never transfer benchmark work to the next test.
    policy = series(.5, 0, [.05] * 30)
    policy['steps'][12]['command'] = dict(op='PHASE', name='idle', mode='idle')
    cases.append(policy)
    reuse = series(.75, 0, [.05] * 30)
    for item in reuse['steps']:
        t = item['time']
        item['counters']['thread:10'] = [10, int(t * 100)] if t < .4 else [20, 0]
    cases.append(reuse)

    # Fault injection exercises the same compiled Recorder, not a Python mock.
    fault_cases = []
    for extra in (dict(read_delay=.08), dict(fail_write=True), dict(fail_read=True)):
        fault_cases.append(dict(steps=[step(0, 0, dict(op='ATTACH', pid=1)), step(.05, 1, **extra)]))
    fault_cases.append(dict(steps=[step(0, 0, dict(op='ATTACH', pid=1), read_delay=.08)]))
    fault_cases.append(dict(steps=[step(0, 0, dict(op='ATTACH', pid=1)), step(.2, 10)]))
    fault_cases.append(dict(steps=[step(0, 10, dict(op='ATTACH', pid=1)), step(.05, 9)]))
    reused_pid = dict(steps=[step(0, 0, dict(op='ATTACH', pid=1)),
                            dict(time=.05, counters={'process': [2, 0]})])
    fault_cases.append(reused_pid)
    all_cases = cases + fault_cases
    run = subprocess.run([binary], input=''.join(json.dumps(case) + '\n' for case in all_cases),
                         capture_output=True, text=True, timeout=90)
    assert run.returncode == 0, run.stderr
    results = [json.loads(line) for line in run.stdout.splitlines()]
    assert len(results) == len(all_cases)
    with tempfile.TemporaryDirectory(prefix='native-accounting-') as directory:
        for index, case in enumerate(cases):
            actual = results[index]
            for event in actual['report']['events']:
                if event['scope'] == 'monitor' and len(event['phase_ids']) > 1:
                    assert event['phase'] is None, event
            equal(normalized(oracle(case, Path(directory))), normalized(actual), f'case-{index}')
    for result in results[len(cases):]:
        assert result['report']['verdict'] == 'ERROR', result
    print(f'{len(cases)} differential vectors and {len(fault_cases)} native fault cases passed')


if __name__ == '__main__':
    main()
