#!/usr/bin/env python3
"""Experimental collector comparison; compile the C++ prototype separately."""
import argparse
import cProfile
import json
import os
from pathlib import Path
import pstats
import selectors
import subprocess
import sys
import time

import cpu_monitor as monitor

TARGET = r'''
import ctypes, json, threading, time, sys
ctypes.CDLL(None).prctl(15, b'odd ) name\n', 0, 0, 0)
stop = threading.Event()
for _ in range(int(sys.argv[1])):
    threading.Thread(target=stop.wait, daemon=True).start()
print(json.dumps({'ready': True}), flush=True)
for line in sys.stdin:
    command = json.loads(line)
    before = time.process_time()
    end = time.monotonic() + command['duration']
    while time.monotonic() < end:
        if command['op'] == 'churn':
            worker = threading.Thread(target=lambda: None)
            worker.start()
            worker.join()
    print(json.dumps({'cpu': time.process_time() - before}), flush=True)
'''


def reply(target):
    with selectors.DefaultSelector() as selector:
        selector.register(target.stdout, selectors.EVENT_READ)
        if not selector.select(10):
            raise TimeoutError('target did not respond')
    return json.loads(target.stdout.readline())


def lean_stat(path):
    with open(path) as stream:
        text = stream.read()
    fields = text[text.rfind(')') + 2:].split()
    return int(fields[19]), int(fields[11]) + int(fields[12]), fields[0]


def lean_snapshot(pid, identity):
    root = f'/proc/{pid}'
    start, ticks, state = lean_stat(root + '/stat')
    if start != identity or state in ('X', 'Z'):
        raise RuntimeError('target identity changed')
    values = {'process': (start, ticks)}
    with os.scandir(root + '/task') as entries:
        for entry in entries:
            try:
                start, ticks, state = lean_stat(entry.path + '/stat')
                if state not in ('X', 'Z'):
                    values['thread:' + entry.name] = (start, ticks)
            except (FileNotFoundError, ProcessLookupError):
                pass
    return values


def python_collect(pid, count, stride, interval, output, lean=False):
    identity = monitor.stat(f'/proc/{pid}/stat')[0]
    cpu, wall = time.process_time(), time.monotonic()
    longest = 0
    with output.open('w') as stream:
        for index in range(count):
            before = time.monotonic()
            if stride and index % stride == 0:
                values = (lean_snapshot if lean else monitor.snapshot)(pid, identity)
            else:
                start, ticks, state = monitor.stat(f'/proc/{pid}/stat')
                if start != identity or state in ('X', 'Z'):
                    raise RuntimeError('target identity changed')
                values = {'process': (start, ticks)}
            stream.write(json.dumps(values) + '\n')
            longest = max(longest, time.monotonic() - before)
            time.sleep(interval)
    return dict(cpu=time.process_time() - cpu, wall=time.monotonic() - wall, max_read=longest)


def cpp_collect(binary, pid, count, stride, interval, output):
    with output.open('w') as stream:
        result = subprocess.run([str(binary), str(pid), str(count), str(stride),
                                 str(round(interval * 1000))], stdout=stream,
                                stderr=subprocess.PIPE, text=True, timeout=20)
    if result.returncode:
        raise RuntimeError(result.stderr)
    return json.loads(result.stderr)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--binary', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    args.output.mkdir(parents=True, exist_ok=False)
    binary = args.binary.resolve()
    results = []

    for workers in (0, 32, 256):
        with subprocess.Popen([sys.executable, '-u', '-c', TARGET, str(workers)],
                              stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                              text=True) as target:
            try:
                assert reply(target) == {'ready': True}
                for repetition in range(2):
                    for stride in (1, 4, 0):
                        # Alternate order to reduce warm-cache/order bias.
                        for language in (('python', 'lean_python', 'cpp') if repetition == 0
                                         else ('cpp', 'lean_python', 'python')):
                            path = args.output / f'{workers}-{stride}-{repetition}-{language}.jsonl'
                            if language != 'cpp':
                                metrics = python_collect(target.pid, 20, stride, .05, path,
                                                         lean=language == 'lean_python')
                            else:
                                metrics = cpp_collect(binary, target.pid, 20, stride, .05, path)
                            rows = [json.loads(line) for line in path.read_text().splitlines()]
                            assert len(rows) == 20
                            for index, row in enumerate(rows):
                                assert len(row) == (workers + 2 if stride and index % stride == 0 else 1)
                            results.append(dict(workers=workers, stride=stride, repetition=repetition,
                                                language=language, **metrics))

                # Actual monitor profiling, distinct from the collector benchmark.
                output = args.output / f'monitor-{workers}'
                output.mkdir()
                recorder = monitor.Recorder(output, .05, .5, 80)
                profiler = cProfile.Profile()
                try:
                    recorder.command(dict(op='ATTACH', pid=target.pid))
                    recorder.command(dict(op='BEGIN', name='profile-idle', mode='idle'))
                    for _ in range(20):
                        time.sleep(.05)
                        profiler.runcall(recorder.sample)
                    recorder.command(dict(op='END', result='PASS'))
                    assert recorder.finish()['verdict'] == 'PASS'
                finally:
                    recorder.log.close()
                profiler.dump_stats(str(output / 'profile.pstats'))
                with (output / 'profile.txt').open('w') as stream:
                    pstats.Stats(profiler, stream=stream).sort_stats('cumulative').print_stats(25)
                print(f'{workers} workers: comparison and full-monitor profile complete', flush=True)

                # Active and departing threads: CPU clock reference plus an
                # independent bracket around one complete C++ snapshot.
                for operation in ('burn', 'churn'):
                    before = monitor.stat(f'/proc/{target.pid}/stat')[1]
                    target.stdin.write(json.dumps(dict(op=operation, duration=1)) + '\n')
                    target.stdin.flush()
                    cpp_collect(binary, target.pid, 25, 1, .05,
                                args.output / f'active-{workers}-{operation}.jsonl')
                    reference = reply(target)['cpu']
                    lower = monitor.snapshot(target.pid, monitor.stat(f'/proc/{target.pid}/stat')[0])
                    snapshot_path = args.output / f'bracket-{workers}-{operation}.jsonl'
                    cpp_collect(binary, target.pid, 1, 1, 0, snapshot_path)
                    upper = monitor.snapshot(target.pid, lower['process'][0])
                    actual = json.loads(snapshot_path.read_text())
                    lean = lean_snapshot(target.pid, lower['process'][0])
                    for subject, (identity, ticks) in lean.items():
                        assert identity == upper[subject][0]
                        assert ticks >= upper[subject][1]
                    for subject, (identity, ticks) in actual.items():
                        assert identity == lower[subject][0] == upper[subject][0]
                        assert lower[subject][1] <= ticks <= upper[subject][1]
                    measured = (actual['process'][1] - before) / monitor.os.sysconf('SC_CLK_TCK')
                    assert abs(measured - reference) < .04, (measured, reference)
                    results.append(dict(workers=workers, operation=operation,
                                        measured_cpu=measured, reference_cpu=reference))
            finally:
                target.terminate()
                target.wait(timeout=5)
                target.stdin.close()
                target.stdout.close()
        (args.output / 'summary.json').write_text(json.dumps(results, indent=2))
    print('All comparisons and reference checks passed', flush=True)


if __name__ == '__main__':
    main()
