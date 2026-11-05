#!/usr/bin/env python3
"""Controlled diagnostic workload; CPU reference comes from the process clock."""
import json
import hashlib
import sys
import threading
import time


def burn(seconds):
    end = time.monotonic() + seconds
    while time.monotonic() < end:
        pass


def perform(command):
    operation = command['op']
    if operation == 'pulse':
        time.sleep(command.get('offset', 0))
        if command.get('thread', False):
            reference = {}

            def measured_burn():
                before = time.thread_time()
                burn(command['duration'])
                reference.update(thread_cpu_seconds=time.thread_time() - before,
                                 tid=threading.get_native_id())

            thread = threading.Thread(target=measured_burn)
            thread.start()
            thread.join()
            return reference
        else:
            burn(command['duration'])
    elif operation == 'multicore':
        # PBKDF2 releases Python's GIL, so these are genuinely concurrent
        # CPU-consuming threads within one measured process.
        references = []
        barrier = threading.Barrier(command['workers'])

        def parallel_worker():
            barrier.wait(timeout=5)
            before = time.thread_time()
            end = time.monotonic() + command['duration']
            while time.monotonic() < end:
                hashlib.pbkdf2_hmac('sha256', b'cpu-test', b'salt', 10000)
            references.append(dict(tid=threading.get_native_id(),
                                   cpu_seconds=time.thread_time() - before))

        threads = [threading.Thread(target=parallel_worker)
                   for _ in range(command['workers'])]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()
        return {'thread_references': references}
    elif operation == 'churn':
        count = 0
        end = time.monotonic() + command['duration']
        while time.monotonic() < end:
            thread = threading.Thread(target=time.sleep, args=(.001,))
            thread.start()
            thread.join()
            count += 1
        return {'threads_created': count}
    elif operation == 'sleep':
        time.sleep(command['duration'])
    else:
        raise ValueError(f'unknown workload: {operation}')
    return {}


print(json.dumps({'ready': True}), flush=True)
for line in sys.stdin:
    command = json.loads(line)
    before_wall = time.monotonic()
    before_cpu = time.process_time()
    details = perform(command)
    print(json.dumps(dict(
        wall_seconds=time.monotonic() - before_wall,
        cpu_seconds=time.process_time() - before_cpu,
        **details,
    )), flush=True)
