#!/usr/bin/env python3
"""Python CPU-monitor reference and protocol client; production server is C++."""
import argparse
from collections import deque
import json
import math
import os
from pathlib import Path
import socket
import sys
import time


# --- Process identity and Linux CPU counters -------------------------------


class MonitorError(Exception):
    pass


def stat(path):
    """Return start ticks, accumulated CPU ticks and process state."""
    # comm may contain spaces and parentheses. Fields below start at field 3.
    data = Path(path).read_text()
    fields = data[data.rfind(')') + 2:].split()
    return (int(fields[19]), int(fields[11]) + int(fields[12]), fields[0])


def snapshot(pid, identity):
    """Read the process and surviving threads, checking the attached identity."""
    start, ticks, state = stat(f'/proc/{pid}/stat')
    if start != identity or state in ('Z', 'X'):
        raise MonitorError('target exited or PID was reused')

    values = {'process': (start, ticks)}
    for task in Path(f'/proc/{pid}/task').iterdir():
        try:
            start, ticks, state = stat(task / 'stat')
            if state not in ('Z', 'X'):
                values[f'thread:{task.name}'] = (start, ticks)
        except (FileNotFoundError, ProcessLookupError):
            # Exit before open produces ENOENT; exit between open and read
            # can produce ESRCH. Neither means the measured process died.
            pass
    return values


# --- Controller-side protocol client ---------------------------------------


def monitor_command():
    """Select an explicit native binary for tests, otherwise the Python oracle."""
    binary = os.environ.get('CPU_MONITOR_BINARY')
    return [binary] if binary else [sys.executable, str(Path(__file__).resolve())]


class Client:
    """One persistent connection per lab; all requests have bounded waits."""

    def __init__(self, path, timeout=5):
        self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_SEQPACKET)
        self.sock.settimeout(timeout)
        deadline = time.monotonic() + timeout
        try:
            while True:
                try:
                    self.sock.connect(str(path))
                    break
                except (FileNotFoundError, ConnectionRefusedError):
                    if time.monotonic() >= deadline:
                        raise TimeoutError('CPU monitor did not become ready')
                    time.sleep(.01)
        except BaseException:
            self.sock.close()
            raise

    def request(self, op, **fields):
        self.sock.sendall(json.dumps(dict(op=op, **fields)).encode())
        packet = self.sock.recv(65536)
        if not packet:
            raise MonitorError('CPU monitor disconnected')

        result = json.loads(packet)
        if not result.get('ok'):
            raise MonitorError(result.get('error', 'invalid monitor response'))
        return result

    def close(self):
        self.sock.close()


def positive(value, label):
    if type(value) not in (int, float):
        raise MonitorError(f'{label} must be a number, not a coercible value')
    value = float(value)
    if not math.isfinite(value) or value <= 0:
        raise MonitorError(f'{label} must be finite and positive')
    return value


# --- Sampling, phase accounting and report generation ----------------------


class RollingWindow:
    """Keep only the counters needed for one rolling CPU window."""

    def __init__(self, seconds, hz):
        self.seconds = seconds
        self.hz = hz
        self.history = deque()
        self.values = {}
        self.last_seen = {}

    def reset(self, now, values, phase):
        self.history.clear()
        self.values = values.copy()
        self.last_seen = {subject: now for subject in values}
        self.history.append((now, values.copy(), phase))

    def advance(self, now, values, phase):
        live_subjects = set(values)
        self.last_seen.update((subject, now) for subject in values)
        self.values.update(values)
        current = self.values.copy()
        self.history.append((now, current, phase))

        while len(self.history) > 1 and now - self.history[1][0] >= self.seconds:
            self.history.popleft()
        before, baseline, _ = self.history[0]
        elapsed = now - before
        if elapsed < self.seconds:
            return None

        percentages = {}
        for subject, (identity, ticks) in current.items():
            previous = baseline.get(subject)
            if not previous or previous[0] != identity:
                # A new thread's lifetime counter begins at zero. Retain the
                # final observed value after exit until it leaves the window.
                previous = (identity, 0)
            percentages[subject] = 100 * (ticks - previous[1]) / self.hz / elapsed

        phase_ids = list(dict.fromkeys(item[2] for item in self.history))
        expired = [subject for subject, last_seen in self.last_seen.items()
                   if subject not in live_subjects and last_seen <= before]
        for subject in expired:
            del self.last_seen[subject]
            del self.values[subject]
        return before, percentages, phase_ids


class Recorder:
    """Keep measurement state independently of the socket server."""

    def __init__(self, output, interval, window, threshold):
        self.output = output
        self.interval = positive(interval, 'interval')
        self.window = positive(window, 'window')
        self.threshold = positive(threshold, 'threshold')
        if self.interval > self.window / 10:
            raise MonitorError('window must contain at least ten configured sample intervals')
        self.max_allowed_gap = 2 * self.interval
        self.hz = os.sysconf('SC_CLK_TCK')

        # Attached process and active phase. A phase owns its rolling history.
        self.pid = None
        self.phase = None
        self.phases = []
        self.events = []
        self.phase_window = RollingWindow(window, self.hz)
        self.monitor_window = RollingWindow(window, self.hz)

        # Monitor health and output lifetime.
        self.samples = 0
        self.max_gap = 0
        self.max_snapshot_duration = 0
        self.started = time.monotonic()
        self.cpu_started = time.process_time()
        self.log = (output / 'samples.jsonl').open('x')
        self.error = None

    def sample(self):
        """Record one interval and evaluate continuous and phase-local windows."""
        values, now = self._read_snapshot(self.pid, self.identity)
        gap = now - self.previous_time
        self.max_gap = max(self.max_gap, gap)
        if gap < 0 or gap > self.max_allowed_gap:
            raise MonitorError('sampling gap too large or clock moved backwards')
        for subject, (identity, ticks) in values.items():
            previous = self.previous.get(subject)
            if ticks < 0 or (previous and previous[0] == identity and ticks < previous[1]):
                raise MonitorError(f'CPU counter moved backwards: {subject}')

        self._write_sample(now, values, gap)
        self.previous, self.previous_time = values, now

        phase_id = self.phase['id'] if self.phase else None
        whole = self.monitor_window.advance(now, values, phase_id)
        if whole:
            before, percentages, phase_ids = whole
            self._record_suspicions(before, now, percentages, phase_ids)

        if self.phase:
            local = self.phase_window.advance(now, values, phase_id)
            if local:
                before, percentages, _ = local
                for subject, cpu in percentages.items():
                    self._record_window_result(subject, before, now, cpu)

        return now

    def _read_snapshot(self, pid, identity):
        """Bound the temporal skew of the sequential process/thread reads."""
        before = time.monotonic()
        values = snapshot(pid, identity)
        now = time.monotonic()
        duration = now - before
        self.max_snapshot_duration = max(self.max_snapshot_duration, duration)
        if duration < 0 or duration > self.interval:
            raise MonitorError('snapshot duration exceeds sampling interval or clock moved backwards')
        return values, now

    def _write_sample(self, now, values, gap):
        percentages = {}
        for subject, (identity, ticks) in values.items():
            previous = self.previous.get(subject)
            if previous and previous[0] == identity and gap > 0:
                percentages[subject] = 100 * (ticks - previous[1]) / self.hz / gap

        record = dict(
            time=now,
            phase=self.phase and self.phase['id'],
            cpu=percentages,
            # Retain raw counters and identities so rates can be audited.
            counters=values,
            gap=gap,
        )
        self.log.write(json.dumps(record) + '\n')
        self.samples += 1

    def _record_suspicions(self, before, now, percentages, phase_ids):
        # Descriptive phase/test boundaries must not erase a sustained loop.
        # Cross-boundary observations never apply a phase-specific FAIL limit.
        for subject, cpu in percentages.items():
            if cpu >= self.threshold:
                self.events.append(dict(
                    scope='monitor',
                    phase=self.phase['id'] if self.phase else None,
                    phase_ids=phase_ids,
                    subject=subject,
                    start=before,
                    end=now,
                    cpu=cpu,
                    suspect=True,
                    violation=False,
                ))

    def _record_window_result(self, subject, before, now, cpu):
        peaks = self.phase['peak_window_cpu']
        peaks[subject] = max(cpu, peaks.get(subject, 0))

        violation = (
            self.phase['mode'] != 'observe'
            and cpu >= self.phase['limit']
        )
        if not violation:
            return

        self.events.append(dict(
            scope='phase',
            phase=self.phase['id'],
            subject=subject,
            start=before,
            end=now,
            cpu=cpu,
            suspect=False,
            violation=True,
        ))
        self.phase['verdict'] = 'FAIL'

    # Control transitions sample first, so the old phase owns its final interval.

    def command(self, msg):
        """Apply one acknowledged protocol transition."""
        op = msg['op']
        if op == 'ATTACH':
            self._attach(msg['pid'])
            return {}

        if self.pid is None:
            raise MonitorError('ATTACH required')
        now = self.sample()

        if op in ('BEGIN', 'PHASE'):
            self._begin_phase(op, msg, now)
        elif op == 'END':
            self._end_test(msg, now)
        elif op == 'FINISH':
            if self.phase or not self.phases:
                raise MonitorError('FINISH requires at least one completed test')
        else:
            raise MonitorError(f'unknown operation: {op}')

        return {'time': now}

    def _attach(self, pid):
        if self.pid is not None:
            raise MonitorError('already attached')
        if type(pid) is not int:
            raise MonitorError('PID must be an integer')
        if pid <= 0:
            raise MonitorError('PID must be positive')

        self.identity = stat(f'/proc/{pid}/stat')[0]
        self.previous, self.previous_time = self._read_snapshot(pid, self.identity)
        self.pid = pid
        self.monitor_window.reset(self.previous_time, self.previous, None)

    def _begin_phase(self, op, msg, now):
        if op == 'BEGIN' and self.phase is not None:
            raise MonitorError('BEGIN requires no active test')
        if op == 'PHASE' and self.phase is None:
            raise MonitorError('PHASE requires an active test')

        mode = msg.get('mode', 'observe')
        if mode not in ('observe', 'idle', 'bounded'):
            raise MonitorError('unknown CPU mode')
        name = msg['name']
        if not isinstance(name, str) or not name:
            raise MonitorError('name must be nonempty text')
        default_limit = 20 if mode == 'idle' else 80
        limit = positive(msg.get('limit', default_limit), 'limit')

        if self.phase:
            self.phase['end'] = now
        self.phase = dict(
            id=len(self.phases),
            name=name,
            mode=mode,
            limit=limit,
            start=now,
            verdict='PASS' if mode != 'observe' else 'OBSERVED',
            peak_window_cpu={},
        )
        self.phases.append(self.phase)

        # Never let a rolling CPU window span two different phase policies.
        self.phase_window.reset(now, self.previous, self.phase['id'])

    def _end_test(self, msg, now):
        if not self.phase:
            raise MonitorError('no active test')
        self.phase.update(end=now, test_result=msg.get('result'))
        self.phase = None
        self.phase_window = RollingWindow(self.window, self.hz)

    def finish(self):
        """Close the time series and atomically publish the final CPU report."""
        # A phase shorter than the evaluation window cannot certify a CPU gate.
        incomplete = any(
            phase['mode'] != 'observe' and not phase['peak_window_cpu']
            for phase in self.phases
        )
        if self.error or incomplete:
            verdict = 'ERROR'
        elif any(phase['verdict'] == 'FAIL' for phase in self.phases):
            verdict = 'FAIL'
        else:
            verdict = 'PASS'

        error = self.error
        if not error and incomplete:
            error = 'required phase shorter than evaluation window'

        report = dict(
            verdict=verdict,
            error=error,
            pid=self.pid,
            start_ticks=getattr(self, 'identity', None),
            interval=self.interval,
            window=self.window,
            suspect_threshold=self.threshold,
            clock_ticks_per_second=self.hz,
            max_allowed_sample_gap=self.max_allowed_gap,
            thread_interval_accounting='lower_bound',
            samples=self.samples,
            max_sample_gap=self.max_gap,
            max_snapshot_duration=self.max_snapshot_duration,
            max_allowed_snapshot_duration=self.interval,
            monitor_cpu_seconds=time.process_time() - self.cpu_started,
            elapsed=time.monotonic() - self.started,
            phases=self.phases,
            events=self.events,
        )

        self.log.close()
        temporary = self.output / 'report.json.tmp'
        temporary.write_text(json.dumps(report, indent=2) + '\n')
        temporary.replace(self.output / 'report.json')
        return report


# --- Server lifetime and command-line entry point ---------------------------


def run_session(connection, recorder, interval, timeout):
    """Serve one controller, sampling between commands until FINISH."""
    last_control = time.monotonic()
    next_sample = last_control + interval
    finished = False

    while not finished:
        now = time.monotonic()
        control_remaining = timeout - (now - last_control)
        if control_remaining <= 0:
            raise MonitorError('control deadline expired')

        # Wake for either an incoming command or the next sampling deadline.
        wait_seconds = max(.001, min(next_sample - now, control_remaining))
        connection.settimeout(wait_seconds)
        try:
            packet, _, flags, _ = connection.recvmsg(65536)
        except socket.timeout:
            packet = None

        if packet is not None:
            if not packet:
                raise MonitorError('controller disconnected before FINISH')
            if flags & socket.MSG_TRUNC:
                raise MonitorError('control packet too large')

            msg = json.loads(packet)
            result = recorder.command(msg)
            last_control = time.monotonic()
            finished = msg['op'] == 'FINISH'
            if finished:
                report = recorder.finish()
                result['verdict'] = report['verdict']
            connection.sendall(json.dumps(dict(ok=True, **result)).encode())

        if not finished and time.monotonic() >= next_sample:
            if recorder.pid is not None:
                recorder.sample()
            next_sample = time.monotonic() + interval

    return report


def serve(args):
    interval = positive(args.interval_ms, 'interval') / 1000
    window = positive(args.window_ms, 'window') / 1000
    threshold = positive(args.suspect_percent, 'threshold')
    timeout = positive(args.control_timeout, 'control timeout')

    # Every invocation owns a new result directory and one listening socket.
    output = Path(args.output)
    output.mkdir(parents=True, exist_ok=False)
    recorder = Recorder(output, interval, window, threshold)
    listener = socket.socket(socket.AF_UNIX, socket.SOCK_SEQPACKET)
    connection = None
    socket_identity = None

    try:
        listener.bind(args.socket)
        bound_stat = Path(args.socket).lstat()
        socket_identity = (bound_stat.st_dev, bound_stat.st_ino)
        os.chmod(args.socket, 0o600)
        listener.listen(1)
        listener.settimeout(timeout)

        connection, _ = listener.accept()
        report = run_session(connection, recorder, interval, timeout)
    except (OSError, ValueError, KeyError, TypeError, MonitorError) as error:
        # Protocol/measurement failures are distinct from CPU-limit failures.
        recorder.error = str(error)
        if not recorder.log.closed:
            report = recorder.finish()
        if connection:
            try:
                connection.sendall(json.dumps(dict(ok=False, error=str(error))).encode())
            except OSError:
                pass
        return 2
    finally:
        if connection:
            connection.close()
        listener.close()
        # An existing connection survives unlink/rebind. Only remove our own
        # pathname, never a successor's socket. Use a private socket directory.
        if socket_identity is not None:
            try:
                current = Path(args.socket).lstat()
                if (current.st_dev, current.st_ino) == socket_identity:
                    Path(args.socket).unlink()
            except FileNotFoundError:
                pass

    return 0 if report['verdict'] == 'PASS' else 1


def main():
    """Parse CLI configuration and run the standalone monitor."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--socket', required=True)
    parser.add_argument('--output', required=True)
    parser.add_argument('--interval-ms', type=float, default=50)
    parser.add_argument('--window-ms', type=float, default=500)
    parser.add_argument('--suspect-percent', type=float, default=80)
    parser.add_argument('--control-timeout', type=float, default=300,
                        help='maximum time without a command, including test execution')
    return serve(parser.parse_args())


if __name__ == '__main__':
    raise SystemExit(main())
