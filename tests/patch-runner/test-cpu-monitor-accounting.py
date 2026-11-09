#!/usr/bin/env python3
"""Deterministic accounting checks with known clocks, counters and identities."""
from contextlib import ExitStack
from pathlib import Path
import tempfile
import random
import unittest
from unittest import mock

import cpu_monitor


class AccountingTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix='cpu-accounting-')
        self.addCleanup(temporary.cleanup)
        patches = ExitStack()
        self.addCleanup(patches.close)
        self.now = 0.0
        self.counters = {'process': (1, 0)}
        patches.enter_context(mock.patch('cpu_monitor.time.monotonic', lambda: self.now))
        patches.enter_context(mock.patch('cpu_monitor.snapshot', lambda *_: self.counters.copy()))
        patches.enter_context(mock.patch('cpu_monitor.stat', return_value=(1, 0, 'S')))
        self.recorder = cpu_monitor.Recorder(Path(temporary.name), .05, .5, 80)
        self.recorder.hz = 100  # Exactly 10 ms ticks for these reference cases.
        self.addCleanup(self.recorder.log.close)
        self.recorder.command({'op': 'ATTACH', 'pid': 1})
        self.recorder.command({'op': 'BEGIN', 'name': 'known-clock', 'mode': 'observe'})

    def take(self, when, counters):
        self.now = when
        self.counters = counters
        self.recorder.sample()

    def test_pulses_across_sampling_boundaries(self):
        for duration in (.25, .5, .75):
            for offset_ms in range(0, 50, 5):
                with self.subTest(duration=duration, offset_ms=offset_ms):
                    self.recorder.events.clear()
                    self.recorder.command({'op': 'END'})
                    base = self.now
                    self.recorder.command({'op': 'BEGIN', 'name': 'pulse'})
                    initial = self.counters['process'][1]
                    start = .1 + offset_ms / 1000
                    for step in range(1, 31):
                        elapsed = step * .05
                        cpu_seconds = min(duration, max(0, elapsed - start))
                        ticks = initial + int(round(cpu_seconds * 100))
                        self.take(base + elapsed, {'process': (1, ticks)})
                    suspected = any(e['suspect'] for e in self.recorder.events)
                    self.assertEqual(suspected, duration >= .5)

    def test_jittered_sampling_with_known_cpu_integral(self):
        rng = random.Random(20261103)
        for case in range(200):
            duration = rng.choice((.25, .5, .75))
            offset = rng.uniform(0, .05)
            with self.subTest(case=case, duration=duration, offset=offset):
                self.recorder.events.clear()
                self.recorder.command({'op': 'END'})
                self.recorder.command({'op': 'BEGIN', 'name': f'jitter-{case}'})
                base = self.now
                initial = self.counters['process'][1]
                elapsed = 0
                while elapsed < 1.5:
                    elapsed += rng.uniform(.03, .07)
                    cpu_seconds = min(duration, max(0, elapsed - offset))
                    ticks = initial + int(cpu_seconds * 100)
                    self.take(base + elapsed, {'process': (1, ticks)})
                suspected = any(e['suspect'] for e in self.recorder.events)
                self.assertEqual(suspected, duration >= .5)

    def test_dense_jitter_search_with_counter_quantization(self):
        rng = random.Random(20261104)
        for case in range(2000):
            self.recorder.events.clear()
            self.recorder.command({'op': 'END'})
            self.recorder.command({'op': 'BEGIN', 'name': f'dense-jitter-{case}'})
            base = self.now
            initial = self.counters['process'][1]
            offset = rng.uniform(.1, .3)
            tick_offset = rng.random()
            elapsed = 0
            while elapsed < 1.5:
                elapsed += rng.uniform(.005, .099)
                integral = min(.5, max(0, elapsed - offset))
                ticks = initial + int(integral * 100 + tick_offset)
                self.take(base + elapsed, {'process': (1, ticks)})
            self.assertTrue(any(e['suspect'] for e in self.recorder.events),
                            f'undetected 500ms loop in jitter case {case}')

    def test_report_records_measurement_units_and_limitations(self):
        self.recorder.command({'op': 'END'})
        report = self.recorder.finish()
        self.assertEqual(report['clock_ticks_per_second'], 100)
        self.assertAlmostEqual(report['max_allowed_sample_gap'], .1)
        self.assertEqual(report['thread_interval_accounting'], 'lower_bound')

    def test_all_cores_are_not_a_percentage_denominator(self):
        for step in range(1, 15):
            self.take(step * .05, {'process': (1, step * 10),
                                  'thread:10': (10, step * 5),
                                  'thread:11': (11, step * 5)})
        peaks = self.recorder.phase['peak_window_cpu']
        self.assertAlmostEqual(peaks['process'], 200)
        self.assertAlmostEqual(peaks['thread:10'], 100)
        self.assertAlmostEqual(peaks['thread:11'], 100)

    def test_phase_change_does_not_charge_old_work_to_idle(self):
        for step in range(1, 15):
            self.take(step * .05, {'process': (1, step * 5)})
        self.recorder.command({'op': 'PHASE', 'name': 'idle', 'mode': 'idle'})
        for step in range(15, 30):
            self.take(step * .05, {'process': (1, 70)})
        self.assertEqual(self.recorder.phase['verdict'], 'PASS')
        self.assertEqual(self.recorder.phase['peak_window_cpu']['process'], 0)

    def test_tid_reuse_does_not_subtract_unrelated_counters(self):
        for step in range(1, 15):
            self.take(step * .05, {'process': (1, 0), 'thread:10': (10, 500)})
        self.recorder.command({'op': 'PHASE', 'name': 'new-thread', 'mode': 'observe'})
        for step in range(15, 30):
            self.take(step * .05, {'process': (1, (step - 14) * 5),
                                  'thread:10': (20, (step - 14) * 5)})
        self.assertAlmostEqual(self.recorder.phase['peak_window_cpu']['thread:10'], 100)

    def test_departed_thread_window_cache_is_bounded(self):
        for step in range(1, 201):
            self.take(step * .05, {'process': (1, step), f'thread:{step}': (step, 1)})
        for step in range(201, 220):
            self.take(step * .05, {'process': (1, 200)})
        # All old threads have been idle for more than a whole rolling window.
        self.assertEqual(set(self.recorder.phase_window.values), {'process'})

    def test_loop_crossing_phase_change_is_still_suspect(self):
        # The same 500ms loop straddles two individually long-enough phases.
        # A descriptive phase boundary must not erase the evidence of the loop.
        for step in range(1, 31):
            elapsed = step * .05
            ticks = round(100 * min(.5, max(0, elapsed - .5)))
            self.take(elapsed, {'process': (1, ticks)})
            if step == 15:
                self.recorder.command({'op': 'PHASE', 'name': 'second-half'})
        self.assertTrue(any(e['suspect'] for e in self.recorder.events))

    def test_near_limit_jitter_cannot_hide_a_loop(self):
        times = [.063601996448, .201721574036, .276506041827, .332746647462,
                 .461530651240, .608114294158, .688879661524, .791603175421,
                 .866014096333, 1.003902876908, 1.127176491956, 1.206908035975,
                 1.285275891788, 1.355580340430, 1.435579105719, 1.536705324520]
        try:
            for when in times:
                ticks = int(100 * min(.5, max(0, when - .183550359831)))
                self.take(when, {'process': (1, ticks)})
        except cpu_monitor.MonitorError:
            return  # Sparse sampling is honestly rejected, not called clean.
        self.assertTrue(any(e['suspect'] for e in self.recorder.events))

    def test_regressing_cpu_counter_is_an_error_not_negative_usage(self):
        self.take(.05, {'process': (1, 10)})
        with self.assertRaises(cpu_monitor.MonitorError):
            self.take(.1, {'process': (1, 9)})

    def test_rapid_phase_markers_do_not_hide_sustained_cpu(self):
        for step in range(1, 101):
            self.take(step * .01, {'process': (1, step)})
            if step % 5 == 0:
                self.recorder.command({'op': 'PHASE', 'name': f'marker-{step}'})
        self.assertTrue(any(e['suspect'] for e in self.recorder.events))

    def test_loop_crossing_test_boundary_is_still_recorded(self):
        for step in range(1, 31):
            self.take(step * .05, {'process': (1, round(100 * min(.5, max(0, step * .05 - .5))))})
            if step == 15:
                self.recorder.command({'op': 'END'})
                self.recorder.command({'op': 'BEGIN', 'name': 'next-test'})
        self.assertTrue(any(e['suspect'] for e in self.recorder.events))

    def test_configuration_cannot_undersample_the_detection_window(self):
        with self.assertRaises(cpu_monitor.MonitorError):
            cpu_monitor.Recorder(Path('/unused'), .2, .5, 80)

    def test_slow_snapshot_is_not_mistaken_for_one_instant(self):
        # /proc process counters are read before thread enumeration. A read
        # taking most of the gap cannot honestly be dated at its end.
        def slow_snapshot(*_):
            self.now += .08
            return self.counters.copy()
        with mock.patch('cpu_monitor.snapshot', side_effect=slow_snapshot):
            with self.assertRaisesRegex(cpu_monitor.MonitorError, 'snapshot'):
                self.recorder.sample()

    def test_slow_attach_baseline_is_also_rejected(self):
        self.recorder.pid = None
        def slow_snapshot(*_):
            self.now += .08
            return self.counters.copy()
        with mock.patch('cpu_monitor.snapshot', side_effect=slow_snapshot):
            with self.assertRaisesRegex(cpu_monitor.MonitorError, 'snapshot'):
                self.recorder.command({'op': 'ATTACH', 'pid': 1})

    def test_snapshot_duration_is_reported(self):
        def delayed_snapshot(*_):
            self.now += .02
            return self.counters.copy()
        with mock.patch('cpu_monitor.snapshot', side_effect=delayed_snapshot):
            self.recorder.sample()
        self.recorder.command({'op': 'END'})
        report = self.recorder.finish()
        self.assertAlmostEqual(report['max_snapshot_duration'], .02)
        self.assertAlmostEqual(report['max_allowed_snapshot_duration'], .05)

    def test_reused_tid_inside_window_does_not_inherit_old_cpu(self):
        self.take(.05, {'process': (1, 5), 'thread:10': (10, 5)})
        for step in range(2, 21):
            self.take(step * .05, {'process': (1, 5), 'thread:10': (20, 0)})
        self.assertEqual(self.recorder.phase['peak_window_cpu']['thread:10'], 0)
        self.assertFalse(any(e['suspect'] for e in self.recorder.events))

    def test_threads_invisible_between_samples_still_count_in_process(self):
        for step in range(1, 21):
            # Every worker has already exited when enumeration happens.
            self.take(step * .05, {'process': (1, min(step, 10) * 5)})
        self.assertTrue(any(e['suspect'] and e['subject'] == 'process'
                            for e in self.recorder.events))

    def test_long_sampling_stalls_cannot_certify_a_short_loop(self):
        # These gaps would average a 500ms full-core pulse below the 80% gate.
        # Such a run must be marked incomplete rather than called clean.
        with self.assertRaises(cpu_monitor.MonitorError):
            self.take(.49, {'process': (1, 0)})
            self.take(.98, {'process': (1, 49)})
            self.take(1.47, {'process': (1, 50)})


if __name__ == '__main__':
    unittest.main()
