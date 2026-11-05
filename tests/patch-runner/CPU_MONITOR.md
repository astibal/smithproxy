# CPU monitor: native implementation and Python reference

The monitor is a standalone C++17 Linux helper. The Python implementation is
retained as a test oracle and protocol client. Each lab starts its own process with
its own Unix `SOCK_SEQPACKET` socket and new output directory. It does not start,
stop or signal the measured proxy. The opt-in real-proxy integration described below exercises a disposable
HTTP CONNECT proxy. Traffic-profile and ProxyNightmare integration remain deferred. The planned branch work proceeds in this order: validate the monitor,
connect ProxyNightmare lifecycle scenarios, then unify runner profiles.

The agreed profile direction is `full` as a selection of independently runnable
profiles, not a separate test inventory. Proposed membership is quick, native,
sanity, traffic, corpus and fuzz. Traffic retains existing transfer/churn/QUIC
checks and gains PN lifecycle checks. Benchmark/coverage/exploratory fuzz remain
separate. This document records the plan, not implemented profile behavior.

## Start and control

```sh
cmake -S tests/patch-runner/cpu-monitor -B /tmp/smithproxy-cpu-build -DCMAKE_BUILD_TYPE=Release
cmake --build /tmp/smithproxy-cpu-build -j 2
/tmp/smithproxy-cpu-build/smithproxy-cpu-monitor \
    --socket /tmp/my-lab-cpu.sock --output /tmp/my-lab-cpu-results
```

The standalone build uses the repository's vendored nlohmann JSON headers and
needs no Smithproxy submodules or running proxy. The main project also builds
the target when its Python-backed native tests are enabled. There is no Python
runtime in the monitor process.

The controller imports `Client` from `cpu_monitor.py` (add the patch-runner
directory to its Python import path):

```python
client = Client('/tmp/my-lab-cpu.sock', timeout=5)
client.request('ATTACH', pid=proxy_pid)
client.request('BEGIN', name='tls-close', mode='observe')
# Run the test; its implementation need not know about the monitor.
client.request('PHASE', name='after-close-notify', mode='idle')
# Wait for the defined quiet interval, including any post-test observation.
client.request('END', result='PASS')
result = client.request('FINISH')
client.close()
# Treat result['verdict'] != 'PASS', a failed request, monitor exit != 0,
# or a missing report as an unsuccessful CPU gate.
```

Messages are JSON objects, one packet per request. Replies contain `ok` and
monotonic `time` for phase transitions; `FINISH` includes the CPU verdict after
writing the report. Only one persistent controller connection is accepted.
ATTACH acknowledges a baseline sample, BEGIN a new test, PHASE closes the previous
phase and starts a new one, END closes the test, FINISH closes monitoring.
PHASE is optional. There is no implicit phase detection from log text.
The functional test result is recorded separately and is not changed by the CPU
monitor. The runner must combine both verdicts.

No command wait is unbounded: the client defaults to five seconds; the server
requires another command within `--control-timeout` (default 300 seconds).
Choose a server timeout longer than the test's own bounded duration. Disconnect,
invalid protocol order, target death or reused PID produce ERROR, not PASS.
Identity uses PID plus `/proc/PID/stat` start time. Thread counters likewise
use TID plus start time. Keep the target alive until FINISH; expected target
termination requires a future explicit protocol extension.

## Sampling and interpretation

Defaults: 50 ms samples, rolling windows at least 500 ms long, suspicious window
at 80% of one CPU core. Options are `--interval-ms`, `--window-ms` and
`--suspect-percent`. Actual elapsed monotonic time is the denominator; this is
not synchronized to the proxy poll cycle. Linux CPU counters have clock-tick
resolution, so individual 50 ms readings are quantized. No single boundary
sample decides the verdict. Continuous suspicious-window detection crosses
phase and test boundaries, so splitting a loop between two labels does not hide
it. Events carry `scope: monitor` and the intersected `phase_ids` (including null
for time outside a test). CPU policy windows stay within their phase: preceding
benchmark CPU must not fail a later idle phase. These events use `scope: phase`.
A suspicious observation alone does not change the CPU verdict. Native events
are marked `attribution: temporal_overlap_only`: CPU use during a test does not
prove that test caused it. A continuous window crossing multiple phases has
`phase: null` and lists all intersected `phase_ids`; it is never assigned solely
to the test active at the end. Work left running by an earlier test and multiple
tests sharing one PID cannot be causally separated using CPU counters alone.
Parallel labs must keep their own PID, controller and monitor context.

Modes:

- `observe`: record suspicious windows without a CPU failure.
- `idle`: fail if any process/thread window reaches the limit (default 20%).
- `bounded`: same gate, with default 80%; pass an explicit `limit` in the message.

All limits are initial configurable values, not yet calibrated for Smithproxy.
100% always means one fully occupied core, even on a many-core host. Process
usage can exceed 100%. A required phase without a complete window is ERROR.
A sampling gap over two configured sample intervals (100 ms by default)
is ERROR anywhere after ATTACH, so a suspended/starved monitor cannot certify a
missing interval. Configuration requires at least ten nominal samples per
window. The gap budget is deliberately stricter than the earlier 150 ms budget:
a near-limit jitter pattern could otherwise dilute a 500 ms pulse below 80%.
Regressing counters or a backwards monotonic clock also invalidate measurement.
Process and thread files are read sequentially, not atomically. A snapshot taking
longer than one configured interval (50 ms by default) is rejected, including
the ATTACH baseline. Reports expose `max_snapshot_duration` and
`max_allowed_snapshot_duration`; sub-budget read skew remains a measurement
limitation, particularly for processes with many threads.

The process aggregate includes CPU from completed threads. For a thread that
exits between samples, its last observed counter is retained until it leaves the rolling window;
per-thread attribution therefore conservatively misses its final partial
interval. Threads which start and finish entirely between samples may appear
only in the process aggregate. Child processes are not included. A thread exiting during enumeration is
normal: missing files (ENOENT), vanished tasks during read (ESRCH), and dead
thread states are skipped. Access errors still fail the measurement; target
process death is still an error.

All process and thread counters are collected at every nominal 50 ms sample.
There is no reduced-frequency thread mode in the native monitor. As in the
reference, the scheduler waits one interval after a completed sampling pass;
actual sample gaps include work and are recorded and bounded.

`report.json` contains phases, peak rolling CPU per process/thread, suspicious
and violating windows, measured sample gaps and monitor CPU time (excluding
interpreter startup). Overlapping windows are individual observations, not
independent incidents. `samples.jsonl` contains the per-interval time series, plus the raw CPU tick
counters and process/thread start identities used to calculate it. Percentages
use `SC_CLK_TCK` ticks per second, stored as `clock_ticks_per_second` in the
report. The report also stores `max_allowed_sample_gap` and labels per-thread
interval accounting as `lower_bound`. Per-interval thread rates require two live
observations: summing them omits a new thread's first observed partial interval
as well as its unobserved final interval. They are therefore a lower-bound
attribution, not an exact per-thread billing record. Rolling-window detection
uses the first observed cumulative counter of a new thread; process totals
retain CPU from all threads, including those never observed individually.
A high CPU window is evidence of consumption, not proof of an epoll loop.
Automatic stack collection is deferred; no debugger attaches in this version.

## Verification

```sh
ctest --test-dir /tmp/smithproxy-cpu-build -L unit --output-on-failure
CPU_MONITOR_BINARY=/tmp/smithproxy-cpu-build/smithproxy-cpu-monitor \
    python3 tests/patch-runner/test-cpu-monitor-diagnostics.py --output /tmp/cpu-native-new -v
```

CTest selects the C++ binary explicitly. `CPU_MONITOR_BINARY` selects it for
direct Python process/protocol tests; without that variable those tests use the
Python reference. Two Python-only reader injections and two Python-only server
injections are skipped for native process runs. They are replaced by native
read-syscall race tests and injected clock/reader/writer cases in the compiled
core. The `cpu-monitor-replay` test executable compares that same core against
Python on 2,032 deterministic vectors plus seven native error cases; it is not
a runtime mode or a replacement server.

Registered as `unit.patch_runner_cpu_monitor` in CTest. The test is serial
relative to other CTest work so intentional host contention does not obscure
the controlled 500 ms pulse. It still explicitly runs two monitors in parallel
and checks their isolation. No root or external network is needed; local Unix
sockets and `/proc` access are required.

Initial local verification (2026-11-03): all ten controlled-process tests passed.
A 500 ms pulse reached approximately 95% of one core in a rolling window and
was detected, including thread attribution; the concurrent sleeping target
passed. The sleeping single-thread target cost 0.0101 CPU seconds over roughly
1.1 wall seconds (about 0.9% of a core). With 32 additional sleeping threads,
the monitor cost 0.0488 CPU seconds over 1.118 seconds (about 4.4% of a core),
with a maximum observed sampling gap of 52.2 ms. These are short local
measurements, not a general overhead guarantee. Thread-count scaling and
parallel monitor overhead must be considered before enabling timing-sensitive
proxy gates. The real Smithproxy/PN path has not been exercised yet.

Repeated verification subsequently reproduced a thread-exit race: Linux may
return ESRCH when a task exits after its stat file is opened but before it is
read. The monitor now skips that departed thread, and still propagates access
errors and process death. Two regression tests cover this behavior. After the
fix, 20 full rounds of the expanded 12-test suite passed (240 checks); the
500 ms pulse and concurrent idle-target isolation passed in every round.
The original intermittent disconnect was not captured, so this reproduction
identifies a consistent failure path rather than proving the original cause.

## Extended measurement diagnostics

```sh
python3 tests/patch-runner/test-cpu-monitor-accounting.py -v
python3 tests/patch-runner/test-cpu-monitor-diagnostics.py \
    --output /tmp/cpu-monitor-diagnostics-new -v
```

The accounting suite is registered as `unit.patch_runner_cpu_accounting`. It
uses known counters and clocks: 30 pulse/offset combinations, 200 reproducible
jitter patterns plus 2,000 near-budget jitter/quantization combinations, multicore normalization, phase isolation, TID reuse, bounded
rolling history and sampling-stall rejection. It does not rely on host speed.

The real-process suite is registered as `extended.patch_runner_cpu_diagnostics`
with `RUN_SERIAL` and a 600-second deadline. It is excluded from the ordinary
native gate unless extended tests are requested. It checks 30 pulse/offset
combinations against `CLOCK_PROCESS_CPUTIME_ID` (Python `process_time`) and
loops crossing phase boundaries, two monitors observing the same target, and
short-lived workers against `CLOCK_THREAD_CPUTIME_ID` (`thread_time`), eight
parallel monitors, two CPU-active threads within one process, a 220 ms sampling
stall, 60 seconds of steady CPU and 180 seconds of thread churn. `--soak-seconds`
can shorten exploratory runs; it must not be confused with the full duration.

The references use different, higher-resolution kernel accounting interfaces
than `/proc/PID/stat` tick fields; they are not independent of the kernel itself.
The process comparison permits three clock ticks plus 5 ms for quantization
and workload command overhead. The thread comparison permits two sample
intervals plus that tolerance, because of the lower-bound attribution above.
Host CPU starvation is reported as a failed workload precondition, not repaired
by lowering the detector threshold. Timeouts bound every child response.

`--output` retains raw monitor reports, interval samples, per-case CPU reference
comparisons, stderr, workload metadata and long-run RSS measurements. Use a new
directory for each invocation. The monitor's rolling cache drops departed
threads after their last ticks leave the window; phase peak summaries and
recorded suspicious windows remain in the report and grow with test duration.

## Failure-path diagnostics

```sh
python3 tests/patch-runner/test-cpu-monitor-faults.py -v
```

Registered as `unit.patch_runner_cpu_faults`. Twelve tests exercise malformed and
oversized packets, invalid phase arguments and command ordering, strict integer
PIDs, existing output preservation, occupied/replaced/removed socket paths,
report publication failure injected sample-write failure, a real child-only file-size limit, and slow
process reads during ATTACH/sampling. Measurement and
protocol failures must not produce a successful CPU gate. Put the socket in a
private per-run directory; cleanup checks pathname identity before removing it,
but is not intended to arbitrate concurrent hostile pathname replacement.

### Snapshot-duration follow-up

A later dry campaign added delayed `/proc` reads at ATTACH and during sampling,
TID reuse inside a rolling window, and workers invisible between samples. The
snapshot-duration guard rejects the delayed reads; the identity/aggregate cases
pass. A real target with 256 sleeping worker threads passed with a 16.8 ms
maximum read duration and 67.6 ms maximum sample gap, but monitoring consumed
0.533 CPU seconds over 2.135 wall seconds (about 25% of one core). Per-thread
50 ms sampling has a material observer cost at that scale; do not extrapolate
single-thread overhead to large targets or many simultaneous monitors.

## Historical collector experiment

`cpu_collector_prototype.cpp` and `compare-cpu-collectors.py` compare counter
collection, independently of the control protocol and CPU verdict logic:

```sh
g++ -O2 -std=c++17 -Wall -Wextra -Werror tests/patch-runner/cpu_collector_prototype.cpp -o /tmp/cpu-collector
python3 tests/patch-runner/compare-cpu-collectors.py --binary /tmp/cpu-collector --output /tmp/cpu-comparison-new
```

The comparison preserves raw samples, CPU clock checks, timings and cProfile
output for the full Python Recorder. It covers 0/32/256 sleeping workers, active
CPU, departing threads and unusual process names. It alternates collector order
and measures current Python, a simpler open/scandir Python variant and C++.
The historical comparison includes strides 1/4/0. Reduced-detail and
process-only modes were rejected for the production monitor; they remain only
as recorded benchmark experiments. All variants sleep 50 ms after collection, so actual gaps also include
collection time. Startup is excluded from timings.

Local full-sample CPU costs at 256 workers were 16.87/11.31/7.50 ms respectively
(two repetitions). Native collection helps but does not eliminate per-thread
cost. Reduced-frequency thread sampling is not planned. The collector prototype
is retained as experimental evidence; the complete native monitor described
above supersedes it.

## Native monitor verification

The complete C++ monitor passed 2,032 differential vectors against the Python
reference, seven injected native error cases, native proc-reader race tests,
process/protocol suites, and all nine extended diagnostics (including the full
60-second CPU and 180-second churn runs). Four CTest unit groups also passed
under AddressSanitizer and UndefinedBehaviorSanitizer. Live process/fault suites
passed three further repetitions. Invalid UTF-8 in parser diagnostics required
replacement during error serialization; malformed-packet tests now pass.

Three alternating whole-monitor runs with 256 idle workers measured Python at
23.8–25.5% of one CPU core and C++ at 9.8–10.7%, with every thread collected on
every pass. CPU cost per sample improved about 2.8×. These are local short-run
measurements; the tests do not claim causal attribution or hard real-time timing.

## Real proxy: opt-in isolated integration

An existing proxy binary can be tested with the C++ monitor without changing
host routing. This needs Linux user/network namespaces, `unshare` with
`--keep-caps`, and `ip`; it uses only the private namespace loopback.

```sh
cmake -S tests/patch-runner/cpu-monitor -B /tmp/smithproxy-cpu-build \
  -DCMAKE_BUILD_TYPE=Release -DCPU_MONITOR_PROXY_BINARY=/absolute/path/to/smithproxy
cmake --build /tmp/smithproxy-cpu-build -j 2
ctest --test-dir /tmp/smithproxy-cpu-build \
  -R '^integration.patch_runner_cpu_real_proxy$' --output-on-failure
```

The main project registers the test against its own Smithproxy target. Labels
are `native;integration;privileged;extended`; it is excluded from the ordinary
hermetic gate. Each invocation retains a new directory under
`real-proxy-results/` with configuration, binary hashes, proxy/monitor logs,
functional phase outcomes and raw CPU reports/samples. Concurrent invocations
need separate lab namespaces and monitor contexts; the wrapper provides them.

Phases cover startup, idle, 40 transfers on four concurrent CONNECT clients,
10 TLS transfers through CONNECT, direct and proxied half-close with delayed
response, 100 reset partial CONNECT requests, and post-traffic idle. Functional
and CPU verdicts stay separate; either failure fails the overall test. TLS here
is transport through CONNECT. Monitoring covers the core PID and
its threads, not privileged helper child processes.

Initial run against source commit `92bfb59` found a functional half-close
failure: all 77,824 payload bytes reached the origin, but EOF did not arrive
within five seconds. The direct control received EOF and returned its response.
The CPU measurement passed; no sustained high-CPU window accompanied the hang.
The failing scenario remains a real failure, not an xfail or a relaxed timeout.

## ProxyNightmare lifecycle profile

`test-patch.sh lifecycle --local` runs selected transparent
TCP/TLS scenarios under this monitor. Each job uses private user, mount and
network namespaces, then creates the ordinary patch-runner namespaces inside
them. Parallel jobs therefore cannot share namespace names, proxy PIDs, monitor
sockets or output paths. The lifecycle profile covers full-duplex close,
receive shutdown, RST after upload, ClientHello followed by FIN, clean TLS close
and idle after `close_notify`. The known delayed-response half-close bug remains
outside this gate.

Functional and CPU verdicts are recorded separately. Lifecycle scenarios use
an 80% bounded limit because ProxyNightmare's internal steps are not separate
monitor phases; this catches a full-core loop without assigning legitimate
handshake work to an artificial idle interval. The coordinator obtains the
pinned ProxyNightmare source, builds and tests it, then stages its binary with
Smithproxy-owned scenarios for remote workers. CMake can
also register `integration.patch_runner_proxy_nightmare_lifecycle` by setting
`PROXY_NIGHTMARE_ROOT`.

Validation against Smithproxy `f205225` and socle `90f3ca5` produced two
concurrent isolated runs. The master half-close fix made full-duplex tiny
buffers pass 2/2. ClientHello followed by FIN retained its exact timeout 2/2
and is tracked as a signature-matched `XFAIL`; a different failure or XPASS
stops the gate. The other four scenarios and CPU measurement passed 2/2 with
no 80%/500 ms event.
