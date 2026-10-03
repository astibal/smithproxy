# Smithproxy patch runner

The normative coverage, target, fuzz-seed and result-recording rules live in
[`tests/docs/TESTING_POLICY.md`](../docs/TESTING_POLICY.md).

`test-patch.sh` builds the current checkout and can exercise the resulting
Smithproxy binary in disposable, dual-stack Linux network labs. Labs can run
locally or over SSH.

## Repository map

Run all commands from the Smithproxy repository root. The runner is
self-contained in the source tree:

```text
tests/patch-runner/
├── test-patch.sh          main command-line entry point
├── remote-scheduler.sh    target-local worker pool for full/fuzz runs
├── fuzz-seeds.py          bounded regression/recent/archive seed selection
├── harness/               network lab, origins, probes and validators
├── corpus/
│   ├── regular/           ordinary protocol conversations
│   ├── edge/              boundary and malformed conversations
│   ├── insanity/          deliberately hostile conversations
│   └── run-suite.sh       corpus and mutation runner
└── vendor/                pinned test-only dependencies such as pplay

tests/tls/tls_testbed.cpp   in-process C++ TLS integration testbed
tests/docs/TESTING_POLICY.md normative coverage and result policy
tests/docs/covered-seeds     successful dynamic and pinned regression seeds
tests/docs/patch-run-history successful top-level invocation history
```

`tests/docs/TESTING_POLICY.md` is the source of truth when changing coverage,
scheduling, pass criteria, result recording or seed lifecycle. Keep this README
as the operator guide and avoid duplicating it in a separate quick-start file.

## Operator quick start

There is no implicit execution target. Every command must name `--local` or at
least one `--remote [USER@]HOST` target. The runner tests the current working
tree, including uncommitted changes; reports mark such builds as `+dirty`.

```bash
# Authoritative command-line help.
tests/patch-runner/test-patch.sh --help

# Build the production smithproxy target only.
tests/patch-runner/test-patch.sh quick --local

# Bounded functional validation on one remote Linux target.
tests/patch-runner/test-patch.sh sanity --remote root@test-runner-1

# Recommended comprehensive correctness gate: modest section parallelism,
# predictable work directory and no unrelated host-load experiment.
tests/patch-runner/test-patch.sh full --remote root@test-runner-1 \
    --parallel 3 --jobs 8 --dir /tmp/patch-runner/manual-full-p3

# Build once, then run three workers on each of two targets.
tests/patch-runner/test-patch.sh full --remote root@test-runner-1 \
    --remote root@test-runner-2 --unique=distributed-full --parallel 3

# Start a lab for manual API/CLI work; Ctrl-C performs cleanup.
tests/patch-runner/test-patch.sh --run --remote root@test-runner-1

# Run the focused end-to-end QUIC/H3 observability suite.
tests/patch-runner/test-patch.sh sanity --suite quic --remote root@test-runner-1
```

For a long foreground run, use `screen` or another terminal multiplexer:

```bash
screen -S smithproxy-full
tests/patch-runner/test-patch.sh full --remote root@test-runner-1 \
    --parallel 3 --dir /tmp/patch-runner/manual-full-p3
# Detach with Ctrl-A D; return with: screen -r smithproxy-full
```

The default work root is `/tmp/patch-runner/<branch>_@_<commit>/`. Prefer an
explicit `--dir` for long runs so reports and live logs have a predictable
location. Useful first checks are:

```bash
tail -f /tmp/patch-runner/manual-full-p3/results/*/test.log
cat /tmp/patch-runner/manual-full-p3/results/*/summary.txt
cat /tmp/patch-runner/manual-full-p3/results/*/sections.tsv
df -h /tmp
```

Remote lab directories and heavy capture artifacts are deliberately retained
for diagnosis. Monitor free space before long runs and remove only explicitly
identified, no-longer-needed work roots.

`--parallel N` controls how many independent sections run simultaneously on
each target. It is a scheduler/load control, not a controlled contention test
of one Smithproxy instance. Use moderate parallelism (normally `3`) for the
correctness gate. Model accept, handshake, transfer or cache contention with a
focused workload that ramps identical flows against one instance and measures
control probes between them; do not infer a product bottleneck merely by
running every unrelated section at once.

Run `tests/patch-runner/test-patch.sh --help` for the authoritative option
syntax.

## Options

| Option | Meaning |
|---|---|
| `--suite NAME` | Run one focused suite or full-run section |
| `--local` | Add the current machine as an explicit target |
| `--remote [USER@]HOST` | Add an SSH target; repeatable for distributed profiles |
| `--env NAME=VALUE` | Override a lab variable; repeatable |
| `--dir DIR` | Override the work-root base |
| `--unique` / `--unique=TAG` | Atomically claim a suffixed work root |
| `--parallel N` | Concurrent section workers per target |
| `--seed SEED` | Replay one exact fuzz seed |
| `--build-dir DIR` | Select a CMake build directory |
| `--shared-binary PATH` | Reuse an absolute executable path on the lab host |
| `--jobs N` | Build parallelism; default `nproc` |
| `--churn-port-range MIN:MAX` | TCP/UDP churn source-port range |
| `--skip-build` | Require and reuse `BUILD_DIR/smithproxy` |
| `--quiet` | Print verdicts, failures and report paths instead of full logs |
| `-h`, `--help` | Print built-in help |

`--quiet` is intentionally unavailable for `benchmark` and `--run`, whose live
output is their primary interface.

## Profiles and coverage

| Check | `quick` | `sanity` | `full` | `fuzz` | `fuzz-dyn` | `benchmark` | `--run` |
|---|:---:|:---:|:---:|:---:|:---:|:---:|:---:|
| Build `smithproxy` | yes | yes | yes | yes | yes | yes | yes |
| Authenticated API startup | - | yes | yes | every shard | every shard | yes | yes |
| IPv4/IPv6 functional layers | - | yes | yes | smoke gate | smoke gate | yes | manual |
| TLS/policy/RTT/transfer/throughput/churn | - | focused | yes | - | - | report only | manual |
| Corpus and capture observability | - | focused | yes | - | - | - | manual |
| Bounded deterministic `fuzz.*` | - | focused | yes | yes | - | - | manual |
| New-seed `fuzz.*` exploration | - | - | - | - | yes | - | manual |
| No-bypass and cleanup checks | - | yes | every section | every shard | every shard | yes | on exit |

Applicable dataplane checks produce separate `PASS4` and `PASS6` verdicts. A
failure in either address family fails its section. Management-only checks use
one verdict.

`sanity` runs in one lab. `full` first runs a serial smoke gate, then exclusive
RTT and TLS throughput phases. Only after both measurement phases are the
remaining isolated sections started:

```text
smoke
├── rtt              (exclusive; no competing load workers)
├── tls-throughput   (exclusive; IPv4/IPv6 download/upload measurement)
└── parallel phase
    ├── tls-policy   (TLS, policy and loaded session-list)
    ├── routing
    ├── transfer     (TLS upload/download at 1/4/16 parallel flows)
    ├── quic         (HTTP/3, CLI diagnostics, native PCAP and GRE)
    ├── tcp-churn
    ├── udp-churn
    ├── capture      (basic capture, capture matrix and HTTP/2 observability)
    ├── corpus-regular
    ├── corpus-edge
    ├── corpus-insanity
    └── fuzz.<area>  (one independently scheduled shard per protocol)
```

TLS throughput measures end-to-end TLS download and upload at 1, 4 and 16
concurrent flows. Throughput has no numeric pass threshold: a completed and
integrity-checked transfer is `PASS`, while TLS, HTTP, process or transfer
failure remains a hard `FAIL`. Its exclusive slot keeps unrelated section load
out of the reported numbers.

`--parallel N` controls concurrent parallel-phase workers on each target; the
default is `3` (`PATCH_TEST_PARALLEL` provides the environment default). A
completed slot is refilled immediately instead of waiting for a batch.
Each section owns its namespaces, interfaces, ports, config, data and results.
The build output is shared without being modified. Distributed runs upload one
self-contained bundle per remote target. A target-local scheduler owns its
worker pool and returns one archive per phase, so P16 does not create an SSH
connection storm. Section labs symlink the staged `smithproxy` binary.

## Selecting one suite

`--suite NAME` is accepted with `sanity`, `full`, `fuzz` and `fuzz-dyn`. The original focused
suites remain available:

```text
tls  transfer  tls-throughput  starttls  policy  routing  rtt  session-list  quic
```

Full-run sections can also be invoked directly:

```text
smoke  tls-policy  routing  rtt  transfer  tls-throughput  quic  tcp-churn  udp-churn  capture
corpus-regular  corpus-edge  corpus-insanity
fuzz.h1  fuzz.h2  fuzz.h2.insanity  fuzz.tls  fuzz.socks5  fuzz.dns  ...
```

Every selected suite still performs API startup, no-bypass and cleanup checks.
The four original focused suites (`tls`, `policy`, `rtt`, `session-list`) also
retain the basic dual-stack HTTP/TLS/UDP smoke around their named check. The
`quic` suite runs its dedicated HTTP/3 origin, diagnostics, PCAP and GRE checks.

Examples:

```bash
tests/patch-runner/test-patch.sh sanity --suite policy --remote root@test-runner-1
tests/patch-runner/test-patch.sh sanity --suite tls-throughput --remote root@test-runner-1
tests/patch-runner/test-patch.sh sanity --suite capture --remote root@test-runner-1
tests/patch-runner/test-patch.sh sanity --suite corpus-edge \
    --remote root@test-runner-1 --env MATCH='h2_generated_*'
```

## Fuzz layers and seeds

`full` includes the mandatory deterministic fuzz layer. `fuzz` runs that layer
alone, and optional `fuzz-dyn` runs every area with one newly generated seed:

```bash
tests/patch-runner/test-patch.sh fuzz --local --parallel 3
tests/patch-runner/test-patch.sh fuzz-dyn \
    --remote root@test-runner-1 --remote root@test-runner-2 --parallel 4
tests/patch-runner/test-patch.sh fuzz --suite fuzz.h2 --local \
    --seed 0123456789abcdef
```

The areas are independent `fuzz.<protocol>` sections. The seed selection and
lifecycle rules are defined in `tests/docs/TESTING_POLICY.md`. Successful complete
dynamic runs append their seed to `tests/docs/covered-seeds`; failed or partially
completed runs only retain the seed in their report.
Dynamic reproduction commands include the generated seed explicitly.

Mandatory replay always includes regression seeds, then adds bounded recent
and rotating archive samples. Tune the cost with `FUZZ_RECENT_SEEDS`,
`FUZZ_ARCHIVE_SEEDS`, `FUZZ_ROTATION_DAYS` and `FUZZ_SEED_MIN_AGE_DAYS`.
`FUZZ_LEVEL` defaults to `245`; TCP fuzz shards also enable deterministic write
scattering.
The distributed profiles split the large H1 and H2 areas into
`regular`/`edge`/`insanity` scheduler subshards; an unsuffixed focused suite
still runs the complete protocol area.

## Work directories and concurrent invocations

The default work root is:

```text
/tmp/patch-runner/<branch>_@_<8-character-commit>/
```

Unsafe branch-name characters are replaced with `-`; detached HEAD uses
`detached`. Override the base with `--dir` or `PATCH_TEST_DIR`.

Two invocations for the same branch and commit would otherwise share the build
directory. Use `--unique=TAG` to append a sanitized label:

```text
/tmp/patch-runner/master_@_622620c9_udp-flaky-results/
```

Bare `--unique` uses `date -I`. Directory claiming is atomic; an existing name
becomes `-2`, `-3`, and so on. The optional value must use the `=` form—
`--unique=my-run`—so the next positional token cannot be consumed accidentally.

Use `--build-dir DIR` or `PATCH_TEST_BUILD_DIR` for an existing CMake build
directory. Build parallelism comes from `--jobs N`, then `PATCH_TEST_JOBS`, then
`nproc`. `PATCH_TEST_RESULTS_DIR` overrides the top-level report root without
moving builds or retained labs. `--skip-build` requires an executable
`DIR/smithproxy`. There are no patch-runner CMake custom targets in the current
project tree; invoke `test-patch.sh` directly.

`--shared-binary /absolute/path` is primarily an internal section-worker
option. It points at an executable already present on the machine running the
lab; full mode supplies it automatically.

## Remote and interactive operation

There is no implicit execution target. Use `--local` for local privileged setup
(through `sudo` unless already root), or one or more `--remote [USER@]HOST`
arguments. `root@host` runs directly; another user requires passwordless remote
`sudo`. Focused and interactive runs require exactly one target; distributed
profiles accept a mixed local/remote worker pool.

`--run` starts Smithproxy plus the origin services, publishes random API and
CLI ports on the selected host's loopback interface, prints connection details,
and waits in the foreground. It does not install host traffic rules. Ctrl-C
stops the processes and removes the lab.

Lab directories are retained after ordinary runs for inspection. Remove them
explicitly when their captures and logs are no longer needed.

## Corpus selection and retries

The committed corpus lives in `corpus/regular`, `corpus/edge` and
`corpus/insanity`; generated deterministic cases are added by `run-suite.sh`.
Filter case basenames with comma-separated shell globs:

```bash
tests/patch-runner/test-patch.sh full --remote root@test-runner-1 \
    --env MATCH='h2_generated_*' \
    --env EXCLUDE='h2_generated_003,h2_generated_017'
```

An empty category is allowed when a full run splits a filtered corpus across
three workers, but the parent fails if no corpus case matched at all.

`corpus/expected-failures.txt` is the source of truth for XFAIL cases. It
currently contains only `edge/http1_connect_ipv6`; an XPASS is reported but is
not a hard failure. Any unexpected failed case fails the run.

TCP corpus cases run once. UDP corpus cases run up to three times:

- first-attempt success: `PASS`;
- second- or third-attempt success: `FLAKY_PASS`;
- three failed attempts: `FAIL`.

A `FLAKY_PASS` is propagated to the full-run section table and overall result,
but the process exits successfully. The compatible pplay engine and its license
are vendored under `vendor/`; no external pplay checkout is used.

For TLS-area corpus and `fuzz.tls`, exact traversal and an immediate two-sided
`PASS*_SAFE_REJECT` are both valid for malformed inputs. A separate TLS
autodetect regression matrix verifies that fragmented recognizable TLS prefixes
cannot reach the plaintext origin; timeout, crash and one-sided teardown remain
hard failures.

The 30 `capture_*` cases are excluded from the ordinary corpus workers and run
only by the dedicated capture matrix. This prevents duplicate stream tuples in
PCAPNG/GRE validation while preserving coverage of all cases.

## Churn and timing controls

TCP and UDP churn use client source ports `20000:29999`, outside the usual Linux
ephemeral range. Override both with `--churn-port-range MIN:MAX`, or set
`CHURN_MIN_PORT` and `CHURN_MAX_PORT`. The range must accommodate the configured
flow counts.

Frequently useful `--env NAME=VALUE` controls:

| Variable | Default | Meaning |
|---|---:|---|
| `TCP_CHURN_WAVES` / `TCP_CHURN_FLOWS` | `20` / `64` | TCP churn volume |
| `TCP_CHURN_PARALLEL` | `64` | Maximum simultaneous TCP churn flows |
| `TCP_CHURN_SYNCHRONIZED` | `0` | Release every TCP wave from one start barrier |
| `TCP_CHURN_INTERVAL` / `TCP_CHURN_SETTLE` | `0.25` / `15` s | TCP timing |
| `TCP_CHURN_TIMEOUT` | `3` s | Per-flow TCP timeout |
| `UDP_CHURN_WAVES` / `UDP_CHURN_FLOWS` | `8` / `96` | UDP churn volume |
| `UDP_CHURN_INTERVAL` / `UDP_CHURN_SETTLE` | `3` / `12` s | UDP timing |
| `UDP_CHURN_TIMEOUT` | `1` s | Per-flow UDP timeout |
| `RTT_SAMPLES` / `RTT_HANDSHAKE_SAMPLES` | `200` / `40` | RTT and fresh-connect samples |
| `RTT_WARMUP` | `20` | Unreported warm-up exchanges |
| `RTT_P95_LIMIT_MS` / `RTT_MAX_LIMIT_MS` | `50` / `250` | TCP/UDP RTT gates |
| `RTT_HANDSHAKE_P95_LIMIT_MS` / `RTT_HANDSHAKE_MAX_LIMIT_MS` | `500` / `2000` | Connect, TLS and HTTPS gates |
| `RTT_TLS_TOTAL_P50_LIMIT_MS` / `RTT_HTTPS_P50_LIMIT_MS` | `7` / `2` | TLS/HTTPS P50 PASS gates |
| `RTT_TLS_TOTAL_P50_FLAKY_LIMIT_MS` / `RTT_HTTPS_P50_FLAKY_LIMIT_MS` | `10` / `10` | TLS/HTTPS P50 FLAKY_PASS ceilings |
| `TLS_THROUGHPUT_BYTES` | `67108864` | Bytes transferred by each throughput flow |
| `TLS_THROUGHPUT_REPEATS` | `3` | Samples per direction and concurrency |
| `TLS_THROUGHPUT_CONCURRENCY` | `1,4,16` | Concurrent flows measured by the exclusive throughput phase |
| `SESSION_LIST_CONNECTIONS` / `SESSION_LIST_SAMPLES` | `256` / `24` | Loaded CLI probe size |
| `SESSION_LIST_P95_LIMIT_MS` / `SESSION_LIST_MAX_LIMIT_MS` | `1000` / `3000` | CLI snapshot gates |
| `TLS_WRITE_CHUNK` | `20480` | Maximum plaintext bytes offered to one `SSL_write()`; intended for comparative transfer tests |
| `SSL_USE_KTLS` | config default | Request OpenSSL KTLS for focused enabled/disabled comparisons |
| `KTLS_PROBE_TEST` / `KTLS_EXPECT_ACTIVE` | `0` / `any` | Hold a TLS flow, record both legs' effective BIO KTLS state, optionally require `on` or `off` |
| `TLS_TEST_VERSION` / `TLS_TEST_CIPHER` | unset | Pin both legs to TLS 1.2/1.3 and, for TLS 1.2, pin the cipher for focused KTLS checks |

`sanity` and `full` enforce all RTT gates. `benchmark` records the same metrics
without latency failures and additionally measures a native origin-namespace
baseline. Its tables report absolute IPv4/IPv6 values and proxy-path deltas.
Payloads, HTTPS responses and the TLS certificate are still verified.

## Capture validation

The capture section generates 22 TCP and 8 UDP conversations for IPv4 and IPv6.
Every direction has a unique marker, expected length and SHA-256 digest. The
validator reconstructs streams from local PCAPNG and GRE packets and requires
both exports to match the manifest.

For simulated TCP it also verifies contiguous sequence numbers, monotonic and
non-future ACKs, SYN/FIN sequence consumption, and rejects payload after FIN or
RST. HTTP/2 observability separately requires the CLI snapshot, PCAPNG and GRE
views to contain exactly 12 requests and 12 responses.

## Results and failure diagnostics

Every top-level run writes:

```text
<report-root>/<UTC timestamp>-<commit>-<profile>[-<suite>]/
├── summary.txt          concise human-readable result
├── summary.md
├── summary.json
├── build.log
├── test.log             except build-only quick runs
├── failure.txt          failed runs only
└── lab-results/         copied-back lab artifacts for a single-lab run
```

`<report-root>` is `<work-root>/results` unless `PATCH_TEST_RESULTS_DIR` is set.
Full-run worker reports remain below their isolated section work roots.

A full run additionally writes `sections.tsv`, `sections.md`, and
`sections/<name>.log`. Each worker keeps its complete report below
`<work-root>/sections/<name>/results/`.

Failure output separates observed evidence (`reason:`) from a heuristic
explanation (`likely:`), includes the report path, and records a shell-escaped
reproduction command. `--quiet` suppresses normal detail but still prints the
result, failed reason, section table and report path.

Every successful top-level invocation also appends a concise entry to
`tests/docs/patch-run-history`, including the tested commit/dirty state, anonymized
target order (`local`, `remote-1`, `remote-2`, ...), and effective section
coverage. The run-local report retains actual targets for diagnostics. Internal
workers do not write history. The runner never commits or pushes either history
or seed-registry changes.

## Requirements

The build side needs Bash, Git, CMake and a configured C++ toolchain. Remote
operation additionally needs SSH and SCP.

The lab host must be Linux with root privileges and provide:

```text
iproute2 (ip, ss)  nftables  socat  util-linux (setsid, unshare, mount)
tcpdump  curl  netcat  OpenSSL  Python 3  coreutils (timeout)
```

The QUIC suite additionally needs `tshark`, an HTTP/3-enabled curl installation
and the prepared Python QUIC runtime. The coordinator copies both runtime
bundles to remote targets; `aioquic` is not required to be installed on the
lab host. Defaults are the sibling directories `../curl-http3` and
`../quic-python`. Prepare the pinned Python bundle once with:

```bash
tests/patch-runner/prepare-quic-runtime.sh
```

Override the locations with `CURL_HTTP3_PREFIX` and `QUIC_PYTHON_PREFIX`.

The runner creates disposable namespaces and veth pairs but does not install
host iptables/nftables traffic-redirection rules. Cleanup verifies that its own
namespaces, API/CLI listeners and interfaces are gone and that ordinary host
addresses/routes are unchanged. While labs run concurrently, temporary
`sp<TAG>{i,o}` interfaces belonging to sibling patch-runner labs are ignored by
that global host-state comparison.
