# Smithproxy patch runner

`test-patch.sh` builds the current checkout and can exercise the resulting
Smithproxy binary in disposable, dual-stack Linux network labs. Labs can run
locally or over SSH.

```bash
# Build only.
tests/patch-runner/test-patch.sh quick

# One comprehensive lab, without the large corpus or churn tests.
tests/patch-runner/test-patch.sh sanity --remote root@tt-px1

# Build once, then run isolated sections with at most three concurrent labs.
tests/patch-runner/test-patch.sh full --remote root@tt-px1 \
    --unique=udp-flaky-results --parallel 3

# Start a lab for manual API/CLI work; Ctrl-C performs cleanup.
tests/patch-runner/test-patch.sh --run --remote root@tt-px1
```

Run `tests/patch-runner/test-patch.sh --help` for the authoritative option
syntax.

## Options

| Option | Meaning |
|---|---|
| `--suite NAME` | Run one focused suite or full-run section |
| `--remote [USER@]HOST` | Create the lab over SSH instead of locally |
| `--env NAME=VALUE` | Override a lab variable; repeatable |
| `--dir DIR` | Override the work-root base |
| `--unique` / `--unique=TAG` | Atomically claim a suffixed work root |
| `--parallel N` | Maximum concurrent post-smoke full sections |
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

| Check | `quick` | `sanity` | `full` | `benchmark` | `--run` |
|---|:---:|:---:|:---:|:---:|:---:|
| Build `smithproxy` | yes | yes | yes | yes | yes |
| Authenticated API startup | - | yes | yes | yes | yes |
| IPv4/IPv6 HTTP, TLS and UDP smoke | - | yes | yes | yes | manual |
| Exact pplay HTTP/1 smoke | - | yes | yes | - | manual |
| TLS protocol/trust/SNI matrix | - | yes | yes | - | manual |
| Policy precedence/profile matrix | - | yes | yes | - | manual |
| Loaded CLI session-list probe | - | yes | yes | - | manual |
| RTT limits and payload validation | - | yes | yes | report only | manual |
| TCP and UDP churn | - | - | yes | - | manual |
| Regular/edge/insanity corpus | - | - | yes | - | manual |
| PCAPNG/GRE capture matrix | - | yes | yes | - | manual |
| HTTP/2 CLI/PCAP/GRE observability | - | yes | yes | - | manual |
| No-bypass and cleanup checks | - | yes | every section | yes | on exit |

Applicable dataplane checks produce separate `PASS4` and `PASS6` verdicts. A
failure in either address family fails its section. Management-only checks use
one verdict.

`sanity` runs in one lab. `full` first runs a serial smoke gate; only when it
passes are these isolated sections started:

```text
smoke
├── tls-policy       (TLS, policy and loaded session-list)
├── rtt
├── tcp-churn
├── udp-churn
├── capture          (basic capture, capture matrix and HTTP/2 observability)
├── corpus-regular
├── corpus-edge
└── corpus-insanity
```

`--parallel N` controls the maximum number of concurrent post-smoke sections;
the default is `3` (`PATCH_TEST_PARALLEL` provides the environment default).
Each section owns its namespaces, interfaces, ports, config, data and results.
The build output is shared without being modified. A remote full run uploads
`smithproxy` once with mode `0555`, and section labs symlink to it instead of
keeping nine binary copies.

## Selecting one suite

`--suite NAME` is accepted with `sanity` and `full`. The original focused
suites remain available:

```text
tls  policy  rtt  session-list
```

Full-run sections can also be invoked directly:

```text
smoke  tls-policy  tcp-churn  udp-churn  capture
corpus-regular  corpus-edge  corpus-insanity
```

Every selected suite still performs API startup, no-bypass and cleanup checks.
The four original focused suites (`tls`, `policy`, `rtt`, `session-list`) also
retain the basic dual-stack HTTP/TLS/UDP smoke around their named check.

Examples:

```bash
tests/patch-runner/test-patch.sh sanity --suite policy --remote root@tt-px1
tests/patch-runner/test-patch.sh sanity --suite capture --remote root@tt-px1
tests/patch-runner/test-patch.sh sanity --suite corpus-edge \
    --remote root@tt-px1 --env MATCH='h2_generated_*'
```

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

Without `--remote`, privileged lab setup runs locally through `sudo` unless the
caller is already root. With `--remote [USER@]HOST`, scripts and inputs are
copied over SSH. `root@host` runs directly; another user requires passwordless
remote `sudo`.

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
tests/patch-runner/test-patch.sh full --remote root@tt-px1 \
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
| `TCP_CHURN_INTERVAL` / `TCP_CHURN_SETTLE` | `0.25` / `15` s | TCP timing |
| `TCP_CHURN_TIMEOUT` | `3` s | Per-flow TCP timeout |
| `UDP_CHURN_WAVES` / `UDP_CHURN_FLOWS` | `8` / `96` | UDP churn volume |
| `UDP_CHURN_INTERVAL` / `UDP_CHURN_SETTLE` | `3` / `12` s | UDP timing |
| `UDP_CHURN_TIMEOUT` | `1` s | Per-flow UDP timeout |
| `RTT_SAMPLES` / `RTT_HANDSHAKE_SAMPLES` | `200` / `40` | RTT and fresh-connect samples |
| `RTT_WARMUP` | `20` | Unreported warm-up exchanges |
| `RTT_P95_LIMIT_MS` / `RTT_MAX_LIMIT_MS` | `50` / `250` | TCP/UDP RTT gates |
| `RTT_HANDSHAKE_P95_LIMIT_MS` / `RTT_HANDSHAKE_MAX_LIMIT_MS` | `500` / `2000` | Connect, TLS and HTTPS gates |
| `RTT_TLS_TOTAL_P50_LIMIT_MS` / `RTT_HTTPS_P50_LIMIT_MS` | `7` / `2` | Additional TLS/HTTPS P50 gates |
| `SESSION_LIST_CONNECTIONS` / `SESSION_LIST_SAMPLES` | `256` / `24` | Loaded CLI probe size |
| `SESSION_LIST_P95_LIMIT_MS` / `SESSION_LIST_MAX_LIMIT_MS` | `1000` / `3000` | CLI snapshot gates |

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

## Requirements

The build side needs Bash, Git, CMake and a configured C++ toolchain. Remote
operation additionally needs SSH and SCP.

The lab host must be Linux with root privileges and provide:

```text
iproute2 (ip, ss)  nftables  socat  util-linux (setsid, unshare, mount)
tcpdump  curl  netcat  OpenSSL  Python 3  coreutils (timeout)
```

The runner creates disposable namespaces and veth pairs but does not install
host iptables/nftables traffic-redirection rules. Cleanup verifies that its own
namespaces, API/CLI listeners and interfaces are gone and that ordinary host
addresses/routes are unchanged. While labs run concurrently, temporary
`sp<TAG>{i,o}` interfaces belonging to sibling patch-runner labs are ignored by
that global host-state comparison.
