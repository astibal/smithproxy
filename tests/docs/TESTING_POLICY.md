# Smithproxy testing policy

This document is the source of truth for the Smithproxy patch runner. Consult
and update it whenever test coverage, scheduling, pass criteria, fuzzing, seed
selection, or result recording changes.

## Goals

The runner must detect functional regressions, timing-sensitive failures and
parser bugs under enough concurrent traffic to expose behavior that a single
quiet lab misses. A successful result must be reproducible and leave a concise,
reviewable record in the repository.

## Explicit execution targets

There is no implicit target. Every invocation must name at least one target:

```sh
tests/patch-runner/test-patch.sh sanity --local
tests/patch-runner/test-patch.sh full --remote root@test-runner-1
tests/patch-runner/test-patch.sh full --local \
  --remote root@test-runner-1 --remote root@test-runner-2
```

`--local` adds the current host to the worker pool. `--remote HOST` is
repeatable. Distributed profiles schedule independent sections across every
target, with `--parallel N` worker slots per target. Interactive and focused
profiles require exactly one target.

The coordinator builds one self-contained bundle and stages it once per remote
host. One remote scheduler process then starts the target-local workers; a
full run must not create one SSH/SCP connection per section. Each phase returns
one result archive per target. This keeps high parallelism from testing
`sshd`'s `MaxSessions`/`MaxStartups` limits instead of Smithproxy.
The bundle includes the pinned QUIC Python runtime and HTTP/3 curl runtime;
fresh targets must not depend on a host-installed `aioquic` package.

Every section owns its namespaces, interfaces, ports, config, traffic and
result directory. The smoke gate runs first. RTT runs alone after smoke so its
latency verdict is not polluted by deliberate load. End-to-end TLS throughput
then runs alone for comparable IPv4/IPv6 download and upload measurements.
Functional, corpus and fuzz sections then consume the configured worker pool.

Cleanup verification compares stable host addresses and routes before and
after each section. Patch-runner veths and OS-managed temporary IPv6 privacy
addresses are excluded: they may be created, removed or expire while parallel
sections run and are not state owned by the runner. All stable host state and
all runner-owned namespaces, interfaces and listeners remain mandatory gates.

## Test layers

- `quick` verifies that the production target builds.
- `native` is the unified CTest-backed layer for C++ unit/integration
  executables, Python process tests and patch-runner self-tests. Its default
  selection is hermetic and mandatory in `full`.
- `coverage` runs the default native selection and a local dataplane `sanity`
  pass under GCC/gcov, then emits combined line coverage in text, JSON and
  browsable HTML forms. The dataplane pass requires local root privileges.
- `sanity` is a bounded functional and dataplane validation.
- `full` is the mandatory comprehensive gate. It contains the functional,
  native, performance, churn, capture, corpus and deterministic `fuzz.*`
  sections. The native gate completes before remote lab sections begin.
- `benchmark` records latency without enforcing latency gates.
- `fuzz` runs only the mandatory deterministic fuzz sections.
- `fuzz-dyn` is optional exploration with one newly generated seed.
- `--run` starts an interactive isolated lab.

A section failure fails its parent run. `FLAKY_PASS` is successful for process
control but remains visibly distinct from `PASS` in reports and history.
The coordinator must always wait for every scheduled worker and aggregate every
section result, including when the final worker makes the active-worker count
zero. Missing section results or an incomplete aggregate report fail the run.

TLS throughput is measurement-only: it has no minimum MiB/s gate. `PASS` means
that every configured TLS/HTTP transfer completed correctly; handshake,
process, protocol or transfer-integrity failure is still a hard `FAIL`. Reports
must retain per-family, per-direction and per-concurrency throughput values.

Repository tests must be registered in CTest instead of requiring knowledge of
another ad-hoc command. Tests which intentionally require public network
access, root-only TUN/RAW facilities, or benchmark-scale work stay registered
but carry `external`, `privileged`, or `benchmark` labels. Long-running soak
and container distribution checks carry `extended` and `platform`. These
labels are excluded from the hermetic native/full gate and can be selected
explicitly; this is isolation, not deletion of coverage.

Line coverage counts executable product lines below `src/` and `socle/` while
excluding test, testbed, fuzz and third-party sources. It is initially a
measurement, not a PASS threshold. Adopt or raise a coverage gate only in a
reviewed policy change backed by a stable baseline; missing/unreadable notes
or an unreadable data file which does exist is always an infrastructure failure.
The built `.gcno` inventory defines the denominator. A built object without a
matching `.gcda` is counted as zero coverage; it must never disappear from the
report merely because no test executed it.
Coverage test executables run serially by default because gcov magnifies the
runtime and resource use of the mempool and large QUIC tests. Explicit
`PATCH_TEST_CTEST_JOBS` may override this for controlled stress experiments;
build parallelism remains controlled independently by `--jobs`.

`--parallel` is a stress and throughput control, not a promise that arbitrary
load is free. Host exhaustion is still a failed run until the limiting layer is
identified. Reproduce product-looking failures in a bounded focused matrix;
raise infrastructure limits or reduce concurrency only when evidence shows the
failure belongs to the execution environment. Never hide a load-sensitive
product failure behind a flaky classification.

## Protocol fuzz sections

Fuzzing is partitioned by protocol or parser area, for example `fuzz.socks5`,
`fuzz.h2`, `fuzz.tls`, `fuzz.dns` and `fuzz.quic`. Each section is an
independently schedulable shard and runs both IPv4 and IPv6 when applicable.
New protocol parsers must gain a corresponding fuzz area or be explicitly
assigned to a documented aggregate area.

Large areas may be split into category subshards such as
`fuzz.h2.regular`, `fuzz.h2.edge` and `fuzz.h2.insanity` for scheduling. The
unsuffixed `fuzz.h2` remains the stable interface for running the whole area.
Focused fuzz runs honor the ordinary `MATCH` and `EXCLUDE` selectors so that a
reported case can be reproduced without replaying its whole protocol area.

Malformed TLS corpus and fuzz inputs have two valid bounded outcomes. If mutation removes
the TLS signature, an exact plaintext replay may pass. If a recognizable TLS
signature remains, an immediate two-sided fail-closed teardown is a pass.
Timeouts, crashes and one-sided failures remain failures. The dedicated TLS
autodetection matrix separately fragments TLS prefixes at the record type,
record header and handshake boundary and proves that their markers never reach
the plaintext origin.

Committed and generated ordinary corpus cases must map to exactly one fuzz
area. The aggregate `raw` area is reserved for genuinely protocol-neutral or
unclassified binary conversations; it must not become a catch-all for cases
that can be assigned to a parser-specific shard.

The mutation engine combines the selected seed with the corpus category and
case name. A seed therefore produces stable mutations as long as its generator
version remains unchanged. Reports must include the seed, generator version,
area and failing case needed for reproduction. `--seed SEED` must reproduce an
exact static or dynamic run rather than generating a replacement seed.

## Seed lifecycle and bounded replay

Successful `fuzz-dyn` runs append a unique seed to `tests/docs/covered-seeds` only
after every scheduled fuzz area passes. The coordinator performs this write
once; workers never update the registry. Failed dynamic seeds remain in the
run report and are not recorded as covered. A `FLAKY_PASS` is recorded in the
general run history but is not strong enough to register a dynamic seed as
covered; seed registration requires a clean `PASS`.

The mandatory fuzz layer has a bounded cost. For each area it replays:

1. every seed marked `regression`;
2. a configurable number of recent eligible seeds; and
3. a configurable deterministic rotating sample of archived seeds.

The defaults are controlled by `FUZZ_RECENT_SEEDS`, `FUZZ_ARCHIVE_SEEDS`,
`FUZZ_ROTATION_DAYS` and `FUZZ_SEED_MIN_AGE_DAYS`. Adding covered seeds grows
the explored space without making one patch run grow without limit.

Any seed that exposes a product failure is a regression seed. After the bug is
fixed, mark that seed `regression`; it then remains in every mandatory fuzz run.
If generator semantics change, bump the generator version rather than silently
changing the meaning of existing seeds.

## Persistent run history

Every successful top-level patch-runner invocation appends one concise row to
`tests/docs/patch-run-history`. The row records UTC time, commit and dirty state,
result, profile, anonymized target order (`local`, `remote-1`, `remote-2`, ...),
effective coverage and report path. Local reports retain the actual targets for
diagnostics; committed history must not publish internal hostnames.
Internal section workers do not append rows; their results are aggregated into
the parent entry.

The runner never commits or pushes these files. Changes to
`tests/docs/covered-seeds` and `tests/docs/patch-run-history` stay in the working tree and
are included in the next normal commit to the current branch.

Failed runs are retained in their ordinary report directories with a
reproduction command and are not written to the successful-run history.

## Planned research labs

- [ ] Add an isolated, explicitly non-production split-engine TLS lab in which
  one running Smithproxy can use a pinned older OpenSSL release on a selected
  TLS leg while retaining the current OpenSSL on the other leg. The preferred
  in-process experiment is a narrow opaque C ABI shim built against the legacy
  headers and loaded into a separate glibc link-map namespace with `dlmopen()`;
  no legacy `SSL*`, `SSL_CTX*`, OpenSSL callbacks or allocators may cross that
  boundary. Ordinary `dlopen()`/`RTLD_DEEPBIND` and a merely renamed SONAME are
  not sufficient isolation. Retain a helper-process implementation as the
  safer fallback and reference result. Run the controlled matrix in both
  directions (legacy client-facing/current origin-facing and the reverse),
  covering protocol bounds, static RSA, DHE/ECDHE, SHA-1, RC4, AES-128 and
  session resumption. Every profile switch must prove both its positive and
  negative case. Keep the lab offline except for its private test network, use
  generated disposable keys, record the exact OpenSSL/build image version,
  and never ship or enable this build as a production artifact.

## Changing this policy

Any change to runner behavior covered here must update this file in the same
commit. Prefer bounded, reproducible coverage over unbounded work. Never weaken
a gate merely to make a flaky or overloaded environment green; isolate the
environmental cause or record an explicit `FLAKY_PASS` threshold instead.
# Authorization failure policy

Policy tests assume fail-closed defaults. No matching rule is a deny, and an
`access-request` feature requires an explicit successful `accept` response.
Legacy availability-first behavior is opt-in through
`settings.policy_fail_open` and
`settings.policy_access_request_fail_open`; tests of those switches must also
prove that explicit deny/reject decisions remain authoritative.
