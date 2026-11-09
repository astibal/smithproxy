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
Result archives contain the section logs and report metadata needed for the
aggregate verdict. Per-case `lab-results/` remain on the execution target for
diagnosis, avoiding thousands of unnecessary coordinator files. The
coordinator must check free inodes before extracting an archive and fail with
a bounded diagnostic when capacity is insufficient.
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
- `sanity` is the bounded isolated smoke gate.
- `traffic` owns synthetic protocol, routing, transfer, churn and capture tests.
- `lifecycle` owns ProxyNightmare socket/TLS state tests. Its C++ monitor samples
  every proxy thread every 50 ms and reports functional and CPU verdicts separately.
- `corpus` owns regular, edge and insanity replay of native traffic samples.
- `full` is the ordered union of `native sanity traffic lifecycle corpus fuzz`.
  It consumes those profile definitions directly instead of maintaining a
  separate full-only suite.
- `benchmark` records latency without enforcing latency gates.
- `fuzz` runs only the mandatory deterministic fuzz sections.
- `fuzz-dyn` is optional exploration with one newly generated seed.
- `--run` starts an interactive isolated lab.

A section failure fails its parent run. `FLAKY_PASS` is successful for process
control but remains visibly distinct from `PASS` in reports and history.
The native gate must fail when CTest finds no tests, including when label
filters exclude every registered test. An empty selection is not a successful run.
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

## Capture output matrix

`--suite capture` schedules `capture-traffic`, `capture-pcapng`, `quic` and
`quic-pcapng`. The same four sections are mandatory in `traffic` and `full`.
Each leg retains a local PCAPNG plus an independent GRE wire capture. No leg
may pass merely because the other output works. Empty captures, missing
records, mismatched payload hashes and undecodable required content fail.

The TCP/UDP inventory consists of the 30 deterministic capture corpus cases
(HTTP/1, HTTP/2, Redis-style, SMTP-style, WebSocket-style, binary TCP and
DNS/syslog/STUN/binary UDP conversations), plus real HTTPS exchanges over TLS
1.2 and TLS 1.3. Both address families are required. Per-case, per-direction
SHA-256 checks cover all 32 cases; HTTP/2 additionally requires twelve live
requests and responses. Protocol-shaped replays prove byte preservation, not
full interoperability with production implementations of those protocols.

The QUIC legs use a real HTTP/3 client and origin with four concurrent requests.
Local and remote PCAPNG must decode from embedded DSB secrets with external
keylogs disabled and contain no SPQ1. Remote `traffic` must instead preserve
SPQ1 identity, payload and semantic records. QUIC currently covers IPv4 only;
this matrix must not be described as covering every protocol or IPv6 QUIC.
New capture traffic types must add expectations for all three output paths.

GRE/PCAPNG reconstruction validates block lengths and preserves received block
order; only the receiver's section/interface preamble is synthesized. It must
not import secrets or packets from the local output to make remote decoding pass.

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

Direct runner invocations never commit or push these files. A publishable
validation must instead use `tests/patch-runner/publish-report.sh`. That wrapper
requires a clean named branch, verifies that the branch and HEAD remain the
tested ones, writes a concise timestamped report below `docs/test-reports/`,
commits only report metadata and pushes explicitly to the same branch name.
Raw logs, complete inventories and lab artifacts remain outside Git.

Failed runs are retained in their ordinary report directories with a
reproduction command and are not written to the successful-run history.

## Planned research labs

### Capture metadata gate (initial stage)

The focused capture suite can enable `--env CAPTURE_METADATA_TEST=1` to
require SXME, SXST, SXTL and SXPP v2 from the live proxy. Missing metadata,
orphan correlation identities, duplicate final summaries or event sequence
numbers, malformed envelopes, and absent JA4/JA4S for the controlled TLS origin
fail the run. The JSON validation report remains in the lab results alongside
the actual captures. The validator has hermetic CTest coverage.
The live gate also compares the origin certificate SHA-256 with the generated
origin certificate and checks the expected ALPN, TLS roles and negotiated
version/cipher presence. These expectations come from the controlled origin,
not from another metadata block emitted by Smithproxy.

This initial stage does not yet prove exact fingerprint values, packet-to-flow
association, annotations, failed handshakes or metadata parity over PCAPNG GRE.
It must not be represented as the complete release gate until those checks
are implemented. Existing packet/payload GRE checks remain independently active.

The retired protocol-checkpoint/flow-journal experiment (2026-10-26) is preserved
with its tests as reversible patches under `docs/design-history/`. It is not a
runtime feature or a native gate. Endpoint rewrite/hold/HPACK/SETTINGS scenarios
remain in `unit.protocol_views`, now using the supported setup-selected Rewrite
mode. Forward-fork ownership and ordinary flow append/pop tests run in
`unit.http1`; historical checkpoint pass counts must not be reported as current
coverage. The old speculative-fork benchmark is archived, not silently measured
under its former labels.

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

## External proxy authentication

Proxy authentication registers `unit.pap` and `integration.auth_client` with
CTest under the `native` and `auth` labels. Both also run in standalone auth
client builds. `integration.proxy_auth` additionally requires the production
Smithproxy executable and explicit paths to the separately built Keyway daemon
and its test-only PAM module (`SMITHPROXY_KEYWAY_EXECUTABLE` and
`SMITHPROXY_KEYWAY_TEST_PAM_MODULE`).

The proxy integration uses a temporary PAM service without modifying system
authentication. It starts isolated local listeners and verifies CONNECT/SOCKS5
authentication before target access, including fragmentation, pipelining,
rejection and broker failure. Keyway's own backend and management API tests
remain in its separate repository.

## CPU monitor groundwork

The native layer includes `unit.patch_runner_cpu_monitor`, a controlled-process
self-test for the standalone [CPU monitor](../patch-runner/CPU_MONITOR.md). It
checks a 500 ms CPU pulse, sleeping targets, concurrent monitor isolation and
control failures. This does not yet enable CPU gates on Smithproxy traffic.
CPU evidence and functional outcomes remain separate. Missing or incomplete
required CPU measurements must never be treated as a passing CPU gate.

CPU accounting has a deterministic native regression suite
(`unit.patch_runner_cpu_accounting`). Long real-process accuracy, concurrency
and soak diagnostics are registered separately as
`extended.patch_runner_cpu_diagnostics`; use the extended label to select them.
The CPU monitor must invalidate measurement after ATTACH with sampling gaps
above two configured intervals (100 ms by default) instead of certifying a time series too sparse for its
short-pulse detector. Per-thread interval attribution is explicitly a lower
bound; the process aggregate is the primary CPU accounting reference.

Continuous suspicious-window detection spans phase/test boundaries; CPU limits
remain local to each phase. Fault-path checks (`unit.patch_runner_cpu_faults`)
cover malformed control traffic, filesystem collisions and write failures.

The CPU monitor server is now `smithproxy-cpu-monitor` (C++17). Native CTest
process/protocol suites select that binary via `CPU_MONITOR_BINARY`; Python
remains the independent reference and client. `unit.patch_runner_cpu_proc`
checks native `/proc` races and access failures, and
`unit.patch_runner_cpu_native_accounting` compares the compiled accounting core
against deterministic Python results. The standalone CMake project under
`tests/patch-runner/cpu-monitor` permits validation without building Smithproxy.
Every sample still includes every live thread. Events describe temporal overlap,
not proven causal ownership by a test; windows crossing phases have no single
phase owner.

`integration.patch_runner_cpu_real_proxy` is an opt-in `privileged;extended`
local integration test with a disposable user/network namespace. It records
functional and CPU verdicts separately and fails if either is unsuccessful.
It covers explicit CONNECT traffic, TLS transport, half-close, resets and idle
recovery. This does not replace transparent-proxy/ProxyNightmare coverage.

### Execution privilege preflight

The patch runner validates its execution backend before configuration, build or
remote staging. SSH and sudo must be non-interactive. Privileged dataplane
profiles accept an existing root login or passwordless `sudo -n`; lifecycle and
privileged native integration tests validate the rootless user/mount/network
namespace path. The probe performs a private tmpfs mount, creates and removes a
nested network namespace, brings up loopback and reads its nftables ruleset.
This is an execution prerequisite check, not a product test. A failed probe is
a setup failure and must not be reported as a Smithproxy regression.

### ProxyNightmare acquisition

The lifecycle profile obtains ProxyNightmare from the repository and exact
40-character commit recorded in `proxy-nightmare.lock`. The coordinator caches
the detached checkout below the work root, builds `pn`, and runs its
deterministic `pn_tests` unit test before staging the binary. Timing-sensitive
upstream network integration tests are exercised against Smithproxy by the
`lifecycle` profile instead. Workers need no Git or internet access.
Smithproxy owns all `.pn` lifecycle scenarios that it executes. A developer may
use `--proxy-nightmare-root` for an explicit prepared checkout; reports record
that override, the available commit metadata, and the binary SHA-256.

Lifecycle expected failures must name one scenario and an exact required log
substring in `proxy-nightmare/expected-failures.json`. The scenario is `XFAIL`
only when both its command fails and that signature is present; a different
failure remains `FAIL`. A successful expected scenario is `XPASS` and fails the
gate until the stale expectation is reviewed and removed.

### Local operational notes

Use repeatable `--note TEXT` arguments for ad hoc setup, build workarounds or
environment changes needed by a run. The runner writes these notes, non-default
compiler flags, dirty-tree state, `FLAKY_PASS`, `XFAIL` and `XPASS` lines to
`report-notes.md`. This diagnostic companion remains with local run artifacts;
`publish-report.sh` does not copy or commit it.
