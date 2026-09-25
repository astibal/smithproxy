# Patch test runner

One command builds the current checkout and optionally exercises it in an
isolated network lab on a remote Linux host.

```bash
tests/patch-runner/test-patch.sh quick
tests/patch-runner/test-patch.sh sanity
tests/patch-runner/test-patch.sh full
tests/patch-runner/test-patch.sh full --remote root@tt-bs1
tests/patch-runner/test-patch.sh benchmark --remote root@tt-bs1
tests/patch-runner/test-patch.sh --run --remote root@tt-bs1
tests/patch-runner/test-patch.sh sanity --suite tls --remote root@tt-bs1
tests/patch-runner/test-patch.sh sanity --suite policy --remote root@tt-bs1
tests/patch-runner/test-patch.sh sanity --suite rtt --remote root@tt-bs1
tests/patch-runner/test-patch.sh sanity --suite session-list --remote root@tt-bs1
tests/patch-runner/test-patch.sh full --remote root@tt-bs1 --tcp-churn-port-range 20000:29999
```

Profiles:

- `quick`: production `smithproxy` target only;
- `sanity`: build plus HTTP/1, HTTP/2, TLS, UDP, RTT, loaded session-list, CLI, PCAP and GRE checks;
- `full`: sanity, TCP/UDP churn and the complete deterministic corpus.
- `benchmark`: run measuring suites without latency gates and print a table;
- `benchmark` also repeats the measurements natively inside the origin network
  namespace and reports P50/P95/P99 deltas. This subtracts Python, socket and
  echo-server overhead; the delta includes Smithproxy and its veth data path.
- `--run`: start the isolated lab without tests, expose random host-loopback CLI
  and API ports, and keep it in the foreground until Ctrl-C. With `--remote`,
  both listeners are on the remote host's loopback interface.

`--suite tls|policy|rtt|session-list` runs one virtual sanity subsection in the same isolated
lab. Without `--suite`, every subsection is always included in `sanity` and
`full`. Suite implementations and their case definitions live below
`harness/suites/`.

Configured CMake builds expose equivalent targets:

```bash
cmake --build build --target patch-test-tls
cmake --build build --target patch-test-policy
cmake --build build --target patch-test-rtt
cmake --build build --target patch-test-sanity
cmake --build build --target benchmark
```

They use the already built `smithproxy` dependency and avoid a nested build.
For a remote lab, configure once with
`-DPATCH_TEST_REMOTE=root@tt-bs1`. An empty value runs locally.

Tests run on the current computer by default; SSH and SCP are used only when
`--remote [USER@]HOST` is supplied. A `root@host` target runs the lab directly,
while any other remote user invokes it through `sudo`.

The default work directory is `/tmp/patch-runner/<branch>_@_<commit>/`, containing
`build`, `labs` and `results`. Slashes and other unsafe branch-name characters
are replaced for use in the directory name; detached HEAD uses `detached`.
Override the root with `--dir` or `PATCH_TEST_DIR`. CMake uses the normal system
compiler. Select an existing configured build using `--build-dir` or
`PATCH_TEST_BUILD_DIR`. Builds use `nproc` parallel jobs by default; override
that with `--jobs N` or `PATCH_TEST_JOBS`.

```bash
tests/patch-runner/test-patch.sh full --remote root@tt-bs1 --jobs 4
```

Reports are written below
`/tmp/patch-runner/<branch>_@_<commit>/results/<timestamp>-<commit>-<profile>/` as
Markdown, JSON and raw logs. The report records the exact commit and whether the
working tree was dirty. Remote logs and capture-validation results are copied
back into `remote-results/`.

## Requirements

Local: Bash, Git, CMake, a configured compiler, SSH and SCP.

For local `sanity` and `full`, the current user needs `sudo` unless already
root. For remote execution: SSH access and passwordless `sudo`, unless using
`root@host`. The lab host needs Linux network namespaces,
iproute2, nftables, socat, tcpdump, tshark, curl, nc, OpenSSL and Python 3.
The test uses unique namespace, interface, port and `/opt/lab` names per run.

## Corpus

`corpus/regular`, `corpus/edge` and `corpus/insanity` contain the committed
sample definitions. `corpus/expected-failures.txt` lists known differences;
currently only `edge/http1_connect_ipv6` is treated as XFAIL. Any other failure
makes the run fail.

The compatible pplay engine is vendored under `vendor/` with its license so the
runner does not depend on mutable files outside this repository.

TCP churn uses client source ports `20000:29999` by default, outside the usual
Linux ephemeral range. Override it with `--tcp-churn-port-range MIN:MAX` or the
`TCP_CHURN_MIN_PORT` and `TCP_CHURN_MAX_PORT` environment variables. The range
must contain at least `TCP_CHURN_WAVES * TCP_CHURN_FLOWS` ports.

## Capture matrix

Both `sanity` and `full` run a dedicated 30-flow capture matrix (22 TCP and
8 UDP cases). Every client and server direction has a unique marker and an
expected byte length plus SHA-256 digest. After Smithproxy shuts down, the
validator reconstructs application streams from both local PCAPNG files and
GRE-encapsulated packets and requires both exports to match the corpus manifest.

The same validation checks IPv4, TCP and UDP lengths and checksums. For the
simulated TCP conversations it additionally verifies contiguous sequence
numbers, monotonic/non-future ACKs, SYN/FIN sequence consumption and rejects
payload after FIN or RST. Results are stored in
`lab-results/capture-matrix/validation.json`.

## RTT probe

Both `sanity` and `full` measure TCP, UDP and TLS timing. The probe records
min/p50/p95/p99/max for fresh TCP connects, persistent TCP echo exchanges, UDP
datagrams, the TCP and cryptographic parts of a TLS connect, the combined TLS
connect, and a complete HTTPS exchange. TCP/UDP use 200 measured exchanges
after 20 warm-ups; connection handshakes use 40 fresh connections. Payloads,
HTTPS responses and the TLS certificate are verified as well.

Ordinary RTT p95/max guards default to 50/250 ms and handshake/HTTPS guards to
500/2000 ms. They can be overridden with `RTT_P95_LIMIT_MS`,
`RTT_MAX_LIMIT_MS`, `RTT_HANDSHAKE_P95_LIMIT_MS` and
`RTT_HANDSHAKE_MAX_LIMIT_MS`. Raw results are stored in
`lab-results/tcp-rtt.json`.

Sanity additionally fails when TLS total-connect P50 exceeds 7 ms or HTTPS RTT
P50 exceeds 2 ms. One handshake uses a fresh SNI to measure the cold certificate
cache path separately; it is reported as `TLS cold total connect` and is not
part of the warm P50 gate. Benchmark mode records these values without applying
latency gates.

## Session-list stress

Sanity holds 256 verified TCP sessions open while taking 24 alternating level
6/8 session-list snapshots over one persistent CLI connection. Every snapshot
must contain all held sessions and finish without a timeout. The default P95 and
maximum limits are 1000 ms and 3000 ms; override them with
`SESSION_LIST_P95_LIMIT_MS` and `SESSION_LIST_MAX_LIMIT_MS`.
