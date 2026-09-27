# Mem-constrained instance sizing

Measured on branch `mem-constrained` at `9a5e0ee`, built with
`OPT_MEMPOOL_DISABLE=Y`.  The process ran in the privileged patch-runner Docker
lab with separate client, proxy and origin network namespaces.

## Results

| Scenario | Result | Peak RSS | Peak PSS | Private dirty | Threads |
|---|---:|---:|---:|---:|---:|
| Idle, 35 s | PASS | 25.3 MiB | 20.6 MiB | 10.5 MiB | 94 |
| Idle, Docker `--cpus 1` | PASS | 25.3 MiB | 20.7 MiB | not recorded | 94 |
| HTTP CONNECT corpus, IPv4 + IPv6 | PASS (2 expected XFAIL cases) | 25.9 MiB | 21.6 MiB | 11.1 MiB | 94 |
| 256 simultaneous TCP sessions | PASS | 34.4 MiB | 29.7 MiB | 20.0 MiB | 95 |

The 256-session run adds about 9.1 MiB RSS over idle, or approximately 36 KiB
per held session.  This is a conservative estimate because the run also takes
repeated, detailed session-list snapshots.

`VmSize` was about 4.5 GiB.  It is reserved virtual address space, primarily
from thread stacks, and is not resident memory.  It must not be used as the pod
memory request.

## Initial deployment recommendation

For the current binary and runner-style configuration:

- memory request: **48 MiB**
- memory limit: **64 MiB**
- expected idle working set: **21-26 MiB**
- intended concurrency: up to roughly **256 light TCP/HTTP sessions**

Use a higher limit when enabling TLS interception, payload capture, large
configuration/policy sets, or large response buffering.  Those paths were not
part of this measurement.

## Main remaining fixed cost

The measured process creates 94 threads even while idle.  The global utility
thread pool is sized as `2 * std::thread::hardware_concurrency()`, and the lab
configuration also enables one worker for plaintext, TLS and UDP plus the API,
CLI, DNS and logging facilities.  Mempool removal therefore does not determine
the minimum footprint anymore; thread and service configuration does.
Docker `--cpus 1` did not reduce the thread count or resident memory: the C++
runtime still reported the host's 16 online CPUs for pool sizing.  A Kubernetes
CPU request/limit alone therefore cannot be relied on to shrink this cost.

For a true single-purpose ephemeral HTTP CONNECT instance, the next experiment
should make the utility-pool size configurable and run one plaintext worker
with TLS, UDP, SOCKS, API and unused background facilities disabled.  A target
of a **32 MiB limit** looks plausible, but is not yet validated by this test.

## Test notes

The CONNECT fixture `edge/http1_connect_ipv6` is already listed as an expected
failure by the corpus.  Both IPv4 and IPv6 executions reached the proxy and were
reported as `XFAIL`; the enclosing isolation/cleanup test passed.  This result
is useful for memory exercise, but it is not proof that application-level HTTP
CONNECT behavior is correct.  Functional CONNECT support needs its own follow-up
test or removal of that expected-failure entry.

The 256-session command used the `session-list` suite with
`SESSION_LIST_CONNECTIONS=256`, `SESSION_LIST_SAMPLES=8`, and
`BASE_TRAFFIC_TEST=0`.  RSS, PSS, `Private_Dirty`, high-water mark and thread
count were sampled from `/proc/<pid>` approximately every 50 ms.
