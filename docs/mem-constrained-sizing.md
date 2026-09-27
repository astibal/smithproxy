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
| Minimal HTTP-only CONNECT, utility pool 5 | PASS (2 expected XFAIL cases) | 24.0 MiB | 19.7 MiB | 9.0 MiB | 13 |
| Minimal HTTP-only, 256 simultaneous TCP sessions | PASS | 32.1 MiB | 27.8 MiB | 17.2 MiB | 14 |
| Explicit SOCKS5 HTTP request, no TPROXY | PASS | 23.4 MiB | 19.1 MiB | 8.5 MiB | 16 |
| Explicit SOCKS5, webhooks/libcurl compiled out | PASS | 21.0 MiB | 16.7 MiB | 8.0 MiB | 16 |
| Explicit SOCKS5, webhooks and HTTP API compiled out | PASS | 16.3 MiB | 11.9 MiB | 7.1 MiB | 14 |
| Routed TPROXY TCP/TLS-MITM/UDP, API absent | PASS | 17.9 MiB | 13.3 MiB | 8.3 MiB | 17 |

The 256-session run adds about 9.1 MiB RSS over idle, or approximately 36 KiB
per held session.  This is a conservative estimate because the run also takes
repeated, detailed session-list snapshots.

`VmSize` was about 4.5 GiB.  It is reserved virtual address space, primarily
from thread stacks, and is not resident memory.  It must not be used as the pod
memory request.

The mem-constrained build also compiles out webhook delivery and does not link
`libcurl`.  The same SOCKS5 end-to-end test dropped by about 2.3 MiB in both
peak RSS and peak PSS.  Webhook settings remain accepted as no-ops so existing
configuration files still load, but webhook actions and the `test webhook` CLI
command are unavailable.  The HTTP API is now compiled out as well.  This
removes `libmicrohttpd` and its transitive `libgnutls` dependency, saving a
further 4.7 MiB peak RSS and 4.8 MiB peak PSS in the same SOCKS5 test.  HTTP API
configuration remains loadable for compatibility, but the mem-constrained
binary contains no API listener or controllers.

## Initial deployment recommendation

For the current binary and runner-style configuration:

- memory request: **32 MiB**
- memory limit: **48 MiB**
- expected light SOCKS working set: **12-17 MiB**
- intended concurrency: up to roughly **256 light TCP/HTTP sessions**

The 256-session result predates the final API/libmicrohttpd removal and applies
to the common binary architecture, not yet to a repeated load run of each new
profile.  The 48 MiB hard limit remains intentionally conservative until SOCKS
and TPROXY each receive their own concurrency curve.

Use a higher limit when enabling TLS interception, payload capture, large
configuration/policy sets, or large response buffering.  Those paths were not
part of this measurement.

## Main remaining fixed cost

The measured process creates 94 threads even while idle.  Its measured thread
inventory was:

- 48 DTLS threads (`dtls_workers` was left at its CPU-derived default),
- 32 global utility-pool threads (`2 * hardware_concurrency`),
- 3 plaintext, 3 TLS and 3 UDP listener/worker threads,
- one each for owner, DNS, CLI, API and the HTTP daemon.

SOCKS and redirect listeners were disabled.  The runner requested one worker
for plaintext, TLS and UDP, but the listener implementation enforces at least
two subordinate workers, producing three threads per listener.  This benchmark
therefore represents a full and accidentally DTLS-heavy instance, not the
intended minimal HTTP-only configuration.  Mempool removal does not determine
the minimum footprint anymore; thread and service configuration does.
Docker `--cpus 1` did not reduce the thread count or resident memory: the C++
runtime still reported the host's 16 online CPUs for pool sizing.  A Kubernetes
CPU request/limit alone therefore cannot be relied on to shrink this cost.

An earlier minimal HTTP experiment set the utility pool to five threads and
ran one plaintext listener with TLS, DTLS, UDP, SOCKS and redirect listeners
disabled.  Its patch-runner API remained enabled for readiness checks, so the
measured 13 threads included owner, DNS, CLI, API and HTTP-daemon threads.
That CONNECT corpus peaked at 24.0 MiB RSS.  The exact same profile held 256
simultaneous sessions with no timeouts and peaked at 32.1 MiB RSS.  Use a
**32 MiB request / 48 MiB limit** for the first deployment; a 32 MiB hard limit
is too tight for the measured 256-session peak.

Disabling TLS exposed a latent STARTTLS-upgrade crash: replacement SSL
communications were used before their static factory/owner initialization.
Initializing both replacement communication objects before socket upgrade
fixed the crash; the minimal IPv4 and IPv6 CONNECT corpus run then completed.

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
