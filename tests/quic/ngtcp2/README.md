# Experimental ngtcp2 A:B bridge

## Working production checkpoint — 2026-11-11

Branch `experiment/ngtcp2-quic`, implementation through `4f2a8852`, is a
working, opt-in drop-in replacement for the **OpenSSL QUIC transport** beneath
the production service. OpenSSL still supplies TLS and cryptography. This is
no longer only the insecure standalone experiment described below.

Rhino's complete `full --parallel 8 --jobs 8` run passed with ngtcp2 selected:

- 72/72 native CTest entries, including the OpenSSL and ngtcp2 service testbeds;
- 71/71 runtime sections, with no reported flaky results;
- IPv4/IPv6 transparency, capture/decryption, hooks, certificate policy,
  lifecycle, corpus, fuzzing, and native throughput checks.

The successful run is retained on Rhino under
`/home/astib/Documents/ChatGPT/Smithproxy/p3-runs/quic-ngtcp2-experiment-20261111/`
`full-p8-isolated-20261111T163424Z/`. Its `launch.sh` records the exact invocation;
the final `summary.txt` and `sections.tsv` are in the `*-full` directory
beneath `lab/results`.

Testing used ngtcp2 1.16.0 and the task's patched OpenSSL 3.5.5 runtime. Library
selection is deliberately outside Git: build-local runtime paths and endpoint
wrappers isolate it from capture tools. An earlier global `LD_LIBRARY_PATH`
override prevented tcpdump from mapping libcrypto and failed four capture
sections; the isolated full rerun passed all four without product changes.

Production-path A/B measurements before this checkpoint showed roughly
1.5–1.9x throughput versus the patched OpenSSL QUIC backend. Initial-packet
captures of twelve A:B pairs showed no repeated ACK/PING echo: incoming PINGs
were acknowledged without adding a responding PING. These are lab observations,
not a guarantee for arbitrary networks or a complete protocol conformance claim.

Keep the single-worker A:B ownership, shared service verification and same-B
certificate/data connection when continuing this branch. The backend is still
opt-in; fixed-tuple QUIC v1 is tested, while migration and stateless
Retry/address-validation equivalence remain open. Passing P8 does not remove
those boundaries. No private OpenSSL sources or deployment paths belong in the
production build configuration.

This standalone executable answers a narrow question: does replacing the QUIC
transport, while keeping Smithproxy's stream bridge and worker ownership, offer
useful throughput headroom?

```
native H3 client A
       |
       v
UDP receiver -> destination-IP dispatcher -> one worker
                                             |
                          ngtcp2 A <-> MFProxy <-> ngtcp2 B
                                             |
                                             v
                                     native H3 origin B
```

Every worker owns its incoming CID table, outgoing socket/CID table, timers and
complete A:B pairs. The receiver moves datagrams only. ngtcp2 has per-connection
state, so the worker supplies the shared scheduling role that OpenSSL engines
serve in the control variant. No third connection is created.

`--insecure-lab` is mandatory. A uses a fixed fixture certificate and B does not
verify certificates. The same executable also supports the existing OpenSSL
listener with verification disabled and the same direct MFProxy bridge. This is
a comparison of transport integrations, not a full Smithproxy policy benchmark.

## Build

Use a completed Smithproxy build for the socle and qpack support libraries.
ngtcp2 and its OpenSSL crypto helper must already be installed or supplied through
CMake's normal include/library search options. This prototype was exercised with
ngtcp2 1.16.0 and OpenSSL 3.5.5. The standalone laboratory is separate from
the default ngtcp2 production integration described below.

```sh
cmake -S tests/quic/ngtcp2 -B /path/to/experiment-build \
    -DCMAKE_BUILD_TYPE=Release \
    -DSMITHPROXY_BUILD_DIR=/path/to/existing-smithproxy-build \
    -DCMAKE_PREFIX_PATH=/path/to/ngtcp2-prefix
cmake --build /path/to/experiment-build -j4
```

Build/runtime selection of OpenSSL stays outside this source tree. Both control
and experimental processes must resolve to the intended libraries; the lab saves
`/proc/PID/maps` for the actual running process.

## Run

Use the native endpoints produced by `tests/patch-runner/prepare-native-h3.sh`.
The root-only lab creates three temporary network namespaces, sets FORWARD DROP,
starts four native origin processes, and runs the existing `tls-transfer.py`
harness. Python handles orchestration and measurement, never application bytes.

```sh
sudo python3 tests/quic/ngtcp2/lab.py \
    --node /path/to/experiment-build/quic_transport_experiment \
    --native /path/to/native-h3-prefix \
    --backend ngtcp2 --family 4 --bytes 134217728 \
    --concurrency 1,4 --repeats 3 --output /path/to/new-result-directory
```

Repeat with `--backend openssl` and `--family 6`. Each transfer checks HTTP status,
byte count, zero payload and stream completion. A small capture checks replies
from the original destination IP:443. All flows use one destination IP and thus
one active proxy worker, even though four workers exist. Native endpoints can use
multiple cores. Results are aggregate MiB/s for the selected concurrency.

The control listener's standalone path normally resolves SNI. Its explicit lab
origin override avoids a DNS dependency; the ngtcp2 path takes its B destination
directly from the intercepted datagram. Both point to the same fixture origin.
Socket buffer sizes use kernel defaults in both variants.

## Intentional experiment boundaries

The node accepts QUIC v1 with H3 and services UDP port 443. It forwards opaque
streams without an HTTP/3 parser. TLS/certificate policies, production lifecycle
reporting, migration, Retry/address-validation policy and admission hardening
are outside this first experiment. Closed pairs are retained until process exit,
with admission capped at 1024 pairs per worker. A fresh process is used per run.

Payload storage is bounded per stream; submitted TX chunks survive until their
ACK callback, and RX credit is returned only after the bridge consumes data.
FIN waits behind preceding bytes. Protocol deadlines use `ppoll` without rounding
sub-millisecond pacing deadlines up to whole milliseconds. A and B must both
complete TLS before MFProxy is created.

A positive result justifies production integration work; it does not establish
production feature parity or attribute the entire difference to library CPU cost.

## Production-service integration

The root build places this transport beneath the ordinary `listener_service`
by default (`SMITHPROXY_ENABLE_NGTCP2=ON`). Supply the ngtcp2 and crypto-helper
install prefix through normal CMake search paths. This
requires ngtcp2's OpenSSL crypto helper and OpenSSL 3.5 TLS-only QUIC API. The
libraries remain external; no vendored or private OpenSSL build is required.

With no environment override, the daemon selects ngtcp2. Set
`SMITHPROXY_QUIC_BACKEND=openssl` to explicitly select the OpenSSL backend.
An explicit `-DSMITHPROXY_ENABLE_NGTCP2=OFF` build needs no ngtcp2 libraries
and defaults to OpenSSL. Missing dependencies in a default build are an error,
not an automatic fallback. Unavailable, unknown or empty runtime selections
fail listener preparation. The startup log records the selected backend.

```
shared UDP receiver -> destination owner -> single worker
                                           |
                            incoming transport / A
                                           |
                           existing listener_service
                       policy, B certificate verification,
                     MITM identity, lifecycle, captures/hooks
                                           |
                           existing stream MitmProxy
                                           |
                            outgoing transport / B
```

A pauses its certificate callback while the same B connection completes the
normal verifier, including trust exceptions, OCSP and CT. B then carries the
application data. Each worker owns both transport schedulers and CID tables;
connections never migrate between workers. The kernel route lookup for B uses
an unsent temporary UDP socket, not a third QUIC or TLS connection.

`integration.quic_ngtcp2_testbed` runs the existing QUIC corpus with this backend;
`integration.quic_testbed` continues to exercise OpenSSL. The native namespace
harness also accepts the backend environment selection. Use its `quic`,
`quic-pcapng`, `quic-cert.*` and `quic-throughput` suites against the actual daemon.
The native throughput test checks every response/payload and must use identical
policies, workers, endpoints, libraries and sample sizes for both backends.

This remains an experimental transport integration, not a deployment switch.
It supports QUIC v1 on the original transparent tuple; migration and stateless
Retry/address-validation policy equivalence are not established. Unlike the
rough node, the production adapter retires abandoned connections and their CID
routes after a bounded close-delivery period. Certificate rejection, lifecycle,
capture and policy behavior are verified by the shared service tests rather
than reimplemented in the adapter.

### Datagram batching regression checks

The QUIC receiver reads at most 16 datagrams per nonblocking `recvmmsg` call.
Each slot has room for a full UDP payload and separate original-destination and
interface metadata. The shared QUIC dispatcher uses this receiver for either
backend; ngtcp2 also uses it on B. Ordinary socle UDP transport is unchanged.
Receive storage costs about 1 MiB per receiver, allocated once rather than on
each packet. No call waits for a batch to fill.

ngtcp2 generates at most 64 packets per connection turn and submits them with
`sendmmsg`. Only the unsent suffix is retained on socket pressure. Packet bytes
and paths remain intact until sent; capture observes only successful sends.
Normal TX batch storage is temporary, not a permanent 64-packet allocation per
connection. The single-worker A:B ownership and existing pacing are unchanged.

To exercise partial batch completion and EAGAIN deterministically, build the
optional test interposer outside the daemon build:

```sh
cc -shared -fPIC -o /path/to/batch-send-faults.so \
  tests/quic/ngtcp2/batch-send-faults.c -ldl -pthread
SMITHPROXY_QUIC_BACKEND=ngtcp2 LD_PRELOAD=/path/to/batch-send-faults.so \
  /path/to/build/quic_testbed
```

Check that the final fault counters include both blocked and shortened sends.
Keep the interposer out of throughput runs. Also run the ordinary testbed with
both backends and the namespace harness's `quic` and `quic-pcapng` suites to
verify transparent tuples, IPv4/IPv6, payload integrity and decrypted captures.

### Dispatcher inbox batching and multi-worker measurements

The receiver groups its packet batch by destination owner and locks each inbox
once. A worker takes up to 64 owned datagrams under one lock, then processes them
outside the lock. Queue packet/byte limits and per-owner ordering are unchanged.
The eventfd remains readable while any queued packet remains; draining the last
packet clears it under the producer's lock. There is no hidden local packet
cache that could outlive the wakeup.

The throughput harness accepts `QUIC_THROUGHPUT_DESTINATIONS=4` (default `1`).
It adds disposable origin aliases .2/.3/.4/.5 and ::2/::3/::4/::5 and distributes
flows round-robin. With `QUIC_WORKERS=4`, these addresses cover all four owners;
raising concurrency against one address alone does not test multi-worker load.
Use identical fixture settings for the baseline and candidate binaries, and
reverse the execution order for a second block. Suggested concurrent flow counts
are 4,16,64 with 16 MiB per flow, alongside the usual single-destination control.

Each throughput sample now records client completion durations and p50/p95.
These include process startup, handshake and transfer; they are not network RTT.
`quic-throughput-workers-v4.txt` and `-v6.txt` preserve the listener acceptance
and receiver-queue drop counters after each family. Inspect these to confirm
owner coverage and account for overload rather than silently excluding it.

### Configurable worker inbox capacities

`settings.tuning.quic_inbox_packets` (default 16384, range 1..1048576) and
`settings.tuning.quic_inbox_bytes` (default 16777216, range 1024..1073741824)
limit each QUIC worker inbox independently. The byte limit counts datagram
payload, excluding queue metadata and kernel socket storage. Allocation grows
on demand; neither value reserves the full capacity at startup.

The first exhausted limit drops the incoming packet. These settings apply to
both backends when using multiple workers; a single worker reads its socket
directly and has no dispatcher inbox. Restart after changing them: an existing
receiver retains its original limits. Four workers per IPv4/IPv6 family can
therefore queue up to 128 MiB of payload with the defaults. Socket receive
buffers are separate and are not changed by these settings.

The A-side listener socket uses `settings.tuning.quic_listener_rcvbuf` (default
1048576 bytes, range 0..1073741824). Zero keeps the OS default. Restart after
changing it. Workers of the same address family share this socket and its receive
buffer; B-side sockets are unaffected. Listener diagnostics show both the request
and the kernel-reported size, which may be clamped and includes doubled accounting
on Linux. This kernel memory is separate from the worker inbox budget.
