# Experimental ngtcp2 A:B bridge

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
ngtcp2 1.16.0 and OpenSSL 3.5.5. The standalone target does not change the default daemon build. The opt-in
production integration is described below.

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

The root build now optionally places the same transport beneath the ordinary
`listener_service`. Enable it with `-DSMITHPROXY_ENABLE_NGTCP2=ON`, supplying the
ngtcp2 and crypto-helper install prefix through normal CMake search paths. This
requires ngtcp2's OpenSSL crypto helper and OpenSSL 3.5 TLS-only QUIC API. The
libraries remain external; no vendored or private OpenSSL build is required.

Select `SMITHPROXY_QUIC_BACKEND=ngtcp2` in the daemon environment. Unset or
`openssl` retains the original backend; unavailable/unknown selections fail
listener preparation. The startup log records the selected backend.

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
