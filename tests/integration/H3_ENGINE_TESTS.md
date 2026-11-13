# H3 engine regression suite

Run from any directory, using an existing configured Debug build:

```sh
python3 tests/integration/h3_engine_suite.py \
    --build /path/to/build --jobs 8 \
    --python-path /path/to/python-packages \
    --output /tmp/h3-suite-results --repeat 2
```

`--python-path` is optional when `aioquic` and `pylsqpack` are already importable.
The network cases require Linux user/network namespaces (`unshare -Urn`), `ip`
and `iptables`. They create their own namespaces, certificates, configuration,
origin and webhook endpoints. They do not modify the host network or live proxy
configuration. `--output` must be a new directory so stale handshake markers or
previous results cannot make a test pass. `--unit-only` needs none of the Python
QUIC dependencies or namespace privileges.

The runner builds its prerequisites and stops on the first failure. Each stage
has a log, duration and exit status in `results.json`. Network cases additionally
retain webhook envelopes, the temporary proxy configuration and proxy log.

| Layer | Coverage |
| --- | --- |
| H3 engine | Shared/dual contexts, late split, every header and encoder-instruction split boundary, blocked QPACK across streams and FIN, reset cancellation, dropped/injected/batched output, raw undeclared rewrite, independent encoding, payload annotations, byte/event replay limits, connection close, duplicate fields and trailers |
| Fragmentation | Every pair of split points in a DATA/extension fixture, two-byte QUIC length, 128 deterministic random segmentations in dual mode; reconstructs only expected application bytes and validates annotation offsets |
| H3 capture decoder | Existing malformed frames, semantic/header violations, response status/body rules, QPACK/header resource limits, control streams and connection-wide errors; selected explicitly by `unit.http3_capture` |
| Shared ProtocolViews | Existing H2/shared protocol transaction and fork regression tests |
| Static QUIC integration | GET→POST rewrite after an initial completed stream, third stream isolation, actual origin response, endpoint metadata and Spider/SIFT equality |
| Dynamic QUIC integration (whole and byte-fragmented HEADERS) | Shared QPACK entries, two blocked streams, split while blocked, method rewrite retaining dynamic references, fragmented delayed encoder instructions, unblock and later stream reuse |

The dynamic fixture proves its own blocking with an independent pylsqpack
Decoder before transmission. Marker files show that both header callbacks
arrived at the proxy before releasing instructions; origin observations show
that neither request was decoded prematurely. A later DATA callback checks the
client's original method after QPACK resolution; server-side callbacks check the
rewritten method. Initially blocked callbacks must not invent HTTP metadata.

Spider and SIFT endpoints are deterministic contract fixtures, not deployed
services. H3 push streams remain opaque to the engine's payload locator. This
suite does not claim a fuzzing campaign, sanitizer coverage, loss/reordering
coverage or complete live Spider addon interoperability. Transport impairment
and lifecycle tests remain in the existing QUIC testbed.
