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
that neither request was decoded prematurely. A metadata event checks the
client's original method after QPACK resolution; server-side callbacks check the
rewritten method. Initially blocked callbacks must not invent HTTP metadata.

Spider and SIFT endpoints are deterministic contract fixtures, not deployed
services. H3 push streams remain opaque to the engine's payload locator. This
suite does not claim a fuzzing campaign, sanitizer coverage, loss/reordering
coverage or complete live Spider addon interoperability. Transport impairment
and lifecycle tests remain in the existing QUIC testbed.

## H3 metadata webhook contract (version 1)

Both Spider and SIFT receive `connection-info` observations with
`payload_layer: "http3.metadata"`. These messages carry no payload and do not
request a rewrite decision. `scope`, `parent_id`, `stream_id` and the envelope
`id` identify the same child as its content callbacks. `side` identifies the
field/transport direction; `protocol_endpoint` identifies the client or server
view in which the observation was decoded. These can differ when a request
unblocks an already received response. Output processing and fork replay emit
no duplicate observations. `protocol_sequence` increases per physical connection;
receivers can restore observation order despite asynchronous HTTP delivery.

`protocol_event` is `headers`, `decode-status`, `fin`, `reset`, or
`connection-close`; the latter two include `protocol_error` when supplied by the
transport. FIN can precede a `headers` event when QPACK instructions arrive late.
A reset cancels the pending field section. The current implementation preserves
the transport's existing FIN notification point, after preceding bytes drain.

A `headers` event adds `flow.http3.header_section` (`request`, `interim`,
`response`, `trailers`) and `flow.http3.headers`, an ordered array of `[name,
value]` pairs retaining duplicates. Response status is also available as
`flow.http3.status`. Request method/authority/path/scheme/URL appear once known.
The event always describes the decoded section, even when the bounded adapter
history cannot retain another copy. Decoder resource limits can still prevent
recovery of a section; these are reported explicitly instead of inventing fields.

Content callbacks and metadata observations expose `protocol_metadata_version: 1`
and `flow.http3.decode` with `state`, `reason`, and `encoding_known`. States are
`pending`, `blocked`, `decoded`, `opaque`, `invalid`, `limited`, or `reset`.
`limited` reasons include `stream-limit`, `header-bytes-limit`,
`header-section-limit`, and `decoder-limit`. `invalid` reports `protocol-error`.
This is observer availability, not a claim that forwarding was rejected.
An empty `L7_encoding` string means known identity encoding only when
`encoding_known` is true; otherwise the encoding is unknown. Only final initial
headers determine body encoding; interim sections and trailers cannot replace it.
Push and extension streams remain opaque rather than claiming a decoded body.

Regression coverage includes interim/final encoding transitions, duplicate
response headers/trailers, QPACK release after FIN without any additional request
DATA, output/replay suppression, explicit resource limits, malformed input and
reset error codes. The real network suite compares metadata at Spider and SIFT
and no longer injects a body byte merely to expose the decoded request metadata.

Non-UTF-8 metadata values are represented losslessly as
`{"encoding":"base64","data":"/w=="}` (here, one byte `ff`). Valid UTF-8 remains
a string. This applies to header values and derived content metadata; consumers
must handle the tagged object instead of treating replacement text as original
bytes. Names/order/duplicates are unchanged. Network tests verify this at both sinks.

Connection-wide decoder failure/limits notify previously observed idle stream
directions immediately, with duplicate state notifications suppressed.
CLI session details and session-list API `http3` use the same diagnostic snapshot:
`split`, `stream_id`, `fork_error`, and either `shared` or independent `client` and
`server` views. Each view has request/response metadata, `closed`, `replayable`,
retained history bytes/events, header bytes and tracked stream count. Diagnostics
never select another active stream or advance the parser.

Following DATA/trailers wait in the observer when a preceding field section is
QPACK-blocked; forwarding itself continues. The deferred wire input is bounded
at 64 KiB per blocked stream (at most eight blocked sections per direction).
Exceeding it reports `limited`/`decoder-limit`; later QPACK release cannot restore
semantics from the incomplete history. Regression cases cover separate/coalesced
DATA and trailers, FIN, late fork/replay, and explicit exhaustion of this bound.
The static network case holds a rewritten stream alive and compares actual CLI
and API snapshots, including GET/POST endpoint separation. The session-list API
now includes QUIC children collected on their owning worker.
