# Automatic capture metadata

Smithproxy can add structured metadata to captured PCAPNG traffic. Metadata is
written to local PCAPNG output and, in PCAPNG pickup mode, to the GRE capture
stream as well.

## Configuration

```libconfig
settings = {
    capture_auto_metadata = TRUE;
    capture_auto_statistics = FALSE;
};

content_profiles = {
    recorded = {
        write_payload = TRUE;
        capture_proto_profiling = TRUE;
    };
};
```

`capture_auto_metadata` enables inexpensive connection, fingerprint and TLS
metadata. `capture_auto_statistics` enables the more expensive entropy and flow
analysis and implies metadata. Neither option has an effect unless the selected
content profile has `write_payload = TRUE` (or global `default_write_payload` is
enabled).

`capture_proto_profiling` enables the protocol audit trail for one content
profile. Global `capture_auto_metadata` is the broad shortcut and enables it
automatically wherever payload capture is active.

## PCAPNG envelope

All records use the non-copyable PCAPNG Custom Block (`0x40000BAD`) and PEN
`67005`. The payload envelope is:

```text
u32 block type
u32 total length
u32 PEN = 67005
char namespace[4]
u16 entry type = 1
u16 version = 1
u32 payload length
byte payload[]
zero padding to 32-bit boundary
u32 total length
```

Numeric fields follow the byte order of the containing PCAPNG section.

The Lua dissector in `tools/wireshark/smithproxy.lua` exposes the envelope,
JSON correlation fields and typed SXPP columns as Wireshark display-filter
fields. See `tools/wireshark/README.md` for installation and examples. A
deterministic capture containing HTTP, TLS 1.3 and all four custom namespaces
is available as `artifacts/synthetic-smithproxy-extensions.pcapng` and can be
regenerated with `tools/wireshark/generate_sample.py`.

The JSON snapshots (`SXME`, `SXST`, `SXTL`) contain both correlation keys:

- `session_id`: process-local Smithproxy connection identifier.
- `proxy_session_key`: stable traffic-log key derived from the protocol and
  client/origin tuple.

## Namespaces

### SXME — connection metadata

Written when the capture session closes, after buffered payload is flushed.
Schema: `smithproxy.metadata.v1`.

The payload includes connection start/end time, duration, policy index,
connection label, detected application and JA4 client/server fingerprints.

### SXST — statistics

Written when the capture session closes if automatic statistics are enabled and
the statistics filter collected usable data. Schema:
`smithproxy.statistics.v1`.

### SXTL — negotiated TLS

Written exactly once when both TLS legs reach `READY`. It is intentionally not
collected during connection teardown, because shutdown or error handling may
already have changed the live OpenSSL state. Schema: `smithproxy.tls.v1`.

```text
client --- L ---> Smithproxy --- R ---> origin
             server role     client role
```

Both `L` and `R` contain the negotiated TLS version, cipher, cipher strength,
key-exchange group (OpenSSL 3), ALPN, SNI, session reuse state and peer
certificate identity. Certificate identity is the SHA-256 digest of the DER
certificate plus subject and issuer CN; the complete certificate is not copied
into every capture.

The `R.verify` object records whether Smithproxy verification ran, its combined
result, OpenSSL result code/text, Smithproxy verification origin and extended
flags. Verification normally belongs to `R`, where Smithproxy acts as the TLS
client. Failed or incomplete handshakes do not produce `SXTL v1`.

### SXPP — protocol profile

An ordered protocol audit trail. Unlike the JSON snapshots above, every SXPP
block contains one RFC 4180 CSV row with fixed columns:

```text
seq,timestamp,timestamp_unix_us,delta_us,side,component,scope,stream_id,event,status,detail
```

`timestamp` is UTC with microsecond precision. `delta_us` uses a monotonic clock
and measures time since the previous row. `side` is `L`, `R`, or `P` (proxy).
The optional `stream_id` correlates multiplexed QUIC streams. `detail` is a
CSV-escaped free-form field for small technical facts such as an ALPN, selected
route, policy, or load-balancer target.

Typical rows are handshake start/ready/failure, TCP connect, QUIC stream open,
policy match, routing decisions, timeouts, and close. Payload read/write calls
are deliberately not logged, so profiling remains an audit trail rather than a
packet-by-packet duplicate. QUIC handshake entries are buffered in the bounded
native-capture journal and exported only after a matching content policy turns
protocol profiling on.

Example (header shown for readability; it is not stored in each block):

```csv
seq,timestamp,timestamp_unix_us,delta_us,side,component,scope,stream_id,event,status,detail
1,2026-09-11T12:00:00.000120Z,1789128000000120,0,L,quic,connection,,HANDSHAKE_STARTED,pending,
2,2026-09-11T12:00:00.018420Z,1789128000018420,18300,R,quic,connection,,HANDSHAKE_READY,ok,h3
3,2026-09-11T12:00:00.020010Z,1789128000020010,1590,P,stream,stream,6,OPENED,ok,
4,2026-09-11T12:00:00.020140Z,1789128000020140,130,P,policy,stream,6,MATCHED,ok,policy=3
```

## Diagnostics

```text
diag capture status
diag capture schemas
```

`status` shows the active automation settings, local/remote capture state,
written block counters and the number of captured `L`/`R` TLS-ready snapshots.
`schemas` prints the PEN, block type and registered namespace/schema versions.
Counters are process-local and reset when Smithproxy restarts.

## Webhook parity

When webhooks are enabled, the final `connection-info` event mirrors generated
capture enrichment under `capture`:

```json
{
  "capture": {
    "metadata": { "schema": "smithproxy.metadata.v1" },
    "statistics": { "schema": "smithproxy.statistics.v1" },
    "tls": { "schema": "smithproxy.tls.v1" },
    "protocol_profile": {
      "schema": "smithproxy.protocol-profile.v1",
      "dropped": 0,
      "events": []
    }
  }
}
```

The JSON objects for metadata, statistics and TLS are the same values written
to `SXME`, `SXST` and `SXTL`. Protocol events are represented as structured JSON
instead of CSV. The in-memory webhook journal is bounded to 1024 events; SXPP
capture remains complete, while `dropped` reports records omitted from the
webhook payload. For QUIC streams, each webhook receives connection-level
events plus events for its own stream ID, not events from sibling streams.
