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
    };
};
```

`capture_auto_metadata` enables inexpensive connection, fingerprint and TLS
metadata. `capture_auto_statistics` enables the more expensive entropy and flow
analysis and implies metadata. Neither option has an effect unless the selected
content profile has `write_payload = TRUE` (or global `default_write_payload` is
enabled).

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
u32 JSON payload length
byte JSON payload[]
zero padding to 32-bit boundary
u32 total length
```

Numeric fields follow the byte order of the containing PCAPNG section.

Every Smithproxy payload contains both correlation keys:

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

## Diagnostics

```text
diag capture status
diag capture schemas
```

`status` shows the active automation settings, local/remote capture state,
written block counters and the number of captured `L`/`R` TLS-ready snapshots.
`schemas` prints the PEN, block type and registered namespace/schema versions.
Counters are process-local and reset when Smithproxy restarts.

