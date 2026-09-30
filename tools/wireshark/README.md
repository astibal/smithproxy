# Smithproxy decrypted QUIC captures

Smithproxy exports intercepted QUIC stream plaintext as synthetic UDP packets
with an `SPQ1` version marker. The same packets can be written to the normal
PCAPNG capture and sent through the configured GRE exporter. Keyed GRE carries
the low 32 bits of the Smithproxy QUIC session ID.

Load `spquic.lua` before opening the capture:

```bash
wireshark -X lua_script:/usr/share/smithproxy/wireshark/spquic.lua capture.pcapng
```

No **Decode As** selection is required. The dissector recognizes the `SPQ1`
marker in UDP payloads and exposes these filterable fields:

```text
spquic.session_id
spquic.stream_id
spquic.offset
spquic.alpn
spquic.fin
spquic.data
sphttp3.method
sphttp3.scheme
sphttp3.authority
sphttp3.path
sphttp3.url
sphttp3.status
sphttp3.header
```

For ALPN `h3`, Smithproxy follows request-stream framing and the per-direction
QPACK encoder stream. Decoded HEADERS are emitted as additional SPQ1 semantic
records, so Wireshark can display pseudo-headers and ordinary fields without
TLS keys or native QUIC conversation state. Raw STREAM records remain present
for byte-exact inspection.

With the default configuration, local captures are stored below
`/var/smithproxy/data`. Test labs replace this path with their isolated `data`
directory. Capture creation still requires a matching content profile with
`write_payload = TRUE` and `captures.local.enabled = true`.

Run the black-box dissector test when `tshark` is installed:

```bash
python3 tools/wireshark/test_spquic.py
```
