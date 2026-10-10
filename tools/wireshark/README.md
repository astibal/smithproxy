# Smithproxy Wireshark dissectors

## Capture metadata (`smithproxy.lua`)

This plugin decodes PCAPNG non-copyable Custom Blocks with Smithproxy PEN
`67005`: `SXME`, `SXST`, `SXTL` and `SXPP` version 1.

```sh
wireshark -X lua_script:tools/wireshark/smithproxy.lua capture.pcapng
tshark -X lua_script:tools/wireshark/smithproxy.lua -r capture.pcapng \
  -Y smithproxy -T fields -e smithproxy.namespace -e smithproxy.schema
```

Useful display filters:

```text
smithproxy
smithproxy.namespace == "SXTL"
smithproxy.schema == "smithproxy.tls.v1"
smithproxy.session_id == "Proxy-DEADBEEF-PTR-12345678"
smithproxy.pp.component == "tls"
smithproxy.pp.event == "SERVER_HELLO"
smithproxy.pp.delta_us > 1000
```

JSON namespaces are also passed to Wireshark's built-in JSON dissector. SXPP
columns are exposed as typed `smithproxy.pp.*` fields.

The sample capture includes one conceptual proxy session with a plain HTTP leg,
a TLS 1.3 leg and all custom namespaces:

```sh
python3 tools/wireshark/generate_sample.py
wireshark -X lua_script:tools/wireshark/smithproxy.lua \
  artifacts/synthetic-smithproxy-extensions.pcapng
python3 tools/wireshark/test_smithproxy.py
```

Install the plugin by copying `smithproxy.lua` to the **Personal Lua Plugins**
folder shown under **Help → About Wireshark → Folders**. Restart Wireshark or
select **Analyze → Reload Lua Plugins**. The plugin requires the
`pcapng_custom_block` dissector table and is tested with Wireshark 4.6.6.

## Decrypted QUIC (`spquic.lua`)

Smithproxy exports intercepted QUIC stream plaintext as synthetic UDP packets
with an `SPQ1` version marker. The same packets can be written to the normal
PCAPNG capture and sent through the configured GRE exporter. Keyed GRE carries
the low 32 bits of the Smithproxy QUIC session ID.

```sh
wireshark -X lua_script:tools/wireshark/spquic.lua capture.pcapng
```

No **Decode As** selection is required. Available fields include:

```text
spquic.session_id  spquic.stream_id  spquic.offset  spquic.alpn
spquic.fin         spquic.data       sphttp3.method sphttp3.url
sphttp3.status     sphttp3.header
```

For ALPN `h3`, the dissector follows request-stream framing and the
per-direction QPACK encoder stream. Decoded HEADERS become additional SPQ1
semantic records; raw STREAM records remain available for byte-exact analysis.

With the default configuration, local captures are stored below
`/var/smithproxy/data`. Capture creation still requires a matching content
profile with `write_payload = TRUE` and `captures.local.enabled = true`.

```sh
python3 tools/wireshark/test_spquic.py
```
