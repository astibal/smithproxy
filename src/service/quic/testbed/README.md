# QUIC integration testbed

This testbed exercises the OpenSSL QUIC listener, verified upstream TLS,
certificate spoofing, ALPN negotiation, and MultiFlow stream forwarding as one
local integration environment. It creates a short-lived CA and origin
certificate for every process; no repository or system certificates are used.

Run the complete suite from the repository root:

```sh
tools/quic-testbed.sh
```

The build directory and parallelism can be overridden without editing the
script:

```sh
QUIC_TESTBED_BUILD_DIR=build-mf QUIC_TESTBED_JOBS=4 tools/quic-testbed.sh
```

The scenarios cover:

- MultiFlow buffering, backpressure, FIN/reset, directionality, and limits;
- QUIC varint and v1/v2 packet-prefix parsing, including malformed packets;
- OpenSSL client/server contexts, verified handshakes, and stream adaptation;
- concurrent verified MITM sessions with multiple bidirectional streams;
- downstream certificate hostname, issuer, and origin-certificate separation;
- SNI and `h3` ALPN propagation to the origin;
- rejection of an SNI absent from the verified origin certificate;
- rejection of unsupported downstream ALPN;
- rejection by a client which does not trust the MITM CA;
- bounded concurrent certificate-verification jobs;
- cleanup when a client disappears during verified certificate preparation;
- repeated verified reconnect and idle-session cleanup;
- real-transport enforcement of the per-session stream limit;
- payloads spanning packet and internal-buffer boundaries (1 to 32,769 bytes);
- prompt service shutdown while multiple verified sessions are live;
- listener session limits, handshake timeouts, stream forwarding, and cleanup.

For repeatable stress runs, pass regular GoogleTest options through the script:

```sh
tools/quic-testbed.sh \
  --gtest_filter=QuicTestbed.ConcurrentVerifiedMitmSessionsAndStreams \
  --gtest_repeat=10 \
  --gtest_break_on_failure
```

The testbed requires an OpenSSL build with QUIC server support. The production
sources retain their `OPENSSL_NO_QUIC` fallback for older OpenSSL versions.

The complete runner currently contains 43 tests across eight suites. A useful
flakiness pass is:

```sh
tools/quic-testbed.sh --gtest_repeat=5 --gtest_break_on_failure
```
