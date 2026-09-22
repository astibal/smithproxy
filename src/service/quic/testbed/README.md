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

- concurrent verified MITM sessions with multiple bidirectional streams;
- downstream certificate hostname, issuer, and origin-certificate separation;
- SNI and `h3` ALPN propagation to the origin;
- rejection of an SNI absent from the verified origin certificate;
- rejection of unsupported downstream ALPN;
- bounded concurrent certificate-verification jobs;
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
