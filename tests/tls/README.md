# TLS integration testbed

The testbed exercises Smithproxy's certificate spoofing against real OpenSSL
handshakes without opening network sockets. Its temporary PKI fixture is copied
under the system temporary directory and removed after each suite.

The matrix covers TLS 1.2 and 1.3, SNI present and absent, four ALPN offers, and
empty, one-byte, and 4 KiB application payloads. Separate tests verify subject,
SAN, issuer, signature, private-key matching, and requested additional SANs.

```sh
# Normal run
tools/tls-testbed.sh

# ASan + UBSan
TLS_TESTBED_SANITIZE=1 tools/tls-testbed.sh

# Stress the complete 50-test matrix 100 times
tools/tls-testbed.sh --gtest_repeat=100 --gtest_brief=1
```

LeakSanitizer is disabled by default because it requires process inspection
that is unavailable in some containers. Enable it on a normal host with
`TLS_TESTBED_DETECT_LEAKS=1`.
