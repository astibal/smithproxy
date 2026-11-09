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

The end-to-end STARTTLS matrix covers SMTP, IMAP, POP3, FTP, XMPP, and HTTP
CONNECT through the SOCKS frontend. Each successful upgrade is exercised both
normally and with plaintext sent byte by byte. Rejected SMTP and HTTP upgrades
verify that the connection remains usable as plaintext, and nested SMTP
STARTTLS verifies that an existing TLS connection survives a second request.
Every case can run over IPv4/IPv6 using either a SOCKS IP literal or FQDN.
Successful cases then verify decrypted data in both directions:

```sh
python3 tests/tls/starttls_socks_integration.py \
  --smithproxy build-full/smithproxy --protocol all --address all
```

The FQDN matrix uses `sslip.io` loopback names and therefore needs DNS access.
Use `--address ipv4-ip` or `--address ipv6-ip` for an entirely offline run.

PXM-017 covers implicit TLS on origin port 443. The client waits for the whole
SOCKS CONNECT success reply before sending ClientHello, then verifies a real
TLS handshake and bidirectional HTTP transfer. Run in an isolated network
namespace so port 443 cannot conflict with a host service:

```sh
unshare -Urn -- sh -c 'ip link set lo up && python3 tests/tls/starttls_socks_integration.py --smithproxy build/smithproxy --implicit-tls --address ipv4-ip'
```

`--implicit-tls` selects this single scenario instead of the STARTTLS matrix.
It permits the stable test origin certificate regardless of expiry or trust.
