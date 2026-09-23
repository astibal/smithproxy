# TLS fuzzing

`tls_clienthello_fuzzer` feeds arbitrary TLS records into Smithproxy's actual
ClientHello parser. AddressSanitizer catches out-of-bounds and lifetime bugs;
UndefinedBehaviorSanitizer catches alignment, integer, and other language-level
undefined behavior.

Run a short local campaign:

```sh
tools/tls-fuzz.sh 60
```

The evolving corpus and crash artifacts stay under `build-tls-fuzz/`. Re-run a
saved artifact directly with `-runs=1` before and after a fix.

This target deliberately covers the pre-handshake parser only. Certificate
spoofing, verification, ALPN negotiation, shutdown, and concurrent connection
lifecycle tests belong to the TLS integration testbed rather than this target.
