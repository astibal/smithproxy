# QUIC fuzzing

Three Clang libFuzzer targets cover progressively larger surfaces:

- `quic_wire_fuzzer` checks QUIC packet-prefix and varint parsing;
- `multiflow_fuzzer` drives flow pairing, buffering, FIN, reset, and close;
- `quic_lifecycle_fuzzer` performs a real OpenSSL QUIC handshake and mutates
  stream lifecycle operations over loopback UDP.

Build and run all targets for 60 seconds each:

```sh
tools/quic-fuzz.sh all 60
```

Run one target for a longer campaign:

```sh
tools/quic-fuzz.sh wire 3600
tools/quic-fuzz.sh multiflow 3600
tools/quic-fuzz.sh lifecycle 3600
```

The persistent corpus is stored below `build-quic-fuzz/corpus`. Crashes,
timeouts, and out-of-memory inputs are written below
`build-quic-fuzz/artifacts`. Reproduce an artifact directly:

```sh
build-quic-fuzz/quic_wire_fuzzer \
  build-quic-fuzz/artifacts/wire/crash-<hash>
```

The lifecycle target needs permission to create loopback UDP sockets. It may
therefore be unavailable in restricted containers even when the pure wire and
MultiFlow targets work.

AddressSanitizer and UndefinedBehaviorSanitizer are always enabled. Leak
detection is disabled by default because LeakSanitizer cannot run in some
ptrace-based CI sandboxes; enable it on a regular host with
`QUIC_FUZZ_DETECT_LEAKS=1`.

The corpus files are deliberately ordinary byte streams. External generators
and replay tools, including Peeplay, can write additional samples into the
matching corpus directory without adapting to a private container format.
