# Paranoid security testing

This profile targets the trust boundaries introduced by privilege separation
and Unix communication brokers. It complements functional tests; it does not
replace the full Smithproxy suite.

```text
untrusted peer
     |
     +-- malformed framing / descriptor abuse / oversized input
     +-- slow, idle, half-closed or excessive sessions
     +-- concurrent filesystem replacement / symlink / non-regular input
     +-- helper or broker disconnect
     v
privileged helper or communication broker
     |
     +-- must remain available after a rejected request
     +-- must not leak descriptors or cross request boundaries
     +-- must preserve file ownership and atomicity invariants
     +-- must not block unrelated clients
```

## Profiles

The smoke profile is bounded enough for CI:

```bash
tests/paranoid/run.sh --profile smoke --seed 12345
```

The soak profile repeats every focused executable in shuffled order under a
normal build, ASan/UBSan and TSan:

```bash
tests/paranoid/run.sh --profile soak --seed 12345
```

The report records both repository revisions, toolchain, kernel and seed. A
failure must always be rerun with the recorded seed before minimizing it.

The runner deliberately uses explicit executable names. A missing CTest entry
therefore cannot silently remove a security boundary from this profile.

Every executable has a hard timeout. TSan does not safely support tests which
fork after its runtime has initialized, so fork-based GRE and local-helper
process-lifecycle cases run under the normal and ASan/UBSan variants but are
explicitly excluded from TSan. This exclusion is printed in `tsan.log` and
recorded in `metadata.txt`; the threaded communication paths still run under
TSan.

## Current hostile coverage

- Invalid, truncated and oversized opcode frames.
- Unknown and throwing operations followed by valid traffic.
- Excess `SCM_RIGHTS` descriptors and descriptor-boundary isolation.
- Slow clients, half-close, binary relay payloads and session exhaustion.
- Symlink, FIFO, directory and oversized configuration input.
- Concurrent atomic replacement and PID ownership/replacement races.
- Broker recovery expectations and Unix socket permission checks.

`socle/tests/security/hostile_peer.hpp` provides the reusable deterministic
frame corpus, send/drain transport driver and Linux FD-count invariant. Both
the socket privilege helper and Smithproxy communication server use the same
harness. New opcode protocols should reuse it and prove that a valid probe
still succeeds after the complete hostile corpus.

## Lab-only follow-up

Process killing, UID/capability transitions, `RLIMIT_NOFILE` exhaustion and
system-call policy validation require the privileged lab harness. They should
not be simulated in an unprivileged unit test because that gives misleading
coverage. Keep those scenarios in the root process lab and store its report
alongside the paranoid report.
