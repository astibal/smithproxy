# Proxy authentication merge validation

Validated Smithproxy `d90ee94d` against its unchanged `master` ancestor
`f7e33377` on 2026-11-02, using an isolated remote test workspace.
No production code changed during this validation.

- full patch-runner gate: PASS, including all 47 selected native CTest cases,
  smoke, RTT, TLS throughput, functional traffic, churn, capture, corpus and
  deterministic protocol fuzzing; no flaky verdicts
- standalone Keyway `3416a03`: both backend and GUI API integration suites PASS
- live Smithproxy → Keyway → Spider: HTTP CONNECT and SOCKS5, native scripts
  and addon veto, rejected AAA, mismatched reply identity and unavailable hook
  all PASS
- cleanup checks: no remaining lab namespaces or API/CLI listeners, and host
  addresses and routes unchanged

The full gate explicitly configured the external Keyway executable and its
isolated test PAM module, so `integration.proxy_auth` was included. No system
PAM policy, account or service configuration was changed. The pinned QUIC
runtime and HTTP/3 client were staged privately for the full regression gate.

Report on the test host:
`/tmp/auth-webhook-review.Y69fmw/merge-gate/results/20261102T112108Z-d90ee94d-full`.
The corresponding successful run is recorded in `patch-run-history`.
