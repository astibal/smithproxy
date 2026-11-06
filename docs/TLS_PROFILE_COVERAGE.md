# TLS profile enforcement coverage

This audit distinguishes configuration loading, library checks and real
application traffic. A loaded boolean is not proof that the negotiated
connection obeys it. TLS-over-TCP and QUIC must be considered separately.

## Live TLS matrix

The patch runner's `tls` and `tls-policy` suites run the profile matrix by
default, including in full P8. `TLS_PROFILE_TEST=0` explicitly disables it;
`TLS_PROFILE_TEST=1` enables it independently of the other TLS probes.

Run from the staged checkout on the test host (Rhino for this audit), so
`--local` means the test host and does not build on the developer workstation:

```sh
tests/patch-runner/test-patch.sh sanity --local --suite tls
```

The matrix covers 18 profiles, TLS 1.2 and TLS 1.3, and IPv4 and IPv6.
Eight additional cases offer a ticket from a permissive policy to a policy
that disables reuse: **80 cases in total**. Each successful case exchanges
application data across three connections. The origin reports its own
version, cipher, ALPN and session-reuse flag in its HTTP response; the client
independently records the same properties of the downstream connection.
JSON evidence is retained in `results/tls-profile4.json` and
`results/tls-profile6.json` inside each lab.

The 2026-11-06 Rhino audit passed all 80 cases against `b8fddbcd` with
OpenSSL 3.5.5. Full P8 also passed all 53 sections, including a second run of
the matrix in `tls-policy`. The three separate QUIC regression probes below
failed on that baseline; they are not included in that green P8 count.

| Profile promise | Live assertion |
| --- | --- |
| Default session reuse | Both legs resume after a fresh connection, for TLS 1.2 and 1.3 |
| `left_disable_reuse` | Downstream never resumes; upstream can still resume |
| `right_disable_reuse` | Upstream never resumes; downstream can still resume |
| Both reuse switches | Neither leg resumes |
| Existing tickets under a stricter policy | A ticket issued under the baseline profile cannot bypass downstream reuse prohibition |
| `use_pfs`, `left_use_pfs`, `right_use_pfs` | TLS 1.2 negotiates RSA key exchange on the restricted leg; a fresh TLS-1.3-only connection is rejected |
| `alpn_block` | Neither leg negotiates ALPN |
| `inspect=false` | The client successfully verifies the original origin identity using only the separate origin CA |
| `allow_self_signed` | Self-signed origin is rejected without the exception and admitted with it |
| `allow_invalid_certs` | Expired origin is rejected without the exception and admitted with it |
| `allow_untrusted_issuers` | Origin signed by an untrusted CA is rejected without the exception and admitted with it |
| Required OCSP stapling | Origin without a staple is rejected |
| `ct_enable` | Origin without SCT evidence is rejected |
| `only_custom_certs` | With both custom lookup sources disabled, the proxy rejects instead of generating a fallback identity |

Certificate-exception cases deliberately disable **client-side** certificate
verification, both for the allow and reject controls. Smithproxy preserves
the failed origin trust verdict in the forged downstream identity; a strict
client may consequently reject an origin which the proxy has admitted.
The test checks proxy admission, not whether the exception also makes the
certificate trustworthy to that client. Accepted exceptional origins must
not enter the trusted upstream resumption cache.

The no-PFS control offers an RSA-authenticated ECDHE cipher and an RSA
key-exchange cipher to the disposable TLS 1.2 origin. It does not lower the
system security level. Fresh TLS 1.3 requires a key share; rejection rather
than a fabricated TLS 1.3 no-PFS success is the expected outcome.

## QUIC findings

At Smithproxy `b8fddbcd`, all four separate QUIC probes completed on Rhino:

| Configuration | Observed result | Verdict |
| --- | --- | --- |
| Baseline | Three HTTP/3 responses; downstream reuse `false,true,true` | PASS |
| Both reuse switches enabled | Still three responses and reuse `false,true,true` | FAIL |
| Common and both directional PFS switches disabled | Fresh QUIC handshake and HTTP/3 still succeed | FAIL |
| `alpn_block=true` | HTTP/3 still succeeds with `h3` | FAIL |

These are opt-in regression probes with ordinary nonzero failure status,
not XFAILs or report-only checks. Run each in a fresh isolated lab:

```sh
tests/patch-runner/test-patch.sh sanity --local --suite quic \
    --env QUIC_TLS_PROFILE_TEST=baseline
# Repeat with no_reuse, no_pfs, no_alpn, and old_ticket.
```

The existing QUIC runtime preparation applies. Evidence is retained in
`results/quic-tls-profile.json`. Each probe has a bounded handshake/request
deadline. A timeout alone does not count as correct rejection: negative
probes additionally require a new, explicit server-side profile rejection
for each attempt and no completed handshake or application response. These focused
probes replace the normal QUIC positive traffic suite for that invocation,
because a correctly rejecting profile cannot also pass its positive control.

## QUIC enforcement patch

The transport now selects the ordered UDP policy using the original source
and destination tuple in ClientHello, before OpenSSL processes a session
ticket. It copies three profile values; it does not retain a mutable profile
or dispatch a webhook from the OpenSSL callback. The existing session setup
continues through certificate verification and forwarding.

- `left_disable_reuse` suppresses new TLS 1.3 tickets and uses a separate
  session-id context to reject tickets issued under a permissive policy.
- Disabling either directional PFS switch rejects QUIC admission: this
  transport requires TLS 1.3 key exchange.
- `alpn_block` rejects QUIC admission because HTTP/3 requires ALPN.

The patched Rhino run passed all five focused probes, plus the live Spider
resumption suite (baseline, addon veto, untrusted origin, and hostname mismatch).
The final full P8 passed all 53 sections, including native CTest (60/60) and
the 80-case TLS matrix. Builds and runtime tests ran on Rhino.

The `old_ticket` probe uses one live listener and three source ports. A
permissive policy issues a ticket, a restrictive policy must perform a full
handshake with that ticket, and a final permissive control must resume with
that same original ticket. This checks policy isolation, not just issuance.

Early rejection in the tested OpenSSL QUIC path does not reliably deliver a
fatal close to the client; the client can observe its deadline instead. The
test therefore checks the explicit policy-rejection diagnostic as well as
absence of a completed handshake. It does not claim prompt alert delivery.

The present upstream QUIC path has no session-ticket cache. There is no
positive upstream-resumption control, so these results do not claim a newly
implemented upstream cache or new handling for `right_disable_reuse`.
Direct non-transparent transport fixtures retain their existing setup path;
the policy integration applies to the production transparent dispatcher.

## Remaining coverage boundaries

| Area | Existing evidence / outstanding work |
| --- | --- |
| ClientHello and handshake timeouts, malformed traffic, fallback | Existing Socle deadline/parser tests and live TLS evasion suite; not a complete timeout-value sweep |
| Client certificate actions | Existing Socle real TLS 1.2/1.3 tests; add policy-to-wire mTLS profile cases |
| OCSP modes, revoked/stale/full-chain results | Existing Socle policy/callback tests; live matrix adds missing-required-staple only |
| Certificate Transparency | Existing callback tests plus live missing-SCT rejection; no live valid-SCT fixture in this matrix |
| SNI/IP custom certificate selection | Existing Socle certificate-selection tests plus live no-fallback rejection; add successful per-policy custom identities |
| SNI bypass and DNS cache options | Existing parser/matching tests; not live-tested here against every DNS/cache toggle |
| Certificate warning replacement and override lifetime | Not covered by this new matrix |
| Alerts and `sslkeylog` profile switch | Not covered by this new matrix; global QUIC keylog capture is a different control |
| QUIC certificate exceptions, bypass and revocation options | Not implied by TLS results; audit after the profile-to-handshake boundary is defined |
| STARTTLS, HTTP CONNECT, SOCKS-specific application paths | Existing integration suites remain separate; the new matrix exercises transparent/autodetected TLS |

The current result is an enforcement matrix with explicit gaps, not a claim
of complete TLS-profile parity or complete QUIC policy support.
