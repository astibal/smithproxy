# Minimal connection webhook control

Optional top-level response block, independent of `action`:

```json
{"control":{"mode":"strict"}}
```

```json
{"action":"accept","control":{"mode":"regular"}}
```

- Default is `regular`. Policy belongs to one connection, both directions.
- Successful (2xx) connection-start/info/stop and connection-content responses
  from the regular webhook can change policy. JSON and SXBN content requests
  use the same JSON response. Global ping/info/hostname notifications have no
  connection policy; the separate SIFT classification service does not control it.
- Missing, malformed or unknown control values leave policy unchanged.
- Async responses keep only shared atomic policy state, never a proxy pointer.
  Updates take effect when processed; overlapping replies use arrival order.
  This is not a negotiated activation barrier or acknowledgement protocol.
- In strict mode, missing content replies, non-2xx status, or non-object JSON
  close the connection before forwarding the current content. Disabled webhook
  and unavailable traffic lock also close it. `not-interested` cannot disable
  strict content delivery. A successful regular downgrade restores fail-open.
- Closure uses existing proxy shutdown, not a promise of an on-wire TCP RST.
  No new `drop` action, translation engine, or idle watchdog is introduced.
- An empty JSON object is a successful unchanged response. This minimal policy
  is transport fail-closed, not validation of every semantic action or HPACK state.

Review core: `src/service/http/webhook_control.hpp`.

Regular content callbacks also expose `info.webhook_control` with `version: 1`,
the current `mode`, and a monotonically increasing `sequence` starting at 1.
The counter belongs to the connection, shared by both directions. This lets
Spider reject mid-connection activation and detect a missing translate callback;
it does not add an activation handshake. SIFT callbacks do not carry this counter.
Tests: `unit.webhook_control`, `integration.webhook_control`,
`integration.webhook_control_binary`.

Validation (2026-10-25): full local build succeeded; all five selected CTest
suites passed (31.15 s): the three above plus both existing need-more JSON/SXBN
regressions. Live cases cover HTTP error, invalid JSON, non-object JSON,
unknown mode preservation, rejection of downgrade on HTTP error, regular
fail-open restoration, and continued callbacks after strict + not-interested.
Async connection notification routing is compiled; its ordering/activation
race is not covered by the live tests and is not an acknowledgement guarantee.

The same five suites passed again after adding capability/sequence metadata
(28.47 s). Control integration checks version, mode and consecutive sequence
for both JSON and SXBN requests.

The companion Spider harness `tests/translate_e2e.py` also runs this real proxy
against the real Spider backend with loopback H2 peers. It checks indexed header
rewrites in both directions, subsequent original values, SETTINGS/PING callbacks,
strict sequence metadata, and peer-visible closure without leaking bytes after
a script exception or missing translate call. Each failure variant passed three
consecutive runs. Only management lease discovery is stubbed; content callbacks
and proxy forwarding are real. This does not cover TLS or fragmented H2 blocks.
