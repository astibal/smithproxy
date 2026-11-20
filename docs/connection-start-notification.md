# Webhook synchronous mode

Webhook delivery is asynchronous by default. An API override owner may request
`synchronous_mode: true` in either the v2 lease or legacy registration. The mode
is stored with that owner's URL, TLS setting and expiry and is read in one
snapshot for every event. A statically configured target uses
`settings.webhook.synchronous_mode`, also disabled by default.

The single mode applies to all controllable events:

- `connection-start` and `connection-stop`
- `http-connect`
- `server-lifecycle`, `tls-lifecycle` and `quic-lifecycle`
- `connection-content`

Smithproxy marks each of these events as
`details.info.synchronous: true|false`. In asynchronous mode it queues the event,
does not wait for the receiver and ignores its response. A full queue drops a
`connection-stop` notification like any other asynchronous event; there is no
direct synchronous fallback. In synchronous mode Smithproxy waits and applies
the existing action-specific response contract.

`access-request` and `proxy-authentication` remain unconditionally synchronous
because they are authorization operations. They are not controlled by
`synchronous_mode`.

The legacy registration field `connection_start_synchronous` is accepted as a
compatibility alias for `synchronous_mode`; new clients must use the new name.

Sift does not own an API override lease and is always synchronous. Its action
and content callbacks complete before proxy processing continues. DNS
observations remain asynchronous telemetry.

The connection integration acquires a synchronous lease and verifies setup and
content decisions. It then replaces that lease with a default asynchronous
owner, blocks the receiver's `drop` response, and verifies that forwarding
continues with `details.info.synchronous: false`.
