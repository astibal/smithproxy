# Webhook API v2: owner-aware lease

The existing webhook override is useful but is a single anonymous 60-second
lease. Any authorized client can silently replace it and any authorized client
can unregister it. Keep those endpoints for compatibility, but do not extend
their semantics.

## Proposed endpoints

```text
POST /api/v2/webhook/lease
POST /api/v2/webhook/lease/release
GET  /api/v2/webhook/lease
```

All three use the normal API authorization. API authorization controls who may
request a lease; the opaque `lease_id` controls who may renew or release the
currently active override.

Initial acquisition:

```json
{
  "url": "http://127.0.0.1:8080/webhook/<callback-secret>",
  "tls_verify": false,
  "ttl_seconds": 60
}
```

```json
{
  "status": "accepted",
  "lease_id": "<random-256-bit-value>",
  "expires_at": 1791475200
}
```

Renewal sends the same fields plus `lease_id`. It succeeds only when that ID
owns the active lease. Release requires only `lease_id`. The status endpoint
must not expose the ID or callback credentials; it returns `active`, expiry and
a server-generated non-secret owner label at most.

## Conflict and expiry rules

```text
no active lease                     -> acquire, 201
same lease_id                       -> renew/update, 200
different lease_id, lease active    -> reject, 409
different lease_id, lease expired   -> acquire, 201
release by owner                    -> release, 200
release by non-owner                -> reject, 409
```

The configured webhook remains the fallback whenever the lease expires or is
released. Lease state is process-local and intentionally disappears on a
Smithproxy restart.

Clamp `ttl_seconds` to a configured range (initially 10..300 seconds). Return
the authoritative expiry so a client can renew around one third of the TTL
with jitter. Callback authentication remains the receiver's responsibility;
Spider currently uses a random callback path because the webhook sender cannot
attach an authorization header.

## Legacy coexistence

The legacy register/unregister endpoints continue to operate only on an
anonymous legacy override. They must return `409` while an owned v2 lease is
active, rather than clobbering it. A v2 acquisition likewise returns `409`
while a non-expired legacy override is active. After expiry either API may
acquire the singleton slot.

## Implementation boundaries

- Put acquisition/renew/release decisions in a small lock-protected lease
  object, independent of HTTP parsing, with deterministic unit tests.
- Generate `lease_id` with `RAND_priv_bytes` and fail closed if entropy fails.
- Compare lease IDs in constant time.
- Never log API keys, session tokens, lease IDs, or callback URLs containing
  secrets.
- Audit acquire, renew conflict, release and expiry using a redacted owner
  label and client address.
- Keep traffic gating separate. A webhook delivery timeout must never become
  an implicit global traffic lock; future forensic stopping is an explicit,
  bounded and auditable traffic-gate operation.
