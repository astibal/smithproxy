# Administrator security model

This document records the security invariants of the native administrator and
GUI bootstrap design. It describes the current `full-admin` implementation;
future transports must preserve the same boundaries.

## Sources of truth

- Smithproxy Core is the only writer of persistent configuration.
- `admin.cfg` is a protected root member of the native CFtar archive.
- Administrator mutations use the typed Admin API and the shared atomic CFtar
  writer. The generic archive-resource API cannot read, replace, or remove
  root control files.
- A missing `admin.cfg` is an inert legacy state. It performs no migration or
  write and retains the existing PAM login path.
- A malformed present `admin.cfg` fails closed. It is not silently replaced.

## Credential capabilities

Credential classes are independent, not progressively stronger aliases:

| Credential | Standard API | Admin API | Archive API |
| --- | ---: | ---: | ---: |
| configured API key | yes | no | no |
| GUI management key | yes | yes | no |
| archive key | no | no | yes |
| managed administrator session | yes | yes | no |
| permitted PAM administrator session | yes | yes | no |

An archive credential therefore cannot manage administrators or use ordinary
diagnostic/configuration endpoints. A management credential cannot download or
restore an archive unless it is separately granted archive capability.

## Runtime GUI credentials

Core owns the management and gateway credential files after bootstrap. It:

- accepts only a fresh launcher seed with safe ownership, mode, size, content,
  regular-file type, and modification time;
- uses no-follow opens and atomic replacement;
- rotates current material on schedule and accepts previous material only for
  a bounded overlap;
- replaces stale or unsafe bootstrap material;
- ignores and restores external replacement after assuming ownership;
- removes both generations when that credential class is disabled;
- starts the proxy data plane even when credential publication fails.

Management credentials are enabled by default. Gateway credentials are
disabled by default and use the same implementation with an independent path
and policy. Default runtime paths are isolated below `tenant-N` for non-primary
tenants; explicitly configured paths remain authoritative.

## Administrator lifecycle and recovery

Enrollment tokens are high-entropy, short-lived, single-use in-memory
capabilities bound to one administrator name. Only a verifier is retained.
Persistence claims the token exclusively; a failed write releases the claim so
the same token may be retried until expiry, while a successful durable write
consumes it.

Enrollment creates a new administrator and never overwrites an existing one.
A privileged local operator can recover access by issuing a token for a new
administrator. Existing administrator credentials remain unchanged. The final
enabled administrator cannot be disabled or removed. Password changes and
disable/remove operations revoke affected live sessions.

When a name exists in `admin.cfg`, the managed record is authoritative and PAM
is not consulted for that name. PAM remains a compatibility fallback only when
no managed administrator with that name exists or no native administrator
store is configured.

## Online attack controls

Password verification is throttled by both source address and the pair of
source address plus administrator name. The source budget bounds attempts with
rotating names. The scoped principal budget prevents brute force against one
name without allowing a remote source to lock that name out for every other
source. Runtime throttle state is bounded and contains no credentials.

Session cookies are paired with CSRF tokens for unsafe methods. Managed
sessions record the administrator generation and become invalid after a
credential or enabled-state change. Logout invalidates only the presented
session.

## Local SSH authentication transport

A forked SSH service receives neither `admin.cfg`, a management key, nor the
general HTTP Admin API. Core publishes a narrow Unix `SOCK_SEQPACKET`
authentication socket. It exposes only the versioned JSON `authenticate`
operation, obtains peer identity through `SO_PEERCRED`, shares the same
managed-admin/PAM ordering and throttling as HTTP login, bounds message size
and receive/send time, never returns or logs passwords, and fails closed.

The default path is `/run/smithproxy/admin-auth.sock`, with mode `0660` inside
the Core-owned runtime directory. `gui.smithproxy.administrator_auth_socket`
and `administrator_auth_socket_enabled` configure it; the
`SMITHPROXY_ADMIN_AUTH_SOCKET` environment variable is a one-time startup
override and an empty value disables publication.
Non-primary tenants default to `/run/smithproxy/tenant-N/admin-auth.sock`.

Request:

```json
{"version":1,"operation":"authenticate","username":"alice","password":"..."}
```

Accepted response:

```json
{"version":1,"status":"accepted","identity":"alice","authentication_method":"password"}
```

Other stable status values are `rejected`, `throttled`, `unavailable`, and
`invalid_request`. A throttled response also carries `retry_after_seconds`.
