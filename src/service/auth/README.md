# External PAM authentication (development)

This directory is a standalone-buildable prototype on `new-AAA`. It keeps PAM
and group lookup in a separate executable, ready for later repository extraction.
There is no local password database, embedded verification backend or fallback
inside the proxy. The old policy-profile authentication feature is unrelated.

```text
HTTP CONNECT / SOCKS5
        |
Smithproxy --comm-auth /run/smithproxy-auth/auth.sock
        | HTTP/JSON over Unix socket
smithproxy-auth-broker --config broker.cfg
        | PAM authentication + account checks
        | NSS primary/supplementary group membership
        + accepted identity / rejected / unavailable
```

## Build and test

The normal Smithproxy build includes `smithproxy-auth-broker` and the diagnostic
`smithproxy-auth-check`. The new proxy client links curl and JSON; PAM belongs to
the broker. Smithproxy's existing administrative CLI PAM dependency is unchanged.

The directory can also be built independently with CMake, a C++17 compiler,
Linux-PAM (including `pam_start_confdir`), libconfig++, libmicrohttpd, libcurl,
nlohmann-json and the repository's lmhttp headers:

```sh
cmake -S src/service/auth -B build-auth -DBUILD_TESTING=ON
cmake --build build-auth -j2
ctest --test-dir build-auth --output-on-failure
```

For an extracted copy, set `LMHPP_INCLUDE_DIR` to the lmhttp include directory.
Tests additionally need GoogleTest and Python 3. Integration tests open local
Unix/TCP sockets and use a temporary PAM configuration and test-only module. They
never change system accounts, group memberships, passwords or `/etc/pam.d`.
The fixed password in the test module is a fixture, not a shipped backend; the
module is not installed. Full builds also register `integration.proxy_auth`.

## Configuration and startup

Copy `broker.example.cfg` and select an existing Linux group. The required
`pam.allowed_group` permits both primary and supplementary membership, resolved
through NSS using the canonical identity returned by PAM. Only that matched
group is returned, not a full identity/group directory.

Provide a dedicated PAM service named by `pam.service`. Its `auth` stack must
verify the password and its `account` stack must allow the account. Configure
those stacks according to the host's PAM policy; the build does not install or
modify a system PAM policy. Password changes, interactive challenges, sessions
and credential establishment are outside this initial implementation. Empty
passwords and accounts requiring a password change are rejected.

Create the socket's parent directory with restricted access. Run the broker and
proxy with the same effective UID, with the privileges required by the selected
PAM stack. The socket is owner-only (umask 0077); this prototype does not grant
access to a separate service UID. Configuration and any custom PAM directory
must be writable only by their administrator.

```sh
smithproxy-auth-broker --config /path/to/broker.cfg
smithproxy --config-file /path/to/smithproxy.cfg --comm-auth /run/smithproxy-auth/auth.sock
smithproxy-auth-check /run/smithproxy-auth/auth.sock USERNAME
```

The check utility reads one password line from standard input. Supply it through
a protected pipe; it does not provide a hidden terminal prompt. Passwords are
never command-line arguments or logged by this code.

`--comm-auth` enables mandatory authentication on HTTP CONNECT and SOCKS5. Without
it, existing unauthenticated behavior remains unchanged. When enabled:

- CONNECT accepts Basic `Proxy-Authorization`; missing/invalid credentials get
  407 with a challenge, unavailable/invalid broker responses get 503. The
  connection closes after failure. CONNECT headers never enter the tunnel.
- SOCKS5 requires username/password method 0x02 (RFC 1929), including the TCP
  control connection for UDP associations. No-auth negotiation and SOCKS4 are
  rejected. Fragmented and pipelined authentication frames are supported.
- Authentication completes before target resolution/connection. A broker outage
  never falls back to anonymous access or an in-process backend.

Use these password-based protocols only on an appropriately protected client
transport/network. Basic and RFC 1929 do not themselves encrypt credentials.
The current HTTP frontend supports CONNECT, not absolute-form HTTP forwarding.
Accepted identity/groups are not yet attached to traffic policy or accounting.

## Version 1 broker API

`POST /v1/pap`, `Content-Type: application/json`, over the configured Unix socket:

```json
{"version":1,"username":"alice","password":"supplied-by-client"}
```

Responses use `Cache-Control: no-store`:

```json
{"version":1,"status":"accepted","identity":"alice","groups":["proxy-users"]}
{"version":1,"status":"rejected"}
{"version":1,"status":"error"}
```

Accepted/rejected responses use HTTP 200; backend initialization failures use
503. Invalid input uses 400, oversized input 413. The broker caps request bodies
at 4096 bytes; credentials are limited to 255 username bytes and 1024 password
bytes, without NUL. JSON requires UTF-8. The client bounds replies to 16384 bytes
and rejects unknown versions, invalid decisions, oversized identities/groups,
non-200 status, redirects and malformed JSON. Environment HTTP proxies are
explicitly disabled; the Unix transport must be configured successfully.

## Deliberate prototype limits

`PapBackend` supports immediate and deferred results; `PapExchange` retains the
original tap/untap lifecycle, generation checks and cancellation. The current
broker client is **synchronous** with a 1500 ms total deadline, so proxy workers
can pause during verification. The lmhttp daemon also runs PAM synchronously.
Slow PAM/NSS calls can outlive a disconnected client; the client deadline does
not cancel PAM. A slow or stuck backend can therefore make subsequent attempts
unavailable. This is not yet a production concurrency or rate-limiting design.

Future work includes bounded asynchronous dispatch, configurable deadlines,
peer/service-UID access, identity propagation and further backends. There is no
authentication cache, session/token scheme, authorization rules engine or
accounting implementation. PAM/NSS can use remotely configured providers without
linking their libraries into Smithproxy.

The daemon refuses an existing socket or file. It removes only its own socket
inode on normal shutdown; after a crash, the administrator must resolve a stale
path explicitly. SIGINT/SIGTERM shut down cleanly when PAM is not blocked.

## Validation recorded for the initial implementation

The full Debug build passed with the repository warning policy. The standalone
build passed both registered suites (including 16 PAP/client unit cases).
The full-build focused selection passed all seven suites:

```sh
ctest --test-dir BUILD --output-on-failure -R '^(unit.pap|unit.httpconnect|integration.auth_broker|integration.proxy_auth|integration.httpconnect|integration.socks5_udp|integration.starttls_socks)$'
```

This covers the new PAM/socket path and existing unauthenticated CONNECT,
STARTTLS-over-SOCKS and UDP behavior. It is a focused development validation,
not a full distributed patch-runner or production PAM deployment qualification.
