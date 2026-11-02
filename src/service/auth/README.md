# External authentication client

Smithproxy owns the generic authentication result, PAP exchange abstraction,
Unix HTTP client and HTTP CONNECT/SOCKS5 protocol integration. The daemon and
its PAM backend have moved to [Smithproxy Keyway](https://github.com/astibal/smithproxy-keyway).
Smithproxy does not build or install the daemon, its backend or its test PAM
module. The existing administrative CLI PAM dependency is unchanged.

The `smithproxy_auth_client` target links curl and JSON. The diagnostic executable
`smithproxy-auth-check` remains installed with Smithproxy.

## Build and test

The normal Smithproxy build includes client unit tests and malformed-reply
integration tests. For real proxy-to-Keyway integration, build Keyway separately
with testing enabled and configure Smithproxy with:

```sh
cmake -S . -B build \
  -DSMITHPROXY_KEYWAY_EXECUTABLE=/path/to/keyway/build/smithproxy-keyway \
  -DSMITHPROXY_KEYWAY_TEST_PAM_MODULE=/path/to/keyway/build/keyway_test_pam.so
cmake --build build -j2
ctest --test-dir build -R 'unit.pap|integration.auth_client|integration.proxy_auth' --output-on-failure
```

These paths register optional tests; they do not add Keyway as a build or
installation dependency. Without them the client still builds and tests alone.
Test accounts and PAM configuration are confined to temporary directories.

## Configuration and startup

Configure Keyway separately, explicitly enable its PAM backend, and select a
dedicated PAM service and allowed group. See the Keyway repository for its
configuration and Unix socket ownership contract. No backend is enabled by
installation and no system PAM policy is installed automatically.

```sh
smithproxy-keyway --config /path/to/keyway.cfg
smithproxy --config-file /path/to/smithproxy.cfg --comm-auth /run/smithproxy-keyway/keyway.sock
smithproxy-auth-check /run/smithproxy-keyway/keyway.sock USERNAME
```

The check utility reads one password line from standard input. Supply it through
a protected pipe; it does not provide a hidden terminal prompt. Passwords are
never command-line arguments or logged by this code.

`--comm-auth` configures only the broker socket. Authentication is explicitly
opted into per protocol; both options default to false when omitted:

```text
settings = {
    socks = { proxy_authorization = true; };
    http_connect = { proxy_authorization = true; };
};
```

These groups extend the existing settings, rather than replacing other options.
The settings are saved with the configuration and can be reloaded. SOCKS keeps
the negotiated choice for the lifetime of its handshake. A required protocol
rejects access if the broker socket is missing or unavailable. Configuring a
socket without enabling a protocol does not require authentication. When enabled:

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
