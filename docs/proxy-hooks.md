# Proxy hooks and transport observations

Smithproxy owns sockets, policy and transport scheduling. Spider executes optional
scripts and returns the supported decisions. Socle provides protocol state and
synchronous callback insert points; it does not know webhook URLs or addon APIs.

```text
Socle COM state/callback -> Smithproxy observer -> ProxyHooks -> Spider addon
                              |                    |
                         native decision      owned wire payload
```

## Implementation map

| Component | Responsibility |
| --- | --- |
| `socle/hostcx.hpp` and COM objects | Host CX socket accessors delegate to COM; COM owns the descriptor value. |
| COM `is_connected` / communication status | Transport/application readiness; TCP completion alone is insufficient for TLS application data. |
| `socle/tls_proto_state.hpp` | TLS role, state and bounded transition history; consecutive duplicates are suppressed. |
| `src/proxy/proxymaker.*` | Shared connection creation/start boundary; policy and protocol paths retain their semantics. |
| `src/proxy/cx_map.hpp` | Small linear vector map, reserves two contexts; `find` does not insert. References can be invalidated by mutation. |
| `src/proxy/proxy_hooks.*` | Wire construction, response handling and supported hook decisions; named argument structures keep calls readable. |
| TLS/QUIC observers | Translate native observations and callback results without exporting live SSL ownership. |
| `MitmProxy::prepare_session_stop` / `finalize` | Prepare owned terminal metadata and enqueue connection stop before destruction. |
| Socle master proxy retirement | Calls the virtual `finalize()` while the object is alive; default implementation is empty. |

The global callback registry is transport infrastructure, not a per-session
webhook registry. Per-object opt-in gates handshake callbacks. Insert points
stay in native code; OpenSSL callbacks are not a place to run remote scripts.
State enum values are not an ordering relation. Bounded history can overflow;
current state remains available and history is not an unlimited event journal.

Observers return explicit continuation/termination decisions. Callers apply
termination in the owning proxy path; an apparently read-only observation must
not conceal an unrelated transport mutation. Reconnect behavior was deliberately
left unchanged by this work.

## Lifetime and retirement

An Epitaph contains owned strings/JSON metadata, never borrowed proxy/CX/SSL
references. It is held through a `unique_ptr`; disabled webhooks do not require
an allocated epitaph. Finalization handles an empty snapshot normally. Destructors
perform destruction, while retirement/finalization handles terminal publication.
Asynchronous delivery must not capture a destroyed proxy. Server terminal events
and connection stop have distinct responsibilities and must retain their order.

## Configuration and operational boundaries

Proxy authentication is opt-in independently for both explicit protocols:

```text
settings = {
    socks = { proxy_authorization = false; };
    http_connect = { proxy_authorization = false; };
};
```

Merge these members into the existing settings; this is not a complete config.
`--comm-auth /path/to/keyway.sock` selects the external broker, not whether a
protocol requires authentication. Required authentication with an unavailable
broker fails closed. Keyway is a separate executable/repository; no internal AAA
fallback is introduced here. Legacy authentication profiles are not these switches.

Content setup negotiates native hook capabilities. TCP TLS ClientHello and start
interception, and QUIC parent start/outcomes, require the corresponding explicit
Spider deployment options. Ordinary transport observer failures follow negotiated
strict/fail-open policy; authentication requires both AAA and all enabled observers
to accept. An addon may narrow authentication but cannot override a failed AAA result.

TCP connected is distinct from TLS established. Before upstream TLS start, a
confirmed but unreported TCP completion can be emitted immediately. Pending TCP
is not reported as connected, and native handshake scheduling is not changed just
to match another proxy's event order.

QUIC has dedicated observations and parent identity; HTTP/3 streams do not each
produce a new parent handshake. The current listener supports IPv4. DTLS, QUIC
client-start/ClientHello interception, live SSL/context replacement and arbitrary
rerouting are outside this implementation.

The [owner-aware webhook lease proposal](webhook-api-v2.md) is a separate design;
it must not be mistaken for the implemented hook payload contract. The matching Spider repository contains
`docs/HOOKS_GUIDE.md`, complete examples under `examples/hooks/`, per-event producer
contracts, and `docs/HOOKS_INTEGRATION_CHECKPOINT.md` with final merged validation.
When extending the contract, update those documents and editor examples together.
