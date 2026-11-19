# Connection-start notification

`connection-start` is an asynchronous lifecycle notification for TCP and QUIC.
It uses the existing bounded webhook queue. Receiver delay, HTTP failure, a
malformed response, or a `drop` response must not delay or reject connection setup.
When the notification queue is full, the existing queue rejection diagnostics
apply; establishing the connection does not wait for delivery.

The reply no longer negotiates rewrite, strict mode, or server/TLS/QUIC lifecycle
observation. Integrations relying on those connection-start replies need a
separate `inspection-start` request. The former synchronous implementation is
preserved as `inspection_start()`, including reply-driven rewrite, strict mode,
and lifecycle options. Normal TCP and QUIC connection setup calls only `start()`;
there is no automatic inspection request or new configuration switch.

When explicitly wired in later, inspection must run after the notification and
before content processing. QUIC setup keeps a separate inspection-start guard,
so calling the notification does not suppress inspection. Both entry points bind
to the same destination; an inspection verdict cannot be reused for another one.
Locally configured content replacement rules still apply. Policy-selected
`access-request` remains synchronous and retains its existing fail-open setting.
SIFT continues receiving asynchronous connection-start notifications.

Regression test (isolated test host only):

```
unshare -n python3 tests/integration/connection_start_async.py /path/to/smithproxy /new/artifact/directory
```

The test withholds the webhook response until application data has crossed the
proxy. It exercises TCP and TLS, then returns either `drop` or invalid JSON and
checks continued data transfer. All certificates are disposable test fixtures;
the test does not contact production services. QUIC wire behavior is not exercised
by this TCP/TLS regression.

The same harness accepts `--inspection` for a test-only binary that calls
`ProxyHooks::inspection_start(..., InspectionStartArgs{})` after a successful
`ProxyHooks::start(...)` in `MitmProxy::webhook_session_start()`. It verifies that
setup waits for the response, then accepts, rejects `drop`, or follows the existing
fail-open behavior for invalid JSON. This wiring is never part of the production
patch. Do not deploy the test-only binary.
