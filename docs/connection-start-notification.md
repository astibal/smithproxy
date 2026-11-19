# Connection-start notification

`connection-start` is an asynchronous lifecycle notification for TCP and QUIC
unless the active webhook override explicitly requests synchronous delivery.
The default path uses the existing bounded webhook queue. Receiver delay, HTTP
failure, a malformed response, or a `drop` response does not delay or reject
connection setup. Queue rejection diagnostics apply as before.

The default delivery is asynchronous and its reply does not negotiate rewrite,
strict mode, or server/TLS/QUIC lifecycle observation. A webhook override may
request `connection_start_synchronous: true` while it registers. Smithproxy then
sends the same single `connection-start` synchronously, marks
`details.info.synchronous: true`, and applies its setup reply. The field is false
for asynchronous webhook and SIFT delivery.

Synchronous delivery runs before content processing and before optional server,
TLS or QUIC lifecycle callbacks. Its verdict belongs to that connection and
destination. Locally configured content replacement rules still apply.
Policy-selected `access-request` remains synchronous and retains its existing
fail-open setting. SIFT always receives asynchronous connection-start
notifications.

Regression test (isolated test host only):

```
unshare -n python3 tests/integration/connection_start_async.py /path/to/smithproxy /new/artifact/directory
```

The test withholds the webhook response until application data has crossed the
proxy. It exercises TCP and TLS, then returns either `drop` or invalid JSON and
checks continued data transfer. All certificates are disposable test fixtures;
the test does not contact production services. QUIC wire behavior is not exercised
by this TCP/TLS regression.

The synchronous integration test acquires a webhook override with
`connection_start_synchronous: true`. It verifies that setup waits for the reply,
then accepts, rejects `drop`, or follows the existing fail-open behavior for an
invalid reply. It then replaces that lease with a default-mode owner, blocks the
new owner's `drop` response, and verifies that forwarding remains asynchronous
with `details.info.synchronous: false`.
