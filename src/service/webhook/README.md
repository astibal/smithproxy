# Webhook communication broker

The webhook broker is intentionally an opaque transport:

```text
libcurl -- Unix SOCK_STREAM -- TcpRelayServer -- fixed TCP endpoint
```

Smithproxy retains ownership of the URL, HTTP request, `Host`, TLS SNI,
certificate verification and credentials. The broker owns only the physical
destination, optional source interface, connection limits and timeouts. It
does not parse or rewrite HTTP and it never terminates TLS.

Example:

```bash
smithproxy-webhook-broker \
  --comm-webhook /run/smithproxy/comm/webhook.sock \
  --destination webhook.example.net --port 443

smithproxy --comm-webhook /run/smithproxy/comm/webhook.sock
```

When `--comm-webhook` is active, failure to connect to the Unix socket is a
webhook failure. There is no direct-network fallback. Without the option,
standalone Smithproxy keeps its existing direct webhook transport.

`TcpRelayServer` is protocol-neutral and can be reused by other outbound
stream integrations. `sx::comm::webhook` is deliberately a thin transport
selection specialization.
