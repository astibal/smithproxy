# Privilege separation

Smithproxy separates the privileged operations required by its core:

- transparent and privileged sockets: `socket`, `setsockopt`, `bind`, `listen`;
- configuration: restricted read, atomic write and backup;
- process state: restricted PID-file checks, write and removal;
- GRE export: raw sockets remain in the internal or external GRE broker;
- CLI and API ingress: listeners can remain in internal or external brokers;
- webhook egress: an external relay can own network access to the fixed target.

Ordinary output files are intentionally not delegated. The target user still
needs filesystem access to configured logs, PCAP/capture directories, TLS key
logs and other enabled outputs. The service manager must also prepare the Unix
socket directory and its ownership before startup.

Start Smithproxy as root and select the unprivileged identity for its core:

```sh
smithproxy --run-as nobody
```

`SMITHPROXY_RUN_AS=nobody` is equivalent; `--run-as` takes precedence. Smithproxy
starts narrowly scoped helpers first, then applies supplementary groups, GID and
UID of the selected account. Starting Smithproxy directly as `nobody` cannot
create the privileged helpers.

The privileged socket helper accepts only its fixed socket operations
(`socket`, `setsockopt`, `bind` and `listen`) and receives descriptors over a
private Unix socket pair. The file helper is restricted to the selected config
and PID paths and implements config read/write/backup and PID operations. It is
not a general filesystem service. Neither helper executes commands or accepts a
network listener.

Communication brokers keep integration traffic out of the core namespace:

```text
--comm-gre PATH       raw GRE export
--comm-cli PATH       CLI ingress
--comm-api PATH       API ingress
--comm-webhook PATH   outbound webhook relay
```

Without a `--comm-*` option, Smithproxy uses its standalone/internal transport.
Unix socket ownership, mode and parent-directory access remain deployment
policy; do not expose the communication directory to untrusted users.

Verify the effective identity and helper activity from the CLI:

```text
diag sys priv stats
diag sys gre stats
diag sys cli stats
diag sys api stats
diag sys webhook stats
```

See `smithproxy-privsep(7)` for the reference page.
