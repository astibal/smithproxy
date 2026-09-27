# On-demand mem-constrained runners

These runners start one short-lived Smithproxy instance per tenant without
Kubernetes.  The common constrained binary currently has two runtime profiles:

| Profile | Interface | Network setup | Tested peak RSS |
|---|---|---|---:|
| `socks` | SOCKS5 on port 1080 | ordinary host/container networking | 16.3 MiB |
| `tproxy` | transparent IPv4 TCP on port 50080 | dedicated Linux netns, policy route and nftables | 16.1 MiB |

`http-connect` is reserved for the implementation expected from upstream; it
is deliberately not emulated here.
Webhook delivery is compiled out of this build profile, so the Smithproxy
binary does not link `libcurl`.  Configured webhook actions are no-ops.
The HTTP API is also compiled out: the binary does not link `libmicrohttpd` or
its transitive `libgnutls` dependency and never opens an API listener.

Both runners default to a conservative envelope above the measured 16.3 MiB
peak RSS of the tested SOCKS5 request:

- 40 MiB systemd soft pressure point or 32 MiB Podman reservation,
- 48 MiB hard memory limit,
- 25% of one CPU,
- 64 tasks (processes plus threads),
- four-hour maximum runtime,
- no automatic restart.

Tenant IDs are restricted to alphanumeric, dot, underscore and dash
characters and are never evaluated as shell input.

Generate a concrete config from the common config without maintaining three
large copies:

```sh
tools/mem-constrained/render-profile.py socks etc/smithproxy.cfg /srv/smithproxy/tenant-123/smithproxy.cfg
tools/mem-constrained/render-profile.py tproxy etc/smithproxy.cfg /srv/smithproxy/tenant-456/smithproxy.cfg
```

The TPROXY profile is intentionally TCP/plaintext-only at this stage. TLS,
UDP and DTLS listeners remain disabled and can later become separate measured
overlays instead of silently increasing every small instance.

## SOCKS: direct systemd runner

The host service manager runs the local binary as a transient service.  The
configured service account must be able to read the config and referenced
certificates and write to any log/data paths named by the config.  The native
SOCKS listener binds according to Smithproxy's listener behavior; protect port
1080 with the host firewall or put the service in a dedicated network namespace
before exposing this runner to untrusted tenants.  Concurrent direct-systemd
instances must receive generated configs with distinct `settings.socks_port`
values.  API and CLI listeners are disabled in the mem-constrained profile, so
they do not introduce additional host-port collisions.

```sh
sudo tools/mem-constrained/systemd-runner.sh start tenant-123 /srv/smithproxy/tenant-123/smithproxy.cfg /usr/bin/smithproxy
sudo tools/mem-constrained/systemd-runner.sh inspect tenant-123
sudo tools/mem-constrained/systemd-runner.sh logs tenant-123
sudo tools/mem-constrained/systemd-runner.sh stop tenant-123
```

The host systemd applies cgroup limits and owns timeout/cleanup.  Smithproxy
does not need systemd inside its process environment.

## SOCKS: Podman runner

The container image must contain `/usr/bin/smithproxy`.  The configuration
directory is mounted read-only at `/config`; runtime state is stored only in
size-limited tmpfs mounts and disappears with the container.  The supplied
config should refer to certificates below `/config`, use `/var/smithproxy` or
`/var/log/smithproxy` for disposable writes, and keep SOCKS on port 1080.

```sh
sudo tools/mem-constrained/podman-runner.sh start tenant-123 /srv/smithproxy/tenant-123 18080 localhost/smithproxy:mem-constrained
sudo tools/mem-constrained/podman-runner.sh inspect tenant-123
sudo tools/mem-constrained/podman-runner.sh logs tenant-123
sudo tools/mem-constrained/podman-runner.sh stop tenant-123
```

The SOCKS5 port is bound to host loopback only.  A frontend can connect to
`127.0.0.1:HOST_PORT` or explicitly publish it through its own controlled
listener.  For example, `curl --socks5-hostname 127.0.0.1:18080 URL` uses the
example above.  Podman's `--timeout` enforces the maximum runtime; systemd is
not required inside the container.

## Safe preview

Both scripts support `--dry-run`.  It validates identifiers and paths, then
prints the exact command without changing host state:

```sh
tools/mem-constrained/systemd-runner.sh --dry-run start demo ./etc/smithproxy.cfg ./build-merged/smithproxy
tools/mem-constrained/podman-runner.sh --dry-run start demo ./etc 18080 example/smithproxy:test
tools/mem-constrained/tproxy-netns-runner.sh --dry-run start demo ./etc/smithproxy.cfg \
    ./tools/mem-constrained/tproxy-network.example tenant-in tenant-out ./build-merged/smithproxy
```

The web application should not execute these scripts directly with arbitrary
arguments.  Put a narrow privileged broker in front of them, allocate tenant
IDs and ports server-side, and allow only start/stop/status operations.

## TPROXY: systemd + network namespace

The TPROXY runner owns two dedicated, initially unconfigured interfaces for
the lifetime of the transient unit:

```text
client/router -- IN_IF -- [tenant netns: nft TPROXY -> Smithproxy] -- OUT_IF -- gateway
```

Copy `tproxy-network.example` to a root-owned file, fill in the three addresses,
and make it non-writable by group/others.  This is trusted administrative input
because the runner sources it.  The Smithproxy config and its certificate/log
paths must be readable/writable by the configured service account.

```sh
sudo tools/mem-constrained/tproxy-netns-runner.sh start tenant-456 \
    /srv/smithproxy/tenant-456/smithproxy.cfg \
    /etc/smithproxy/tenant-456.network tenant-in tenant-out /usr/bin/smithproxy
sudo tools/mem-constrained/tproxy-netns-runner.sh inspect tenant-456
sudo tools/mem-constrained/tproxy-netns-runner.sh stop tenant-456
```

Only the tenant namespace receives the policy route and nftables table; host
routing/firewall rules are untouched.  The supervisor requires root to create
and clean the namespace, while Smithproxy itself is launched as the configured
unprivileged user.  On normal stop or timeout both interfaces are flushed,
brought down and returned to the host.  Unexpected host power loss may require
manual namespace cleanup, so a production broker should reconcile stale
`sx-mc-*` namespaces before reusing interfaces.

## Integration tests

The patch runner has a dedicated no-TPROXY SOCKS test:

```sh
tests/patch-runner/test-patch.sh sanity --suite socks
```

It starts an isolated origin and the SOCKS-only profile, then performs a real
HTTP request through `curl --socks5-hostname 127.0.0.1:1080`.  The test verifies
that the origin sees the proxy-side address and that all namespaces/listeners
are removed afterward.

The minimal transparent path has a separate test:

```sh
tests/patch-runner/test-patch.sh sanity --suite tproxy
```

It verifies original-destination transparent HTTP, confirms the API is absent,
then stops Smithproxy and proves that forwarding cannot bypass the proxy.
