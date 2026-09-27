# On-demand mem-constrained runners

These runners start one short-lived Smithproxy instance per tenant without
Kubernetes.  The mem-constrained profile exposes a SOCKS5 interface on port
1080 and intentionally does not configure TPROXY, routes or nftables.

Both runners default to the measured initial envelope:

- 40 MiB systemd soft pressure point or 32 MiB Podman reservation,
- 48 MiB hard memory limit,
- 25% of one CPU,
- 64 tasks (processes plus threads),
- four-hour maximum runtime,
- no automatic restart.

Tenant IDs are restricted to 1-63 alphanumeric, dot, underscore and dash
characters and are never evaluated as shell input.

## Direct systemd runner

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

## Podman runner

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
```

The web application should not execute these scripts directly with arbitrary
arguments.  Put a narrow privileged broker in front of them, allocate tenant
IDs and ports server-side, and allow only start/stop/status operations.

## Integration test

The patch runner has a dedicated no-TPROXY SOCKS test:

```sh
tests/patch-runner/test-patch.sh sanity --suite socks
```

It starts an isolated origin and the SOCKS-only profile, then performs a real
HTTP request through `curl --socks5-hostname 127.0.0.1:1080`.  The test verifies
that the origin sees the proxy-side address and that all namespaces/listeners
are removed afterward.
