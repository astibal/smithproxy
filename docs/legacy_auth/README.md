# Legacy captive-auth backup

This directory preserves a mechanical rollback of the removed Python-era
captive authentication backend. The backend exchanged login tokens and IPv4/
IPv6 identity tables through POSIX shared memory and named semaphores.

The backend was removed because its Python 2 authentication portal is obsolete
and the login tables have not been used for years. Keeping them in the proxy
flow added filesystem semaphore operations and other system calls without a
current consumer. Shared memory was a reasonable design for the original
deployment, but is unnecessary complexity for the current product. A future
identity implementation should use a simpler interface without filesystem
semaphores rather than revive this runtime path.

Baseline revisions:

- Smithproxy: `e6b70c83f532409049c01ed4c0926711cb9a44ee`
- Socle: `fdf7998013bc156fd977e2e989fb7b128c635c35`

The patches are intentionally split at the submodule boundary. Apply them to
the removal revision from the Smithproxy checkout root:

```sh
git apply docs/legacy_auth/restore-smithproxy.patch
git -C socle apply ../docs/legacy_auth/restore-socle.patch
```

Both patches were generated in reverse from the removal working tree and
validated with `git apply --check`. They restore source/configuration content;
they do not create commits or move the Socle parent pointer.

The TLS certificate historically named `portal-cert.pem` is not part of the
removal because the current HTTPS API still consumes it. Renaming that shared
certificate is a separate migration.
