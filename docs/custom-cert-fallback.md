# External custom server certificates

Custom server identities normally live in CFtar. An optional read-only directory
can supply identities that are absent from the archive:

```
settings.custom_cert_fallback_dir = "/var/lib/smithproxy/custom-certs";
```

The default is an empty string, which disables external lookup. The path must be
absolute and outside `/etc/smithproxy`, including after resolving symlinks: the
managed directory may be retired during native configuration migration.

```
custom-certs/
  sni/example.test/fullchain.pem
  sni/example.test/key.pem
  ip/192.0.2.1/cert.pem
  ip/192.0.2.1/key.pem
  ip/192.0.2.1/issuer.pem
```

Both the fullchain/key and cert/key with optional issuer.pem, issuer2.pem,
issuer3.pem layouts are supported. Existing SNI/IP profile switches also apply
to the fallback. Externally supplied server identities satisfy `only_custom_certs`.

The order is primary SNI, primary IP, external SNI, external IP. A matching but
invalid primary identity blocks the external fallback; it must be repaired or
explicitly removed. Identities already imported into CFtar retain priority after
an external renewal. Remove them from the archive if they should be maintained
exclusively in the external directory.

This setting never supplies a CA, trust bundle, default identity, API certificate
or outbound client certificate. It does not import, rewrite or delete external
files. Missing external directories are not created. The process loading the
certificates must have filesystem access, including when `--run-as` is used.

After replacing the certificate and key together, use the existing authenticated
`/api/do/ssl/custom/reload` operation to refresh the custom identity cache. There
is no filesystem watcher. Reload drops removed identities and clears cached TLS
sessions; established connections are not renegotiated. Publish a consistent
certificate/key pair before requesting reload. An invalid external identity is
not used. Configuration changes to the directory require configuration reload
before the custom-certificate reload.

Schema 1052 preserves this optional path in both legacy and native configuration.
The directory remains host-local state and is not included in CFtar backups.

## Verification

Build `custom_cert_fallback_tests`, `smithproxy`, `smithproxy-default-cftar` and
`sx_gtests` with a Debug configuration. On an isolated test host run:

```
tests/custom-certs/run.sh --build-dir /path/to/build
```

The runner supports `--suite unit|process|regression` and sections
`selection|paths|migration|tls`. Process and regression tests use a private
network namespace and require root. `SMITHPROXY_COVERAGE=ON` enables gcov data.
