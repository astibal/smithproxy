# sx_ctlog

`sx_ctlog` builds the OpenSSL `ct_log_list.cnf` consumed by Smithproxy.

## Signed automatic update

```sh
sx_ctlog update \
  --url https://publisher.example/log_list.json \
  --signature-url https://publisher.example/log_list.sig \
  --signer-key /etc/smithproxy/ct-log-list-signer.pem \
  --cache-dir /var/cache/smithproxy/ctlog \
  --output /etc/smithproxy/ct_log_list.cnf
```

The signer key is deliberately local and pinned. Downloading it together with
the list would make signature verification meaningless. The updater:

1. downloads JSON and its detached RSA/SHA-256 signature;
2. retries a mismatched or failed pair (default: three attempts);
3. verifies the signature with the pinned public key;
4. rejects lists older than 70 days or dated more than 24 hours ahead;
5. validates every DER SubjectPublicKeyInfo and `log_id == SHA-256(key)`;
6. rejects duplicate log IDs;
7. makes OpenSSL load the generated CONF before atomically replacing output;
8. caches only a fully verified JSON/signature pair;
9. uses the still-fresh, reverified cache when the publisher is unavailable.

Policy options:

```text
--max-age-days N  freshness limit (default 70)
--retries N       download attempts, 1..20 (default 3)
--exclude-tiled   omit tiled/static CT API entries
```

Source selection is intentionally explicit. Chrome asks third-party
CT-enforcing applications not to fetch or rely on Chrome's own log list and
signing key.

## Offline conversion

For an already authenticated/local input:

```sh
sx_ctlog convert log_list.json ct_log_list.cnf
```

This performs the key, ID, duplicate and OpenSSL checks, but cannot authenticate
the JSON document itself.

## Build

The main Smithproxy build produces and installs `sx_ctlog`. Standalone build:

```sh
cmake -S tools/ctlog -B build-ctlog
cmake --build build-ctlog
```

OpenSSL's CONF format stores only descriptions and verification keys. It does
not retain operator identity, log state or temporal intervals, so this enables
SCT signature validation rather than implementing a browser CT policy.
