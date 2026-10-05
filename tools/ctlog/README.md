# sx_ctlog

`sx_ctlog` builds the OpenSSL `ct_log_list.cnf` consumed by Smithproxy.

## Trust model

```text
Apple CT policy ─┐
                 ├─ C++ publisher ─ policy filter ─ Smithproxy signature
Cloudflare Radar ┘                                      │
                                                       GitHub
                                                         │
embedded Smithproxy public key ─ C++ updater ─ OpenSSL ct_log_list.cnf
```

Apple provides keys and the authoritative policy state. Cloudflare Radar
independently corroborates log URL and API type. The publisher fails closed on
an identity discrepancy. Lifecycle state differences are retained as audit
warnings because Apple and Cloudflare apply separate CT policies and may update
at different times. The publisher retains only Apple's `qualified`, `usable`,
`readonly` and `retired` logs, and excludes `pending`, `rejected` and unknown
states.

The Smithproxy RSA-3072 signature does not claim that either upstream is
infallible. It authenticates the exact policy result selected by Smithproxy, so
GitHub and intermediate caches can be treated as untrusted transport. The
private key exists only on the publisher; clients receive a pinned public key.

## Local publisher

The complete local build, test, publish and signature verification can be run
with one command:

```sh
./tools/ctlog/publish-local.sh
```

It uses the signing key and Cloudflare token from
`~/.config/smithproxy/ctlog/` and writes the result to
`/tmp/smithproxy-ct-publish`. These paths can be overridden with
`CTLOG_SIGNING_KEY`, `CTLOG_CLOUDFLARE_TOKEN_FILE` and `CTLOG_OUTPUT_DIR`.

Set a read-only Cloudflare Radar API token without putting it on the command
line, then run:

```sh
export CLOUDFLARE_API_TOKEN='...'

sx_ctlog publish \
  --apple-url https://valid.apple.com/ct/log_list/current_log_list.json \
  --cloudflare-url https://api.cloudflare.com/client/v4/radar/ct/logs \
  --signer-key ~/.config/smithproxy/ctlog/signing-key.pem \
  --output-dir ./publish
```

Alternatively use `--cloudflare-token-file FILE`. The output directory gets:

```text
log_list.json       normalized Smithproxy policy
log_list.sig        detached RSA/SHA-256 signature
ct_log_list.cnf     OpenSSL-compatible list
policy-report.json  provenance, hashes, state counts and cross-check result
```

The GitHub workflow runs this same C++ publisher and uploads those files to a
stable `ctlog-latest` release. It needs `CTLOG_SIGNING_KEY_B64` and
`CLOUDFLARE_API_TOKEN` repository secrets.

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
ctest --test-dir build-ctlog --output-on-failure
```

OpenSSL's CONF format stores only descriptions and verification keys. It does
not retain operator identity, log state or temporal intervals, so this enables
SCT signature validation rather than implementing a browser CT policy.
