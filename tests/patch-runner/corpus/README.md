# Deterministic pplay corpus

The corpus defines bounded client/server byte streams that should cross
Smithproxy without payload modification. Pplay verifies that both endpoints
receive exactly the scripted bytes.

```text
regular/   valid representative protocol traffic
edge/      valid or nearly valid boundary conditions
insanity/  deliberately malformed but bounded inputs
```

## Inventory

`run-suite.sh all` currently selects 685 cases per address family:

| Source | Regular | Edge | Insanity | Total |
|---|---:|---:|---:|---:|
| Committed fixture files | 51 | 48 | 56 | 155 |
| `_generated_case.py` parameter sets | 134 | 133 | 133 | 400 |
| Generated HTTP/2 cases | 40 | 30 | 30 | 100 |
| Capture matrix cases | 12 | 10 | 8 | 30 |
| **Total** | **237** | **221** | **227** | **685** |

The full patch runner executes 655 ordinary corpus cases per family and sends
the 30 `capture_*` cases to its dedicated capture section. Thus all 685 remain
covered without recording the capture flows twice.

Coverage includes HTTP/1 framing and ambiguity, cleartext HTTP/2 and HPACK, DNS
over TCP and UDP, SMTP, IMAP, POP3, FTP, Redis, MQTT, SOCKS, SSH, WebSocket,
Memcached, PostgreSQL, MySQL, AMQP, Telnet, TLS-like records, NTP, syslog, STUN,
TFTP, SNMP, QUIC-like datagrams and protocol-neutral streams.

Safety limits in `_common.py` cap a conversation at 256 messages and 256 KiB.
The runner handles one case at a time per address-family worker and gives each
pplay process a 15-second death timer.

Explicit fixtures named `udp_*.py`, generated UDP cases and
`capture_udp_*` use datagrams. Other cases use TCP. TCP cases get one attempt;
UDP cases get up to three attempts and report `FLAKY_PASS` when only a retry
succeeds.

## Local self-test

The repository contains the compatible engine at `../vendor/pplay.py`; no
external checkout or patch is required.

```bash
PPLAY_PY=../vendor/pplay.py ./run-suite.sh regular
PPLAY_PY=../vendor/pplay.py ./run-suite.sh all
PPLAY_PY=../vendor/pplay.py MATCH=http2_prior_knowledge ./run-suite.sh regular
PPLAY_PY=../vendor/pplay.py MATCH='h2_generated_*' \
  EXCLUDE='*003,*017' ./run-suite.sh all
```

`MATCH` selects case basenames matching any comma-separated shell glob.
`EXCLUDE` is applied afterwards. Both filters include committed, generated and
capture cases. A direct invocation with no matches is an error. Section workers
use `ALLOW_EMPTY=1` because a global full-run filter may legitimately select
cases from only one category; the parent still fails when all categories are
empty.

Optional deterministic mutation and TCP segmentation:

```bash
PPLAY_PY=../vendor/pplay.py FUZZ_LEVEL=245 FUZZ_MAGIC=smithproxy-001 \
  SCATTER=1 ./run-suite.sh all
```

`FUZZ_MAGIC` is combined with category and case name, so repeated runs are
reproducible. `SCATTER=1` affects TCP writes; it does not fragment UDP.

## Through Smithproxy

The preferred interface is the patch runner:

```bash
../test-patch.sh sanity --suite corpus-regular --remote root@tt-px1
../test-patch.sh full --remote root@tt-px1 --env MATCH='h2_generated_*'
```

For a manually prepared compatible lab, the default namespace names are
`sxr-client` and `sxr-origin`:

```bash
sudo env PPLAY_PY=../vendor/pplay.py MODE=runner ./run-suite.sh all
```

Override `CLIENT_NS`, `SERVER_NS`, `IP_FAMILY`, `SERVER_BIND`,
`CLIENT_TARGET`, `PORT`, or `SOURCE_PORT` when the lab differs. `IP_FAMILY`
accepts `4` or `6`; the default is `4`.

## Results

Each case writes client/server logs below:

```text
<results>/<category>/<case>/
```

Set `RESULTS` to change the root. A case passes only when both sides exit zero,
both reach end-of-transmission, and neither reports different data. The final
line is machine-readable:

```text
family=IPv4 passed=N flaky=N failed=N xfailed=N xpassed=N results=PATH
```

Expected failures come from `expected-failures.txt` by default. Override its
path with `EXPECTED_FAILURES_FILE`. An unexpected failure makes the process
non-zero; XFAIL and `FLAKY_PASS` do not.
