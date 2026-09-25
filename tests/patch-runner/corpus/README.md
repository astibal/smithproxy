# PPlay parser suite

Deterministic client/server byte streams intended to cross Smithproxy without
payload modification. The cases test parser behavior; pplay itself only checks
that both endpoints received the exact expected bytes.

```text
regular/   valid, representative protocol traffic
edge/      valid or nearly valid boundary conditions
insanity/  deliberately malformed but bounded inputs
```

The corpus contains 455 conversations: 151 regular, 148 edge and 156 insanity
cases. They cover HTTP/1 framing and ambiguity, cleartext HTTP/2 frames and HPACK,
DNS over TCP and UDP, SMTP, IMAP, POP3, FTP, Redis, MQTT, SOCKS, SSH banners,
WebSocket, Memcached, PostgreSQL, MySQL, AMQP, Telnet, TLS-like records, NTP,
syslog, STUN, TFTP, SNMP, QUIC-like datagrams and protocol-neutral streams.

Safety limits are enforced by `_common.py`: at most 256 messages and 256 KiB per
conversation. The runner is sequential, uses one connection at a time and gives
each pplay process a 15-second death timer. There are no compression bombs,
unbounded loops, high connection rates or multi-gigabyte payloads.

Files named `udp_*.py` are executed as UDP conversations; all other fixtures use
TCP. UDP cases still use one socket and a small, fixed datagram sequence.

The current pplay master needs `../runner/pplay-python314.patch` on Python 3.14.
For two-ended scripted fuzz replay it also needs
`../runner/pplay-fuzz-server-sync.patch`; without it, the server recreates its
PPlayScript after `accept()` and loses the fuzzed packet expectations.

## Local pplay self-test

```bash
PPLAY_PY=/path/to/pplay.py ./run-suite.sh regular
PPLAY_PY=/path/to/pplay.py ./run-suite.sh all
PPLAY_PY=/path/to/pplay.py MATCH=http2_prior_knowledge ./run-suite.sh regular
PPLAY_PY=/path/to/pplay.py MATCH='h2_generated_*' EXCLUDE='*003,*017' ./run-suite.sh all
```

`MATCH` selects cases matching any of its comma-separated shell globs.
`EXCLUDE` then skips cases matching any of its comma-separated shell globs.
Both filters operate on the case name without its `.py` suffix and include
generated and capture-matrix cases.

The categories also contain 400 parametrically generated, independently reported
cases: the original 100 per category plus 100 extended cases split as 34 regular,
33 edge and 33 insanity.

Another 100 `h2_generated_*` cases exercise HTTP/2 multiplexing, DATA framing,
SETTINGS and control frames, HPACK dynamic-table reuse, CONTINUATION boundaries,
padding, priority, stream teardown and deliberately malformed state transitions.
They are split as 40 regular, 30 edge and 30 insanity cases and can be selected
with `MATCH='h2_generated_*'`. Run the corpus with deterministic byte mutation
and TCP segmentation using:

```bash
PPLAY_PY=/path/to/pplay.py FUZZ_LEVEL=245 FUZZ_MAGIC=smithproxy-001 SCATTER=1 \
  ./run-suite.sh all
```

## Through an already running runner lab

The namespaces `sxr-client` and `sxr-origin` must already exist and Smithproxy
must be between them:

```bash
sudo env PPLAY_PY=/path/to/pplay.py MODE=runner ./run-suite.sh all
```

Or let the existing lab test create the namespaces and keep Smithproxy running
while the complete suite executes:

```bash
sudo env \
  PPLAY_PY=/path/to/pplay.py \
  PPLAY_SUITE=/opt/lab/smithproxy-runner/pplay-suite \
  bash /opt/lab/smithproxy-runner/runner/tests/lab-test.sh
```

Set `PPLAY_SUITE_CATEGORY=regular`, `edge` or `insanity` to run one tier.

Logs are stored under `results/<category>/<case>/`. A case passes only when both
sides exit successfully, both reach end-of-transmission and neither reports a
payload difference.
