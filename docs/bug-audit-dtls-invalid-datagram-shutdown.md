# Bug Audit: DTLS invalid datagram blocks shutdown

## Observation

During the routed TPROXY profile test, one arbitrary UDP payload sent to
destination port 443 was delivered by nftables to the active transparent DTLS
listener on port 50443.  Functional TCP, TLS and UDP checks completed, but
Smithproxy did not terminate during runner cleanup and the isolated test
container had to be stopped externally.

## Reproduction conditions

- mem-constrained binary at `fa82f9c` plus the uncommitted routed-listener
  profile work later committed with this case;
- `accept_tproxy=TRUE`, `dtls_workers=1`;
- policy route `fwmark 1 -> local table 100`;
- nftables `udp dport 443 tproxy to :50443`;
- send a non-DTLS UDP payload to a routed destination on port 443;
- request normal Smithproxy/runner termination.

The same full routed-listener test shuts down cleanly when no malformed DTLS
payload is injected.

## Impact and follow-up

This can delay or prevent cleanup of an on-demand TPROXY instance after
malformed traffic reaches the DTLS listener.  It is not required to implement
the profile wiring itself, but must be investigated before claiming robust
DTLS service.  A focused task should add a bounded shutdown regression test,
locate the blocked receiver/worker and ensure malformed input cannot prevent
termination.
