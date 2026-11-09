Protocol snapshots and journals: a useful detour <3
==================================================
Retired: 2026-10-26. Historical experiment, NOT a supported runtime API.

What was beautiful
------------------
EngineCtx::protocol_snapshot() captured protocol parsing state. The flow-aware
overload also retained an append/pop journal: popped blocks kept their ownership,
the original tail could be shortened, and positions/counters could be restored.
Repeated restore, rejected nested transactions, expired owners and independent
HPACK tables had dedicated tests. This was a narrow protocol checkpoint, not a
snapshot of inspectors, DNS publication or the entire proxy.

Why it did not stay
-------------------
Rollback cannot reconcile two different wire histories. The sender still uses
its original framing and HPACK state; the receiver sees what the webhook sent.
Replacing the input parser's history with the output history loses information
needed for the next input. Two endpoint-local, bidirectional views are the model.

The intermediate SnapshotFork mode preserved a deep pre-input copy for every
unchanged callback until the first mutation. It worked as an experiment, but
paid for a fork even when the webhook never rewrote anything.

What replaced it
---------------
  connection-start
      Observe: one context, input analysis only
      Rewrite: one forward fork before the first adapted input
          sender view -> webhook -> receiver view

Both views advance forward; neither rewinds. Output analysis has no second
webhook or inspector side effects. The immutable Huffman tree remains shared.
The generic adapter and EngineCtx::protocol_fork() remain live; only the unused
rollback API/journal and speculative SnapshotFork path have been retired.
The same-size unreserved replacement escape hatch is unchanged.

Archive contents and direction
------------------------------
restore-smithproxy.patch: cleaned tree -> previous experimental implementation,
including checkpoint tests, old benchmark and the prior endpoint-view test mode.
It also reverses the later H2-adapter extraction to restore a coherent source tree.
restore-socle.patch: cleaned Socle -> previous append/pop journal.
manifest.json: source heads and before/after SHA-256 identities of affected files.

This is a source archive, not a recommendation to restore the old runtime path.
The patches preserve the actual pre-cleanup working files, not merely committed
HEAD: important setup/rewrite changes were still uncommitted at retirement.
Documentation and this archive are outside the restoration patch, intentionally.
The baseline was Smithproxy d7aaef2 plus working changes and Socle 7651014.
The final live Socle tree is back at decc93f with no local changes. Its restore
patch recreates the experimental 7651014 journal from that original baseline;
no cleanup commit or history rewrite in Socle is required.

Inspect or restore in a disposable COPY of this working tree, never blindly
over a different dirty checkout. Check both patches before applying either:

  git -C socle apply --check ../docs/design-history/protocol-checkpoints-20261026/restore-socle.patch
  git apply --check docs/design-history/protocol-checkpoints-20261026/restore-smithproxy.patch

Then repeat those commands without --check, Socle first. Reconfigure/rebuild;
the restored checkpoint suite is registered as unit.protocol_checkpoint.
Both patches were checked and round-tripped against the archived source bytes
when generated. Later changes can make them conflict; that is not license to
force-apply them. Historical results remain in tests/docs/protocol-*.txt.

Coverage after retirement
-------------------------
Rollback-only tests are archived with their removed implementation. Rewrite,
hold, SETTINGS/ACK, HPACK continuation, mixed traffic, annotations and generic
adapter tests remain live, now using setup-selected Rewrite. Dedicated fork
tests cover independent metadata, decoder ownership, pending state and borrowed
body/compression buffers. Ordinary stream/datagram append/pop remains tested.
See validation.txt for the actual post-cleanup run; no historical count is
silently carried forward as a new test result.
