# Event trail: initial implementation

Selected code paths emit freeform structured observations through
`logan::event(Event)`. This API is independent of log thresholds and does not
write another ordinary log line. There is no JSON or delivery code in Socle.

`logan_events::EventScope` owns a bounded trail and installs it as the active
thread-local trail. On exit (including early return and exception unwinding):

1. Detach and take the trail.
2. Invoke the supplied enrichment lambda with `EventContext&` and
   `const EventBatch&`. Captures must remain alive until scope exit.
3. Pass the owned enriched batch to `EventCollector`.
4. Restore the previous active trail, if nested.

Enrichment-generated observations are ignored, so they cannot contaminate
this batch or an outer scope. Observations without an active scope are ignored.
Scopes must remain on their creating thread and obey normal lexical LIFO
lifetime. The collector is worker-owned, not a concurrent queue. Take/clear
is one owner-thread operation; it does not promise cross-thread atomic access.

The trail retains the latest 64 events, with at most 1024 bytes each for
message and local context. It counts overwritten events. Enriched context
uses up to 16 key/value fields (128/1024 bytes). No fixed endpoint or side
schema is imposed. Limits are byte limits, not Unicode character boundaries.

The collector keeps up to 1024 pending entries. Repeatable events with equal
message, context, level, kind and enriched context merge across scopes;
individual events remain separate. Merged entries carry occurrence count and
first/last observation times using a monotonic clock. Full-collector drops are
counted. An enrichment/collection exception increments the loss indicator
(the exact number of lost observations is not available in that case).

## Phase 1: coexistence with CLI history

The existing `logan_lite::event(level, format, ...)`, `event_detail()` and
`event_block()` interfaces remain available. Administrative/configuration
producers and non-migrated connection events retain their behavior. The new
`logan::event(Event)` returns whether an active scope accepted the observation;
a migrated producer can preserve legacy fallback outside instrumented scopes.

MasterProxy wraps each live child's socket-processing call in EventScope.
The enrichment lambda supplies a worker-local connection sequence, then calls
`baseProxy::enrich_event_context()`. The default supplies the final proxy text;
MitmProxy adds its session ID and, for TLS fatal alerts, upstream TLS diagnostic
details. Certificate diagnostics are computed at scope exit, not by walking
peer pointers in the scoped TLS callback. Details are owned and capped at 16 KiB.
Connection context survives child destruction. TLS objects already removed by
processing cannot supply additional diagnostics; the local alert is retained.

The fatal TLS alert producer now selects exactly one reporting path: scoped
when available, legacy otherwise. Both respect `suppress_all` and suppression
of operational decode errors. Normal close notifications do not emit events.
Existing ordinary diagnostic logs remain unchanged. Terminal asynchronous TCP
connect errors are the other initial scoped producer.

The collector merges repeated messages with equal context and keeps the latest
enriched diagnostic detail. `Events::publish()` adapts completed deliveries to
the existing bounded history: one summary (including repetition count) plus
human-readable detail per aggregated observation. `show event list` and
`show event detail` work unchanged, as does `execute events clear`. Clearing
history does not cancel pending observations, which can appear on a later flush.
Legacy and scoped producers share an atomic event-ID allocator. Publishing a
scoped delivery does not inherit an unrelated legacy event_block ID.

## Polling and delivery

MasterProxy checks `take_due()` from its existing socket/timer loop, approximately
every five seconds, and publishes the delivery into CLI history. No new timer
or thread is created. Child closure leaves pending owned records in the master
collector; master shutdown drains the remainder into history. An empty collector
produces no delivery. Timer and teardown producers remain legacy in phase 1.

The history sink is wired; webhook subscriptions and transport are not. A future
webhook sink must consume the same owned delivery, not drain CLI history or race
the existing history sink for collector contents. Cross-connection suppression
and asynchronous network delivery remain follow-up work. Collector state and
CLI history are in-memory, not durable.

## Phase 2 (not implemented)

Migrate remaining legacy producers to structured writes as appropriate, retaining
non-proxy administrative events and their history. This is not an automatic
conversion of every existing log.event call.

## Verification

`event_trail_tests`, `event_history_tests`, and `event_tls_tests` are CMake
targets, registered as CTest `unit.event_trail`, `unit.event_history`, and
`unit.event_tls`. The latter two cover legacy/scoped coexistence, detail
retention, concurrent IDs, history eviction/clear, TLS suppression and fallback.
It checks final-state enrichment, repeated and individual events, nested scopes,
early returns, exceptions, thread isolation, ring wrap, text limits, collector
capacity, and polling-based draining. It can also be built directly:

```sh
c++ -std=c++17 -pthread -I socle/common socle/tests/event_trail_tests.cpp \
    -o /tmp/event-trail-tests
/tmp/event-trail-tests
```
