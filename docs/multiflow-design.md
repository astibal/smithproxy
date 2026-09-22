# Multiflow proxy design

Status: initial design spike  
Target branch: `mf-quic`

## Goal

Add a transport-neutral representation of multiplexed connections without making
QUIC, HTTP/3 or another multiplexed protocol a special case in `baseProxy`.

The first target is QUIC with HTTP/3. The same layer should also be usable for
HTTP/2 and other protocols which carry multiple independently controlled byte
flows over one physical connection.

## Existing ownership model

The current model has two different `Com` roles:

```text
baseProxy --non-owning--> baseCom (poll root / worker template)

baseHostCX --unique_ptr--> baseCom (one endpoint)
     |
     +-- fds_ identifies the endpoint in baseCom operations
```

Important properties which the multiflow design must preserve:

- `baseHostCX` destroys its `baseCom` and closes its endpoint.
- `baseCom::replicate()` creates the object assigned to a new `baseHostCX`.
- readiness is currently expressed using an integer socket or pseudo-socket.
- `baseProxy` expects two endpoint contexts and byte-oriented reads and writes.
- UDP already uses virtual negative descriptors, but its global datagram pool is
  not a suitable ownership model for multiplexed connections.

Sharing one `baseCom` instance between multiple `baseHostCX` objects would
conflict with the current `unique_ptr` ownership and cleanup semantics.

## Proposed object model

```text
                             owns
MFReactor / worker  ----------------------> MFTransport
                                                 |
                      owns active flows          | protocol engine
                    +----------------------------+ QUIC connection
                    |                            | HTTP/2 connection
                    v                            |
              MFConnection                      v
              +---------------------> MFStreamState [flow id 4]
              +---------------------> MFStreamState [flow id 8]
              +---------------------> MFStreamState [flow id 12]
                    ^                           ^
                    | weak_ptr                  | weak_ptr
                    |                           |
baseHostCX --owns--> MFFlowCom          baseHostCX --owns--> MFFlowCom
                       flow id 4                              flow id 8
```

There are three distinct responsibilities:

1. **`MFTransport`** owns physical I/O and the protocol library connection.
2. **`MFConnection`** owns stream state, scheduling and connection-wide limits.
3. **`MFFlowCom`** is a per-flow compatibility adapter owned by `baseHostCX`.

`MFFlowCom` must never own the connection. It holds a `weak_ptr` to
`MFConnection` and a stable flow identifier. Destruction of a flow adapter may
close or detach only that flow, never the physical connection.

## Core types

Names and signatures are provisional. They describe the contract, not the
first implementation verbatim.

```cpp
using MFConnectionId = std::uint64_t; // internal stable id, not QUIC CID
using MFFlowId = std::uint64_t;

enum class MFFlowKind {
    application,
    control,
    protocol_internal
};

enum class MFFlowDirection {
    bidirectional,
    send_only,
    receive_only
};

enum class MFEventType {
    flow_open,
    readable,
    writable,
    peer_fin,
    reset,
    connection_close
};

struct MFFlowHandle {
    std::weak_ptr<MFConnection> connection;
    MFFlowId id;
    std::uint64_t generation;
};
```

The generation prevents a stale adapter from addressing a reused internal flow
slot. QUIC stream IDs themselves are not reused, but the generic layer should
not depend on that property.

### `MFTransport`

```cpp
class MFTransport {
public:
    virtual ~MFTransport() = default;

    // Called by the owning worker after physical readiness/timer events.
    virtual void process_io(std::uint32_t events) = 0;
    virtual void process_timeout() = 0;

    // Flush protocol output to the physical transport.
    virtual void flush() = 0;
    virtual int native_fd() const = 0;
};
```

QUIC packet parsing, ACK handling, loss recovery, congestion control and QUIC
connection IDs stay below this interface.

### `MFConnection`

```cpp
class MFConnection : public std::enable_shared_from_this<MFConnection> {
public:
    virtual ~MFConnection() = default;

    virtual std::shared_ptr<MFFlowState> open_flow(MFFlowDirection) = 0;
    virtual std::shared_ptr<MFFlowState> find_flow(MFFlowId) = 0;

    virtual ssize_t read(MFFlowHandle, void*, std::size_t) = 0;
    virtual ssize_t write(MFFlowHandle, const void*, std::size_t) = 0;
    virtual void finish(MFFlowHandle) = 0;
    virtual void reset(MFFlowHandle, std::uint64_t error) = 0;

    virtual bool readable(MFFlowHandle) const = 0;
    virtual bool writable(MFFlowHandle) const = 0;
};
```

The connection owns `MFFlowState`. The state contains receive/send queues,
FIN/reset state, protocol credit and watermarks. It does not contain policy or
HTTP-specific data.

### `MFFlowCom`

`MFFlowCom` derives from `baseCom`, but represents one logical byte flow rather
than a socket:

```cpp
class MFFlowCom : public baseCom {
public:
    MFFlowCom(std::shared_ptr<MFConnection>, MFFlowHandle);

    baseCom* replicate() override;
    ssize_t read(int token, void*, size_t, int flags) override;
    ssize_t peek(int token, void*, size_t, int flags) override;
    ssize_t write(int token, const void*, size_t, int flags) override;
    void shutdown(int token) override;
    void close(int token) override;

    bool readable(int token) override;
    bool writable(int token) override;
    int translate_socket(int token) const override;

private:
    MFFlowHandle flow_;
};
```

The integer accepted by inherited methods is an opaque local token. It is not a
native file descriptor and must never reach `close(2)`, `fcntl(2)` or epoll.
The initial implementation may encode it as a negative value for compatibility,
but new multiflow code must use `MFFlowHandle` internally.

`replicate()` cannot create an unattached arbitrary flow. It returns a factory
adapter tied to the same connection; the caller must attach a concrete flow
before I/O. A later cleanup should replace this ambiguous operation with an
explicit endpoint factory.

## Event and readiness model

Only the physical transport is registered in epoll. Logical flows are scheduled
from an in-memory ready queue:

```text
epoll: UDP socket readable
          |
          v
QUICTransport::process_io()
          |
          +-- stream 4 readable ----+
          +-- stream 8 writable ----+--> MFReadyQueue
          +-- stream 12 reset ------+
                                           |
                                           v
                                    BaseMFProxy::drain_events()
```

One readiness transition adds at most one queue entry for `(connection, flow,
event class)`. This avoids an unbounded event queue when an application does not
consume a readable stream.

`MFFlowCom::readable()` and `writable()` query flow state. They do not poll the
physical descriptor.

### Writable definition

A flow is writable only when all relevant limits allow progress:

```text
local send queue below high watermark
AND stream flow-control credit
AND connection flow-control credit
AND transport is not closing
```

Congestion-window exhaustion alone should not necessarily make application
writes fail. A bounded local send queue absorbs short stalls. Once its high
watermark is reached, `write()` returns `-1/EAGAIN` and the peer-side proxy read
is paused. Falling below the low watermark produces one writable event.

## `BaseMFProxy`

`BaseMFProxy` coordinates connections and creates one ordinary proxy child for
each application flow. It should not itself copy application bytes.

```text
BaseMFProxy (connection scope)
    |
    +-- protocol/internal flows: handled by transport adapter
    |
    +-- application flow opened
           |
           +-- left MFFlowCom + HostCX
           +-- policy decision
           +-- right MFFlowCom + HostCX
           +-- child flow proxy / inspector chain
```

This preserves the existing filtering and buffering path per application flow.
Connection-wide metadata is shared read-only with child flows; request and
inspection state remains per flow.

The initial design should use composition instead of deriving all connection
logic from `baseProxy`. A small `BaseMFProxy` connection coordinator can create
normal flow proxy instances. Inheriting directly from `baseProxy` would expose
socket-list assumptions which do not represent the physical connection.

## Flow pairing

Flow IDs are local to one side and must not be assumed equal:

```cpp
struct MFPair {
    MFFlowHandle left;
    MFFlowHandle right;
    std::unique_ptr<baseProxy> proxy;
};

std::unordered_map<MFFlowId, std::shared_ptr<MFPair>> left_index;
std::unordered_map<MFFlowId, std::weak_ptr<MFPair>> right_index;
```

Opening the upstream flow can be delayed until policy has accepted enough
metadata. A reset before pairing is valid and must not create an upstream flow.

## Closing rules

Half-close, reset and connection close are different events:

| Input event | Local action | Peer action |
|---|---|---|
| peer FIN | mark receive EOF | send FIN after buffered data |
| local graceful close | reject new writes | send FIN after queue drains |
| peer RESET | discard receive side as configured | reset paired flow |
| policy block | mark flow blocked | protocol-specific reset/error |
| connection close | invalidate all handles | terminate every paired flow |

Destroying `MFFlowCom` performs an idempotent detach. It must not synchronously
destroy `MFConnection`, invoke callbacks on a partially destroyed `HostCX`, or
close the physical descriptor.

## Threading

Version 1 uses strict worker affinity:

- a physical connection and all its flows live on one worker thread;
- protocol-library calls happen only on that thread;
- policy results from other threads return as queued commands;
- flow adapters contain no independent mutexes in the normal data path.

Cross-worker stream distribution is explicitly deferred. It adds ordering,
ownership and transport-callback problems without helping the initial QUIC
implementation.

## Protocol adapters

```text
MFTransport / MFConnection
    |
    +-- QuicConnectionAdapter
    |      +-- application streams exposed as MFFlowCom
    |      +-- crypto/control streams remain private
    |
    +-- Http2ConnectionAdapter
           +-- DATA exposed as byte flow
           +-- frame/control state remains private
```

For HTTP/3, not every QUIC stream is an application flow. QUIC crypto streams,
HTTP/3 control streams and QPACK encoder/decoder streams remain internal to the
adapter. Only request streams cross into policy and inspection code.

## Error representation

Do not overload `errno` as the canonical error model. The multiflow core uses a
typed error and `MFFlowCom` maps it to legacy return values:

```cpp
struct MFError {
    enum class Scope { flow, connection, transport } scope;
    enum class Reason { reset, refused, timeout, protocol, internal } reason;
    std::uint64_t protocol_code;
};
```

This retains QUIC/H3 error codes for diagnostics while allowing legacy proxy
code to observe `EAGAIN`, `ECONNRESET` or EOF.

## Observability

Every log/session record should carry:

```text
internal connection id
transport protocol and version
local flow id / peer flow id
flow kind and direction
connection and flow close codes
SNI and ALPN where available
```

Raw QUIC connection IDs are protocol metadata. They must not be used as object
addresses or stable database primary keys because peers can rotate them.

## Prototype plan

The architecture should be validated without a QUIC dependency first.

### Phase 1: fake multiflow transport

Implement an in-memory `FakeMFConnection` with:

- multiple bidirectional flows;
- independent FIN and RESET;
- connection close;
- send/receive watermarks and `EAGAIN`;
- deterministic ready queue.

Tests must verify that destroying one `HostCX/MFFlowCom` does not affect sibling
flows or close the connection.

### Phase 2: flow proxy bridge

Create `BaseMFProxy` and pass fake application flows through the existing
`baseHostCX` buffering and filter path. Validate backpressure in both directions.

### Phase 3: QUIC transport

Attach a QUIC library below the proven interface. Initially expose metadata and
echo flows, then add upstream pairing and HTTP/3 request streams.

## Decisions made by this spike

1. One physical connection is **not** represented by one shared `baseCom` in
   several `baseHostCX` instances.
2. Each exposed application flow gets its own `MFFlowCom`, owned by its
   `baseHostCX` exactly as today.
3. Physical I/O and protocol state live in a shared connection object outside
   the `baseCom` ownership tree.
4. Only the physical descriptor is placed in epoll; logical readiness uses a
   deduplicated queue.
5. The first version keeps every connection and all its flows on one worker.
6. Control/protocol streams are not exposed as application proxy flows.

## Open questions

1. Should a flow use a small child `baseProxy`, or should the byte-pump portion
   of `baseProxy` first be extracted into a reusable `FlowProxy`?
2. Can `MFFlowCom` safely implement every inherited socket operation as an
   unsupported operation, or should `baseCom` be split into byte-channel and
   socket-management interfaces first?
3. Which layer owns upstream connection pooling and QUIC connection reuse?
4. At which event is policy evaluated: QUIC handshake, HTTP/3 headers, or both?
5. Is HTTP/3 inspection initially metadata-only, or must request bodies pass
   through existing content filters in the first milestone?

The first two questions should be answered by the fake-transport prototype,
before selecting or integrating a QUIC library.
