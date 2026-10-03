# Bug audit

This file records product defects found while expanding test coverage. Each
entry names the failure mode, impact, correction and regression evidence so a
coverage increase remains reviewable as more than a percentage change.

| ID | Area | Finding and impact | Correction | Regression evidence |
| --- | --- | --- | --- | --- |
| PXM-001 | Proxy connect | A failed upstream `connect()` returned a negative descriptor, but the proxy registered it with the event loop and reported success. This could leave a half-created flow with invalid handlers. | Reject non-positive descriptors before monitor/handler registration and ownership transfer. | `ProxyMakerUtils.RejectsFailedUpstreamBeforeRegisteringHandlers` |
| PXM-002 | Proxy ownership | `route_existing()` temporarily adopted a caller-owned raw pointer in a `unique_ptr`. An exception while routing could delete an object still owned by the caller. | Route through a non-owning overload; the owning overload delegates with `get()`. | Production build plus the focused ProxyMaker ownership tests exercise the shared route/connect helper boundary. |
| PXM-003 | Policy routing | Failure to select or apply a configured routing target was logged but policy processing continued toward the original destination. That made a routing failure fail open. | Propagate routing failure from `policy()` and abort proxy creation. | Full native suite; routing errors now have an explicit false return path. |
| PXM-004 | UDP accept | The accepted UDP context was transferred into a child proxy before source-address resolution. On resolution failure the context was manually deleted, then deleted again when the child proxy unwound. | Resolve the source before transferring ownership to the child proxy. | ASan build and native/dataplane lifecycle runs; ownership is transferred only after the failing operation. |
| PXM-005 | Transparent source | `std::stoi` accepted trailing bytes and negative values, which could wrap into an `unsigned short` source port. | Parse the complete decimal field with `from_chars` and accept only `1..65535`. | `ProxyMakerUtils.ParsesOnlyCompleteValidSourcePorts` |
| PXM-006 | Proxy setup | Proxy policy/connect helpers dereferenced missing contexts or transports on partially constructed flows. | Validate the proxy, both contexts and their communication objects before policy/connect work. | `ProxyMakerUtils.RejectsFailedUpstreamBeforeRegisteringHandlers` and full native suite. |
