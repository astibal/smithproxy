# Interface roles and policies

Linux packet-info socket APIs are required. TCP listeners enable IP_PKTINFO and
IPV6_RECVPKTINFO; the accepted connection reads IP_PKTOPTIONS or
IPV6_2292PKTOPTIONS before policy selection, including delayed TLS initialization.
UDP retains the first datagram's interface on its existing flow. No helper daemon
or packet verdict queue is involved. The index is the kernel's logical ingress
at the socket layer, not a promise of the original physical port or first SYN.

```
settings = {
    interfaces = (
        { match = { if_name = "enp2s0"; }; role = "Guest"; },
        { match = { if_address = "10.20.0.0/16"; }; role = "Office"; }
    );
};
```

Rules are ordered: first match wins for each interface. If both selectors are
present, both must match. if_name is an exact system name; if_address is an IP or
CIDR containing at least one assigned interface address, not a traffic selector
or a route to that network. IPv4 and IPv6 are supported. Multiple interfaces may
have the same role. A selector matching no interfaces is valid.

Unmatched loopbacks have role Local; interfaces referenced by unicast default
routes have role Outside; every other interface, including unaddressed devices,
has role Inside. Defaults in all routing tables count, including backup defaults;
this is classification, not a claim that all those routes are selected. Defaults
using RTA_NH_ID nexthop objects are currently unresolved: role metadata becomes
unavailable rather than guessing Inside. Inline multipath defaults are supported. There
are no order-dependent numbered aliases. A custom role replaces the automatic
role. Removing settings.interfaces restores automatic roles. Diagnostics remain
available through `diag sys netlink info`, now including per-interface roles.

Policies accept optional nonempty string selectors `ingress_role` and
`egress_role`. Omission means unrestricted. A non-existent role matches no
interfaces. If an active policy needs interface metadata that cannot be obtained,
selection denies rather than skipping a potential deny rule. Configurations
without role selectors do not require route lookups and retain existing behavior.

Egress means the result of a destination-only kernel RTM_GETROUTE query at policy
selection. Queries use private sockets and a 100 ms whole-exchange deadline; they
run once per destination endpoint per selection, not once per rule. Hostnames
must already have been resolved. IPv4-mapped targets are normalized. Unreachable,
blackhole, prohibited, ambiguous and failed results are unknown, not interface 0.
This does not model custom source/mark/UID/VRF/port-based routing or enforce the
physical path after later routing changes. No NFQUEUE/NFLOG enforcement is added.

Role assignment uses immutable snapshots. A failed default-route dump makes role
metadata unavailable and triggers resynchronization; it does not turn an uncertain uplink into an authorized
Inside interface. Local-address protection continues to use address validity
independently. Interface and routing notifications refresh the snapshot.

## Configuration transactions

`parse_interface_roles()` is a pure candidate parser: it does not query the
network or mutate NetworkCtx. `load_settings()` parses the complete list before
publishing one replacement snapshot under its existing configuration lock.
Serialization retains list order. Applying the previous configuration through
`load_settings()` restores its rules, including restoring defaults when the list
is absent. This follows cfg-transactions' apply/rollback path; candidate
preparation must not call the runtime setter. Malformed selectors set LOAD_ERRORS
and leave the previous role map intact, allowing the transaction layer to reject
and roll back the commit. Pure semantic prevalidation can call the parser.

## Validation

Build and run `sx_gtests_network_context` and the InterfaceMetadata and
PolicyInterfaces tests in `sx_gtests`.

For the real veth/TPROXY tests, build the probe with the same compiler as the
project and run in a disposable user/network namespace:

```
g++ -std=c++20 -pthread -Isrc src/service/network_context.cpp \
    tests/integration/network_context_probe.cpp -o /tmp/network-context-probe
unshare -Urn python3 tests/integration/interface_ingress.py /tmp/network-context-probe
```

The script checks TCP/UDP IPv4/IPv6, IPv4 accepted by IPv6, local and TPROXY
traffic, route lookup, automatic roles with/without default routes and custom-role
reset. It needs iproute2, nftables and enabled unprivileged user namespaces.
