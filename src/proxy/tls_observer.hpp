#pragma once

#include <protocol_hooks.hpp>

namespace sx::proxy {

// Synchronous bridge from Socle to the proxy owning the transport.
class TlsObserver {
public:
    // Install once during process startup, before workers can enter TLS.
    static void register_callbacks();

private:
    static socle::ProtocolHookResult start(baseCom& com) noexcept;
    static socle::ProtocolHookResult client_hello(baseCom& com) noexcept;
    static socle::ProtocolHookResult observe(baseCom& com, const char* event) noexcept;
};

} // namespace sx::proxy
