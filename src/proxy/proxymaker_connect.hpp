#pragma once

#include <functional>
#include <memory>
#include <optional>
#include <string>
#include <utility>

namespace sx::proxy { class QuicObserver; }

namespace sx::proxymaker {

// The handshake needs only these profile values, not a mutable policy object.
struct QuicTlsPolicy {
    bool use_pfs = true;
    bool alpn_block = false;
    bool disable_reuse = false;  // Downstream; upstream has no ticket cache.
};

// A multiplexed session exists before its individual MitmProxy streams. Keep
// its setup alive across certificate verification and the forwarding connect.
class SessionSetup {
public:
    virtual ~SessionSetup() = default;
    virtual void ingress_ifindex(unsigned) {}
    virtual proxy::QuicObserver* quic_observer() { return nullptr; }
    virtual std::string connection_id() const { return {}; }
    virtual std::optional<QuicTlsPolicy> tls_policy(
        std::string const&, std::string const&) { return QuicTlsPolicy {}; }
    virtual bool start(std::string const& host, std::string const& port) = 0;
};

using SessionSetupFactory = std::function<std::shared_ptr<SessionSetup>(
    std::string const& source_host, std::string const& source_port)>;

inline bool connection_start(SessionSetup* setup,
                             std::string const& host, std::string const& port) {
    return !setup || setup->start(host, port);
}

// The transport retains ownership of its socket and polling registration.
// A denied setup must never reach the supplied transport connector.
template<class Connector>
auto connect(SessionSetup* setup, std::string const& host,
             std::string const& port, Connector&& connector) -> decltype(connector()) {
    if (!connection_start(setup, host, port)) return {};

    return std::forward<Connector>(connector)();
}

} // namespace sx::proxymaker
