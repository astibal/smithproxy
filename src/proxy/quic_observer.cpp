#include <proxy/quic_observer.hpp>
#include <proxy/proxymaker_connect.hpp>
#include <proxy/proxy_hooks.hpp>
#include <log/logan.hpp>

namespace sx::proxy {

void QuicObserver::register_callbacks() {
    quic::Hooks::registry().handshake = &QuicObserver::dispatch;
}

bool QuicObserver::dispatch(proxymaker::SessionSetup& setup, quic::HookEvent& event) noexcept {

    auto* observer = setup.quic_observer();
    if(!observer) return true;

    try {
        if(observer->terminated_) return false;
        const bool proceed = observer->observe(event);
        observer->terminated_ = !proceed;
        return proceed;
    } catch(...) {
        static logan_lite log {"proxy.quic"};
        _war("QUIC callback failed; applying %s policy",
             observer->strict_ ? "strict" : "fail-open");
        observer->terminated_ = observer->strict_;
        return !observer->strict_;
    }
}

bool QuicObserver::observe(quic::HookEvent& event) {

    const bool start = event.kind == quic::HookEvent::Kind::start;
    auto& completed = outcomes_[event.client ? 0 : 1];
    if(start) {
        ++attempts_[1];
        completed = false;
        if(!start_) return true;
    } else {
        if(completed) return true;
        completed = true;
    }

    const char* phase = "failed";
    if(start) phase = "start";
    else if(event.kind == quic::HookEvent::Kind::established) phase = "established";
    ProxyHooks::QuicArgs args;
    args.connection_id = id_;
    args.strict = strict_;
    args.meta = meta_;
    args.observation = {
        {"protocol", "quic"},
        {"envelope", {{"version", 1}, {"connection_id", id_}, {"attempt", attempts_[event.client ? 0 : 1]},
            {"side", event.client ? "client" : "server"}, {"event", phase}}},
        {"sni", event.sni}, {"cipher", event.cipher}, {"tls_version", "TLSv1.3"}
    };
    if(!event.error.empty()) args.observation["error"] = event.error;
    if(start) {
        args.observation["upstream"] = {
            {"sni", event.sni}, {"alpn", event.alpn}, {"ciphers", nullptr}
        };
    } else {
        // The negotiated ALPN is text for QUIC's supported HTTP/3 protocol.
        args.observation["alpn"] = event.alpn;
        args.observation["certificates"] = event.certificates;
    }

    const auto reply = ProxyHooks::quic(args);
    if(!reply.at("proceed").get<bool>()) return false;
    if(!start) return true;
    if(!reply.contains("upstream")) return true;

    // Validate before publishing any accepted settings to the transport.
    // Invalid accepted mutations fail closed, independently of availability.
    try {
        const auto& offer = reply.at("upstream");
        auto sni = offer.at("sni").get<std::string>();
        auto alpn = offer.at("alpn").get<std::string>();
        std::optional<std::string> ciphers;
        if(!offer.at("ciphers").is_null()) ciphers = offer.at("ciphers").get<std::string>();
        if(sni.size() > 255 || sni.find('\0') != std::string::npos ||
           alpn.empty() || alpn.size() > 255 ||
           (ciphers && (ciphers->size() > 4096 || ciphers->find('\0') != std::string::npos))) {
            return false;
        }

        event.sni = std::move(sni);
        event.alpn = std::move(alpn);
        event.ciphers = std::move(ciphers);
    } catch(...) {
        return false;
    }

    return true;
}

} // namespace sx::proxy
