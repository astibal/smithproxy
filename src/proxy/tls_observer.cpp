#include <proxy/tls_observer.hpp>
#include <proxy/mitmproxy.hpp>
#include <sslcom.hpp>
#include <stdexcept>

namespace sx::proxy {

void TlsObserver::register_callbacks() {

    auto& hooks = socle::ProtocolHooks::registry();
    hooks.tls_client_hello = &TlsObserver::client_hello;
    hooks.tls_client_start = &TlsObserver::start;
    hooks.tls_server_start = &TlsObserver::start;
}

socle::ProtocolHookResult TlsObserver::start(baseCom& com) noexcept {

    observe(com, "start");

    bool strict = false;
    try {
        auto* cx = com.owner_cx();
        auto* proxy = cx ? dynamic_cast<MitmProxy*>(cx->parent_proxy()) : nullptr;
        auto* tls = dynamic_cast<SSLCom*>(&com);
        if(!proxy || !tls || cx->com() != &com || !proxy->tls_observer_enabled()) {
            return socle::ProtocolHookResult::Continue;
        }

        strict = proxy->webhook_control_->strict();

        // OpenSSL's server role faces the client. This hook observes or vetoes;
        // certificate selection and handshake scheduling stay native.
        if(tls->tls_proto_role() == socle::TlsProtoRole::server) {
            if(!proxy->webhook_tls_start_client_) {
                return socle::ProtocolHookResult::Continue;
            }

            ProxyHooks::TlsClientStartArgs args;
            args.attempt = proxy->tls_lifecycle(*cx).attempt;
            args.sni = tls->get_sni();

            const bool proceed = ProxyHooks::tls_start_client(*proxy, args);
            return proceed ? socle::ProtocolHookResult::Continue : socle::ProtocolHookResult::Terminate;
        }

        // OpenSSL's client role is the addon API's upstream/server leg.
        if(!proxy->webhook_tls_start_server_) {
            return socle::ProtocolHookResult::Continue;
        }

        // Catch up a completed TCP connection before reporting TLS start.
        // A pending connection keeps its native handshake scheduling.
        proxy->observe_readiness('r', cx);
        if(proxy->state().dead() || cx->error() || com.error()) {
            return socle::ProtocolHookResult::Terminate;
        }

        const auto ciphers = tls->upstream_cipher_filter();

        ProxyHooks::TlsStartArgs args;
        args.attempt = proxy->tls_lifecycle(*cx).attempt;
        args.upstream_sni = tls->get_sni();
        args.upstream_alpn = tls->get_peer_alpn();
        args.upstream_ciphers = ciphers;
        args.alpn_blocked = tls->opt.alpn_block;

        const auto decision = ProxyHooks::tls_start_server(*proxy, args);
        if(!decision.proceed) {
            return socle::ProtocolHookResult::Terminate;
        }

        if(decision.update_upstream) {
            // Once an update is accepted, application errors must not resume
            // a handshake with an incomplete or different offer.
            strict = true;
            if(!tls->configure_upstream_start(decision.upstream_sni, decision.upstream_alpn,
                                               decision.upstream_cipher_list)) {
                return socle::ProtocolHookResult::Terminate;
            }
        }
    }
    catch(...) {
        static logan_lite log {"proxy.tls"};
        _war("TLS start callback failed; applying %s policy", strict ? "strict" : "fail-open");
        return strict ? socle::ProtocolHookResult::Terminate : socle::ProtocolHookResult::Continue;
    }

    return socle::ProtocolHookResult::Continue;
}

socle::ProtocolHookResult TlsObserver::client_hello(baseCom& com) noexcept {
    observe(com, "client-hello");

    // The parser belongs to the outbound COM. The hook describes its peer:
    // the client-facing TLS attempt, shared with later outcome observations.
    bool strict = false;
    try {
        auto* owner = com.owner_cx();
        auto* proxy = owner ? dynamic_cast<MitmProxy*>(owner->parent_proxy()) : nullptr;
        auto* tls = dynamic_cast<SSLCom*>(&com);
        if(!proxy || !tls || !proxy->tls_observer_enabled() ||
           !proxy->webhook_tls_clienthello_) {
            return socle::ProtocolHookResult::Continue;
        }

        strict = proxy->webhook_control_->strict();
        auto* client = tls->peer() ? tls->peer()->owner_cx() : nullptr;
        if(!client || client->parent_proxy() != proxy || owner->com() != &com) {
            throw std::runtime_error("ClientHello has no matching client context");
        }

        const auto& hello = tls->client_hello_buffer();
        if(hello.size() <= 9) {
            throw std::runtime_error("ClientHello has no complete handshake body");
        }

        // Socle normalizes record fragments before invoking us. Strip the
        // record and handshake headers; the adapter expects only the body.
        ProxyHooks::ClientHelloArgs args;
        args.attempt = proxy->tls_lifecycle(*client).attempt;
        args.body = std::string_view(reinterpret_cast<const char*>(hello.data()) + 9,
                                     hello.size() - 9);
        args.upstream_sni = tls->get_sni();
        args.upstream_alpn = tls->get_peer_alpn();
        args.alpn_blocked = tls->opt.alpn_block;

        const auto decision = ProxyHooks::client_hello(*proxy, args);
        if(!decision.proceed || (decision.ignore_connection && !tls->bypass_me_and_peer())) {
            return socle::ProtocolHookResult::Terminate;
        }

        if(!decision.ignore_connection && decision.update_upstream &&
           !tls->configure_upstream_hello(decision.upstream_sni, decision.upstream_alpn,
                                          decision.upstream_cipher_list)) {
            return socle::ProtocolHookResult::Terminate;
        }
    }
    catch(...) {
        static logan_lite log {"proxy.tls"};
        _war("ClientHello callback failed; applying %s policy", strict ? "strict" : "fail-open");
        return strict ? socle::ProtocolHookResult::Terminate : socle::ProtocolHookResult::Continue;
    }

    return socle::ProtocolHookResult::Continue;
}

socle::ProtocolHookResult TlsObserver::observe(baseCom& com, const char* event) noexcept {

    // Borrow the existing ownership chain only for this call. No observer
    // registration, saved proxy pointer, or shared ownership is needed.
    try {
        static logan_lite log {"proxy.tls"};

        auto* cx = com.owner_cx();
        auto* proxy = cx ? dynamic_cast<MitmProxy*>(cx->parent_proxy()) : nullptr;
        auto* tls = dynamic_cast<SSLCom*>(&com);

        if(!proxy || !tls || cx->com() != &com) {
            _err("TLS observer: transport has no matching MitmProxy owner");
            return socle::ProtocolHookResult::Continue;
        }

        if(!proxy->tls_observer_enabled()) {
            return socle::ProtocolHookResult::Continue;
        }

        const auto* role = tls->tls_proto_role() == socle::TlsProtoRole::client
            ? "client" : "server";

        _deb("TLS %s: proxy=%p socket=%d local_role=%s",
             event, static_cast<void*>(proxy), com.socket(), role);
    }
    catch(...) {
        // Diagnostics must neither escape Socle's noexcept callback nor
        // change the outcome of a handshake.
    }

    return socle::ProtocolHookResult::Continue;
}

} // namespace sx::proxy
