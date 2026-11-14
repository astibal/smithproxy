#include <proxy/quic/hooks.hpp>
#include <proxy/quic/openssl.hpp>
#include <proxy/quic_observer.hpp>
#include <proxy/proxymaker_connect.hpp>
#include <log/logan.hpp>
#include <ossl_util.hpp>

namespace sx::quic {
namespace {

bool dispatch(proxymaker::SessionSetup* setup, HookEvent& event) {

    const auto callback = Hooks::registry().handshake;
    if(!setup || !callback || !setup->quic_observer()) {
        return true;
    }

    const bool proceed = callback(*setup, event);
    if(!proceed) {
        static logan_lite log {"proxy.quic"};
        _war("QUIC handshake terminated by callback: side=%s event=%d",
             event.client ? "client" : "server", static_cast<int>(event.kind));
    }

    return proceed;
}

} // namespace

#if SMITHPROXY_OPENSSL_QUIC
std::unique_ptr<openssl_connection> connect_with_hooks(
    SSL_CTX* context, const sockaddr* peer, socklen_t size,
    const std::string& server_name, std::string* error, proxymaker::SessionSetup* setup,
    std::function<bool(SSL*)> const& configure, SSL* port) {

    if(!setup || !setup->quic_observer()) {
        return connect_openssl_quic(context, peer, size, server_name, "h3", error,
                                    nullptr, configure, port);
    }

    HookEvent offer;
    offer.sni = server_name;
    offer.alpn = "h3";
    if(!hook_start(setup, offer)) {
        if(error) *error = "QUIC start rejected by callback";
        return nullptr;
    }

    auto connection = connect_openssl_quic(
        context, peer, size, server_name, offer.alpn, error, &offer, configure, port);
    if(!connection) {
        hook_failure(setup, server_name, error && !error->empty()
            ? *error : "QUIC upstream creation failed");
    }

    return connection;
}
#endif

bool hook_failure(proxymaker::SessionSetup* setup, std::string const& name,
                  std::string const& error) {
    HookEvent event;
    event.kind = HookEvent::Kind::failed;
    event.sni = name;
    event.error = error;
    return dispatch(setup, event);
}

bool apply_hook_offer(SSL* ssl, const HookEvent& offer, const std::string& identity) {

    // Verification identity remains unchanged. Only the wire offer is mutable.
    if(offer.sni != identity) {
        auto* name = offer.sni.empty() ? nullptr : const_cast<char*>(offer.sni.c_str());
        if(SSL_set_tlsext_host_name(ssl, name) != 1) return false;
    }

    return !offer.ciphers || SSL_set_ciphersuites(ssl, offer.ciphers->c_str()) == 1;
}

bool hook_start(proxymaker::SessionSetup* setup, HookEvent& event) {

    event.kind = HookEvent::Kind::start;
    return dispatch(setup, event);
}

bool hook_outcome(proxymaker::SessionSetup* setup, SSL* ssl, bool client,
                  const char* failure) {

    if(!setup || !setup->quic_observer() || !ssl ||
       !setup->quic_observer()->outcome_pending(client)) {
        return true;
    }

    // Do not invent a failure while the native handshake is still pending.
    const bool established = SSL_is_init_finished(ssl);
    if(!established && !failure) {
        return true;
    }

    HookEvent event;
    event.client = client;
    event.kind = established ? HookEvent::Kind::established : HookEvent::Kind::failed;
    if(!established) event.error = failure;
    if(auto name = socle::ossl::server_name(ssl)) {
        event.sni = *name;
    }
    if(const auto* cipher = SSL_get_current_cipher(ssl)) {
        event.cipher = SSL_CIPHER_get_name(cipher);
    }

    event.alpn = socle::ossl::selected_alpn(ssl);

    for(auto& pem : socle::ossl::peer_certificates_pem(ssl)) {
        if(!pem.empty()) event.certificates.push_back(std::move(pem));
    }

    return dispatch(setup, event);
}

} // namespace sx::quic
