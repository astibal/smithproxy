#include <proxy/quic/hooks.hpp>
#include <proxy/quic/openssl.hpp>
#include <proxy/quic_observer.hpp>
#include <proxy/proxymaker_connect.hpp>
#include <log/logan.hpp>
#include <openssl/pem.h>

namespace sx::quic {
namespace {

void append_certificate(HookEvent& event, X509* certificate) {

    if(!certificate) return;
    std::unique_ptr<BIO, decltype(&BIO_free)> output(BIO_new(BIO_s_mem()), BIO_free);
    if(!output || PEM_write_bio_X509(output.get(), certificate) != 1) return;

    char* data = nullptr;
    const auto size = BIO_get_mem_data(output.get(), &data);
    if(size > 0) event.certificates.emplace_back(data, size);
}

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
    const std::string& server_name, std::string* error, proxymaker::SessionSetup* setup) {

    if(!setup || !setup->quic_observer()) {
        return connect_openssl_quic(context, peer, size, server_name, error);
    }

    HookEvent offer;
    offer.sni = server_name;
    offer.alpn = "h3";
    if(!hook_start(setup, offer)) {
        if(error) *error = "QUIC start rejected by callback";
        return nullptr;
    }

    auto connection = connect_openssl_quic(
        context, peer, size, server_name, offer.alpn, error, &offer);
    if(!connection) {
        HookEvent failed;
        failed.kind = HookEvent::Kind::failed;
        failed.sni = server_name;
        failed.error = error && !error->empty() ? *error : "QUIC upstream creation failed";
        dispatch(setup, failed);
    }

    return connection;
}
#endif

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
    if(const auto* name = SSL_get_servername(ssl, TLSEXT_NAMETYPE_host_name)) {
        event.sni = name;
    }
    if(const auto* cipher = SSL_get_current_cipher(ssl)) {
        event.cipher = SSL_CIPHER_get_name(cipher);
    }

    const unsigned char* alpn = nullptr;
    unsigned int size = 0;
    SSL_get0_alpn_selected(ssl, &alpn, &size);
    if(size) event.alpn.assign(reinterpret_cast<const char*>(alpn), size);

    std::unique_ptr<X509, decltype(&X509_free)> leaf(SSL_get1_peer_certificate(ssl), X509_free);
    append_certificate(event, leaf.get());
    const auto* chain = SSL_get_peer_cert_chain(ssl);
    for(int i = 0; chain && i < sk_X509_num(chain); ++i) {
        auto* certificate = sk_X509_value(chain, i);
        if(!leaf || X509_cmp(leaf.get(), certificate) != 0) append_certificate(event, certificate);
    }

    return dispatch(setup, event);
}

} // namespace sx::quic
