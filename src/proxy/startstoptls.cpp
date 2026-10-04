#include <proxy/startstoptls.hpp>

#include <proxy/mitmcom.hpp>
#include <proxy/mitmhost.hpp>
#include <proxy/mitmproxy.hpp>
#include <service/cfgapi/cfgapi.hpp>

#include <sslcom.hpp>

MitmHostCX* StartStopTls::checked_peer(MitmHostCX& client, bool expect_tls) const {
    auto* peer = MitmHostCX::from_baseHostCX(client.peer());
    PairState const state {
        .has_peer = peer != nullptr,
        .client_owned = client.parent_proxy() == &owner_,
        .peer_owned = peer and peer->parent_proxy() == &owner_,
        .client_tls = dynamic_cast<SSLCom*>(client.com()) != nullptr,
        .peer_tls = peer and dynamic_cast<SSLCom*>(peer->com()) != nullptr
    };

    if(validate(state, expect_tls) != PairStatus::Ready) {
        return nullptr;
    }

    return peer;
}

bool StartStopTls::start(MitmHostCX& client) {
    auto* peer = checked_peer(client, false);
    if(not peer) {
        return false;
    }

    // Both halves of a proxied connection intentionally share one master
    // transport.  Preserve it before replacing either baseCom: the old peer
    // transport can own references which become invalid during replacement.
    auto* master = client.com()->master();

    auto* new_client_com = new MySSLMitmCom();
    auto* new_peer_com = new MySSLMitmCom();
    client.com(new_client_com);
    peer->com(new_peer_com);

    // Replacing baseHostCX::com() does not initialize the new transport.
    // Do it explicitly so STARTTLS also works when no SSL listener happened
    // to initialize the process-wide TLS factory beforehand.
    new_client_com->init(&client);
    new_peer_com->init(peer);

    client.peer(peer);
    peer->peer(&client);

    client.com()->master(master);
    peer->com()->master(master);

    // TLS policy must be complete before either side can enter SSL_connect or
    // SSL_accept.  Applying it afterwards made STARTTLS behaviour depend on
    // whether the upstream handshake completed synchronously.
    if(not CfgFactory::get()->policy_apply_tls(client.matched_policy(), client.com()) or
       not CfgFactory::get()->policy_apply_tls(client.matched_policy(), client.peercom())) {
        client.error(true);
        peer->error(true);
        return false;
    }

    // The accepted/client side cannot start its server handshake before the
    // upstream/client side has enough information to spoof the certificate.
    client.waiting_for_peercom(true);

    if(new_peer_com->upgrade_client_socket(peer->socket()) < 0 or
       new_client_com->upgrade_server_socket(client.socket()) < 0) {
        client.error(true);
        peer->error(true);
        return false;
    }

    // Preserve the existing STARTTLS behaviour: spoofing may initialize the
    // accepted side once more after the upstream hello is available.
    new_client_com->upgraded(false);

    client.comlog().append(
            "\n STARTTLS: plain connection upgraded to SSL/TLS, continuing with inspection.\n\n");
    client.opening(true);

    return true;
}
