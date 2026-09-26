/*
 * TLS transport transitions owned by a MitmProxy session.
 */

#ifndef SMITHPROXY_STARTSTOPTLS_HPP
#define SMITHPROXY_STARTSTOPTLS_HPP

class MitmHostCX;
class MitmProxy;

class StartStopTls {
public:
    explicit StartStopTls(MitmProxy& owner) noexcept : owner_(owner) {}

    StartStopTls(StartStopTls const&) = delete;
    StartStopTls& operator=(StartStopTls const&) = delete;

    // Upgrade a connected plaintext pair. `client` is the accepted/client side.
    bool start(MitmHostCX& client);

private:
    MitmHostCX* checked_peer(MitmHostCX& client, bool expect_tls) const;

    MitmProxy& owner_;
};

#endif // SMITHPROXY_STARTSTOPTLS_HPP
