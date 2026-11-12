#include "proxy/quic/transport.hpp"
#include <sslcertstore.hpp>
#include <cstdlib>
#include <poll.h>

#if SMITHPROXY_OPENSSL_QUIC
namespace sx::quic {
#ifdef SMITHPROXY_ENABLE_NGTCP2
unique_ssl_ctx make_ngtcp2_context(bool server);
std::unique_ptr<worker_transport> make_ngtcp2_worker(
    SSL_CTX*, SSL_CTX*, int, int, bool, datagram_observer, datagram_source, size_t);
#endif
namespace {

// Preserve the established OpenSSL scheduling and routing behind the same
// worker contract. This wrapper introduces no extra engine ticks or I/O.
class openssl_worker final : public worker_transport {
public:
    openssl_worker(std::unique_ptr<openssl_listener> listener, unique_ssl upstream)
        : listener_(std::move(listener)), upstream_(std::move(upstream)) {}
    bool handle_events() override { return listener_->handle_events(); }
    bool handle_upstream() override { return SSL_handle_events(upstream_.get()) == 1; }
    std::shared_ptr<transport_connection> accept() override { return listener_->accept(); }
    std::shared_ptr<transport_connection> connect(
        SSL_CTX* ctx, const sockaddr* peer, socklen_t size, std::string const& name,
        std::string* error, proxymaker::SessionSetup* setup,
        std::function<bool(SSL*)> const& configure) override {
        return connect_with_hooks(ctx, peer, size, name, error, setup, configure, upstream_.get());
    }
    bool flush_output(datagram_endpoint const& peer, datagram_endpoint const& local,
                      uint64_t association) override {
        return listener_->flush_output(peer, local, association);
    }
    std::chrono::nanoseconds timeout() const override {
        std::chrono::nanoseconds result {-1};
        for (auto* ssl : {listener_->handle_native(), upstream_.get()}) {
            timeval tv {}; int infinite = 1;
            if (SSL_get_event_timeout(ssl, &tv, &infinite) != 1 || infinite) continue;
            // Keep OpenSSL's established millisecond polling granularity. The
            // ngtcp2 backend supplies its finer pacing deadlines independently.
            auto ms = std::chrono::seconds(tv.tv_sec) + std::chrono::milliseconds((tv.tv_usec + 999) / 1000);
            if (result.count() < 0 || ms < result) result = ms;
        }
        return result;
    }
    short desired_socket_events() const override { return listener_->desired_socket_events(); }
    int upstream_fd() const override { return SSL_get_fd(upstream_.get()); }
    short upstream_events() const override {
        return POLLIN | (SSL_net_write_desired(upstream_.get()) > 0 ? POLLOUT : 0);
    }
    std::string last_error() const override { return listener_->last_error(); }
    datagram_endpoint current_peer() const override { return listener_->current_peer(); }
    datagram_endpoint current_local() const override { return listener_->current_local(); }
    unsigned current_ingress_ifindex() const override { return listener_->current_ingress_ifindex(); }
    uint64_t current_association() const override { return listener_->current_association(); }
    bool bind_connection_route(SSL* ssl) override { return listener_->bind_connection_route(ssl); }
private:
    std::unique_ptr<openssl_listener> listener_;
    unique_ssl upstream_;
};
}

transport_backend configured_transport_backend() {
    auto* name = std::getenv("SMITHPROXY_QUIC_BACKEND");
    if (!name || std::string(name) == "openssl") return transport_backend::openssl;
#ifdef SMITHPROXY_ENABLE_NGTCP2
    if (std::string(name) == "ngtcp2") return transport_backend::ngtcp2;
#endif
    return transport_backend::unavailable;
}

unique_ssl_ctx make_transport_context(transport_backend backend, bool server) {
    if (backend == transport_backend::openssl) return make_openssl_quic_context(server);
#ifdef SMITHPROXY_ENABLE_NGTCP2
    if (backend == transport_backend::ngtcp2) return make_ngtcp2_context(server);
#endif
    return {};
}

std::unique_ptr<worker_transport> make_worker_transport(
    transport_backend backend, SSL_CTX* server, SSL_CTX* client, int fd, int family,
    bool transparent, datagram_observer observer, datagram_source source, size_t max_connections) {
    if (backend == transport_backend::openssl) {
        auto upstream = make_openssl_quic_client_engine(client, family);
        if (!upstream) return {};
        auto listener = openssl_listener::create(server, fd, transparent, std::move(observer), std::move(source));
        if (!listener) return {};
        return std::make_unique<openssl_worker>(std::move(listener), std::move(upstream));
    }
#ifdef SMITHPROXY_ENABLE_NGTCP2
    if (backend == transport_backend::ngtcp2)
        return make_ngtcp2_worker(server, client, fd, family, transparent,
                                  std::move(observer), std::move(source), max_connections);
#endif
    (void)max_connections;
    return {};
}
} // namespace sx::quic
#endif
