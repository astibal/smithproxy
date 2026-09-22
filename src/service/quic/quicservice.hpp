#ifndef SMITHPROXY_QUICSERVICE_HPP
#define SMITHPROXY_QUICSERVICE_HPP

#include "proxy/quic/openssl.hpp"
#include "proxy/multiflow/mfproxy.hpp"

#include <atomic>
#include <cstdint>
#include <memory>
#include <string>
#include <vector>

namespace sx::quic {

/** First daemon-facing QUIC listener. One instance owns one UDP socket/event loop. */
class listener_service final {
public:
    listener_service(std::uint16_t port, std::string certificate,
                     std::string private_key, bool transparent,
                     std::uint16_t upstream_port = 443);
    ~listener_service();

    listener_service(listener_service const&) = delete;
    listener_service& operator=(listener_service const&) = delete;

    bool prepare();
    void run();
    void stop();

    bool ready() const { return ready_; }
    std::uint16_t bound_port() const { return bound_port_; }
    std::string const& last_error() const { return last_error_; }
    std::size_t connection_count() const { return connections_.size(); }

private:
    bool open_socket();
    std::shared_ptr<openssl_connection> connect_upstream(std::string const& host);
    void fail(std::string message);

    std::uint16_t port_;
    std::uint16_t bound_port_ = 0;
    std::string certificate_;
    std::string private_key_;
    bool transparent_;
    std::uint16_t upstream_port_;
    int udp_fd_ = -1;
    std::atomic_bool stopping_ = false;
    bool ready_ = false;
    std::string last_error_;

#if SMITHPROXY_OPENSSL_QUIC
    unique_ssl_ctx context_;
    unique_ssl_ctx client_context_;
    std::unique_ptr<openssl_listener> listener_;
    struct session {
        std::shared_ptr<openssl_connection> downstream;
        std::shared_ptr<openssl_connection> upstream;
        std::unique_ptr<multiflow::MFProxy> proxy;
    };
    std::vector<std::shared_ptr<openssl_connection>> pending_;
    std::vector<session> sessions_;
    std::vector<std::shared_ptr<openssl_connection>> connections_;
#else
    std::vector<std::shared_ptr<void>> connections_;
#endif
};

} // namespace sx::quic

#endif
