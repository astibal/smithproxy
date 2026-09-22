#ifndef SMITHPROXY_QUICSERVICE_HPP
#define SMITHPROXY_QUICSERVICE_HPP

#include "proxy/quic/openssl.hpp"

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
                     std::string private_key, bool transparent);
    ~listener_service();

    listener_service(listener_service const&) = delete;
    listener_service& operator=(listener_service const&) = delete;

    bool prepare();
    void run();
    void stop();

    bool ready() const { return ready_; }
    std::string const& last_error() const { return last_error_; }
    std::size_t connection_count() const { return connections_.size(); }

private:
    bool open_socket();
    void fail(std::string message);

    std::uint16_t port_;
    std::string certificate_;
    std::string private_key_;
    bool transparent_;
    int udp_fd_ = -1;
    std::atomic_bool stopping_ = false;
    bool ready_ = false;
    std::string last_error_;

#if SMITHPROXY_OPENSSL_QUIC
    unique_ssl_ctx context_;
    std::unique_ptr<openssl_listener> listener_;
    std::vector<std::shared_ptr<openssl_connection>> connections_;
#else
    std::vector<std::shared_ptr<void>> connections_;
#endif
};

} // namespace sx::quic

#endif
