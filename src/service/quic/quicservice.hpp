#ifndef SMITHPROXY_QUICSERVICE_HPP
#define SMITHPROXY_QUICSERVICE_HPP

#include "proxy/quic/openssl.hpp"
#include "proxy/multiflow/mfproxy.hpp"

#include <atomic>
#include <chrono>
#include <cstdint>
#include <future>
#include <memory>
#include <map>
#include <string>
#include <vector>

namespace sx::quic {

struct lifecycle_options {
    std::chrono::milliseconds handshake_timeout { std::chrono::seconds(10) };
    std::chrono::milliseconds idle_timeout { std::chrono::minutes(5) };
    std::chrono::milliseconds drain_timeout { std::chrono::seconds(3) };
};

/** First daemon-facing QUIC listener. One instance owns one UDP socket/event loop. */
class listener_service final {
public:
    listener_service(std::uint16_t port, std::string certificate,
                     std::string private_key, bool transparent,
                     std::uint16_t upstream_port = 443,
                     bool verify_upstream = true,
                     lifecycle_options lifecycle = {});
    ~listener_service();

    listener_service(listener_service const&) = delete;
    listener_service& operator=(listener_service const&) = delete;

    bool prepare();
    void run();
    void stop();

    bool ready() const { return ready_; }
    std::uint16_t bound_port() const { return bound_port_; }
    std::string const& last_error() const { return last_error_; }
    std::size_t connection_count() const { return connection_count_; }

private:
    bool open_socket();
    std::shared_ptr<openssl_connection> connect_upstream(std::string const& host);
    std::shared_ptr<openssl_connection> connect_upstream(
        datagram_endpoint const& target, std::string const& server_name);
#if SMITHPROXY_OPENSSL_QUIC
    static int certificate_callback(SSL* ssl, void* argument);
    int prepare_verified_certificate(SSL* downstream);
    struct verified_certificate;
    verified_certificate verify_and_spoof(datagram_endpoint destination,
                                           std::string server_name);
    bool install_verified_certificate(SSL* downstream,
                                      verified_certificate const& verified);
#endif
    void fail(std::string message);

    std::uint16_t port_;
    std::uint16_t bound_port_ = 0;
    std::string certificate_;
    std::string private_key_;
    bool transparent_;
    std::uint16_t upstream_port_;
    bool verify_upstream_;
    lifecycle_options lifecycle_;
    int udp_fd_ = -1;
    std::atomic_bool stopping_ = false;
    std::atomic_size_t connection_count_ = 0;
    bool ready_ = false;
    std::string last_error_;

#if SMITHPROXY_OPENSSL_QUIC
    unique_ssl_ctx context_;
    unique_ssl_ctx client_context_;
    std::unique_ptr<openssl_listener> listener_;
    enum class session_state { handshake, active, draining };
    struct session {
        session_state state = session_state::handshake;
        std::chrono::steady_clock::time_point created = std::chrono::steady_clock::now();
        std::chrono::steady_clock::time_point last_activity = created;
        std::chrono::steady_clock::time_point draining_since {};
        std::shared_ptr<openssl_connection> downstream;
        std::shared_ptr<openssl_connection> upstream;
        std::unique_ptr<multiflow::MFProxy> proxy;
    };
    std::vector<session> sessions_;
    struct staged_upstream {
        std::shared_ptr<openssl_connection> connection;
        std::chrono::steady_clock::time_point created = std::chrono::steady_clock::now();
    };
    std::map<SSL*, staged_upstream> staged_upstreams_;
    struct verified_certificate {
        std::shared_ptr<openssl_connection> connection;
        std::shared_ptr<X509> certificate;
        std::shared_ptr<EVP_PKEY> private_key;
    };
    struct certificate_job {
        std::future<verified_certificate> result;
        std::chrono::steady_clock::time_point created = std::chrono::steady_clock::now();
    };
    std::map<SSL*, certificate_job> certificate_jobs_;
    std::map<std::string, datagram_endpoint> original_destinations_;
    void start_draining(session& value, std::chrono::steady_clock::time_point now,
                        std::uint64_t protocol_error = 0);
    void cleanup_sessions();
#endif
};

} // namespace sx::quic

#endif
