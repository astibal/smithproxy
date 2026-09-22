#include "service/quic/quicservice.hpp"

#include <cerrno>
#include <cstring>
#include <utility>

#if SMITHPROXY_OPENSSL_QUIC
#include <arpa/inet.h>
#include <fcntl.h>
#include <netdb.h>
#include <netinet/in.h>
#include <poll.h>
#include <sys/socket.h>
#include <unistd.h>
#endif

namespace sx::quic {

namespace {

#if SMITHPROXY_OPENSSL_QUIC
int select_h3(SSL*, const unsigned char** output, unsigned char* output_size,
              const unsigned char* input, unsigned input_size, void*) {
    static constexpr unsigned char supported[] = { 2, 'h', '3' };
    return SSL_select_next_proto(const_cast<unsigned char**>(output), output_size,
                                 supported, sizeof(supported), input, input_size)
            == OPENSSL_NPN_NEGOTIATED
        ? SSL_TLSEXT_ERR_OK
        : SSL_TLSEXT_ERR_NOACK;
}
#endif

} // namespace

listener_service::listener_service(std::uint16_t port, std::string certificate,
                                   std::string private_key, bool transparent,
                                   std::uint16_t upstream_port)
    : port_(port), certificate_(std::move(certificate)),
      private_key_(std::move(private_key)), transparent_(transparent),
      upstream_port_(upstream_port) {}

listener_service::~listener_service() {
    stop();
#if SMITHPROXY_OPENSSL_QUIC
    connections_.clear();
    sessions_.clear();
    pending_.clear();
    listener_.reset();
    context_.reset();
    if (udp_fd_ >= 0) ::close(udp_fd_);
#endif
}

void listener_service::fail(std::string message) {
    last_error_ = std::move(message);
    ready_ = false;
}

bool listener_service::open_socket() {
#if SMITHPROXY_OPENSSL_QUIC
    udp_fd_ = ::socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (udp_fd_ < 0) {
        fail(std::string("socket: ") + std::strerror(errno));
        return false;
    }

    int enabled = 1;
    if (::setsockopt(udp_fd_, SOL_SOCKET, SO_REUSEADDR, &enabled, sizeof(enabled)) != 0) {
        fail(std::string("SO_REUSEADDR: ") + std::strerror(errno));
        return false;
    }
    if (transparent_
        && ::setsockopt(udp_fd_, SOL_IP, IP_TRANSPARENT, &enabled, sizeof(enabled)) != 0) {
        fail(std::string("IP_TRANSPARENT: ") + std::strerror(errno));
        return false;
    }

    auto const flags = ::fcntl(udp_fd_, F_GETFL, 0);
    if (flags < 0 || ::fcntl(udp_fd_, F_SETFL, flags | O_NONBLOCK) != 0) {
        fail(std::string("O_NONBLOCK: ") + std::strerror(errno));
        return false;
    }

    sockaddr_in address {};
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = htonl(INADDR_ANY);
    address.sin_port = htons(port_);
    if (::bind(udp_fd_, reinterpret_cast<sockaddr*>(&address), sizeof(address)) != 0) {
        fail(std::string("bind: ") + std::strerror(errno));
        return false;
    }
    socklen_t address_size = sizeof(address);
    if (::getsockname(udp_fd_, reinterpret_cast<sockaddr*>(&address), &address_size) != 0) {
        fail(std::string("getsockname: ") + std::strerror(errno));
        return false;
    }
    bound_port_ = ntohs(address.sin_port);
    return true;
#else
    fail("OpenSSL was built without QUIC server support (requires OpenSSL 3.5+)");
    return false;
#endif
}

bool listener_service::prepare() {
#if SMITHPROXY_OPENSSL_QUIC
    if (ready_) return true;
    stopping_ = false;
    context_ = make_openssl_quic_context(true);
    client_context_ = make_openssl_quic_context(false);
    if (!context_ || !client_context_) {
        fail("cannot create OpenSSL QUIC context: " + openssl_error_stack());
        return false;
    }
    if (SSL_CTX_use_certificate_chain_file(context_.get(), certificate_.c_str()) != 1
        || SSL_CTX_use_PrivateKey_file(context_.get(), private_key_.c_str(), SSL_FILETYPE_PEM) != 1
        || SSL_CTX_check_private_key(context_.get()) != 1) {
        fail("cannot load QUIC certificate/key: " + openssl_error_stack());
        return false;
    }
    SSL_CTX_set_alpn_select_cb(context_.get(), select_h3, nullptr);
    // Initial spike behavior, matching the existing QUIC transport test. This
    // must be replaced by Smithproxy's policy-aware upstream verification.
    SSL_CTX_set_verify(client_context_.get(), SSL_VERIFY_NONE, nullptr);

    if (!open_socket()) return false;
    listener_ = openssl_listener::create(context_.get(), udp_fd_, transparent_);
    if (!listener_) {
        fail("cannot create OpenSSL QUIC listener: " + openssl_error_stack());
        return false;
    }
    ready_ = true;
    last_error_.clear();
    return true;
#else
    return open_socket();
#endif
}

void listener_service::run() {
#if SMITHPROXY_OPENSSL_QUIC
    if (!ready_ && !prepare()) return;

    pollfd descriptor { udp_fd_, POLLIN, 0 };
    while (!stopping_) {
        auto const polled = ::poll(&descriptor, 1, 50);
        if (polled < 0 && errno != EINTR) {
            fail(std::string("poll: ") + std::strerror(errno));
            break;
        }

        if (!listener_->handle_events() && !stopping_) {
            fail("OpenSSL QUIC listener event failure: " + openssl_error_stack());
            break;
        }
        while (auto accepted = listener_->accept()) {
            auto connection = std::shared_ptr<openssl_connection>(std::move(accepted));
            connections_.push_back(connection);
            pending_.push_back(std::move(connection));
        }
        for (auto const& connection : pending_) {
            connection->drain_events();
        }
        for (auto iterator = pending_.begin(); iterator != pending_.end();) {
            auto const& downstream = *iterator;
            if (!downstream->handshake_complete()) {
                ++iterator;
                continue;
            }
            auto upstream = connect_upstream(downstream->server_name());
            if (upstream) {
                session linked { downstream, upstream, nullptr };
                linked.proxy = std::make_unique<multiflow::MFProxy>(linked.downstream,
                                                                    linked.upstream);
                sessions_.push_back(std::move(linked));
            } else {
                downstream->close(1);
            }
            iterator = pending_.erase(iterator);
        }
        for (auto& linked : sessions_) {
            // Do not consume downstream flow-open events until the opposite
            // connection can actually create the matching stream.
            if (!linked.upstream->handshake_complete()) {
                linked.upstream->drain_events();
                continue;
            }
            linked.proxy->pump_once();
        }
    }
#endif
}

std::shared_ptr<openssl_connection> listener_service::connect_upstream(
    std::string const& host) {
#if SMITHPROXY_OPENSSL_QUIC
    if (host.empty() || !client_context_) return nullptr;
    addrinfo hints {};
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_DGRAM;
    hints.ai_protocol = IPPROTO_UDP;
    addrinfo* addresses = nullptr;
    auto const port = std::to_string(upstream_port_);
    if (::getaddrinfo(host.c_str(), port.c_str(), &hints, &addresses) != 0) return nullptr;

    std::shared_ptr<openssl_connection> result;
    for (auto* current = addresses; current && !result; current = current->ai_next) {
        std::string error;
        auto connection = connect_openssl_quic(client_context_.get(), current->ai_addr,
                                                current->ai_addrlen, host, &error);
        if (connection) result = std::shared_ptr<openssl_connection>(std::move(connection));
    }
    ::freeaddrinfo(addresses);
    return result;
#else
    (void)host;
    return nullptr;
#endif
}

void listener_service::stop() {
    stopping_ = true;
}

} // namespace sx::quic
