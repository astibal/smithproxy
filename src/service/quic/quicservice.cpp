#include "service/quic/quicservice.hpp"

#include <cerrno>
#include <cstring>
#include <utility>

#if SMITHPROXY_OPENSSL_QUIC
#include <arpa/inet.h>
#include <fcntl.h>
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
                                   std::string private_key, bool transparent)
    : port_(port), certificate_(std::move(certificate)),
      private_key_(std::move(private_key)), transparent_(transparent) {}

listener_service::~listener_service() {
    stop();
#if SMITHPROXY_OPENSSL_QUIC
    connections_.clear();
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
    if (!context_) {
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
            connections_.emplace_back(std::move(accepted));
        }
        for (auto const& connection : connections_) {
            connection->drain_events();
        }
    }
#endif
}

void listener_service::stop() {
    stopping_ = true;
}

} // namespace sx::quic
