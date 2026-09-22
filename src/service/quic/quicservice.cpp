#include "service/quic/quicservice.hpp"

#include <algorithm>
#include <cerrno>
#include <cstring>
#include <thread>
#include <utility>

#if SMITHPROXY_OPENSSL_QUIC
#include <arpa/inet.h>
#include <fcntl.h>
#include <netdb.h>
#include <netinet/in.h>
#include <poll.h>
#include <sys/socket.h>
#include <unistd.h>
#include <sslcertstore.hpp>
#include <sslmitmcom.hpp>
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

std::string endpoint_key(datagram_endpoint const& endpoint) {
    if (!endpoint.valid()) return {};
    auto const* begin = reinterpret_cast<char const*>(&endpoint.address);
    return std::string(begin, begin + endpoint.size);
}
#endif

} // namespace

listener_service::listener_service(std::uint16_t port, std::string certificate,
                                   std::string private_key, bool transparent,
                                   std::uint16_t upstream_port, bool verify_upstream)
    : port_(port), certificate_(std::move(certificate)),
      private_key_(std::move(private_key)), transparent_(transparent),
      upstream_port_(upstream_port), verify_upstream_(verify_upstream) {}

listener_service::~listener_service() {
    stop();
#if SMITHPROXY_OPENSSL_QUIC
    sessions_.clear();
    staged_upstreams_.clear();
    connection_count_ = 0;
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
    if (transparent_
        && ::setsockopt(udp_fd_, SOL_IP, IP_RECVORIGDSTADDR,
                        &enabled, sizeof(enabled)) != 0) {
        fail(std::string("IP_RECVORIGDSTADDR: ") + std::strerror(errno));
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
    if (verify_upstream_) {
        if (!SSLFactory::factory().set_verify_locations(client_context_.get())) {
            fail("cannot load QUIC upstream trust store");
            return false;
        }
        SSL_CTX_set_verify(client_context_.get(), SSL_VERIFY_PEER, nullptr);
        SSL_CTX_set_cert_cb(context_.get(), certificate_callback, this);
    } else {
        SSL_CTX_set_verify(client_context_.get(), SSL_VERIFY_NONE, nullptr);
    }

    if (!open_socket()) return false;
    listener_ = openssl_listener::create(
        context_.get(), udp_fd_, transparent_,
        [this](datagram_endpoint const& peer, datagram_endpoint const& destination) {
            original_destinations_[endpoint_key(peer)] = destination;
        });
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
            session incoming;
            if (auto found = staged_upstreams_.find(connection->native_handle());
                found != staged_upstreams_.end()) {
                incoming.upstream = std::move(found->second.connection);
                staged_upstreams_.erase(found);
            }
            incoming.downstream = std::move(connection);
            sessions_.push_back(std::move(incoming));
            ++connection_count_;
        }
        auto const now = std::chrono::steady_clock::now();
        static constexpr auto handshake_timeout = std::chrono::seconds(10);
        for (auto& linked : sessions_) {
            if (linked.state == session_state::handshake) {
                linked.downstream->drain_events();
                if (linked.downstream->closed() || now - linked.created >= handshake_timeout) {
                    linked.state = session_state::closed;
                } else if (!verify_upstream_ && linked.downstream->handshake_complete()
                           && !linked.upstream) {
                    linked.upstream = connect_upstream(linked.downstream->server_name());
                    if (!linked.upstream) linked.state = session_state::closed;
                } else if (linked.upstream) {
                    linked.upstream->drain_events();
                    if (linked.upstream->closed()) {
                        linked.state = session_state::closed;
                    } else if (linked.upstream->handshake_complete()) {
                        linked.proxy = std::make_unique<multiflow::MFProxy>(
                            linked.downstream, linked.upstream);
                        linked.state = session_state::active;
                    }
                }
            } else if (linked.state == session_state::active) {
                linked.proxy->pump_once();
                if (linked.downstream->closed() || linked.upstream->closed()) {
                    linked.state = session_state::closed;
                }
            }
        }
        auto const before = sessions_.size();
        sessions_.erase(std::remove_if(sessions_.begin(), sessions_.end(), [](auto& linked) {
            if (linked.state != session_state::closed) return false;
            if (linked.downstream) linked.downstream->close();
            if (linked.upstream) linked.upstream->close();
            return true;
        }), sessions_.end());
        connection_count_ -= before - sessions_.size();
        for (auto iterator = staged_upstreams_.begin(); iterator != staged_upstreams_.end();) {
            if (now - iterator->second.created < handshake_timeout) {
                ++iterator;
                continue;
            }
            iterator->second.connection->close();
            iterator = staged_upstreams_.erase(iterator);
        }
    }
#endif
}

int listener_service::certificate_callback(SSL* ssl, void* argument) {
    auto* service = static_cast<listener_service*>(argument);
    return service ? service->prepare_verified_certificate(ssl) : 0;
}

int listener_service::prepare_verified_certificate(SSL* downstream) {
    if (!downstream) return 0;
    if (staged_upstreams_.find(downstream) != staged_upstreams_.end()) return 1;

    auto const* raw_name = SSL_get_servername(downstream, TLSEXT_NAMETYPE_host_name);
    if (!raw_name || *raw_name == '\0') return 0;
    std::string const server_name(raw_name);
    datagram_endpoint peer_endpoint;
    BIO_ADDR* peer_address = BIO_ADDR_new();
    if (peer_address) {
        if (BIO_dgram_get_peer(SSL_get_rbio(downstream), peer_address) > 0) {
            peer_endpoint = endpoint_from_bio_address(peer_address);
        }
        BIO_ADDR_free(peer_address);
    }
    auto found_destination = original_destinations_.find(endpoint_key(peer_endpoint));
    if (found_destination == original_destinations_.end()) return 0;
    auto const destination = found_destination->second;
    original_destinations_.erase(found_destination);
    std::uint16_t destination_port = 0;
    auto const family = destination.address.ss_family;
    if (family == AF_INET) {
        destination_port = ntohs(reinterpret_cast<sockaddr_in const*>(
            &destination.address)->sin_port);
    } else if (family == AF_INET6) {
        destination_port = ntohs(reinterpret_cast<sockaddr_in6 const*>(
            &destination.address)->sin6_port);
    }
    // A shared UDP socket cannot select a different source port per datagram.
    // Bare transparent mode therefore requires TPROXY --on-port 0 and a
    // listener bound to the original service port.
    if (destination_port == 0 || destination_port != bound_port_) return 0;
    auto upstream = connect_upstream(destination, server_name);
    if (!upstream) return 0;

    auto const deadline = std::chrono::steady_clock::now() + std::chrono::seconds(5);
    while (!upstream->handshake_complete() && !upstream->closed()
           && std::chrono::steady_clock::now() < deadline) {
        upstream->drain_events();
        std::this_thread::sleep_for(std::chrono::milliseconds(1));
    }
    if (!upstream->handshake_complete()
        || SSL_get_verify_result(upstream->native_handle()) != X509_V_OK) {
        upstream->close(1);
        return 0;
    }

    X509* certificate = SSL_get1_peer_certificate(upstream->native_handle());
    if (!certificate) {
        upstream->close(1);
        return 0;
    }
    auto const installed = install_spoofed_certificate(downstream, certificate, server_name);
    X509_free(certificate);
    if (!installed) {
        upstream->close(1);
        return 0;
    }
    staged_upstreams_.emplace(downstream, staged_upstream { std::move(upstream) });
    return 1;
}

bool listener_service::install_spoofed_certificate(SSL* downstream, X509* upstream,
                                                   std::string const& server_name) {
    if (!downstream || !upstream || server_name.empty()) return false;
    if (X509_check_host(upstream, server_name.c_str(), server_name.size(), 0, nullptr) != 1) {
        return false;
    }

    SpoofOptions options;
    options.sni = server_name;
    auto& factory = SSLFactory::factory();
    auto const store_key = SSLFactory::make_store_key(upstream, options);
    auto lock = std::scoped_lock(factory.lock());
    auto install = [downstream](X509* certificate, EVP_PKEY* key) {
        return certificate && key
            && SSL_use_certificate(downstream, certificate) == 1
            && SSL_use_PrivateKey(downstream, key) == 1
            && SSL_check_private_key(downstream) == 1;
    };
    auto cached = factory.find_mitm(store_key);
    if (cached) return install(cached->chain.cert, cached->chain.key);

    auto forged = factory.spoof(upstream, false, nullptr);
    if (!forged || !forged->chain.cert || !forged->chain.key) return false;
    if (!install(forged->chain.cert, forged->chain.key)) return false;
    EVP_PKEY_up_ref(forged->chain.key);
    return factory.add_mitm(store_key, *forged);
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

std::shared_ptr<openssl_connection> listener_service::connect_upstream(
    datagram_endpoint const& target, std::string const& server_name) {
#if SMITHPROXY_OPENSSL_QUIC
    if (!target.valid() || server_name.empty() || !client_context_) return nullptr;
    std::string error;
    auto connection = connect_openssl_quic(
        client_context_.get(), reinterpret_cast<sockaddr const*>(&target.address),
        target.size, server_name, &error);
    return connection
        ? std::shared_ptr<openssl_connection>(std::move(connection))
        : nullptr;
#else
    (void)target;
    (void)server_name;
    return nullptr;
#endif
}

void listener_service::stop() {
    stopping_ = true;
}

} // namespace sx::quic
