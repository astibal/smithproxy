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
        : SSL_TLSEXT_ERR_ALERT_FATAL;
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
                                   std::uint16_t upstream_port, bool verify_upstream,
                                   lifecycle_options lifecycle, resource_limits limits,
                                   std::string upstream_host)
    : port_(port), certificate_(std::move(certificate)),
      private_key_(std::move(private_key)), transparent_(transparent),
      upstream_port_(upstream_port), upstream_host_(std::move(upstream_host)),
      verify_upstream_(verify_upstream), lifecycle_(lifecycle), limits_(limits) {}

diagnostics_snapshot listener_service::diagnostics() const {
    return {
        connection_count_.load(), accepted_sessions_.load(), completed_sessions_.load(),
        handshake_timeouts_.load(), handshake_failures_.load(), idle_timeouts_.load(),
        upstream_failures_.load(), alpn_failures_.load(),
        session_limit_rejections_.load(), stream_limit_rejections_.load(),
        certificate_job_limit_rejections_.load()
    };
}

listener_service::~listener_service() {
    stop();
#if SMITHPROXY_OPENSSL_QUIC
    sessions_.clear();
    for (auto& job : certificate_jobs_) {
        try {
            auto result = job.second.result.get();
            if (result.connection) result.connection->close();
        } catch (...) {
        }
    }
    certificate_jobs_.clear();
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
    auto attach_staged_upstream = [this](session& incoming) {
        if (!incoming.downstream || incoming.upstream) return;
        auto found = staged_upstreams_.find(incoming.downstream->native_handle());
        if (found == staged_upstreams_.end()) return;
        incoming.upstream = std::move(found->second.connection);
        staged_upstreams_.erase(found);
    };
    while (!stopping_) {
        auto const polled = ::poll(&descriptor, 1, 50);
        if (polled < 0 && errno != EINTR) {
            fail(std::string("poll: ") + std::strerror(errno));
            break;
        }

        // Do not pre-classify this shared UDP socket with MSG_PEEK. OpenSSL may
        // receive a batch after the peek, so a following DTLS datagram could
        // still cross that boundary and make the apparent demultiplexing racy.
        // Supporting QUIC and DTLS on one port requires a dispatcher which owns
        // recvmsg() and injects only classified QUIC datagrams into OpenSSL.
        if (!listener_->handle_events() && !stopping_) {
            fail("OpenSSL QUIC listener event failure: " + openssl_error_stack());
            break;
        }
        while (auto accepted = listener_->accept()) {
            auto connection = std::shared_ptr<openssl_connection>(std::move(accepted));
            if (sessions_.size() >= limits_.max_sessions) {
                ++session_limit_rejections_;
                connection->close(0x107);
                continue;
            }
            session incoming;
            incoming.downstream = std::move(connection);
            attach_staged_upstream(incoming);
            sessions_.push_back(std::move(incoming));
            ++connection_count_;
            ++accepted_sessions_;
        }
        auto const now = std::chrono::steady_clock::now();
        for (auto& linked : sessions_) {
            if (linked.state == session_state::handshake) {
                attach_staged_upstream(linked);
                // Once the client handshake completes, preserve any early
                // flow_open events until MFProxy exists. Draining here would
                // irreversibly discard streams opened while the upstream leg
                // is still finishing its handshake.
                if (!linked.downstream->handshake_complete()) {
                    linked.downstream->drain_events();
                }
                if (linked.downstream->closed()) {
                    ++handshake_failures_;
                    start_draining(linked, now);
                } else if (now - linked.created >= lifecycle_.handshake_timeout) {
                    ++handshake_timeouts_;
                    start_draining(linked, now);
                } else if (!verify_upstream_ && linked.downstream->handshake_complete()
                           && !linked.upstream) {
                    linked.upstream = connect_upstream(linked.downstream->server_name());
                    if (!linked.upstream) {
                        ++upstream_failures_;
                        start_draining(linked, now);
                    }
                } else if (linked.upstream) {
                    linked.upstream->drain_events();
                    if (linked.upstream->closed()) {
                        ++upstream_failures_;
                        start_draining(linked, now);
                    } else if (linked.upstream->handshake_complete()) {
                        auto const downstream_alpn = linked.downstream->negotiated_alpn();
                        auto const upstream_alpn = linked.upstream->negotiated_alpn();
                        if (downstream_alpn.empty() || downstream_alpn != upstream_alpn) {
                            ++alpn_failures_;
                            start_draining(linked, now, 1);
                            continue;
                        }
                        linked.proxy = std::make_unique<multiflow::MFProxy>(
                            linked.downstream, linked.upstream,
                            multiflow::MFProxy::limits {
                                limits_.max_streams_per_session,
                                limits_.stream_buffer_bytes });
                        linked.state = session_state::active;
                        linked.last_activity = now;
                    }
                }
            } else if (linked.state == session_state::active) {
                if (linked.proxy->pump_once() != 0) linked.last_activity = now;
                auto const rejected = linked.proxy->limit_rejections();
                if (rejected > linked.reported_stream_limit_rejections) {
                    stream_limit_rejections_ +=
                        rejected - linked.reported_stream_limit_rejections;
                    linked.reported_stream_limit_rejections = rejected;
                }
                if (linked.downstream->closed() || linked.upstream->closed()
                    || now - linked.last_activity >= lifecycle_.idle_timeout) {
                    if (!linked.downstream->closed() && !linked.upstream->closed()) {
                        ++idle_timeouts_;
                    }
                    start_draining(linked, now);
                }
            } else {
                if (linked.downstream) linked.downstream->drain_events();
                if (linked.upstream) linked.upstream->drain_events();
            }
        }
        auto const before = sessions_.size();
        sessions_.erase(std::remove_if(sessions_.begin(), sessions_.end(), [&](auto& linked) {
            return linked.state == session_state::draining
                && now - linked.draining_since >= lifecycle_.drain_timeout;
        }), sessions_.end());
        connection_count_ -= before - sessions_.size();
        completed_sessions_ += before - sessions_.size();
        for (auto iterator = staged_upstreams_.begin(); iterator != staged_upstreams_.end();) {
            if (now - iterator->second.created < lifecycle_.handshake_timeout) {
                ++iterator;
                continue;
            }
            iterator->second.connection->close();
            ++upstream_failures_;
            iterator = staged_upstreams_.erase(iterator);
        }
    }
    cleanup_sessions();
#endif
}

#if SMITHPROXY_OPENSSL_QUIC
void listener_service::start_draining(session& value,
                                      std::chrono::steady_clock::time_point now,
                                      std::uint64_t protocol_error) {
    if (value.state == session_state::draining) return;
    value.state = session_state::draining;
    value.draining_since = now;
    value.proxy.reset();
    if (value.downstream) value.downstream->close(protocol_error);
    if (value.upstream) value.upstream->close(protocol_error);
}

void listener_service::cleanup_sessions() {
    completed_sessions_ += sessions_.size();
    for (auto& linked : sessions_) {
        if (linked.downstream) linked.downstream->close();
        if (linked.upstream) linked.upstream->close();
    }
    sessions_.clear();
    for (auto& staged : staged_upstreams_) staged.second.connection->close();
    staged_upstreams_.clear();
    for (auto& job : certificate_jobs_) {
        try {
            auto result = job.second.result.get();
            if (result.connection) result.connection->close();
        } catch (...) {
        }
    }
    certificate_jobs_.clear();
    original_destinations_.clear();
    connection_count_ = 0;
}
#endif

#if SMITHPROXY_OPENSSL_QUIC
int listener_service::certificate_callback(SSL* ssl, void* argument) {
    auto* service = static_cast<listener_service*>(argument);
    return service ? service->prepare_verified_certificate(ssl) : 0;
}

int listener_service::prepare_verified_certificate(SSL* downstream) {
    if (!downstream) return 0;
    if (staged_upstreams_.find(downstream) != staged_upstreams_.end()) return 1;

    if (auto found = certificate_jobs_.find(downstream);
        found != certificate_jobs_.end()) {
        if (found->second.result.wait_for(std::chrono::milliseconds(0))
            != std::future_status::ready) {
            return -1;
        }
        verified_certificate verified;
        try {
            verified = found->second.result.get();
        } catch (...) {
            certificate_jobs_.erase(found);
            return 0;
        }
        certificate_jobs_.erase(found);
        if (!verified.connection || !install_verified_certificate(downstream, verified)) {
            ++upstream_failures_;
            if (verified.connection) verified.connection->close(1);
            return 0;
        }
        staged_upstreams_.emplace(
            downstream, staged_upstream { std::move(verified.connection) });
        return 1;
    }

    auto const* raw_name = SSL_get_servername(downstream, TLSEXT_NAMETYPE_host_name);
    if (!raw_name || *raw_name == '\0') return 0;
    std::string const server_name(raw_name);
    datagram_endpoint destination;
    if (transparent_) {
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
        destination = found_destination->second;
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
    }
    if (certificate_jobs_.size() >= limits_.max_certificate_jobs) {
        ++certificate_job_limit_rejections_;
        return 0;
    }
    try {
        certificate_jobs_.emplace(
            downstream,
            certificate_job { std::async(std::launch::async,
                [this, destination, server_name]() mutable {
                    return verify_and_spoof(std::move(destination), std::move(server_name));
                }) });
    } catch (...) {
        return 0;
    }
    return -1;
}

listener_service::verified_certificate listener_service::verify_and_spoof(
    datagram_endpoint destination, std::string server_name) {
    verified_certificate verified;
    auto upstream = transparent_
        ? connect_upstream(destination, server_name)
        : connect_upstream(server_name);
    if (!upstream) return verified;

    auto const deadline = std::chrono::steady_clock::now() + std::chrono::seconds(5);
    while (!upstream->handshake_complete() && !upstream->closed()
           && std::chrono::steady_clock::now() < deadline) {
        upstream->drain_events();
        std::this_thread::sleep_for(std::chrono::milliseconds(1));
    }
    if (!upstream->handshake_complete()
        || SSL_get_verify_result(upstream->native_handle()) != X509_V_OK) {
        upstream->close(1);
        return verified;
    }
    if (upstream->negotiated_alpn() != "h3") {
        upstream->close(1);
        return verified;
    }

    X509* certificate = SSL_get1_peer_certificate(upstream->native_handle());
    if (!certificate) {
        upstream->close(1);
        return verified;
    }
    if (X509_check_host(certificate, server_name.c_str(), server_name.size(), 0, nullptr) != 1) {
        X509_free(certificate);
        upstream->close(1);
        return verified;
    }

    SpoofOptions options;
    options.sni = server_name;
    auto& factory = SSLFactory::factory();
    auto const store_key = SSLFactory::make_store_key(certificate, options);
    auto lock = std::scoped_lock(factory.lock());
    auto retain = [&verified](X509* cert, EVP_PKEY* key) {
        if (!cert || !key || X509_up_ref(cert) != 1) return false;
        if (EVP_PKEY_up_ref(key) != 1) {
            X509_free(cert);
            return false;
        }
        verified.certificate = std::shared_ptr<X509>(cert, X509_free);
        verified.private_key = std::shared_ptr<EVP_PKEY>(key, EVP_PKEY_free);
        return true;
    };
    auto cached = factory.find_mitm(store_key);
    bool ready = cached && retain(cached->chain.cert, cached->chain.key);
    if (!ready) {
        auto forged = factory.spoof(certificate, false, nullptr);
        if (forged && forged->chain.cert && forged->chain.key) {
            ready = retain(forged->chain.cert, forged->chain.key);
            // ptr_cache uses allocator state tied to the allocating thread.
            // Certificate jobs run asynchronously, so publishing a new cache
            // node here would leave teardown to free it from another thread.
            // Keep the retained result session-local; existing cache entries
            // remain readable until cache publication is moved to its owner.
            X509_free(forged->chain.cert);
            forged->nullify(); // SSLFactory::spoof() returns def_sr_key as borrowed.
        }
    }
    X509_free(certificate);
    if (!ready) {
        upstream->close(1);
        return {};
    }
    verified.connection = std::move(upstream);
    return verified;
}

bool listener_service::install_verified_certificate(
    SSL* downstream, verified_certificate const& verified) {
    return downstream && verified.certificate && verified.private_key
        && SSL_use_certificate(downstream, verified.certificate.get()) == 1
        && SSL_use_PrivateKey(downstream, verified.private_key.get()) == 1
        && SSL_check_private_key(downstream) == 1;
}

std::shared_ptr<openssl_connection> listener_service::connect_upstream(
    std::string const& host) {
    if (host.empty() || !client_context_) return nullptr;
    addrinfo hints {};
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_DGRAM;
    hints.ai_protocol = IPPROTO_UDP;
    addrinfo* addresses = nullptr;
    auto const port = std::to_string(upstream_port_);
    auto const& address_host = upstream_host_.empty() ? host : upstream_host_;
    if (::getaddrinfo(address_host.c_str(), port.c_str(), &hints, &addresses) != 0) {
        return nullptr;
    }

    std::shared_ptr<openssl_connection> result;
    for (auto* current = addresses; current && !result; current = current->ai_next) {
        std::string error;
        auto connection = connect_openssl_quic(client_context_.get(), current->ai_addr,
                                                current->ai_addrlen, host, &error);
        if (connection) result = std::shared_ptr<openssl_connection>(std::move(connection));
    }
    ::freeaddrinfo(addresses);
    return result;
}

std::shared_ptr<openssl_connection> listener_service::connect_upstream(
    datagram_endpoint const& target, std::string const& server_name) {
    if (!target.valid() || server_name.empty() || !client_context_) return nullptr;
    std::string error;
    auto connection = connect_openssl_quic(
        client_context_.get(), reinterpret_cast<sockaddr const*>(&target.address),
        target.size, server_name, &error);
    return connection
        ? std::shared_ptr<openssl_connection>(std::move(connection))
        : nullptr;
}
#endif

void listener_service::stop() {
    stopping_ = true;
}

} // namespace sx::quic
