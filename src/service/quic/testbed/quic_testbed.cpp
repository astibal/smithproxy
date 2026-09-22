#include <gtest/gtest.h>

#include "proxy/quic/openssl.hpp"
#include "service/quic/quicservice.hpp"

#include <sslcertstore.hpp>
#include <log/logger.hpp>
#include <openssl/pem.h>
#include <openssl/x509v3.h>

#include <arpa/inet.h>
#include <fcntl.h>
#include <unistd.h>

#include <atomic>
#include <algorithm>
#include <chrono>
#include <cstring>
#include <filesystem>
#include <deque>
#include <map>
#include <memory>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

namespace quic = sx::quic;
namespace mf = sx::multiflow;
using namespace std::chrono_literals;

#if SMITHPROXY_OPENSSL_QUIC
namespace {

constexpr char test_sni[] = "localhost";
std::string test_pki_directory;

sockaddr_in loopback(std::uint16_t port);

std::string pki_file(char const* name) {
    return test_pki_directory + "/" + name;
}

using unique_pkey = std::unique_ptr<EVP_PKEY, decltype(&EVP_PKEY_free)>;
using unique_x509 = std::unique_ptr<X509, decltype(&X509_free)>;

unique_pkey generate_rsa_key() {
    EVP_PKEY_CTX* context = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, nullptr);
    EVP_PKEY* key = nullptr;
    if (!context || EVP_PKEY_keygen_init(context) != 1
        || EVP_PKEY_CTX_set_rsa_keygen_bits(context, 2048) != 1
        || EVP_PKEY_keygen(context, &key) != 1) {
        EVP_PKEY_CTX_free(context);
        return { nullptr, EVP_PKEY_free };
    }
    EVP_PKEY_CTX_free(context);
    return { key, EVP_PKEY_free };
}

bool add_extension(X509* certificate, X509* issuer, int nid, char const* value) {
    X509V3_CTX context;
    X509V3_set_ctx(&context, issuer, certificate, nullptr, nullptr, 0);
    X509_EXTENSION* extension = X509V3_EXT_conf_nid(nullptr, &context, nid,
                                                    const_cast<char*>(value));
    if (!extension) return false;
    auto const added = X509_add_ext(certificate, extension, -1) == 1;
    X509_EXTENSION_free(extension);
    return added;
}

unique_x509 generate_certificate(EVP_PKEY* key, char const* common_name,
                                 X509* issuer, EVP_PKEY* issuer_key, long serial,
                                 bool certificate_authority) {
    unique_x509 certificate(X509_new(), X509_free);
    if (!certificate || X509_set_version(certificate.get(), 2) != 1
        || ASN1_INTEGER_set(X509_get_serialNumber(certificate.get()), serial) != 1
        || X509_gmtime_adj(X509_getm_notBefore(certificate.get()), -60) == nullptr
        || X509_gmtime_adj(X509_getm_notAfter(certificate.get()), 86400) == nullptr
        || X509_set_pubkey(certificate.get(), key) != 1) {
        return { nullptr, X509_free };
    }
    X509_NAME* subject = X509_get_subject_name(certificate.get());
    if (!subject
        || X509_NAME_add_entry_by_txt(subject, "CN", MBSTRING_ASC,
                                      reinterpret_cast<unsigned char const*>(common_name),
                                      -1, -1, 0) != 1
        || X509_set_issuer_name(certificate.get(), issuer
            ? X509_get_subject_name(issuer) : subject) != 1) {
        return { nullptr, X509_free };
    }
    if (certificate_authority) {
        if (!add_extension(certificate.get(), certificate.get(), NID_basic_constraints,
                           "critical,CA:TRUE")
            || !add_extension(certificate.get(), certificate.get(), NID_key_usage,
                              "critical,keyCertSign,cRLSign")) {
            return { nullptr, X509_free };
        }
    } else if (!add_extension(certificate.get(), issuer, NID_basic_constraints,
                              "critical,CA:FALSE")
               || !add_extension(certificate.get(), issuer, NID_key_usage,
                                 "critical,digitalSignature,keyEncipherment")
               || !add_extension(certificate.get(), issuer, NID_ext_key_usage,
                                 "serverAuth,clientAuth")
               || !add_extension(certificate.get(), issuer, NID_subject_alt_name,
                                 "DNS:localhost")) {
        return { nullptr, X509_free };
    }
    if (X509_sign(certificate.get(), issuer_key ? issuer_key : key, EVP_sha256()) <= 0) {
        return { nullptr, X509_free };
    }
    return certificate;
}

bool write_key(std::string const& path, EVP_PKEY* key) {
    BIO* output = BIO_new_file(path.c_str(), "w");
    if (!output) return false;
    auto const written = PEM_write_bio_PrivateKey(output, key, nullptr, nullptr, 0,
                                                   nullptr, nullptr) == 1;
    BIO_free(output);
    return written;
}

bool write_certificate(std::string const& path, X509* certificate) {
    BIO* output = BIO_new_file(path.c_str(), "w");
    if (!output) return false;
    auto const written = PEM_write_bio_X509(output, certificate) == 1;
    BIO_free(output);
    return written;
}

bool create_test_pki() {
    std::string pattern = "/tmp/smithproxy-quic-testbed-XXXXXX";
    std::vector<char> directory(pattern.begin(), pattern.end());
    directory.push_back('\0');
    auto* created = mkdtemp(directory.data());
    if (!created) return false;
    test_pki_directory = created;

    auto ca_key = generate_rsa_key();
    auto ca = generate_certificate(ca_key.get(), "Smithproxy QUIC Test CA",
                                   nullptr, nullptr, 1, true);
    auto leaf_key = generate_rsa_key();
    auto leaf = generate_certificate(leaf_key.get(), "localhost", ca.get(),
                                     ca_key.get(), 2, false);
    if (!ca_key || !ca || !leaf_key || !leaf) return false;
    if (!write_key(pki_file("ca-key.pem"), ca_key.get())
        || !write_certificate(pki_file("ca-cert.pem"), ca.get())) {
        return false;
    }
    for (auto const* prefix : { "srv", "cl", "portal" }) {
        if (!write_key(pki_file((std::string(prefix) + "-key.pem").c_str()), leaf_key.get())
            || !write_certificate(pki_file((std::string(prefix) + "-cert.pem").c_str()),
                                  leaf.get())) {
            return false;
        }
    }
    return true;
}

int select_h3(SSL*, const unsigned char** output, unsigned char* output_size,
              const unsigned char* input, unsigned input_size, void*) {
    static constexpr unsigned char supported[] = { 2, 'h', '3' };
    return SSL_select_next_proto(const_cast<unsigned char**>(output), output_size,
                                 supported, sizeof(supported), input, input_size)
            == OPENSSL_NPN_NEGOTIATED
        ? SSL_TLSEXT_ERR_OK
        : SSL_TLSEXT_ERR_ALERT_FATAL;
}

bool make_nonblocking(int fd) {
    auto const flags = fcntl(fd, F_GETFL, 0);
    return flags >= 0 && fcntl(fd, F_SETFL, flags | O_NONBLOCK) == 0;
}

std::vector<unsigned char> fingerprint(X509* certificate) {
    std::vector<unsigned char> result(EVP_MAX_MD_SIZE);
    unsigned int size = 0;
    if (!certificate
        || X509_digest(certificate, EVP_sha256(), result.data(), &size) != 1) {
        return {};
    }
    result.resize(size);
    return result;
}

quic::unique_ssl_ctx make_verified_client_context() {
    auto context = quic::make_openssl_quic_context(false);
    if (!context) return {};
    if (SSL_CTX_load_verify_locations(context.get(), pki_file("ca-cert.pem").c_str(),
                                      nullptr) != 1) {
        return {};
    }
    SSL_CTX_set_verify(context.get(), SSL_VERIFY_PEER, nullptr);
    return context;
}

class origin_server {
public:
    origin_server() {
        context_ = quic::make_openssl_quic_context(true);
        if (!context_) return;

        X509* source = nullptr;
        BIO* input = BIO_new_file(pki_file("srv-cert.pem").c_str(), "r");
        if (input) {
            source = PEM_read_bio_X509(input, nullptr, nullptr, nullptr);
            BIO_free(input);
        }
        if (!source) return;

        std::vector<std::string> additional_sans { "DNS:localhost" };
        auto& factory = SSLFactory::factory();
        std::optional<CertificateChainCtx> generated;
        {
            auto lock = std::scoped_lock(factory.lock());
            generated = factory.spoof(source, false, &additional_sans);
        }
        X509_free(source);
        if (!generated || !generated->chain.cert || !generated->chain.key) return;

        certificate_fingerprint_ = fingerprint(generated->chain.cert);
        bool const installed = SSL_CTX_use_certificate(context_.get(), generated->chain.cert) == 1
            && SSL_CTX_use_PrivateKey(context_.get(), generated->chain.key) == 1
            && SSL_CTX_check_private_key(context_.get()) == 1;
        X509_free(generated->chain.cert);
        generated->nullify(); // SSLFactory::spoof() lends the factory's server key.
        if (!installed) return;
        SSL_CTX_set_alpn_select_cb(context_.get(), select_h3, nullptr);

        fd_ = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
        if (fd_ < 0 || !make_nonblocking(fd_)) return;
        sockaddr_in address {};
        address.sin_family = AF_INET;
        address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        if (bind(fd_, reinterpret_cast<sockaddr*>(&address), sizeof(address)) != 0) return;
        socklen_t size = sizeof(address);
        if (getsockname(fd_, reinterpret_cast<sockaddr*>(&address), &size) != 0) return;
        port_ = ntohs(address.sin_port);
        listener_ = quic::openssl_listener::create(context_.get(), fd_, false);
        if (!listener_) return;
        ready_ = true;
        thread_ = std::thread([this]() { run(); });
    }

    ~origin_server() {
        stopping_ = true;
        if (thread_.joinable()) thread_.join();
        connections_.clear();
        listener_.reset();
        if (fd_ >= 0) close(fd_);
    }

    bool ready() const { return ready_; }
    std::uint16_t port() const { return port_; }
    std::vector<unsigned char> const& certificate_fingerprint() const {
        return certificate_fingerprint_;
    }
    std::size_t handshake_count() const { return handshake_count_; }
    std::size_t echoed_messages() const { return echoed_messages_; }

    std::vector<std::string> observed_sni() const {
        auto lock = std::scoped_lock(observations_lock_);
        return observed_sni_;
    }

    std::vector<std::string> observed_alpn() const {
        auto lock = std::scoped_lock(observations_lock_);
        return observed_alpn_;
    }

private:
    struct connection_state {
        std::unique_ptr<quic::openssl_connection> connection;
        std::vector<mf::flow_handle> flows;
        bool handshake_recorded = false;
    };

    void run() {
        while (!stopping_) {
            listener_->handle_events();
            while (auto accepted = listener_->accept()) {
                connections_.push_back({ std::move(accepted), {}, false });
            }
            for (auto& state : connections_) {
                auto events = state.connection->drain_events();
                if (state.connection->handshake_complete() && !state.handshake_recorded) {
                    state.handshake_recorded = true;
                    ++handshake_count_;
                    auto lock = std::scoped_lock(observations_lock_);
                    observed_sni_.push_back(state.connection->server_name());
                    observed_alpn_.push_back(state.connection->negotiated_alpn());
                }
                for (auto const& event : events) {
                    if (event.type == mf::event_type::flow_open && event.flow) {
                        state.flows.push_back(*event.flow);
                    } else if ((event.type == mf::event_type::reset
                                || event.type == mf::event_type::peer_fin)
                               && event.flow) {
                        state.flows.erase(
                            std::remove(state.flows.begin(), state.flows.end(), *event.flow),
                            state.flows.end());
                    }
                }
                for (auto const flow : state.flows) {
                    unsigned char buffer[2048] {};
                    auto const read = state.connection->read(flow, buffer, sizeof(buffer));
                    if (read.size == 0) continue;
                    std::size_t offset = 0;
                    while (offset < read.size) {
                        auto const written = state.connection->write(
                            flow, buffer + offset, read.size - offset);
                        offset += written.size;
                        if (written.status == mf::io_status::would_block) break;
                        if (written.status != mf::io_status::ok) break;
                    }
                    if (offset == read.size) ++echoed_messages_;
                }
            }
            std::this_thread::sleep_for(1ms);
        }
        for (auto& state : connections_) state.connection->close();
    }

    quic::unique_ssl_ctx context_;
    int fd_ = -1;
    std::uint16_t port_ = 0;
    bool ready_ = false;
    std::unique_ptr<quic::openssl_listener> listener_;
    std::atomic_bool stopping_ = false;
    std::thread thread_;
    std::vector<connection_state> connections_;
    std::vector<unsigned char> certificate_fingerprint_;
    std::atomic_size_t handshake_count_ = 0;
    std::atomic_size_t echoed_messages_ = 0;
    mutable std::mutex observations_lock_;
    std::vector<std::string> observed_sni_;
    std::vector<std::string> observed_alpn_;
};

/** Deterministic bidirectional UDP relay used to inject transport faults. */
class udp_fault_relay {
public:
    struct profile {
        std::size_t drop_every = 0;
        std::size_t duplicate_every = 0;
        std::size_t reorder_every = 0;
        std::size_t mtu = 65535;
        std::chrono::milliseconds delay {};
    };

    udp_fault_relay(std::uint16_t target_port, profile faults)
        : faults_(faults) {
        target_ = loopback(target_port);
        fd_ = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
        if (fd_ < 0 || !make_nonblocking(fd_)) return;
        auto address = loopback(0);
        if (bind(fd_, reinterpret_cast<sockaddr*>(&address), sizeof(address)) != 0) return;
        socklen_t size = sizeof(address);
        if (getsockname(fd_, reinterpret_cast<sockaddr*>(&address), &size) != 0) return;
        port_ = ntohs(address.sin_port);
        ready_ = true;
        thread_ = std::thread([this]() { run(); });
    }

    ~udp_fault_relay() {
        stopping_ = true;
        if (thread_.joinable()) thread_.join();
        if (fd_ >= 0) close(fd_);
    }

    bool ready() const { return ready_; }
    std::uint16_t port() const { return port_; }
    std::size_t received() const { return received_; }
    std::size_t dropped() const { return dropped_; }
    std::size_t duplicated() const { return duplicated_; }
    std::size_t reordered() const { return reordered_; }
    std::size_t mtu_dropped() const { return mtu_dropped_; }

private:
    struct queued_datagram {
        std::vector<unsigned char> data;
        sockaddr_in destination {};
        std::chrono::steady_clock::time_point due;
    };

    static bool same_endpoint(sockaddr_in const& lhs, sockaddr_in const& rhs) {
        return lhs.sin_family == rhs.sin_family
            && lhs.sin_port == rhs.sin_port
            && lhs.sin_addr.s_addr == rhs.sin_addr.s_addr;
    }

    void enqueue(std::vector<unsigned char> const& data, sockaddr_in destination,
                 std::chrono::milliseconds extra_delay = {}) {
        queue_.push_back({ data, destination,
                           std::chrono::steady_clock::now() + faults_.delay + extra_delay });
    }

    void receive_one() {
        unsigned char buffer[65536] {};
        sockaddr_in source {};
        socklen_t source_size = sizeof(source);
        auto const count = recvfrom(fd_, buffer, sizeof(buffer), 0,
                                    reinterpret_cast<sockaddr*>(&source), &source_size);
        if (count <= 0) return;
        ++received_;
        bool const from_target = same_endpoint(source, target_);
        if (!from_target) client_ = source;
        if (from_target && client_.sin_port == 0) return;
        sockaddr_in const destination = from_target ? client_ : target_;
        auto const size = static_cast<std::size_t>(count);
        if (size > faults_.mtu) {
            ++mtu_dropped_;
            return;
        }
        if (faults_.drop_every != 0 && received_ % faults_.drop_every == 0) {
            ++dropped_;
            return;
        }
        std::vector<unsigned char> data(buffer, buffer + size);
        if (faults_.reorder_every != 0 && received_ % faults_.reorder_every == 0) {
            // A delayed selected datagram is overtaken by subsequent traffic.
            enqueue(data, destination, 15ms);
            ++reordered_;
        } else {
            enqueue(data, destination);
        }
        if (faults_.duplicate_every != 0 && received_ % faults_.duplicate_every == 0) {
            enqueue(data, destination, 1ms);
            ++duplicated_;
        }
    }

    void flush_due() {
        auto const now = std::chrono::steady_clock::now();
        for (auto iterator = queue_.begin(); iterator != queue_.end();) {
            if (iterator->due > now) {
                ++iterator;
                continue;
            }
            sendto(fd_, iterator->data.data(), iterator->data.size(), 0,
                   reinterpret_cast<sockaddr*>(&iterator->destination),
                   sizeof(iterator->destination));
            iterator = queue_.erase(iterator);
        }
    }

    void run() {
        while (!stopping_) {
            for (;;) {
                auto const before = received_.load();
                receive_one();
                if (received_.load() == before) break;
            }
            flush_due();
            std::this_thread::sleep_for(1ms);
        }
        flush_due();
    }

    profile faults_;
    int fd_ = -1;
    std::uint16_t port_ = 0;
    bool ready_ = false;
    sockaddr_in target_ {};
    sockaddr_in client_ {};
    std::deque<queued_datagram> queue_;
    std::atomic_bool stopping_ = false;
    std::thread thread_;
    std::atomic_size_t received_ = 0;
    std::atomic_size_t dropped_ = 0;
    std::atomic_size_t duplicated_ = 0;
    std::atomic_size_t reordered_ = 0;
    std::atomic_size_t mtu_dropped_ = 0;
};

struct client_flow {
    mf::flow_handle handle;
    std::string expected;
    std::string received;
};

struct client_state {
    std::unique_ptr<quic::openssl_connection> connection;
    std::vector<client_flow> flows;
};

sockaddr_in loopback(std::uint16_t port) {
    sockaddr_in result {};
    result.sin_family = AF_INET;
    result.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    result.sin_port = htons(port);
    return result;
}

/** Own the service thread and guarantee bounded cleanup on every assertion path. */
class running_service {
public:
    explicit running_service(quic::listener_service& service)
        : service_(service), thread_([this]() { service_.run(); }) {}

    ~running_service() { stop(); }

    void stop() {
        service_.stop();
        if (thread_.joinable()) thread_.join();
    }

private:
    quic::listener_service& service_;
    std::thread thread_;
};

/** Progress one client until its handshake completes, closes, or times out. */
bool await_handshake(quic::openssl_connection& connection,
                     std::chrono::milliseconds timeout = 3s) {
    auto const deadline = std::chrono::steady_clock::now() + timeout;
    while (!connection.handshake_complete() && !connection.closed()
           && std::chrono::steady_clock::now() < deadline) {
        connection.drain_events();
        std::this_thread::sleep_for(1ms);
    }
    return connection.handshake_complete();
}

class QuicFaultProfile : public ::testing::TestWithParam<udp_fault_relay::profile> {};

TEST_P(QuicFaultProfile, VerifiedMitmSurvivesUdpImpairment) {
    origin_server origin;
    ASSERT_TRUE(origin.ready());
    quic::listener_service proxy(0, pki_file("srv-cert.pem"), pki_file("srv-key.pem"), false,
                                 origin.port(), true, {}, {}, "127.0.0.1");
    ASSERT_TRUE(proxy.prepare()) << proxy.last_error();
    running_service runner(proxy);
    udp_fault_relay relay(proxy.bound_port(), GetParam());
    ASSERT_TRUE(relay.ready());

    auto context = make_verified_client_context();
    ASSERT_NE(context, nullptr);
    auto const address = loopback(relay.port());
    std::string error;
    auto client = quic::connect_openssl_quic(
        context.get(), reinterpret_cast<sockaddr const*>(&address), sizeof(address),
        test_sni, &error);
    ASSERT_NE(client, nullptr) << error;
    ASSERT_TRUE(await_handshake(*client, 15s))
        << "received=" << relay.received()
        << " dropped=" << relay.dropped()
        << " duplicated=" << relay.duplicated()
        << " reordered=" << relay.reordered()
        << " mtu_dropped=" << relay.mtu_dropped();

    auto const flow = client->open_flow(mf::direction::bidirectional);
    ASSERT_NE(flow.generation, 0U);
    std::string payload(8192, '\0');
    for (std::size_t index = 0; index < payload.size(); ++index) {
        payload[index] = static_cast<char>('a' + (index % 19));
    }
    std::size_t sent = 0;
    std::string received;
    auto const deadline = std::chrono::steady_clock::now() + 15s;
    while (received.size() < payload.size()
           && std::chrono::steady_clock::now() < deadline) {
        client->drain_events();
        if (sent < payload.size()) {
            auto const written = client->write(flow, payload.data() + sent,
                                                payload.size() - sent);
            sent += written.size;
        }
        unsigned char buffer[2048] {};
        auto const read = client->read(flow, buffer, sizeof(buffer));
        if (read.size != 0) {
            received.append(reinterpret_cast<char const*>(buffer), read.size);
        }
        std::this_thread::sleep_for(1ms);
    }
    EXPECT_EQ(received, payload);
    EXPECT_GT(relay.received(), 0U);
    if (GetParam().drop_every != 0) {
        EXPECT_GT(relay.dropped(), 0U);
    }
    if (GetParam().duplicate_every != 0) {
        EXPECT_GT(relay.duplicated(), 0U);
    }
    if (GetParam().reorder_every != 0) {
        EXPECT_GT(relay.reordered(), 0U);
    }
    EXPECT_EQ(relay.mtu_dropped(), 0U);
    client->close();
}

std::string fault_profile_name(
    testing::TestParamInfo<udp_fault_relay::profile> const& info) {
    static constexpr char const* names[] {
        "PeriodicLoss", "Duplication", "Reordering", "Delay", "Mtu1250"
    };
    return names[info.index];
}

INSTANTIATE_TEST_SUITE_P(
    UdpNetworkConditions, QuicFaultProfile,
    ::testing::Values(
        udp_fault_relay::profile { 13, 0, 0, 65535, 0ms },
        udp_fault_relay::profile { 0, 5, 0, 65535, 0ms },
        udp_fault_relay::profile { 0, 0, 4, 65535, 0ms },
        udp_fault_relay::profile { 0, 0, 0, 65535, 10ms },
        udp_fault_relay::profile { 0, 0, 0, 1250, 0ms }),
    fault_profile_name);

TEST(QuicTestbed, ConcurrentVerifiedMitmSessionsAndStreams) {
    origin_server origin;
    ASSERT_TRUE(origin.ready()) << quic::openssl_error_stack();

    auto client_context = make_verified_client_context();
    ASSERT_NE(client_context, nullptr) << quic::openssl_error_stack();
    unique_x509 test_ca(nullptr, X509_free);
    BIO* ca_input = BIO_new_file(pki_file("ca-cert.pem").c_str(), "r");
    ASSERT_NE(ca_input, nullptr);
    test_ca.reset(PEM_read_bio_X509(ca_input, nullptr, nullptr, nullptr));
    BIO_free(ca_input);
    ASSERT_NE(test_ca, nullptr);
    auto const origin_address = loopback(origin.port());
    std::string direct_error;
    auto direct = quic::connect_openssl_quic(
        client_context.get(), reinterpret_cast<sockaddr const*>(&origin_address),
        sizeof(origin_address), test_sni, &direct_error);
    ASSERT_NE(direct, nullptr) << direct_error;
    auto const direct_deadline = std::chrono::steady_clock::now() + 3s;
    while (!direct->handshake_complete() && !direct->closed()
           && std::chrono::steady_clock::now() < direct_deadline) {
        direct->drain_events();
        std::this_thread::sleep_for(1ms);
    }
    ASSERT_TRUE(direct->handshake_complete())
        << "verify=" << SSL_get_verify_result(direct->native_handle())
        << " errors=" << quic::openssl_error_stack();
    direct->close();

    quic::lifecycle_options lifecycle;
    lifecycle.handshake_timeout = 5s;
    lifecycle.idle_timeout = 30s;
    lifecycle.drain_timeout = 100ms;
    quic::resource_limits limits;
    limits.max_sessions = 64;
    limits.max_streams_per_session = 32;
    limits.max_certificate_jobs = 32;
    quic::listener_service proxy(0, pki_file("srv-cert.pem"), pki_file("srv-key.pem"), false,
                                 origin.port(), true, lifecycle, limits, "127.0.0.1");
    ASSERT_TRUE(proxy.prepare()) << proxy.last_error();
    std::thread proxy_thread([&proxy]() { proxy.run(); });
    struct proxy_guard {
        quic::listener_service& service;
        std::thread& thread;
        ~proxy_guard() {
            service.stop();
            if (thread.joinable()) thread.join();
        }
    } cleanup { proxy, proxy_thread };

    auto const proxy_address = loopback(proxy.bound_port());
    constexpr std::size_t client_count = 12;
    constexpr std::size_t streams_per_client = 4;
    std::vector<client_state> clients;
    for (std::size_t index = 0; index < client_count; ++index) {
        std::string error;
        auto connection = quic::connect_openssl_quic(
            client_context.get(), reinterpret_cast<sockaddr const*>(&proxy_address),
            sizeof(proxy_address), test_sni, &error);
        ASSERT_NE(connection, nullptr) << error;
        clients.push_back({ std::move(connection), {} });
    }

    auto const handshake_deadline = std::chrono::steady_clock::now() + 10s;
    while (std::chrono::steady_clock::now() < handshake_deadline) {
        std::size_t ready = 0;
        for (auto& client : clients) {
            client.connection->drain_events();
            if (client.connection->handshake_complete()) ++ready;
        }
        if (ready == clients.size()) break;
        std::this_thread::sleep_for(1ms);
    }
    std::size_t completed_client_handshakes = 0;
    std::size_t closed_clients = 0;
    for (auto const& client : clients) {
        if (client.connection->handshake_complete()) ++completed_client_handshakes;
        if (client.connection->closed()) ++closed_clients;
    }
    auto const handshake_diagnostics = proxy.diagnostics();
    ASSERT_EQ(completed_client_handshakes, client_count)
        << "closed_clients=" << closed_clients
        << " handshake_failures=" << handshake_diagnostics.handshake_failures
        << " upstream_failures=" << handshake_diagnostics.upstream_failures
        << " first_verify="
        << SSL_get_verify_result(clients.front().connection->native_handle())
        << " openssl=" << quic::openssl_error_stack();
    ASSERT_EQ(proxy.connection_count(), client_count)
        << "accepted=" << handshake_diagnostics.accepted_sessions
        << " completed=" << handshake_diagnostics.completed_sessions
        << " handshake_failures=" << handshake_diagnostics.handshake_failures
        << " handshake_timeouts=" << handshake_diagnostics.handshake_timeouts
        << " upstream_failures=" << handshake_diagnostics.upstream_failures
        << " alpn_failures=" << handshake_diagnostics.alpn_failures
        << " origin_handshakes=" << origin.handshake_count();
    ASSERT_EQ(origin.handshake_count(), client_count + 1); // Includes direct PKI smoke test.

    for (std::size_t client_index = 0; client_index < clients.size(); ++client_index) {
        auto& client = clients[client_index];
        ASSERT_TRUE(client.connection->handshake_complete());
        EXPECT_EQ(client.connection->negotiated_alpn(), "h3");
        std::unique_ptr<X509, decltype(&X509_free)> peer(
            SSL_get1_peer_certificate(client.connection->native_handle()), X509_free);
        ASSERT_NE(peer, nullptr);
        EXPECT_EQ(X509_check_host(peer.get(), test_sni, std::strlen(test_sni), 0, nullptr), 1);
        EXPECT_EQ(X509_NAME_cmp(X509_get_issuer_name(peer.get()),
                                X509_get_subject_name(test_ca.get())), 0);
        EXPECT_NE(fingerprint(peer.get()), origin.certificate_fingerprint());

        for (std::size_t stream_index = 0; stream_index < streams_per_client; ++stream_index) {
            auto const handle = client.connection->open_flow(mf::direction::bidirectional);
            ASSERT_NE(handle.generation, 0U);
            auto message = "client-" + std::to_string(client_index)
                + "/stream-" + std::to_string(stream_index);
            auto const written = client.connection->write(handle, message.data(), message.size());
            ASSERT_EQ(written.status, mf::io_status::ok);
            ASSERT_EQ(written.size, message.size());
            client.flows.push_back({ handle, std::move(message), {} });
        }
    }

    auto const echo_deadline = std::chrono::steady_clock::now() + 10s;
    while (std::chrono::steady_clock::now() < echo_deadline) {
        std::size_t complete = 0;
        for (auto& client : clients) {
            client.connection->drain_events();
            for (auto& flow : client.flows) {
                unsigned char buffer[256] {};
                auto const read = client.connection->read(flow.handle, buffer, sizeof(buffer));
                if (read.size != 0) {
                    flow.received.append(reinterpret_cast<char const*>(buffer), read.size);
                }
                if (flow.received == flow.expected) ++complete;
            }
        }
        if (complete == client_count * streams_per_client) break;
        std::this_thread::sleep_for(1ms);
    }

    for (auto const& client : clients) {
        for (auto const& flow : client.flows) EXPECT_EQ(flow.received, flow.expected);
    }
    EXPECT_EQ(origin.echoed_messages(), client_count * streams_per_client);
    auto const observed_sni = origin.observed_sni();
    auto const observed_alpn = origin.observed_alpn();
    ASSERT_EQ(observed_sni.size(), client_count + 1); // Includes direct PKI smoke test.
    ASSERT_EQ(observed_alpn.size(), client_count + 1);
    for (auto const& value : observed_sni) EXPECT_EQ(value, test_sni);
    for (auto const& value : observed_alpn) EXPECT_EQ(value, "h3");

    for (auto& client : clients) client.connection->close();
    auto const cleanup_deadline = std::chrono::steady_clock::now() + 5s;
    while (proxy.connection_count() != 0
           && std::chrono::steady_clock::now() < cleanup_deadline) {
        std::this_thread::sleep_for(5ms);
    }
    auto const diagnostics = proxy.diagnostics();
    EXPECT_EQ(diagnostics.accepted_sessions, client_count);
    EXPECT_EQ(diagnostics.upstream_failures, 0U);
    EXPECT_EQ(diagnostics.alpn_failures, 0U);
}

TEST(QuicTestbed, RejectsSniNotPresentOnVerifiedOrigin) {
    origin_server origin;
    ASSERT_TRUE(origin.ready());
    quic::listener_service proxy(0, pki_file("srv-cert.pem"), pki_file("srv-key.pem"), false,
                                 origin.port(), true, {}, {}, "127.0.0.1");
    ASSERT_TRUE(proxy.prepare()) << proxy.last_error();
    std::thread proxy_thread([&proxy]() { proxy.run(); });
    struct guard {
        quic::listener_service& service;
        std::thread& thread;
        ~guard() {
            service.stop();
            if (thread.joinable()) thread.join();
        }
    } cleanup { proxy, proxy_thread };

    auto client_context = quic::make_openssl_quic_context(false);
    ASSERT_NE(client_context, nullptr);
    SSL_CTX_set_verify(client_context.get(), SSL_VERIFY_NONE, nullptr);
    auto const address = loopback(proxy.bound_port());
    std::string error;
    auto client = quic::connect_openssl_quic(
        client_context.get(), reinterpret_cast<sockaddr const*>(&address), sizeof(address),
        "not-localhost.invalid", &error);
    ASSERT_NE(client, nullptr) << error;

    auto const deadline = std::chrono::steady_clock::now() + 5s;
    while (!client->closed() && proxy.diagnostics().upstream_failures == 0
           && std::chrono::steady_clock::now() < deadline) {
        client->drain_events();
        std::this_thread::sleep_for(1ms);
    }
    EXPECT_FALSE(client->handshake_complete());
    EXPECT_GE(proxy.diagnostics().upstream_failures, 1U);
    client->close();
}

TEST(QuicTestbed, RejectsUnsupportedDownstreamAlpn) {
    quic::listener_service proxy(0, pki_file("srv-cert.pem"), pki_file("srv-key.pem"),
                                 false, 9, false);
    ASSERT_TRUE(proxy.prepare()) << proxy.last_error();
    std::thread proxy_thread([&proxy]() { proxy.run(); });
    struct guard {
        quic::listener_service& service;
        std::thread& thread;
        ~guard() {
            service.stop();
            if (thread.joinable()) thread.join();
        }
    } cleanup { proxy, proxy_thread };

    auto context = quic::make_openssl_quic_context(false);
    ASSERT_NE(context, nullptr);
    SSL_CTX_set_verify(context.get(), SSL_VERIFY_NONE, nullptr);
    auto const address = loopback(proxy.bound_port());
    std::string error;
    auto client = quic::connect_openssl_quic(
        context.get(), reinterpret_cast<sockaddr const*>(&address), sizeof(address),
        test_sni, "hq-29", &error);
    ASSERT_NE(client, nullptr) << error;
    auto const deadline = std::chrono::steady_clock::now() + 3s;
    while (proxy.diagnostics().handshake_failures == 0
           && std::chrono::steady_clock::now() < deadline) {
        client->drain_events();
        std::this_thread::sleep_for(1ms);
    }
    EXPECT_FALSE(client->handshake_complete());
    EXPECT_GE(proxy.diagnostics().handshake_failures, 1U);
    client->close();
}

TEST(QuicTestbed, RejectsCertificateJobsBeyondConfiguredLimit) {
    quic::resource_limits limits;
    limits.max_certificate_jobs = 0;
    quic::listener_service proxy(0, pki_file("srv-cert.pem"), pki_file("srv-key.pem"),
                                 false, 9, true, {}, limits, "127.0.0.1");
    ASSERT_TRUE(proxy.prepare()) << proxy.last_error();
    std::thread proxy_thread([&proxy]() { proxy.run(); });
    struct guard {
        quic::listener_service& service;
        std::thread& thread;
        ~guard() {
            service.stop();
            if (thread.joinable()) thread.join();
        }
    } cleanup { proxy, proxy_thread };

    auto context = quic::make_openssl_quic_context(false);
    ASSERT_NE(context, nullptr);
    SSL_CTX_set_verify(context.get(), SSL_VERIFY_NONE, nullptr);
    auto const address = loopback(proxy.bound_port());
    std::string error;
    auto client = quic::connect_openssl_quic(
        context.get(), reinterpret_cast<sockaddr const*>(&address), sizeof(address),
        test_sni, &error);
    ASSERT_NE(client, nullptr) << error;
    auto const deadline = std::chrono::steady_clock::now() + 3s;
    while (proxy.diagnostics().certificate_job_limit_rejections == 0
           && std::chrono::steady_clock::now() < deadline) {
        client->drain_events();
        std::this_thread::sleep_for(1ms);
    }
    EXPECT_FALSE(client->handshake_complete());
    EXPECT_GE(proxy.diagnostics().certificate_job_limit_rejections, 1U);
    client->close();
}

TEST(QuicTestbed, ClientRejectsMitmCertificateWithoutTestCaTrust) {
    origin_server origin;
    ASSERT_TRUE(origin.ready());
    quic::listener_service proxy(0, pki_file("srv-cert.pem"), pki_file("srv-key.pem"), false,
                                 origin.port(), true, {}, {}, "127.0.0.1");
    ASSERT_TRUE(proxy.prepare()) << proxy.last_error();
    running_service runner(proxy);

    auto context = quic::make_openssl_quic_context(false);
    ASSERT_NE(context, nullptr);
    SSL_CTX_set_verify(context.get(), SSL_VERIFY_PEER, nullptr);
    auto const address = loopback(proxy.bound_port());
    std::string error;
    auto client = quic::connect_openssl_quic(
        context.get(), reinterpret_cast<sockaddr const*>(&address), sizeof(address),
        test_sni, &error);
    ASSERT_NE(client, nullptr) << error;

    EXPECT_FALSE(await_handshake(*client));
    EXPECT_NE(SSL_get_verify_result(client->native_handle()), X509_V_OK);
    client->close();
}

TEST(QuicTestbed, CleansUpClientClosedDuringVerifiedHandshake) {
    origin_server origin;
    ASSERT_TRUE(origin.ready());
    quic::lifecycle_options lifecycle;
    lifecycle.drain_timeout = 20ms;
    quic::listener_service proxy(0, pki_file("srv-cert.pem"), pki_file("srv-key.pem"), false,
                                 origin.port(), true, lifecycle, {}, "127.0.0.1");
    ASSERT_TRUE(proxy.prepare()) << proxy.last_error();
    running_service runner(proxy);

    auto context = make_verified_client_context();
    ASSERT_NE(context, nullptr);
    auto const address = loopback(proxy.bound_port());
    std::string error;
    auto client = quic::connect_openssl_quic(
        context.get(), reinterpret_cast<sockaddr const*>(&address), sizeof(address),
        test_sni, &error);
    ASSERT_NE(client, nullptr) << error;

    auto const accept_deadline = std::chrono::steady_clock::now() + 3s;
    while (proxy.diagnostics().accepted_sessions == 0
           && std::chrono::steady_clock::now() < accept_deadline) {
        client->drain_events();
        std::this_thread::sleep_for(1ms);
    }
    ASSERT_EQ(proxy.diagnostics().accepted_sessions, 1U);
    client->close(0x10);

    auto const cleanup_deadline = std::chrono::steady_clock::now() + 5s;
    while (proxy.connection_count() != 0
           && std::chrono::steady_clock::now() < cleanup_deadline) {
        client->drain_events();
        std::this_thread::sleep_for(2ms);
    }
    EXPECT_EQ(proxy.connection_count(), 0U);
    EXPECT_EQ(proxy.diagnostics().completed_sessions, 1U);
}

TEST(QuicTestbed, RepeatedVerifiedReconnectsReleaseEveryIdleSession) {
    origin_server origin;
    ASSERT_TRUE(origin.ready());
    quic::lifecycle_options lifecycle;
    lifecycle.idle_timeout = 100ms;
    lifecycle.drain_timeout = 20ms;
    quic::listener_service proxy(0, pki_file("srv-cert.pem"), pki_file("srv-key.pem"), false,
                                 origin.port(), true, lifecycle, {}, "127.0.0.1");
    ASSERT_TRUE(proxy.prepare()) << proxy.last_error();
    running_service runner(proxy);

    auto context = make_verified_client_context();
    ASSERT_NE(context, nullptr);
    auto const address = loopback(proxy.bound_port());
    constexpr std::size_t reconnects = 12;
    for (std::size_t iteration = 0; iteration < reconnects; ++iteration) {
        std::string error;
        auto client = quic::connect_openssl_quic(
            context.get(), reinterpret_cast<sockaddr const*>(&address), sizeof(address),
            test_sni, &error);
        ASSERT_NE(client, nullptr) << "iteration=" << iteration << " " << error;
        ASSERT_TRUE(await_handshake(*client, 5s)) << "iteration=" << iteration;
        client->close();
        auto const deadline = std::chrono::steady_clock::now() + 2s;
        while (proxy.connection_count() != 0
               && std::chrono::steady_clock::now() < deadline) {
            client->drain_events();
            std::this_thread::sleep_for(2ms);
        }
        ASSERT_EQ(proxy.connection_count(), 0U) << "iteration=" << iteration;
    }
    EXPECT_EQ(proxy.diagnostics().accepted_sessions, reconnects);
    EXPECT_EQ(proxy.diagnostics().completed_sessions, reconnects);
    EXPECT_EQ(origin.handshake_count(), reconnects);
}

TEST(QuicTestbed, EnforcesStreamLimitOnRealQuicConnection) {
    origin_server origin;
    ASSERT_TRUE(origin.ready());
    quic::resource_limits limits;
    limits.max_streams_per_session = 2;
    quic::listener_service proxy(0, pki_file("srv-cert.pem"), pki_file("srv-key.pem"), false,
                                 origin.port(), true, {}, limits, "127.0.0.1");
    ASSERT_TRUE(proxy.prepare()) << proxy.last_error();
    running_service runner(proxy);

    auto context = make_verified_client_context();
    ASSERT_NE(context, nullptr);
    auto const address = loopback(proxy.bound_port());
    std::string error;
    auto client = quic::connect_openssl_quic(
        context.get(), reinterpret_cast<sockaddr const*>(&address), sizeof(address),
        test_sni, &error);
    ASSERT_NE(client, nullptr) << error;
    ASSERT_TRUE(await_handshake(*client, 5s));

    for (std::size_t index = 0; index < 5; ++index) {
        auto const flow = client->open_flow(mf::direction::bidirectional);
        ASSERT_NE(flow.generation, 0U);
        auto const payload = std::string("limited-") + std::to_string(index);
        auto const written = client->write(flow, payload.data(), payload.size());
        ASSERT_EQ(written.status, mf::io_status::ok);
    }
    auto const deadline = std::chrono::steady_clock::now() + 3s;
    while (proxy.diagnostics().stream_limit_rejections < 3
           && std::chrono::steady_clock::now() < deadline) {
        client->drain_events();
        std::this_thread::sleep_for(1ms);
    }
    EXPECT_EQ(proxy.diagnostics().stream_limit_rejections, 3U);
    client->close();
}

TEST(QuicTestbed, EchoesPayloadsAcrossPacketAndBufferBoundaries) {
    origin_server origin;
    ASSERT_TRUE(origin.ready());
    quic::listener_service proxy(0, pki_file("srv-cert.pem"), pki_file("srv-key.pem"), false,
                                 origin.port(), true, {}, {}, "127.0.0.1");
    ASSERT_TRUE(proxy.prepare()) << proxy.last_error();
    running_service runner(proxy);

    auto context = make_verified_client_context();
    ASSERT_NE(context, nullptr);
    auto const address = loopback(proxy.bound_port());
    std::string error;
    auto client = quic::connect_openssl_quic(
        context.get(), reinterpret_cast<sockaddr const*>(&address), sizeof(address),
        test_sni, &error);
    ASSERT_NE(client, nullptr) << error;
    ASSERT_TRUE(await_handshake(*client, 5s));

    std::vector<std::size_t> const sizes { 1, 1199, 1200, 2048, 4097, 16384, 32769 };
    struct transfer {
        mf::flow_handle flow;
        std::string payload;
        std::size_t sent = 0;
        std::string received;
    };
    std::vector<transfer> transfers;
    for (auto const size : sizes) {
        auto const flow = client->open_flow(mf::direction::bidirectional);
        ASSERT_NE(flow.generation, 0U);
        std::string payload(size, '\0');
        for (std::size_t index = 0; index < size; ++index) {
            payload[index] = static_cast<char>('A' + (index % 23));
        }
        transfers.push_back({ flow, std::move(payload), 0, {} });
    }

    auto const deadline = std::chrono::steady_clock::now() + 10s;
    while (std::chrono::steady_clock::now() < deadline) {
        client->drain_events();
        std::size_t complete = 0;
        for (auto& transfer : transfers) {
            if (transfer.sent < transfer.payload.size()) {
                auto const written = client->write(
                    transfer.flow, transfer.payload.data() + transfer.sent,
                    transfer.payload.size() - transfer.sent);
                transfer.sent += written.size;
            }
            unsigned char buffer[4096] {};
            auto const read = client->read(transfer.flow, buffer, sizeof(buffer));
            if (read.size != 0) {
                transfer.received.append(reinterpret_cast<char const*>(buffer), read.size);
            }
            if (transfer.received == transfer.payload) ++complete;
        }
        if (complete == transfers.size()) break;
        std::this_thread::sleep_for(1ms);
    }
    for (auto const& transfer : transfers) {
        EXPECT_EQ(transfer.received, transfer.payload)
            << "payload_size=" << transfer.payload.size();
    }
    client->close();
}

TEST(QuicTestbed, StopClosesLiveVerifiedSessionsPromptly) {
    origin_server origin;
    ASSERT_TRUE(origin.ready());
    quic::listener_service proxy(0, pki_file("srv-cert.pem"), pki_file("srv-key.pem"), false,
                                 origin.port(), true, {}, {}, "127.0.0.1");
    ASSERT_TRUE(proxy.prepare()) << proxy.last_error();
    running_service runner(proxy);

    auto context = make_verified_client_context();
    ASSERT_NE(context, nullptr);
    auto const address = loopback(proxy.bound_port());
    std::vector<std::unique_ptr<quic::openssl_connection>> clients;
    for (std::size_t index = 0; index < 8; ++index) {
        std::string error;
        auto client = quic::connect_openssl_quic(
            context.get(), reinterpret_cast<sockaddr const*>(&address), sizeof(address),
            test_sni, &error);
        ASSERT_NE(client, nullptr) << error;
        clients.push_back(std::move(client));
    }
    auto const deadline = std::chrono::steady_clock::now() + 5s;
    while (std::chrono::steady_clock::now() < deadline) {
        std::size_t complete = 0;
        for (auto& client : clients) {
            client->drain_events();
            if (client->handshake_complete()) ++complete;
        }
        if (complete == clients.size()) break;
        std::this_thread::sleep_for(1ms);
    }
    ASSERT_EQ(proxy.connection_count(), clients.size());

    auto const started = std::chrono::steady_clock::now();
    runner.stop();
    EXPECT_LT(std::chrono::steady_clock::now() - started, 500ms);
    EXPECT_EQ(proxy.connection_count(), 0U);
}

} // namespace
#endif

int main(int argc, char** argv) {
    ::testing::InitGoogleTest(&argc, argv);
#if SMITHPROXY_OPENSSL_QUIC
    Log::init();
    Log::get()->level(WAR);
    if (!create_test_pki()) return 2;
    auto& factory = SSLFactory::factory();
    factory.certs_path() = test_pki_directory + "/";
    factory.ca_file() = pki_file("ca-cert.pem");
    factory.ca_path().clear();
    factory.init();
#endif
    auto const result = RUN_ALL_TESTS();
#if SMITHPROXY_OPENSSL_QUIC
    // Release cache entries before the custom allocator's static teardown.
    factory.destroy();
    std::filesystem::remove_all(test_pki_directory);
#endif
    return result;
}
