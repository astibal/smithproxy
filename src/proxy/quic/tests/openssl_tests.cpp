#include <gtest/gtest.h>

#include "proxy/multiflow/mfflowcom.hpp"
#include "proxy/quic/openssl.hpp"

#if SMITHPROXY_OPENSSL_QUIC
#include <arpa/inet.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <unistd.h>

#include <algorithm>
#include <chrono>
#include <cstring>
#include <thread>
#endif

namespace quic = sx::quic;
namespace mf = sx::multiflow;

TEST(OpenSslQuic, CapabilityMatchesBuildVersion) {
#if OPENSSL_VERSION_NUMBER >= 0x30500000L && !defined(OPENSSL_NO_QUIC)
    EXPECT_TRUE(quic::openssl_quic_available());
#else
    EXPECT_FALSE(quic::openssl_quic_available());
#endif
}

TEST(OpenSslQuic, CreatesClientAndServerContextsWhenAvailable) {
    auto client = quic::make_openssl_quic_context(false);
    auto server = quic::make_openssl_quic_context(true);

    if (quic::openssl_quic_available()) {
        ASSERT_NE(client, nullptr) << quic::openssl_error_stack();
        ASSERT_NE(server, nullptr) << quic::openssl_error_stack();
#if SMITHPROXY_OPENSSL_QUIC
        EXPECT_EQ(SSL_CTX_get_ssl_method(client.get()), OSSL_QUIC_client_method());
        EXPECT_EQ(SSL_CTX_get_ssl_method(server.get()), OSSL_QUIC_server_method());
#endif
    } else {
        EXPECT_EQ(client, nullptr);
        EXPECT_EQ(server, nullptr);
    }
}

#if SMITHPROXY_OPENSSL_QUIC
namespace {

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

quic::datagram_endpoint loopback_endpoint(std::uint16_t port) {
    sockaddr_in address {};
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    address.sin_port = htons(port);

    quic::datagram_endpoint result;
    std::memcpy(&result.address, &address, sizeof(address));
    result.size = sizeof(address);
    return result;
}

} // namespace

TEST(OpenSslQuicDispatcher, IgnoresZeroLengthConnectionIds) {
    quic::detail::datagram_route_table routes;
    routes.remember({}, {loopback_endpoint(10001), loopback_endpoint(443)});

    EXPECT_EQ(routes.size(), 0U);

    // This is a valid v1 Initial prefix with an empty source CID. Learning it
    // must retain only its non-empty destination CID.
    std::vector<unsigned char> initial {
        0xc0, 0x00, 0x00, 0x00, 0x01,
        0x02, 0xaa, 0xbb,
        0x00,
        0x00, 0x01, 0x00,
    };
    routes.learn(initial.data(), initial.size(),
                 {loopback_endpoint(10001), loopback_endpoint(443)});
    EXPECT_EQ(routes.size(), 1U);
}

TEST(OpenSslQuicDispatcher, ResolvesOnlyUnambiguousKnownRoutes) {
    quic::detail::datagram_route_table routes;
    auto const first = quic::detail::datagram_route {
        loopback_endpoint(10001), loopback_endpoint(443),
    };
    auto const second = quic::detail::datagram_route {
        loopback_endpoint(10002), loopback_endpoint(443),
    };

    routes.remember({0xaa}, first);
    routes.remember({0xaa, 0xbb}, second);

    // Both known CID prefixes match, but they belong to different clients.
    // Returning no route is the fail-closed behavior that prevents a leak.
    std::vector<unsigned char> ambiguous {0x40, 0xaa, 0xbb, 0x01};
    EXPECT_FALSE(routes.resolve(ambiguous.data(), ambiguous.size()));

    std::vector<unsigned char> unknown {0x40, 0xcc, 0xdd, 0x01};
    EXPECT_FALSE(routes.resolve(unknown.data(), unknown.size()));

    std::vector<unsigned char> known {0x40, 0xaa, 0x01};
    auto const resolved = routes.resolve(known.data(), known.size());
    ASSERT_TRUE(resolved);
    EXPECT_EQ(reinterpret_cast<sockaddr_in const*>(&resolved->peer.address)->sin_port,
              htons(10001));
}

TEST(OpenSslQuicDispatcher, EvictsOldRoutesAtItsConfiguredBound) {
    quic::detail::datagram_route_table routes(2);
    auto const route = quic::detail::datagram_route {
        loopback_endpoint(10001), loopback_endpoint(443),
    };

    routes.remember({0x01}, route);
    routes.remember({0x02}, route);
    routes.remember({0x03}, route);

    EXPECT_EQ(routes.size(), 2U);
    std::vector<unsigned char> evicted {0x40, 0x01, 0x00};
    EXPECT_FALSE(routes.resolve(evicted.data(), evicted.size()));
}

TEST(OpenSslQuic, CreatesNonBlockingServerListenerObject) {
    auto context = quic::make_openssl_quic_context(true);
    ASSERT_NE(context, nullptr) << quic::openssl_error_stack();

    quic::unique_ssl listener(SSL_new_listener(context.get(), 0));
    ASSERT_NE(listener, nullptr) << quic::openssl_error_stack();
    EXPECT_EQ(SSL_is_listener(listener.get()), 1);
    EXPECT_EQ(SSL_set_blocking_mode(listener.get(), 0), 1);
    EXPECT_EQ(SSL_get_blocking_mode(listener.get()), 0);
}

TEST(OpenSslQuic, OutgoingAdapterCompletesHandshake) {
    auto server_context = quic::make_openssl_quic_context(true);
    auto client_context = quic::make_openssl_quic_context(false);
    ASSERT_NE(server_context, nullptr);
    ASSERT_NE(client_context, nullptr);
    ASSERT_EQ(SSL_CTX_use_certificate_chain_file(server_context.get(),
                                                 "etc/certs/default/srv-cert.pem"), 1);
    ASSERT_EQ(SSL_CTX_use_PrivateKey_file(server_context.get(),
                                         "etc/certs/default/srv-key.pem", SSL_FILETYPE_PEM), 1);
    SSL_CTX_set_alpn_select_cb(server_context.get(), select_h3, nullptr);
    SSL_CTX_set_verify(client_context.get(), SSL_VERIFY_NONE, nullptr);

    auto const server_fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    ASSERT_GE(server_fd, 0);
    ASSERT_TRUE(make_nonblocking(server_fd));
    sockaddr_in server_address {};
    server_address.sin_family = AF_INET;
    server_address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    ASSERT_EQ(bind(server_fd, reinterpret_cast<sockaddr*>(&server_address),
                   sizeof(server_address)), 0);
    socklen_t address_size = sizeof(server_address);
    ASSERT_EQ(getsockname(server_fd, reinterpret_cast<sockaddr*>(&server_address),
                          &address_size), 0);

    quic::datagram_endpoint observed_destination;
    auto listener = quic::openssl_listener::create(
        server_context.get(), server_fd, true,
        [&observed_destination](auto const&, auto const& local) {
            observed_destination = local;
        });
    ASSERT_NE(listener, nullptr) << quic::openssl_error_stack();
    std::string error;
    auto client = quic::connect_openssl_quic(
        client_context.get(), reinterpret_cast<sockaddr*>(&server_address),
        sizeof(server_address), "localhost", &error);
    ASSERT_NE(client, nullptr) << error;

    std::unique_ptr<quic::openssl_connection> server;
    auto const deadline = std::chrono::steady_clock::now() + std::chrono::seconds(3);
    while (std::chrono::steady_clock::now() < deadline
           && (!client->handshake_complete() || !server || !server->handshake_complete())) {
        client->drain_events();
        listener->handle_events();
        if (!server) server = listener->accept();
        if (server) server->drain_events();
        std::this_thread::sleep_for(std::chrono::milliseconds(1));
    }

    EXPECT_TRUE(client->handshake_complete()) << quic::openssl_error_stack();
    ASSERT_NE(server, nullptr);
    EXPECT_TRUE(server->handshake_complete()) << quic::openssl_error_stack();
    EXPECT_EQ(client->negotiated_alpn(), "h3");
    EXPECT_EQ(server->negotiated_alpn(), "h3");
    EXPECT_EQ(server->server_name(), "localhost");
    ASSERT_TRUE(observed_destination.valid());
    auto const* observed = reinterpret_cast<sockaddr_in const*>(&observed_destination.address);
    EXPECT_EQ(observed->sin_family, AF_INET);
    EXPECT_EQ(observed->sin_port, server_address.sin_port);

    std::string rejected_error;
    auto rejected = quic::connect_openssl_quic(
        client_context.get(), reinterpret_cast<sockaddr*>(&server_address),
        sizeof(server_address), "localhost", "hq-interop", &rejected_error);
    std::unique_ptr<quic::openssl_connection> rejected_server;
    auto const reject_deadline = std::chrono::steady_clock::now()
        + std::chrono::milliseconds(500);
    while (rejected && std::chrono::steady_clock::now() < reject_deadline
           && !rejected->closed() && !rejected->handshake_complete()) {
        rejected->drain_events();
        listener->handle_events();
        if (!rejected_server) rejected_server = listener->accept();
        if (rejected_server) rejected_server->drain_events();
        std::this_thread::sleep_for(std::chrono::milliseconds(1));
    }
    EXPECT_TRUE(!rejected || rejected->closed());
    if (rejected) {
        EXPECT_FALSE(rejected->handshake_complete());
    }
    if (rejected_server) rejected_server->close();
    client->close();
    server->close();
    close(server_fd);
}

TEST(OpenSslQuic, TransparentDispatcherKeepsConcurrentHandshakesIsolated) {
    auto server_context = quic::make_openssl_quic_context(true);
    auto client_context = quic::make_openssl_quic_context(false);
    ASSERT_NE(server_context, nullptr);
    ASSERT_NE(client_context, nullptr);
    ASSERT_EQ(SSL_CTX_use_certificate_chain_file(server_context.get(),
                                                 "etc/certs/default/srv-cert.pem"), 1);
    ASSERT_EQ(SSL_CTX_use_PrivateKey_file(server_context.get(),
                                         "etc/certs/default/srv-key.pem", SSL_FILETYPE_PEM), 1);
    SSL_CTX_set_alpn_select_cb(server_context.get(), select_h3, nullptr);
    SSL_CTX_set_verify(client_context.get(), SSL_VERIFY_NONE, nullptr);

    auto const server_fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    ASSERT_GE(server_fd, 0);
    ASSERT_TRUE(make_nonblocking(server_fd));
    sockaddr_in server_address {};
    server_address.sin_family = AF_INET;
    server_address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    ASSERT_EQ(bind(server_fd, reinterpret_cast<sockaddr*>(&server_address),
                   sizeof(server_address)), 0);
    socklen_t address_size = sizeof(server_address);
    ASSERT_EQ(getsockname(server_fd, reinterpret_cast<sockaddr*>(&server_address),
                          &address_size), 0);

    auto listener = quic::openssl_listener::create(server_context.get(), server_fd, true);
    ASSERT_NE(listener, nullptr) << quic::openssl_error_stack();

    // OpenSSL clients currently send an empty source CID in their first
    // Initial. Starting them together exercises the scoped tuple fallback and
    // catches the old failure mode where one client's output reached another.
    constexpr std::size_t client_count = 8;
    std::vector<std::unique_ptr<quic::openssl_connection>> clients;
    for (std::size_t index = 0; index < client_count; ++index) {
        std::string error;
        auto client = quic::connect_openssl_quic(
            client_context.get(), reinterpret_cast<sockaddr*>(&server_address),
            sizeof(server_address), "client-" + std::to_string(index) + ".test", &error);
        ASSERT_NE(client, nullptr) << error;
        clients.push_back(std::move(client));
    }

    std::vector<std::unique_ptr<quic::openssl_connection>> servers;
    auto const deadline = std::chrono::steady_clock::now() + std::chrono::seconds(5);
    while (std::chrono::steady_clock::now() < deadline) {
        for (auto& client : clients) client->drain_events();
        ASSERT_TRUE(listener->handle_events()) << listener->last_error();
        while (auto accepted = listener->accept()) servers.push_back(std::move(accepted));
        for (auto& server : servers) server->drain_events();

        auto const clients_ready = std::all_of(clients.begin(), clients.end(),
            [](auto const& value) { return value->handshake_complete(); });
        auto const servers_ready = servers.size() == client_count
            && std::all_of(servers.begin(), servers.end(),
                [](auto const& value) { return value->handshake_complete(); });
        if (clients_ready && servers_ready) break;
        std::this_thread::sleep_for(std::chrono::milliseconds(1));
    }

    ASSERT_EQ(servers.size(), client_count);
    for (auto const& client : clients) {
        EXPECT_TRUE(client->handshake_complete()) << quic::openssl_error_stack();
        EXPECT_EQ(client->negotiated_alpn(), "h3");
    }
    for (auto const& server : servers) {
        EXPECT_TRUE(server->handshake_complete()) << quic::openssl_error_stack();
        EXPECT_EQ(server->negotiated_alpn(), "h3");
    }

    for (auto& client : clients) client->close();
    for (auto& server : servers) server->close();
    close(server_fd);
}

TEST(OpenSslQuic, OutgoingAdapterVerifiesChainAndServerName) {
    auto server_context = quic::make_openssl_quic_context(true);
    auto client_context = quic::make_openssl_quic_context(false);
    ASSERT_NE(server_context, nullptr);
    ASSERT_NE(client_context, nullptr);
    ASSERT_EQ(SSL_CTX_use_certificate_chain_file(server_context.get(),
                                                 "etc/certs/default/srv-cert.pem"), 1);
    ASSERT_EQ(SSL_CTX_use_PrivateKey_file(server_context.get(),
                                         "etc/certs/default/srv-key.pem", SSL_FILETYPE_PEM), 1);
    SSL_CTX_set_alpn_select_cb(server_context.get(), select_h3, nullptr);
    ASSERT_EQ(SSL_CTX_load_verify_locations(client_context.get(),
                                            "etc/certs/default/ca-cert.pem", nullptr), 1);
    SSL_CTX_set_verify(client_context.get(), SSL_VERIFY_PEER, nullptr);
    // Repository fixtures are intentionally old; this test targets chain and
    // hostname wiring rather than fixture renewal policy.
    ASSERT_EQ(X509_VERIFY_PARAM_set_flags(SSL_CTX_get0_param(client_context.get()),
                                          X509_V_FLAG_NO_CHECK_TIME), 1);

    auto const server_fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    ASSERT_GE(server_fd, 0);
    ASSERT_TRUE(make_nonblocking(server_fd));
    sockaddr_in address {};
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    ASSERT_EQ(bind(server_fd, reinterpret_cast<sockaddr*>(&address), sizeof(address)), 0);
    socklen_t address_size = sizeof(address);
    ASSERT_EQ(getsockname(server_fd, reinterpret_cast<sockaddr*>(&address), &address_size), 0);
    auto listener = quic::openssl_listener::create(server_context.get(), server_fd, true);
    ASSERT_NE(listener, nullptr);

    std::string error;
    auto client = quic::connect_openssl_quic(
        client_context.get(), reinterpret_cast<sockaddr*>(&address), sizeof(address),
        "Smithproxy-Server-Certificate", &error);
    ASSERT_NE(client, nullptr) << error;
    std::unique_ptr<quic::openssl_connection> server;
    auto const deadline = std::chrono::steady_clock::now() + std::chrono::seconds(3);
    while (std::chrono::steady_clock::now() < deadline
           && (!client->handshake_complete() || !server || !server->handshake_complete())) {
        client->drain_events();
        listener->handle_events();
        if (!server) server = listener->accept();
        if (server) server->drain_events();
        std::this_thread::sleep_for(std::chrono::milliseconds(1));
    }
    EXPECT_TRUE(client->handshake_complete()) << quic::openssl_error_stack();
    EXPECT_EQ(SSL_get_verify_result(client->native_handle()), X509_V_OK);
    EXPECT_EQ(client->negotiated_alpn(), "h3");
    client->close();
    if (server) server->close();
    close(server_fd);
}

TEST(OpenSslQuic, LoopbackHandshakeExposesBidirectionalStream) {
    auto server_context = quic::make_openssl_quic_context(true);
    auto client_context = quic::make_openssl_quic_context(false);
    ASSERT_NE(server_context, nullptr) << quic::openssl_error_stack();
    ASSERT_NE(client_context, nullptr) << quic::openssl_error_stack();

    ASSERT_EQ(SSL_CTX_use_certificate_chain_file(server_context.get(),
                                                 "etc/certs/default/srv-cert.pem"), 1)
        << quic::openssl_error_stack();
    ASSERT_EQ(SSL_CTX_use_PrivateKey_file(server_context.get(),
                                         "etc/certs/default/srv-key.pem", SSL_FILETYPE_PEM), 1)
        << quic::openssl_error_stack();
    SSL_CTX_set_alpn_select_cb(server_context.get(), select_h3, nullptr);
    SSL_CTX_set_verify(client_context.get(), SSL_VERIFY_NONE, nullptr);

    auto const server_fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    auto const client_fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    ASSERT_GE(server_fd, 0);
    ASSERT_GE(client_fd, 0);
    ASSERT_TRUE(make_nonblocking(server_fd));
    ASSERT_TRUE(make_nonblocking(client_fd));

    sockaddr_in server_address {};
    server_address.sin_family = AF_INET;
    server_address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    server_address.sin_port = 0;
    ASSERT_EQ(bind(server_fd, reinterpret_cast<sockaddr*>(&server_address),
                   sizeof(server_address)), 0);
    socklen_t address_size = sizeof(server_address);
    ASSERT_EQ(getsockname(server_fd, reinterpret_cast<sockaddr*>(&server_address),
                          &address_size), 0);
    ASSERT_EQ(connect(client_fd, reinterpret_cast<sockaddr*>(&server_address),
                      sizeof(server_address)), 0);

    auto listener = quic::openssl_listener::create(server_context.get(), server_fd, true);
    ASSERT_NE(listener, nullptr) << quic::openssl_error_stack();
    EXPECT_TRUE(listener->local_address_enabled());

    quic::unique_ssl client(SSL_new(client_context.get()));
    ASSERT_NE(client, nullptr) << quic::openssl_error_stack();
    ASSERT_EQ(SSL_set_fd(client.get(), client_fd), 1);
    ASSERT_EQ(SSL_set_blocking_mode(client.get(), 0), 1);
    ASSERT_EQ(SSL_set_tlsext_host_name(client.get(), "localhost"), 1);
    static constexpr unsigned char alpn[] = { 2, 'h', '3' };
    ASSERT_EQ(SSL_set_alpn_protos(client.get(), alpn, sizeof(alpn)), 0);

    std::unique_ptr<quic::openssl_connection> server;
    auto const deadline = std::chrono::steady_clock::now() + std::chrono::seconds(3);
    while (std::chrono::steady_clock::now() < deadline
           && (!SSL_is_init_finished(client.get())
               || !server || !SSL_is_init_finished(server->native_handle()))) {
        SSL_connect(client.get());
        listener->handle_events();
        if (!server) server = listener->accept();
        if (server) SSL_do_handshake(server->native_handle());
        SSL_handle_events(client.get());
        std::this_thread::sleep_for(std::chrono::milliseconds(1));
    }
    ASSERT_TRUE(SSL_is_init_finished(client.get())) << quic::openssl_error_stack();
    ASSERT_NE(server, nullptr) << quic::openssl_error_stack();
    ASSERT_TRUE(SSL_is_init_finished(server->native_handle())) << quic::openssl_error_stack();
    EXPECT_EQ(server->negotiated_alpn(), "h3");

    auto client_connection = std::make_shared<quic::openssl_connection>(std::move(client));
    std::shared_ptr<quic::openssl_connection> server_connection(std::move(server));
    auto const client_flow = client_connection->open_flow(mf::direction::bidirectional);
    ASSERT_NE(client_flow.generation, 0U) << quic::openssl_error_stack();
    mf::MFFlowCom client_com(client_connection, client_flow);
    static constexpr char message[] = "smithproxy-quic";

    mf::flow_handle server_flow;
    std::unique_ptr<mf::MFFlowCom> server_com;
    std::string received;
    bool sent = false;
    auto const stream_deadline = std::chrono::steady_clock::now() + std::chrono::seconds(3);
    while (std::chrono::steady_clock::now() < stream_deadline && received.empty()) {
        if (!sent) {
            auto const written = client_com.write(client_com.token(), message, sizeof(message) - 1, 0);
            ASSERT_GE(written, 0);
            sent = written == static_cast<ssize_t>(sizeof(message) - 1);
        }
        client_connection->drain_events();
        ASSERT_TRUE(listener->handle_events()) << listener->last_error();
        for (auto const& event : server_connection->drain_events()) {
            if (event.type == mf::event_type::flow_open && event.flow) {
                server_flow = *event.flow;
                server_com = std::make_unique<mf::MFFlowCom>(server_connection, server_flow);
            }
        }
        if (server_com) {
            char buffer[64] {};
            auto const read_size = server_com->read(server_com->token(), buffer, sizeof(buffer), 0);
            if (read_size > 0) received.assign(buffer, static_cast<std::size_t>(read_size));
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(1));
    }
    EXPECT_EQ(received, message);

    ASSERT_EQ(client_connection->finish(client_flow), mf::io_status::ok);
    static constexpr char after_fin[] = "must-not-be-written";
    auto const rejected_after_fin = client_connection->write(
        client_flow, after_fin, sizeof(after_fin) - 1);
    EXPECT_EQ(rejected_after_fin.size, 0U);
    EXPECT_EQ(rejected_after_fin.status, mf::io_status::eof);

    bool saw_fin = false;
    auto const fin_deadline = std::chrono::steady_clock::now() + std::chrono::seconds(3);
    while (std::chrono::steady_clock::now() < fin_deadline && !saw_fin) {
        client_connection->drain_events();
        ASSERT_TRUE(listener->handle_events()) << listener->last_error();
        char byte = 0;
        auto const read_result = server_connection->read(server_flow, &byte, sizeof(byte));
        if (read_result.status == mf::io_status::eof) {
            for (auto const& event : server_connection->drain_events()) {
                if (event.type == mf::event_type::peer_fin && event.flow == server_flow) {
                    saw_fin = true;
                }
            }
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(1));
    }
    EXPECT_TRUE(saw_fin);

    auto const reset_flow = client_connection->open_flow(mf::direction::bidirectional);
    ASSERT_NE(reset_flow.generation, 0U);
    static constexpr char reset_payload[] = "reset-me";
    ASSERT_EQ(client_connection->write(reset_flow, reset_payload,
                                       sizeof(reset_payload) - 1).status,
              mf::io_status::ok);
    mf::flow_handle reset_peer_flow;
    auto const reset_open_deadline = std::chrono::steady_clock::now()
        + std::chrono::seconds(3);
    while (std::chrono::steady_clock::now() < reset_open_deadline
           && reset_peer_flow.generation == 0) {
        client_connection->drain_events();
        ASSERT_TRUE(listener->handle_events()) << listener->last_error();
        for (auto const& event : server_connection->drain_events()) {
            if (event.type == mf::event_type::flow_open && event.flow) {
                reset_peer_flow = *event.flow;
            }
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(1));
    }
    ASSERT_NE(reset_peer_flow.generation, 0U);
    ASSERT_EQ(client_connection->reset(reset_flow, 0x107), mf::io_status::ok);

    bool saw_reset = false;
    auto const reset_deadline = std::chrono::steady_clock::now() + std::chrono::seconds(3);
    while (std::chrono::steady_clock::now() < reset_deadline && !saw_reset) {
        client_connection->drain_events();
        ASSERT_TRUE(listener->handle_events()) << listener->last_error();
        for (auto const& event : server_connection->drain_events()) {
            if (event.type == mf::event_type::reset && event.flow == reset_peer_flow
                && event.protocol_error == 0x107) {
                saw_reset = true;
            }
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(1));
    }
    EXPECT_TRUE(saw_reset);

    client_connection->close();
    server_connection->close();
    close(client_fd);
    close(server_fd);
}
#endif
