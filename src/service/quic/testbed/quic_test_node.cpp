#include "proxy/quic/openssl.hpp"
#include "service/quic/quicservice.hpp"

#include <sslcertstore.hpp>
#include <log/logger.hpp>

#include <arpa/inet.h>
#include <fcntl.h>
#include <openssl/pem.h>
#include <openssl/x509v3.h>
#include <sys/socket.h>
#include <unistd.h>

#include <atomic>
#include <chrono>
#include <cstring>
#include <iostream>
#include <memory>
#include <string>
#include <thread>
#include <vector>

namespace quic = sx::quic;
namespace mf = sx::multiflow;
using namespace std::chrono_literals;

#if SMITHPROXY_OPENSSL_QUIC
namespace {

std::string path(std::string const& directory, char const* file) {
    return directory + "/" + file;
}

bool nonblocking(int fd) {
    auto const flags = fcntl(fd, F_GETFL, 0);
    return flags >= 0 && fcntl(fd, F_SETFL, flags | O_NONBLOCK) == 0;
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

sockaddr_in endpoint(std::string const& address, std::uint16_t port) {
    sockaddr_in result {};
    result.sin_family = AF_INET;
    result.sin_port = htons(port);
    inet_pton(AF_INET, address.c_str(), &result.sin_addr);
    return result;
}

int run_origin(std::string const& directory, std::string const& address,
               std::uint16_t port) {
    auto context = quic::make_openssl_quic_context(true);
    if (!context
        || SSL_CTX_use_certificate_chain_file(context.get(), path(directory, "srv-cert.pem").c_str()) != 1
        || SSL_CTX_use_PrivateKey_file(context.get(), path(directory, "srv-key.pem").c_str(),
                                       SSL_FILETYPE_PEM) != 1) {
        std::cerr << "origin TLS setup failed: " << quic::openssl_error_stack() << '\n';
        return 2;
    }
    SSL_CTX_set_alpn_select_cb(context.get(), select_h3, nullptr);
    auto const fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (fd < 0 || !nonblocking(fd)) return 2;
    auto local = endpoint(address, port);
    if (bind(fd, reinterpret_cast<sockaddr*>(&local), sizeof(local)) != 0) {
        std::cerr << "origin bind failed: " << std::strerror(errno) << '\n';
        close(fd);
        return 2;
    }
    auto listener = quic::openssl_listener::create(context.get(), fd, false);
    if (!listener) {
        close(fd);
        return 2;
    }
    std::cout << "READY origin\n" << std::flush;
    struct origin_connection {
        std::unique_ptr<quic::openssl_connection> connection;
        std::vector<mf::flow_handle> flows;
    };
    std::vector<origin_connection> connections;
    auto const deadline = std::chrono::steady_clock::now() + 30s;
    while (std::chrono::steady_clock::now() < deadline) {
        listener->handle_events();
        while (auto connection = listener->accept()) {
            connections.push_back({ std::move(connection), {} });
        }
        for (auto& state : connections) {
            for (auto const& event : state.connection->drain_events()) {
                if (event.type == mf::event_type::flow_open && event.flow) {
                    state.flows.push_back(*event.flow);
                }
            }
            for (auto const flow : state.flows) {
                unsigned char buffer[4096] {};
                auto const read = state.connection->read(flow, buffer, sizeof(buffer));
                if (read.size == 0) continue;
                auto const written = state.connection->write(flow, buffer, read.size);
                if (written.size == read.size) {
                    std::cout << "PASS origin echo="
                              << std::string(reinterpret_cast<char const*>(buffer), read.size)
                              << std::flush;
                }
            }
        }
        std::this_thread::sleep_for(1ms);
    }
    close(fd);
    return 0;
}

int run_proxy(std::string const& directory, std::uint16_t port) {
    auto& factory = SSLFactory::factory();
    factory.certs_path() = directory + "/";
    factory.ca_file() = path(directory, "ca-cert.pem");
    factory.ca_path().clear();
    factory.init();
    quic::listener_service service(port, path(directory, "srv-cert.pem"),
                                   path(directory, "srv-key.pem"), true, port, true);
    if (!service.prepare()) {
        std::cerr << "proxy setup failed: " << service.last_error() << '\n';
        factory.destroy();
        return 2;
    }
    std::cout << "READY proxy\n" << std::flush;
    std::thread watchdog([&service]() {
        std::this_thread::sleep_for(30s);
        service.stop();
    });
    service.run();
    watchdog.join();
    factory.destroy();
    return 0;
}

int run_forward_proxy(std::string const& directory, std::uint16_t listen_port,
                      std::string const& upstream_address,
                      std::uint16_t upstream_port) {
    auto& factory = SSLFactory::factory();
    factory.certs_path() = directory + "/";
    factory.ca_file() = path(directory, "ca-cert.pem");
    factory.ca_path().clear();
    factory.init();
    quic::listener_service service(listen_port, path(directory, "srv-cert.pem"),
                                   path(directory, "srv-key.pem"), false,
                                   upstream_port, true, {}, {}, upstream_address);
    if (!service.prepare()) {
        std::cerr << "forward proxy setup failed: " << service.last_error() << '\n';
        factory.destroy();
        return 2;
    }
    std::cout << "READY forward\n" << std::flush;
    std::thread watchdog([&service]() {
        std::this_thread::sleep_for(30s);
        service.stop();
    });
    service.run();
    watchdog.join();
    factory.destroy();
    return 0;
}

int run_client(std::string const& directory, std::string const& address,
               std::uint16_t port, std::string const& sni) {
    auto context = quic::make_openssl_quic_context(false);
    if (!context
        || SSL_CTX_load_verify_locations(context.get(), path(directory, "ca-cert.pem").c_str(),
                                         nullptr) != 1) {
        return 2;
    }
    SSL_CTX_set_verify(context.get(), SSL_VERIFY_PEER, nullptr);
    auto remote = endpoint(address, port);
    std::string error;
    auto connection = quic::connect_openssl_quic(
        context.get(), reinterpret_cast<sockaddr*>(&remote), sizeof(remote), sni, &error);
    if (!connection) {
        std::cerr << error << '\n';
        return 2;
    }
    auto const handshake_deadline = std::chrono::steady_clock::now() + 10s;
    while (!connection->handshake_complete() && !connection->closed()
           && std::chrono::steady_clock::now() < handshake_deadline) {
        connection->drain_events();
        std::this_thread::sleep_for(1ms);
    }
    if (!connection->handshake_complete() || connection->negotiated_alpn() != "h3") {
        std::cerr << "client handshake failed\n";
        return 3;
    }
    std::unique_ptr<X509, decltype(&X509_free)> certificate(
        SSL_get1_peer_certificate(connection->native_handle()), X509_free);
    if (!certificate
        || X509_check_host(certificate.get(), sni.c_str(), sni.size(), 0, nullptr) != 1) {
        std::cerr << "client certificate identity failed\n";
        return 3;
    }
    auto const flow = connection->open_flow(mf::direction::bidirectional);
    static constexpr char payload[] = "smithproxy-transparent-quic";
    auto const written = connection->write(flow, payload, sizeof(payload) - 1);
    if (written.size != sizeof(payload) - 1) return 3;
    std::string received;
    auto const echo_deadline = std::chrono::steady_clock::now() + 10s;
    while (received.size() < sizeof(payload) - 1
           && std::chrono::steady_clock::now() < echo_deadline) {
        connection->drain_events();
        unsigned char buffer[128] {};
        auto const read = connection->read(flow, buffer, sizeof(buffer));
        if (read.size != 0) {
            received.append(reinterpret_cast<char const*>(buffer), read.size);
        }
        std::this_thread::sleep_for(1ms);
    }
    if (received != payload) return 4;
    std::cout << "PASS client sni=" << sni << " alpn=h3 echo=" << received << '\n';
    return 0;
}

} // namespace
#endif

int main(int argc, char** argv) {
#if SMITHPROXY_OPENSSL_QUIC
    Log::init();
    Log::get()->level(WAR);
    if (argc < 4) {
        std::cerr << "usage: quic_test_node MODE PKI_DIR ADDRESS [PORT] [SNI|UPSTREAM_PORT]\n";
        return 64;
    }
    std::string const mode = argv[1];
    std::string const directory = argv[2];
    std::string const address = argv[3];
    auto const port = static_cast<std::uint16_t>(argc > 4 ? std::stoi(argv[4]) : 443);
    if (mode == "origin") return run_origin(directory, address, port);
    if (mode == "proxy") return run_proxy(directory, port);
    if (mode == "forward") {
        auto const upstream_port = static_cast<std::uint16_t>(
            argc > 5 ? std::stoi(argv[5]) : 443);
        return run_forward_proxy(directory, port, address, upstream_port);
    }
    if (mode == "client") {
        return run_client(directory, address, port, argc > 5 ? argv[5] : "localhost");
    }
    return 64;
#else
    (void)argc;
    (void)argv;
    std::cerr << "OpenSSL QUIC support unavailable\n";
    return 77;
#endif
}
