#include "proxy/quic/openssl.hpp"

#include <arpa/inet.h>
#include <fcntl.h>
#include <unistd.h>

#include <algorithm>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <string>
#include <thread>
#include <vector>

namespace quic = sx::quic;
namespace mf = sx::multiflow;

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

bool nonblocking(int fd) {
    auto const flags = fcntl(fd, F_GETFL, 0);
    return flags >= 0 && fcntl(fd, F_SETFL, flags | O_NONBLOCK) == 0;
}

struct endpoint_pair {
    quic::unique_ssl_ctx server_context;
    quic::unique_ssl_ctx client_context;
    int server_fd = -1;
    std::unique_ptr<quic::openssl_listener> listener;
    std::unique_ptr<quic::openssl_connection> client;
    std::unique_ptr<quic::openssl_connection> server;

    ~endpoint_pair() {
        server.reset();
        client.reset();
        listener.reset();
        if (server_fd >= 0) close(server_fd);
    }
};

bool establish(endpoint_pair& pair) {
    pair.server_context = quic::make_openssl_quic_context(true);
    pair.client_context = quic::make_openssl_quic_context(false);
    if (!pair.server_context || !pair.client_context) return false;
    if (SSL_CTX_use_certificate_chain_file(pair.server_context.get(),
                                           "etc/certs/default/srv-cert.pem") != 1
        || SSL_CTX_use_PrivateKey_file(pair.server_context.get(),
                                       "etc/certs/default/srv-key.pem",
                                       SSL_FILETYPE_PEM) != 1) {
        return false;
    }
    SSL_CTX_set_alpn_select_cb(pair.server_context.get(), select_h3, nullptr);
    SSL_CTX_set_verify(pair.client_context.get(), SSL_VERIFY_NONE, nullptr);
    pair.server_fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (pair.server_fd < 0 || !nonblocking(pair.server_fd)) return false;
    sockaddr_in address {};
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    if (bind(pair.server_fd, reinterpret_cast<sockaddr*>(&address), sizeof(address)) != 0) {
        return false;
    }
    socklen_t address_size = sizeof(address);
    if (getsockname(pair.server_fd, reinterpret_cast<sockaddr*>(&address),
                    &address_size) != 0) {
        return false;
    }
    pair.listener = quic::openssl_listener::create(
        pair.server_context.get(), pair.server_fd, false);
    if (!pair.listener) return false;
    std::string error;
    pair.client = quic::connect_openssl_quic(
        pair.client_context.get(), reinterpret_cast<sockaddr*>(&address),
        sizeof(address), "localhost", &error);
    if (!pair.client) return false;

    for (std::size_t iteration = 0; iteration < 2000; ++iteration) {
        pair.client->drain_events();
        pair.listener->handle_events();
        if (!pair.server) pair.server = pair.listener->accept();
        if (pair.server) pair.server->drain_events();
        if (pair.server && pair.client->handshake_complete()
            && pair.server->handshake_complete()) {
            return true;
        }
        if (pair.client->closed() || (pair.server && pair.server->closed())) return false;
        std::this_thread::yield();
    }
    return false;
}

mf::flow_handle select_flow(std::vector<mf::flow_handle> const& flows,
                            std::uint8_t selector) {
    if (flows.empty()) return { selector, static_cast<mf::generation_id>(selector) };
    return flows[selector % flows.size()];
}

void collect(std::unique_ptr<quic::openssl_connection>& connection,
             std::vector<mf::flow_handle>& flows) {
    if (!connection) return;
    for (auto const& event : connection->drain_events()) {
        if (event.type == mf::event_type::flow_open && event.flow) {
            flows.push_back(*event.flow);
        }
    }
}

} // namespace
#endif

extern "C" int LLVMFuzzerTestOneInput(std::uint8_t const* data, std::size_t size) {
#if SMITHPROXY_OPENSSL_QUIC
    if (!data || size == 0) return 0;
    endpoint_pair pair;
    if (!establish(pair)) return 0;
    std::vector<mf::flow_handle> client_flows;
    std::vector<mf::flow_handle> server_flows;
    std::size_t offset = 0;
    auto next = [&]() { return offset < size ? data[offset++] : std::uint8_t { 0 }; };

    for (std::size_t operations = 0;
         offset < size && operations < 128 && pair.client && pair.server;
         ++operations) {
        auto const opcode = next() % 9;
        bool const client_side = (next() & 1U) != 0;
        auto& connection = client_side ? pair.client : pair.server;
        auto& flows = client_side ? client_flows : server_flows;
        auto const flow = select_flow(flows, next());
        switch (opcode) {
            case 0: {
                auto const direction = (next() & 1U) != 0
                    ? mf::direction::send_only : mf::direction::bidirectional;
                auto const created = connection->open_flow(direction);
                if (created.generation != 0) flows.push_back(created);
                break;
            }
            case 1: {
                auto const available = std::min<std::size_t>(next() % 33, size - offset);
                connection->write(flow, data + offset, available);
                offset += available;
                break;
            }
            case 2: {
                unsigned char buffer[128] {};
                connection->read(flow, buffer, next() % sizeof(buffer));
                break;
            }
            case 3: connection->finish(flow); break;
            case 4: connection->reset(flow, next()); break;
            case 5: connection->close(next()); break;
            case 6: collect(connection, flows); break;
            case 7: pair.listener->handle_events(); break;
            case 8:
                collect(pair.client, client_flows);
                collect(pair.server, server_flows);
                break;
        }
        pair.listener->handle_events();
        collect(pair.client, client_flows);
        collect(pair.server, server_flows);
    }
#else
    (void)data;
    (void)size;
#endif
    return 0;
}
