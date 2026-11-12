// Deliberately small protocol benchmark, not a deployable proxy. Both transports
// use the same MFProxy and fixed credentials; neither verifies the B certificate.
#include "connection.hpp"
#include "proxy/multiflow/mfproxy.hpp"
#include "service/quic/quicservice.hpp"
#include "service/quic/worker_dispatcher.hpp"
#include <sslcertstore.hpp>
#include <arpa/inet.h>
#include <poll.h>
#include <pthread.h>
#include <unistd.h>
#include <algorithm>
#include <atomic>
#include <csignal>
#include <iostream>
#include <limits>
#include <stdexcept>
#include <thread>
#include <unordered_map>

namespace q = sx::quic;
namespace ex = q::experiment;
namespace mf = sx::multiflow;
namespace {
volatile sig_atomic_t stopping = 0;
std::atomic_bool failed {false};
void interrupt(int) { stopping = 1; }

// Socket ownership stays with the worker (egress) or the shared receiver.
struct socket_owner {
    int fd = -1;
    ~socket_owner() { if (fd >= 0) ::close(fd); }
};

q::datagram_endpoint endpoint(std::string const& address, uint16_t port, int family) {
    q::datagram_endpoint result;
    result.address.ss_family = family;
    if (family == AF_INET) {
        auto* in = reinterpret_cast<sockaddr_in*>(&result.address);
        in->sin_port = htons(port);
        result.size = sizeof(*in);
        if (inet_pton(family, address.c_str(), &in->sin_addr) != 1)
            throw std::runtime_error("invalid IPv4 address");
    } else {
        auto* in = reinterpret_cast<sockaddr_in6*>(&result.address);
        in->sin6_port = htons(port);
        result.size = sizeof(*in);
        if (inet_pton(family, address.c_str(), &in->sin6_addr) != 1)
            throw std::runtime_error("invalid IPv6 address");
    }
    return result;
}

// Original-destination metadata is used on both legs. On A, IP_TRANSPARENT and
// source-address ancillary data preserve the origin's IP:443 on every reply.
int open_socket(q::datagram_endpoint& local, bool transparent) {
    socket_owner socket;
    int family = local.address.ss_family;
    socket.fd = ::socket(family, SOCK_DGRAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
    if (socket.fd < 0) throw std::runtime_error("socket failed");
    auto option = [&](int level, int name, int value) {
        if (setsockopt(socket.fd, level, name, &value, sizeof(value)))
            throw std::runtime_error("setsockopt failed");
    };
    if (family == AF_INET6) option(IPPROTO_IPV6, IPV6_V6ONLY, 1);
    if (transparent) option(family == AF_INET ? IPPROTO_IP : IPPROTO_IPV6,
                            family == AF_INET ? IP_TRANSPARENT : IPV6_TRANSPARENT, 1);
    option(family == AF_INET ? IPPROTO_IP : IPPROTO_IPV6,
           family == AF_INET ? IP_RECVORIGDSTADDR : IPV6_RECVORIGDSTADDR, 1);
    option(family == AF_INET ? IPPROTO_IP : IPPROTO_IPV6,
           family == AF_INET ? IP_PKTINFO : IPV6_RECVPKTINFO, 1);
    if (bind(socket.fd, reinterpret_cast<sockaddr*>(&local.address), local.size)
        || getsockname(socket.fd, reinterpret_cast<sockaddr*>(&local.address), &local.size))
        throw std::runtime_error("bind/getsockname failed");
    return std::exchange(socket.fd, -1);
}

int select_h3(SSL*, const unsigned char** out, unsigned char* size,
              const unsigned char* in, unsigned length, void*) {
    static constexpr unsigned char h3[] {2, 'h', '3'};
    return SSL_select_next_proto(const_cast<unsigned char**>(out), size,
                                 h3, sizeof(h3), in, length) == OPENSSL_NPN_NEGOTIATED
        ? SSL_TLSEXT_ERR_OK : SSL_TLSEXT_ERR_ALERT_FATAL;
}

q::unique_ssl_ctx context(bool server, std::string const& cert, std::string const& key) {
    q::unique_ssl_ctx ctx(SSL_CTX_new(server ? TLS_server_method() : TLS_client_method()));
    if (!ctx || !SSL_CTX_set_min_proto_version(ctx.get(), TLS1_3_VERSION)
        || !SSL_CTX_set_max_proto_version(ctx.get(), TLS1_3_VERSION))
        throw std::runtime_error("TLS context failed");
    SSL_CTX_set_verify(ctx.get(), SSL_VERIFY_NONE, nullptr);
    if (server) {
        if (SSL_CTX_use_certificate_chain_file(ctx.get(), cert.c_str()) != 1
            || SSL_CTX_use_PrivateKey_file(ctx.get(), key.c_str(), SSL_FILETYPE_PEM) != 1
            || SSL_CTX_check_private_key(ctx.get()) != 1)
            throw std::runtime_error("test certificate failed");
        SSL_CTX_set_alpn_select_cb(ctx.get(), select_h3, nullptr);
        SSL_CTX_set_num_tickets(ctx.get(), 0);
    }
    return ctx;
}

// ngtcp2 has per-connection state, not an OpenSSL-style engine. This worker
// supplies the shared input/output scheduling and owns every A:B pair it admits.
class worker {
public:
    worker(std::shared_ptr<q::worker_dispatcher> receiver, size_t index,
           q::datagram_endpoint egress, std::string const& cert, std::string const& key)
        : receiver_(std::move(receiver)), index_(index), local_(egress),
          server_(context(true, cert, key)), client_(context(false, cert, key)) {
        output_.fd = open_socket(local_, false);
    }

    // Bound receive and transmit batches; otherwise wake only for input or the
    // earliest actual protocol deadline. The 100 ms cap merely allows shutdown.
    void run() {
        std::string name = "ng_w" + std::to_string(index_);
        pthread_setname_np(pthread_self(), name.c_str());
        bool immediate = true;
        while (!stopping && !failed && !receiver_->error()) {
            auto ts = ex::now();
            auto deadline = ts + 100 * NGTCP2_MILLISECONDS;
            short output_events = POLLIN, input_events = 0;
            for (auto& pair : pairs_) {
                for (auto* c : {pair->a.get(), pair->b.get()}) deadline = std::min(deadline, c->deadline());
                if (pair->a->send_blocked()) input_events = POLLOUT;
                if (pair->b->send_blocked()) output_events |= POLLOUT;
            }
            // Keep sub-millisecond pacing deadlines intact. Rounding each one
            // up to a poll() millisecond would manufacture a throughput limit.
            auto wait = immediate || deadline <= ts ? 0 : deadline - ts;
            timespec timeout {static_cast<time_t>(wait / NGTCP2_SECONDS),
                              static_cast<long>(wait % NGTCP2_SECONDS)};
            pollfd fds[] {{receiver_->wake_fd(index_), POLLIN, 0},
                          {output_.fd, output_events, 0},
                          {receiver_->socket_fd(), input_events, 0}};
            if (::ppoll(fds, 3, &timeout, nullptr) < 0 && errno != EINTR) throw std::runtime_error("poll failed");
            ts = ex::now();
            q::datagram_packet packet;
            for (size_t n = 0; n < 64 && receiver_->pop(index_, packet); ++n) receive(packet, true, ts);
            for (size_t n = 0; n < 64 && q::receive_datagram(output_.fd, packet); ++n) receive(packet, false, ts);
            immediate = false;
            for (auto& pair : pairs_) {
                pair->a->expire(ts);
                pair->b->expire(ts);
                if (!pair->bridge && pair->a->established() && pair->b->established()) {
                    pair->bridge = std::make_unique<mf::MFProxy>(pair->a, pair->b);
                    ++active_;
                }
                if (pair->bridge) immediate |= pair->bridge->pump_once() != 0;
                else if (pair->a->ended() || pair->b->ended()) {
                    pair->a->close(); pair->b->close();
                }
                immediate |= pair->a->transmit(receiver_->socket_fd(), ts) == 64;
                immediate |= pair->b->transmit(output_.fd, ts) == 64;
            }
        }
        std::cout << "worker=" << index_ << " accepted=" << pairs_.size()
                  << " active=" << active_ << " dropped=" << receiver_->dropped(index_) << '\n';
    }

private:
    struct session {
        std::shared_ptr<ex::connection> a, b;
        std::unique_ptr<mf::MFProxy> bridge;
    };
    using routes = std::unordered_map<std::string, session*>;

    // The stable session address exists before either connection constructor
    // registers its first CID. A/B maps are separate even for identical CIDs.
    ex::cid_router router(session* owner, bool downstream) {
        return [this, owner, downstream](ngtcp2_cid const& cid, bool add) {
            auto& map = downstream ? inbound_ : outbound_;
            std::string key(reinterpret_cast<char const*>(cid.data), cid.datalen);
            if (add) {
                auto [it, inserted] = map.emplace(key, owner);
                if (!inserted && it->second != owner) throw std::runtime_error("CID collision");
            } else if (auto it = map.find(key); it != map.end() && it->second == owner) map.erase(it);
        };
    }

    // Only an eligible downstream Initial creates a pair. The original target
    // address is the B destination; there is no certificate-probe connection C.
    void receive(q::datagram_packet const& packet, bool downstream, ex::timestamp ts) {
        ngtcp2_version_cid header {};
        if (ngtcp2_pkt_decode_version_cid(&header, packet.data.data(), packet.data.size(), 16)) return;
        auto& map = downstream ? inbound_ : outbound_;
        auto found = map.find(std::string(reinterpret_cast<char const*>(header.dcid), header.dcidlen));
        session* pair = found == map.end() ? nullptr : found->second;
        if (!pair) {
            ngtcp2_pkt_hd initial {};
            if (!downstream || pairs_.size() == 1024
                || ngtcp2_accept(&initial, packet.data.data(), packet.data.size()) != 0
                || initial.version != NGTCP2_PROTO_VER_V1) return;
            auto value = std::make_unique<session>();
            pair = value.get();
            pair->a = std::make_shared<ex::connection>(server_.get(), true, packet.local,
                packet.peer, &initial, router(pair, true), ts);
            pair->b = std::make_shared<ex::connection>(client_.get(), false, local_,
                packet.local, nullptr, router(pair, false), ts);
            pairs_.push_back(std::move(value));
        }
        (downstream ? pair->a : pair->b)->receive(packet, ts);
    }

    std::shared_ptr<q::worker_dispatcher> receiver_;
    size_t index_, active_ = 0;
    q::datagram_endpoint local_;
    socket_owner output_;
    q::unique_ssl_ctx server_, client_;
    routes inbound_, outbound_;
    // Closed pairs are retained for this bounded, short-lived lab process so
    // stale CIDs cannot create new sessions. Production retirement is deferred.
    std::vector<std::unique_ptr<session>> pairs_;
};

} // namespace

int main(int argc, char** argv) {
    if (argc != 9 || std::string(argv[1]) != "--insecure-lab") {
        std::cerr << "usage: quic_transport_experiment --insecure-lab ngtcp2|openssl CERT KEY EGRESS_IP ORIGIN_IP 4|6 WORKERS\n";
        return 2;
    }
    try {
        std::string backend = argv[2], cert = argv[3], key = argv[4];
        if (backend != "openssl" && backend != "ngtcp2") throw std::runtime_error("unknown backend");
        int family = std::stoi(argv[7]) == 6 ? AF_INET6 : AF_INET;
        size_t workers = std::stoul(argv[8]);
        if (!workers || workers > 16) throw std::runtime_error("workers must be 1..16");
        signal(SIGINT, interrupt); signal(SIGTERM, interrupt);
        auto receiver = std::make_shared<q::worker_dispatcher>(workers);
        std::vector<std::unique_ptr<worker>> native;
        std::vector<std::unique_ptr<q::listener_service>> openssl;
        socket_owner input;
        if (backend == "ngtcp2") {
            if (ngtcp2_crypto_ossl_init()) throw std::runtime_error("crypto init failed");
            auto bind_address = endpoint(family == AF_INET ? "0.0.0.0" : "::", 443, family);
            input.fd = open_socket(bind_address, true);
            if (!receiver->attach_socket(input.fd)) throw std::runtime_error("receiver attach failed");
            for (size_t i = 0; i < workers; ++i)
                native.push_back(std::make_unique<worker>(receiver, i, endpoint(argv[5], 0, family), cert, key));
        } else {
            // The production context helper always attaches its central trust
            // store, even though this lab explicitly disables peer verification.
            // Its standalone path resolves SNI; supply the lab origin explicitly
            // because origin.runner.lab has no DNS record in these namespaces.
            SSLFactory::factory().ca_file() = cert;
            for (size_t i = 0; i < workers; ++i) {
                auto service = std::make_unique<q::listener_service>(443, cert, key, true, 443, false,
                    q::lifecycle_options{}, q::resource_limits{}, argv[6], q::flow_proxy_factory{},
                    false, sx::proxymaker::SessionSetupFactory{}, std::nullopt, std::nullopt, family);
                service->assign_worker(receiver, i);
                if (!service->prepare()) throw std::runtime_error(service->last_error());
                openssl.push_back(std::move(service));
            }
        }
        if (!receiver->start()) throw std::runtime_error("receiver start failed");
        std::vector<std::thread> threads;
        for (size_t i = 0; i < workers; ++i) threads.emplace_back([&, i] {
            try { if (backend == "ngtcp2") native[i]->run(); else openssl[i]->run(); }
            catch (std::exception const& e) { std::cerr << e.what() << '\n'; failed = true; }
        });
        std::cout << "READY backend=" << backend << " workers=" << workers << " bridge=MFProxy verify_B=off\n" << std::flush;
        while (!stopping && !failed && !receiver->error()) std::this_thread::sleep_for(std::chrono::milliseconds(50));
        for (auto& service : openssl) service->stop();
        receiver->stop();
        for (auto& thread : threads) thread.join();
        return failed || receiver->error() ? 1 : 0;
    } catch (std::exception const& e) {
        std::cerr << e.what() << ": " << q::openssl_error_stack() << '\n';
        return 2;
    }
}
