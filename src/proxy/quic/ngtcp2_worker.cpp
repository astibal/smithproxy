#include "proxy/quic/ngtcp2.hpp"
#include "proxy/quic/transport.hpp"
#include <sslcertstore.hpp>
#include <arpa/inet.h>
#include <poll.h>
#include <unistd.h>
#include <algorithm>
#include <cstring>
#include <limits>
#include <stdexcept>
#include <mutex>
#include <set>
#include <unordered_map>

namespace sx::quic {
namespace {
struct socket_owner {
    int fd = -1;
    ~socket_owner() { if (fd >= 0) ::close(fd); }
};

// The outbound socket is shared by all B legs on this worker, never connected
// to a single peer. Original-destination metadata supplies each received path.
int open_output_socket(int family) {
    socket_owner socket;
    socket.fd = ::socket(family, SOCK_DGRAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
    if (socket.fd < 0) throw std::runtime_error("ngtcp2 output socket failed");
    int one = 1;
    int level = family == AF_INET ? IPPROTO_IP : IPPROTO_IPV6;
    int original = family == AF_INET ? IP_RECVORIGDSTADDR : IPV6_RECVORIGDSTADDR;
    if (setsockopt(socket.fd, level, original, &one, sizeof(one)))
        throw std::runtime_error("ngtcp2 output metadata failed");
    datagram_endpoint local;
    local.address.ss_family = family;
    local.size = family == AF_INET ? sizeof(sockaddr_in) : sizeof(sockaddr_in6);
    if (::bind(socket.fd, reinterpret_cast<sockaddr*>(&local.address), local.size))
        throw std::runtime_error("ngtcp2 output bind failed");
    return std::exchange(socket.fd, -1);
}

// Ask the kernel for the route's local IP without sending a datagram. This is
// only an unsent UDP route lookup, not another TLS/QUIC connection. Its temporary
// port is replaced by the shared worker socket's port before creating B.
datagram_endpoint outgoing_path(int fd, sockaddr const* peer, socklen_t size) {
    socket_owner lookup;
    lookup.fd = ::socket(peer->sa_family, SOCK_DGRAM | SOCK_CLOEXEC, 0);
    datagram_endpoint local, bound;
    local.size = bound.size = sizeof(sockaddr_storage);
    if (lookup.fd < 0 || ::connect(lookup.fd, peer, size)
        || getsockname(lookup.fd, reinterpret_cast<sockaddr*>(&local.address), &local.size)
        || getsockname(fd, reinterpret_cast<sockaddr*>(&bound.address), &bound.size))
        throw std::runtime_error("ngtcp2 output route lookup failed");
    if (peer->sa_family == AF_INET)
        reinterpret_cast<sockaddr_in*>(&local.address)->sin_port = reinterpret_cast<sockaddr_in*>(&bound.address)->sin_port;
    else
        reinterpret_cast<sockaddr_in6*>(&local.address)->sin6_port = reinterpret_cast<sockaddr_in6*>(&bound.address)->sin6_port;
    return local;
}

bool same_endpoint(datagram_endpoint const& a, datagram_endpoint const& b) {
    if (a.address.ss_family != b.address.ss_family) return false;
    if (a.address.ss_family == AF_INET) {
        auto* x = reinterpret_cast<sockaddr_in const*>(&a.address);
        auto* y = reinterpret_cast<sockaddr_in const*>(&b.address);
        return x->sin_port == y->sin_port && x->sin_addr.s_addr == y->sin_addr.s_addr;
    }
    auto* x = reinterpret_cast<sockaddr_in6 const*>(&a.address);
    auto* y = reinterpret_cast<sockaddr_in6 const*>(&b.address);
    return x->sin6_port == y->sin6_port && x->sin6_scope_id == y->sin6_scope_id
        && std::memcmp(&x->sin6_addr, &y->sin6_addr, sizeof(in6_addr)) == 0;
}

class ngtcp2_worker final : public worker_transport {
    struct entry {
        std::shared_ptr<ng::connection> connection;
        datagram_endpoint peer, local;
        uint64_t association = 0;
        unsigned ifindex = 0;
        bool downstream = false;
        ng::timestamp retirement = 0;
        std::set<std::string> cids;
    };
    using routes = std::unordered_map<std::string, entry*>;
public:
    ngtcp2_worker(SSL_CTX* server, int fd, int family, datagram_observer observer,
                  datagram_source source, size_t limit)
        : server_(server), fd_(fd), source_(std::move(source)), observer_(std::move(observer)), limit_(limit) {
        // Even a loopback/non-transparent listener needs the actual destination
        // address. A wildcard bind is not a valid ngtcp2 path.
        int enabled = 1;
        auto level = family == AF_INET ? IPPROTO_IP : IPPROTO_IPV6;
        auto option = family == AF_INET ? IP_RECVORIGDSTADDR : IPV6_RECVORIGDSTADDR;
        if (setsockopt(fd_, level, option, &enabled, sizeof(enabled)))
            throw std::runtime_error("ngtcp2 input metadata failed");
        output_.fd = open_output_socket(family);
    }

    // Separate A/B passes match the service's existing scheduling. TLS resume
    // happens under the saved A tuple, even when no new packet accompanied it.
    bool handle_events() override { return progress(true); }
    bool handle_upstream() override { return progress(false); }
    std::shared_ptr<transport_connection> accept() override {
        if (accepted_.empty()) return {};
        auto result = std::move(accepted_.front()); accepted_.pop_front();
        return result;
    }

    // Apply the ordinary hook offer and verifier before B emits its Initial.
    // The resulting connection is retained by the same certificate job and then
    // handed to the same stream bridge; there is no probe/data split.
    std::shared_ptr<transport_connection> connect(
        SSL_CTX* tls, sockaddr const* peer, socklen_t size, std::string const& name,
        std::string* error, proxymaker::SessionSetup* setup,
        std::function<bool(SSL*)> const& configure) override {
        HookEvent offer;
        offer.sni = name; offer.alpn = "h3";
        if (!hook_start(setup, offer)) {
            if (error) *error = "QUIC start rejected by callback";
            return {};
        }
        try {
            if (!tls || !peer || size > sizeof(sockaddr_storage))
                throw std::runtime_error("invalid ngtcp2 peer");
            datagram_endpoint remote;
            remote.size = size; std::memcpy(&remote.address, peer, size);
            return create(tls, false, outgoing_path(output_.fd, peer, size), remote, 0, nullptr, ng::now(),
                [&](SSL* ssl) {
                    if (offer.alpn.empty() || offer.alpn.size() > 255) return false;
                    std::vector<unsigned char> alpn {static_cast<unsigned char>(offer.alpn.size())};
                    alpn.insert(alpn.end(), offer.alpn.begin(), offer.alpn.end());
                    std::array<unsigned char, sizeof(in6_addr)> binary {};
                    bool numeric = inet_pton(AF_INET, name.c_str(), binary.data()) == 1
                        || inet_pton(AF_INET6, name.c_str(), binary.data()) == 1;
                    bool identity = numeric
                        ? X509_VERIFY_PARAM_set1_ip_asc(SSL_get0_param(ssl), name.c_str()) == 1
                        : SSL_set_tlsext_host_name(ssl, name.c_str()) == 1 && SSL_set1_host(ssl, name.c_str()) == 1;
                    if (!identity || SSL_set_alpn_protos(ssl, alpn.data(), alpn.size())
                        || !apply_hook_offer(ssl, offer, name)) return false;
                    return !configure || configure(ssl);
                });
        } catch (std::exception const& e) {
            if (error) *error = e.what();
            hook_failure(setup, name, e.what());
            return {};
        }
    }

    // Writes performed by the bridge mark application progress; the following
    // worker pass sends them in a bounded batch, just like the OpenSSL path.
    bool flush_output(datagram_endpoint const&, datagram_endpoint const&, uint64_t) override { return true; }
    std::chrono::nanoseconds timeout() const override {
        auto ts = ng::now();
        auto earliest = std::numeric_limits<ng::timestamp>::max();
        for (auto const& value : entries_) {
            earliest = std::min(earliest, value->connection->deadline());
            if (value->retirement) earliest = std::min(earliest, value->retirement);
        }
        if (earliest == std::numeric_limits<ng::timestamp>::max()) return std::chrono::nanoseconds(-1);
        return std::chrono::nanoseconds(earliest > ts ? earliest - ts : 0);
    }
    short desired_socket_events() const override { return POLLIN | (blocked(true) ? POLLOUT : 0); }
    int upstream_fd() const override { return output_.fd; }
    short upstream_events() const override { return POLLIN | (blocked(false) ? POLLOUT : 0); }
    std::string last_error() const override { return error_; }
    datagram_endpoint current_peer() const override { return current_ ? current_->peer : datagram_endpoint {}; }
    datagram_endpoint current_local() const override { return current_ ? current_->local : datagram_endpoint {}; }
    unsigned current_ingress_ifindex() const override { return current_ ? current_->ifindex : 0; }
    uint64_t current_association() const override { return current_ ? current_->association : 0; }
    bool bind_connection_route(SSL* ssl) override {
        return current_ && current_->connection && current_->connection->native_handle() == ssl;
    }

private:
    /** Register both issued CIDs and the original Initial CID under one stable owner. */
    ng::cid_router router(entry* owner) {
        return [this, owner](ngtcp2_cid const& cid, bool add) {
            auto& map = owner->downstream ? incoming_ : outgoing_;
            std::string key(reinterpret_cast<char const*>(cid.data), cid.datalen);
            if (add) {
                auto [it, inserted] = map.emplace(key, owner);
                if (!inserted && it->second != owner) throw std::runtime_error("ngtcp2 CID collision");
                owner->cids.insert(std::move(key));
            } else {
                map.erase(key); owner->cids.erase(key);
            }
        };
    }

    std::shared_ptr<ng::connection> create(
        SSL_CTX* tls, bool downstream, datagram_endpoint local, datagram_endpoint peer,
        unsigned ifindex, ngtcp2_pkt_hd const* initial, ng::timestamp started,
        std::function<bool(SSL*)> configure) {
        auto value = std::make_unique<entry>();
        auto* owner = value.get();
        owner->local = local; owner->peer = peer; owner->ifindex = ifindex;
        owner->downstream = downstream;
        owner->association = downstream ? next_association_++ : 0;
        datagram_observer observer;
        if (downstream && observer_) observer = [this, owner](datagram_view const& packet) {
            auto view = packet; view.association = owner->association;
            observer_(view);
        };
        try {
            owner->connection = std::make_shared<ng::connection>(tls, downstream, local, peer,
                initial, router(owner), started, std::move(configure), std::move(observer),
                [this, owner] { current_ = owner; });
        } catch (...) {
            erase_routes(*owner);
            throw;
        }
        auto result = owner->connection;
        entries_.push_back(std::move(value));
        return result;
    }

    /** Recover the CID owner before invoking any TLS callback or capture observer. */
    void receive(datagram_packet const& packet, bool downstream, ng::timestamp ts) {
        if (!packet.peer.valid() || !packet.local.valid()) return;
        ngtcp2_version_cid header {};
        if (ngtcp2_pkt_decode_version_cid(&header, packet.data.data(), packet.data.size(), 16)) return;
        auto& map = downstream ? incoming_ : outgoing_;
        std::string key(reinterpret_cast<char const*>(header.dcid), header.dcidlen);
        auto it = map.find(key);
        entry* owner = it == map.end() ? nullptr : it->second;
        if (!owner) {
            // Leave one receive batch beyond the steady A:B capacity so the
            // common service can reject/count excess sessions itself. Retired
            // transports remain bounded while their close packet drains.
            ngtcp2_pkt_hd initial {};
            if (!downstream || entries_.size() >= 2 * limit_ + 64
                || ngtcp2_accept(&initial, packet.data.data(), packet.data.size()) != 0
                || initial.version != NGTCP2_PROTO_VER_V1) return;
            auto connection = create(server_, true, packet.local, packet.peer, packet.ingress_ifindex, &initial, ts, {});
            owner = incoming_.at(key);
            accepted_.push_back(std::move(connection));
        }
        // Migration needs dispatcher/transparent-routing agreement. Preserve the
        // original tuple until that capability is implemented and tested.
        if (!same_endpoint(owner->peer, packet.peer) || !same_endpoint(owner->local, packet.local)) return;
        current_ = owner;
        if (downstream && observer_) observer_({datagram_direction::ingress, packet.peer, packet.local,
            owner->association, packet.data.data(), packet.data.size()});
        owner->connection->receive(packet, ts);
    }

    bool progress(bool downstream) {
        try {
            auto ts = ng::now();
            datagram_packet packet;
            for (size_t n = 0; n < 64; ++n) {
                bool got = downstream ? (source_ ? source_(packet) : receive_datagram(fd_, packet))
                                      : receive_datagram(output_.fd, packet);
                if (!got) break;
                receive(packet, downstream, ts);
            }
            for (auto& value : entries_) {
                if (value->downstream != downstream) continue;
                current_ = value.get();
                value->connection->progress_transport();
                value->connection->expire(ts);
                value->connection->transmit(downstream ? fd_ : output_.fd, ts);
            }
            retire(ts);
            return true;
        } catch (std::exception const& e) {
            error_ = e.what(); return false;
        }
    }

    /** Keep abandoned legs briefly for close delivery, then remove every CID. */
    void retire(ng::timestamp ts) {
        for (auto it = entries_.begin(); it != entries_.end();) {
            auto& value = **it;
            if (value.connection.use_count() != 1) { ++it; continue; }
            if (!value.retirement) {
                value.connection->close();
                value.retirement = ts + 3 * NGTCP2_SECONDS;
            }
            if (value.retirement > ts) { ++it; continue; }
            if (current_ == &value) current_ = nullptr;
            erase_routes(value);
            it = entries_.erase(it);
        }
    }
    void erase_routes(entry const& value) {
        auto& map = value.downstream ? incoming_ : outgoing_;
        for (auto const& cid : value.cids) map.erase(cid);
    }
    bool blocked(bool downstream) const {
        return std::any_of(entries_.begin(), entries_.end(), [=](auto const& value) {
            return value->downstream == downstream && value->connection->send_blocked();
        });
    }

    SSL_CTX* server_;
    int fd_;
    socket_owner output_;
    datagram_source source_;
    datagram_observer observer_;
    size_t limit_;
    uint64_t next_association_ = 1;
    entry* current_ = nullptr;
    std::string error_;
    routes incoming_, outgoing_;
    std::vector<std::unique_ptr<entry>> entries_;
    std::deque<std::shared_ptr<transport_connection>> accepted_;
};
}

// TLS uses the same trust and CT store as OpenSSL QUIC. Only the QUIC record
// method differs: ngtcp2 owns records and uses OpenSSL's public TLS-only API.
unique_ssl_ctx make_ngtcp2_context(bool server) {
    static std::once_flag initialized;
    std::call_once(initialized, [] {
        if (ngtcp2_crypto_ossl_init()) throw std::runtime_error("ngtcp2 crypto initialization failed");
    });
    unique_ssl_ctx context(SSL_CTX_new(server ? TLS_server_method() : TLS_client_method()));
    if (!context || SSL_CTX_set_min_proto_version(context.get(), TLS1_3_VERSION) != 1
        || SSL_CTX_set_max_proto_version(context.get(), TLS1_3_VERSION) != 1
        || !SSLFactory::factory().set_verify_locations(context.get())) return {};
    if (!server && SSLFactory::factory().is_ct_available()
        && SSL_CTX_set_ctlog_list_file(context.get(), SSLFactory::factory().ctlogfile().c_str()) != 1) return {};
    if (server) SSL_CTX_set_keylog_callback(context.get(), ng::connection::record_keylog);
    return context;
}

std::unique_ptr<worker_transport> make_ngtcp2_worker(
    SSL_CTX* server, SSL_CTX*, int fd, int family, bool, datagram_observer observer,
    datagram_source source, size_t limit) {
    try { return std::make_unique<ngtcp2_worker>(server, fd, family, std::move(observer), std::move(source), limit); }
    catch (...) { return {}; }
}
} // namespace sx::quic
