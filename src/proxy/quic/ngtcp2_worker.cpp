#include "proxy/quic/error_stats.hpp"
#include "proxy/quic/tls_log.hpp"
#include <vars.hpp>
#include <privileged_socket.hpp>
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
// Worker-created descriptors use socle's RAII value wrapper. The downstream
// descriptor is borrowed; only output and temporary route-lookup FDs are owned.
using owned_socket = socle::raw::unique<int>;

// The outbound socket is shared by all B legs on this worker, never connected
// to a single peer. Original-destination metadata supplies each received path.
int open_output_socket(int family) {
    owned_socket socket {socle::socket(family, SOCK_DGRAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0), close_descriptor};
    if (socket.value < 0) {
        ++stats.errors.worker_open_output_socket_ngtcp2_output_socket_failed;
        throw std::runtime_error("ngtcp2 output socket failed");
    }
    int one = 1;
    int level = family == AF_INET ? IPPROTO_IP : IPPROTO_IPV6;
    int original = family == AF_INET ? IP_RECVORIGDSTADDR : IPV6_RECVORIGDSTADDR;
    if (socle::setsockopt(socket.value, level, original, &one, sizeof(one))) {
        ++stats.errors.worker_open_output_socket_ngtcp2_output_metadata_failed;
        throw std::runtime_error("ngtcp2 output metadata failed");
    }
    datagram_endpoint local;
    local.address.ss_family = family;
    local.size = family == AF_INET ? sizeof(sockaddr_in) : sizeof(sockaddr_in6);
    if (socle::bind(socket.value, reinterpret_cast<sockaddr*>(&local.address), local.size)) {
        ++stats.errors.worker_open_output_socket_ngtcp2_output_bind_failed;
        throw std::runtime_error("ngtcp2 output bind failed");
    }
    return socket.release();
}

// Ask the kernel for the route's local IP without sending a datagram. This is
// only an unsent UDP route lookup, not another TLS/QUIC connection. Its temporary
// port is replaced by the shared worker socket's port before creating B.
datagram_endpoint outgoing_path(int fd, sockaddr const* peer, socklen_t size) {
    owned_socket lookup {socle::socket(peer->sa_family, SOCK_DGRAM | SOCK_CLOEXEC, 0), close_descriptor};
    datagram_endpoint local, bound;
    local.size = bound.size = sizeof(sockaddr_storage);
    bool const route_selected = lookup.value >= 0 && ::connect(lookup.value, peer, size) == 0;
    bool const addresses_known = route_selected
        && getsockname(lookup.value, reinterpret_cast<sockaddr*>(&local.address), &local.size) == 0
        && getsockname(fd, reinterpret_cast<sockaddr*>(&bound.address), &bound.size) == 0;
    if (!addresses_known) {
        ++stats.errors.worker_outgoing_path_ngtcp2_output_route_lookup_failed;
        throw std::runtime_error("ngtcp2 output route lookup failed");
    }
    if (peer->sa_family == AF_INET)
        reinterpret_cast<sockaddr_in*>(&local.address)->sin_port = reinterpret_cast<sockaddr_in*>(&bound.address)->sin_port;
    else
        reinterpret_cast<sockaddr_in6*>(&local.address)->sin6_port = reinterpret_cast<sockaddr_in6*>(&bound.address)->sin6_port;
    return local;
}

// Compare network identity rather than sockaddr padding bytes.
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

// Configure identity, ALPN and the shared policy before B can emit its Initial.
// Numeric destinations use IP verification without sending an IP literal as SNI.
bool configure_upstream_tls(SSL* ssl, std::string const& name, HookEvent const& offer,
                            std::function<bool(SSL*)> const& configure) {
    if (offer.alpn.empty() || offer.alpn.size() > 255) return false;

    std::vector<unsigned char> alpn {static_cast<unsigned char>(offer.alpn.size())};
    alpn.insert(alpn.end(), offer.alpn.begin(), offer.alpn.end());
    std::array<unsigned char, sizeof(in6_addr)> binary {};
    bool numeric = inet_pton(AF_INET, name.c_str(), binary.data()) == 1
        || inet_pton(AF_INET6, name.c_str(), binary.data()) == 1;
    bool identity = numeric
        ? X509_VERIFY_PARAM_set1_ip_asc(SSL_get0_param(ssl), name.c_str()) == 1
        : SSL_set_tlsext_host_name(ssl, name.c_str()) == 1 && SSL_set1_host(ssl, name.c_str()) == 1;
    if (!identity) return false;
    if (SSL_set_alpn_protos(ssl, alpn.data(), alpn.size()) != 0) return false;
    if (!apply_hook_offer(ssl, offer, name)) return false;
    return !configure || configure(ssl);
}

// The worker owns socket I/O and CID routing for both legs. Entries have stable
// addresses: callbacks borrow their owner until retirement removes every route.
class ngtcp2_worker final : public worker_transport {
    static constexpr ng::timestamp close_delivery_grace = 3 * NGTCP2_SECONDS;

    struct entry {
        std::shared_ptr<ng::connection> connection;
        datagram_endpoint peer;
        datagram_endpoint local;
        uint64_t association = 0;
        unsigned ifindex = 0;
        bool downstream = false;
        ng::timestamp retirement = 0;
        std::set<std::string> cids;
    };
    // Borrowed routing aliases; entries_ owns their targets until erase_routes().
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
        if (socle::setsockopt(fd_, level, option, &enabled, sizeof(enabled))) {
            ++stats.errors.worker_worker_ngtcp2_input_metadata_failed;
            throw std::runtime_error("ngtcp2 input metadata failed");
        }
        // Original destination identifies the target, not the ingress interface.
        // Role-based admission needs pktinfo on both direct and dispatched A paths.
        auto const interface_option = family == AF_INET ? IP_PKTINFO : IPV6_RECVPKTINFO;
        if (socle::setsockopt(fd_, level, interface_option, &enabled, sizeof(enabled))) {
            ++stats.errors.worker_input_interface_metadata_failed;
            throw std::runtime_error("ngtcp2 input interface metadata failed");
        }
        output_.value = open_output_socket(family);
    }

    // Separate A/B passes match the service's existing scheduling. TLS resume
    // happens under the saved A tuple, even when no new packet accompanied it.
    bool handle_events() override { return progress(true); }
    bool handle_upstream() override { return progress(false); }
    // Transfer a newly received A leg to the service once; the worker retains
    // its transport owner until the service releases the complete session.
    std::shared_ptr<transport_connection> accept() override {
        if (accepted_.empty()) return {};
        auto result = std::move(accepted_.front());
        accepted_.pop_front();
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
        offer.sni = name;
        offer.alpn = "h3";
        if (!hook_start(setup, offer)) {
            if (error) *error = "QUIC start rejected by callback";
            return {};
        }
        try {
            if (!tls || !peer || size > sizeof(sockaddr_storage)) {
                ++stats.errors.worker_connect_invalid_ngtcp2_peer;
                throw std::runtime_error("invalid ngtcp2 peer");
            }
            datagram_endpoint remote;
            remote.size = size;
            std::memcpy(&remote.address, peer, size);
            return create(tls, false, outgoing_path(output_.value, peer, size), remote, 0, nullptr, ng::now(),
                [&](SSL* ssl) {
                    return configure_upstream_tls(ssl, name, offer, configure);
                });
        } catch (std::exception const& e) {
            ++stats.errors.worker_connect_exception;
            if (error) *error = e.what();
            hook_failure(setup, name, e.what());
            return {};
        }
    }

    // Writes performed by the bridge mark application progress; the following
    // worker pass sends them in a bounded batch, just like the OpenSSL path.
    bool flush_output(datagram_endpoint const&, datagram_endpoint const&, uint64_t) override { return true; }

    // Include both transport expiry and close-delivery retirement in ppoll.
    // A negative duration tells the service there is no pending deadline.
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
    int upstream_fd() const override { return output_.value; }
    short upstream_events() const override { return POLLIN | (blocked(false) ? POLLOUT : 0); }
    std::string last_error() const override { return error_; }
    datagram_endpoint current_peer() const override { return current_ ? current_->peer : datagram_endpoint {}; }
    datagram_endpoint current_local() const override { return current_ ? current_->local : datagram_endpoint {}; }
    unsigned current_ingress_ifindex() const override { return current_ ? current_->ifindex : 0; }
    uint64_t current_association() const override { return current_ ? current_->association : 0; }
    bool bind_connection_route(SSL* ssl) override {
        return current_ && current_->connection && current_->connection->handle_native() == ssl;
    }

private:
    /** Register both issued CIDs and the original Initial CID under one stable owner. */
    ng::cid_router router(entry* owner) {
        return [this, owner](ngtcp2_cid const& cid, bool add) {
            auto& map = owner->downstream ? incoming_ : outgoing_;
            std::string key(reinterpret_cast<char const*>(cid.data), cid.datalen);
            if (add) {
                auto [it, inserted] = map.emplace(key, owner);
                if (!inserted && it->second != owner) {
                    ++stats.errors.worker_router_ngtcp2_cid_collision;
                    throw std::runtime_error("ngtcp2 CID collision");
                }
                try {
                    owner->cids.insert(key);
                } catch (...) {
                    ++stats.errors.worker_register_cid_exception;
                    if (inserted) map.erase(it);
                    ++stats.errors.worker_register_cid_rethrow;
                    throw;
                }
            } else {
                map.erase(key);
                owner->cids.erase(key);
            }
        };
    }

    // Build under a stable owner and roll back CID registrations on failure.
    // No callback can outlive the entry retained in entries_.
    std::shared_ptr<ng::connection> create(
        SSL_CTX* tls, bool downstream, datagram_endpoint local, datagram_endpoint peer,
        unsigned ifindex, ngtcp2_pkt_hd const* initial, ng::timestamp started,
        std::function<bool(SSL*)> configure) {
        auto value = std::make_unique<entry>();
        auto* owner = value.get();
        owner->local = local;
        owner->peer = peer;
        owner->ifindex = ifindex;
        owner->downstream = downstream;
        owner->association = downstream ? next_association_++ : 0;
        datagram_observer observer;
        if (downstream && observer_) {
            observer = [this, owner](datagram_view const& packet) {
                auto view = packet;
                view.association = owner->association;
                observer_(view);
            };
        }
        try {
            owner->connection = std::make_shared<ng::connection>(tls, downstream, local, peer,
                initial, router(owner), started, std::move(configure), std::move(observer),
                [this, owner] { current_ = owner; });
            auto result = owner->connection;
            entries_.push_back(std::move(value));
            return result;
        } catch (...) {
            ++stats.errors.worker_create_exception;
            erase_routes(*owner);
            if (current_ == owner) current_ = nullptr;
            ++stats.errors.worker_create_throw;
            throw;
        }
    }

    // Resolve an existing CID, or admit a v1 Initial on A. Unknown B packets
    // cannot create sessions. The common service owns admission diagnostics.
    entry* find_or_accept(datagram_packet const& packet, bool downstream, ng::timestamp ts) {
        ngtcp2_version_cid header {};
        if (ngtcp2_pkt_decode_version_cid(&header, packet.data.data(), packet.data.size(), 16)) return nullptr;
        auto& map = downstream ? incoming_ : outgoing_;
        std::string key(reinterpret_cast<char const*>(header.dcid), header.dcidlen);
        auto it = map.find(key);
        entry* owner = it == map.end() ? nullptr : it->second;
        if (owner) return owner;

        // Leave one receive batch beyond the steady A:B capacity so the
        // common service can reject/count excess sessions itself. Retired
        // transports remain bounded while their close packet drains.
        ngtcp2_pkt_hd initial {};
        if (!downstream || entries_.size() >= 2 * limit_ + ng::packet_batch_limit) return nullptr;
        if (ngtcp2_accept(&initial, packet.data.data(), packet.data.size()) != 0) return nullptr;
        if (initial.version != NGTCP2_PROTO_VER_V1) return nullptr;

        auto connection = create(server_, true, packet.local, packet.peer,
                                 packet.ingress_ifindex, &initial, ts, {});
        owner = incoming_.at(key);
        accepted_.push_back(std::move(connection));
        return owner;
    }

    // Restore the service's callback context before TLS processing or capture.
    void receive(datagram_packet const& packet, bool downstream, ng::timestamp ts) {
        if (!packet.peer.valid() || !packet.local.valid()) return;
        auto* owner = find_or_accept(packet, downstream, ts);
        if (!owner) return;
        // Migration needs dispatcher/transparent-routing agreement. Preserve the
        // original tuple until that capability is implemented and tested.
        if (!same_endpoint(owner->peer, packet.peer) || !same_endpoint(owner->local, packet.local)) return;
        current_ = owner;
        if (downstream && observer_) observer_({datagram_direction::ingress, packet.peer, packet.local,
            owner->association, packet.data.data(), packet.data.size()});
        owner->connection->receive(packet, ts);
    }

    // Bound ingress work so a busy socket cannot starve timers or the bridge.
    void receive_batch(bool downstream, ng::timestamp ts) {
        if (downstream && source_) {
            std::array<datagram_packet, ng::packet_batch_limit> packets;
            auto count = source_(packets.data(), packets.size());
            for (size_t n = 0; n < count; ++n) receive(packets[n], downstream, ts);
            return;
        }
        int fd = downstream ? fd_ : output_.value;
        for (size_t n = 0; n < ng::packet_batch_limit;) {
            auto count = receiver_.receive(fd, [&](datagram_packet&& packet) {
                receive(packet, downstream, ts);
            });
            if (count <= 0) break;
            n += count;
            if (static_cast<size_t>(count) < datagram_receiver::capacity) break;
        }
    }

    // TLS may resume without a fresh datagram. Reinstall each owner's tuple
    // before callbacks, then service its timers and bounded packet output.
    void progress_connections(bool downstream, ng::timestamp ts) {
        int fd = downstream ? fd_ : output_.value;
        for (auto& value : entries_) {
            if (value->downstream != downstream) continue;
            current_ = value.get();
            value->connection->progress_transport();
            value->connection->expire(ts);
            value->connection->transmit(fd, ts);
        }
    }

    // One worker turn uses one timestamp for receive, expiry and transmission.
    // Report errors to the shared service rather than throwing across its loop.
    bool progress(bool downstream) {
        try {
            auto ts = ng::now();
            receive_batch(downstream, ts);
            progress_connections(downstream, ts);
            retire(ts);
            return true;
        } catch (std::exception const& e) {
            ++stats.errors.worker_progress_exception;
            error_ = e.what();
            return false;
        }
    }

    /** Keep abandoned legs briefly for close delivery, then remove every CID. */
    void retire(ng::timestamp ts) {
        for (auto it = entries_.begin(); it != entries_.end();) {
            auto& value = **it;
            if (value.connection.use_count() != 1) {
                ++it;
                continue;
            }
            if (!value.retirement) {
                value.connection->close();
                value.retirement = ts + close_delivery_grace;
            }
            if (value.retirement > ts) {
                ++it;
                continue;
            }
            if (current_ == &value) current_ = nullptr;
            erase_routes(value);
            it = entries_.erase(it);
        }
    }

    // Remove aliases before destroying the owner borrowed by the routing table.
    void erase_routes(entry const& value) {
        auto& map = value.downstream ? incoming_ : outgoing_;
        for (auto const& cid : value.cids) map.erase(cid);
    }

    // POLLOUT is needed only while an encrypted datagram is retained after EAGAIN.
    bool blocked(bool downstream) const {
        return std::any_of(entries_.begin(), entries_.end(), [=](auto const& value) {
            return value->downstream == downstream && value->connection->send_blocked();
        });
    }

    SSL_CTX* server_;
    int fd_;
    owned_socket output_ {-1, close_descriptor};
    datagram_receiver receiver_;
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
        if (ngtcp2_crypto_ossl_init()) {
            ++stats.errors.worker_make_ngtcp2_context_ngtcp2_crypto_initialization_failed;
            throw std::runtime_error("ngtcp2 crypto initialization failed");
        }
    });
    unique_ssl_ctx context(SSL_CTX_new(server ? TLS_server_method() : TLS_client_method()));
    if (!context || SSL_CTX_set_min_proto_version(context.get(), TLS1_3_VERSION) != 1
        || SSL_CTX_set_max_proto_version(context.get(), TLS1_3_VERSION) != 1
        || !SSLFactory::factory().set_verify_locations(context.get())) return {};
    if (!server && SSLFactory::factory().is_ct_available()
        && SSL_CTX_set_ctlog_list_file(context.get(), SSLFactory::factory().ctlogfile().c_str()) != 1) return {};
    SSL_CTX_set_info_callback(context.get(), logging::tls_info);
    if (server) SSL_CTX_set_keylog_callback(context.get(), ng::connection::record_keylog);
    return context;
}

// Keep construction failure compatible with the service factory contract.
std::unique_ptr<worker_transport> make_ngtcp2_worker(
    SSL_CTX* server, SSL_CTX*, int fd, int family, bool, datagram_observer observer,
    datagram_source source, size_t limit) {
    try {
        return std::make_unique<ngtcp2_worker>(server, fd, family, std::move(observer), std::move(source), limit);
    } catch (...) {
        ++stats.errors.worker_make_worker_exception;
        return {};
    }
}
} // namespace sx::quic
