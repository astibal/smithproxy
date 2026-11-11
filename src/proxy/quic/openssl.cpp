#include <ancillary_ifindex.hpp>
#include "proxy/quic/openssl.hpp"
#include "proxy/quic/socket_io_detail.hpp"
#include "proxy/quic/wire.hpp"
#include <sslcertstore.hpp>
#include <ancillary_address.hpp>

#include <openssl/err.h>

#include <algorithm>
#include <arpa/inet.h>
#include <array>
#include <cerrno>
#include <cstdlib>
#include <cstring>
#include <deque>
#include <fcntl.h>
#include <map>
#include <mutex>
#include <netinet/in.h>
#include <poll.h>
#include <sstream>
#include <sys/socket.h>
#include <sys/stat.h>
#include <unistd.h>
#include <utility>

namespace sx::quic {

namespace {

#if SMITHPROXY_OPENSSL_QUIC
std::mutex keylog_lock;

/** OpenSSL owns one shared-store handle for the lifetime of each SSL object. */
void free_keylog_store(void*, void* value, CRYPTO_EX_DATA*, int, long, void*) {
    delete static_cast<std::shared_ptr<keylog_store>*>(value);
}

int keylog_store_index() {
    static int const index = SSL_get_ex_new_index(
        0, nullptr, nullptr, nullptr, free_keylog_store);
    return index;
}

std::shared_ptr<keylog_store> ssl_keylog_store(SSL* ssl, bool create) {
    if (!ssl) return {};

    auto const index = keylog_store_index();
    if (index < 0) return {};
    auto* stored = static_cast<std::shared_ptr<keylog_store>*>(
        SSL_get_ex_data(ssl, index));
    if (stored) return *stored;
    if (!create) return {};

    auto handle = std::make_unique<std::shared_ptr<keylog_store>>(
        std::make_shared<keylog_store>());
    auto result = *handle;
    if (SSL_set_ex_data(ssl, index, handle.get()) != 1) return {};
    handle.release();
    return result;
}

/**
 * Append one standard NSS key-log record for downstream QUIC decryption.
 *
 * SSLKEYLOGFILE is deliberately opt-in: QUIC traffic secrets are as sensitive
 * as plaintext. Opening the file for each callback keeps rotation and lab
 * namespaces simple, while the mutex prevents records from multiple listener
 * contexts being interleaved.
 */
void append_quic_keylog_line(const SSL* ssl, const char* line) {
    if (!line || *line == '\0') return;

    // Retain secrets independently of SSLKEYLOGFILE. The file is only an
    // optional lab aid; the in-memory store belongs to the accepted session.
    if (auto store = ssl_keylog_store(const_cast<SSL*>(ssl), true)) {
        store->append(line);
    }

    auto const* path = std::getenv("SSLKEYLOGFILE");
    if (!path || *path == '\0') return;

    std::lock_guard lock(keylog_lock);
    auto const fd = ::open(path, O_WRONLY | O_CREAT | O_APPEND | O_CLOEXEC, 0600);
    if (fd < 0) return;
    ::fchmod(fd, 0600);

    std::string record(line);
    record.push_back('\n');
    std::size_t written = 0;
    while (written < record.size()) {
        auto const result = ::write(fd, record.data() + written,
                                    record.size() - written);
        if (result <= 0) break;
        written += static_cast<std::size_t>(result);
    }
    ::close(fd);
}
#endif

} // namespace

#if SMITHPROXY_OPENSSL_QUIC
void keylog_store::append(std::string line) {
    if (line.empty()) return;
    std::lock_guard lock(mutex_);
    if (std::find(lines_.begin(), lines_.end(), line) == lines_.end()) {
        lines_.push_back(std::move(line));
    }
}

std::vector<std::string> keylog_store::snapshot() const {
    std::lock_guard lock(mutex_);
    return lines_;
}
#endif

std::string openssl_error_stack() {
    std::ostringstream output;
    bool first = true;
    while (auto const error = ERR_get_error()) {
        std::array<char, 256> message {};
        ERR_error_string_n(error, message.data(), message.size());
        if (!first) output << "; ";
        output << message.data();
        first = false;
    }
    return output.str();
}

unique_ssl_ctx make_openssl_quic_context(bool server) {
#if SMITHPROXY_OPENSSL_QUIC
    unique_ssl_ctx context(SSL_CTX_new(server ? OSSL_QUIC_server_method()
                                             : OSSL_QUIC_client_method()));
    if (context && !SSLFactory::factory().set_verify_locations(context.get())) {
        return nullptr;
    }
    if (context && !server && SSLFactory::factory().is_ct_available()
        && SSL_CTX_set_ctlog_list_file(context.get(), SSLFactory::factory().ctlogfile().c_str()) != 1)
        return nullptr;
    // Capture only the intercepted/downstream leg. Upstream secrets describe
    // a different QUIC connection and must not be mixed into its wire capture.
    // The callback always runs so production can retain secrets internally;
    // SSLKEYLOGFILE remains an optional additional test output.
    if (context && server) {
        SSL_CTX_set_keylog_callback(context.get(), append_quic_keylog_line);
    }
    return context;
#else
    (void)server;
    return nullptr;
#endif
}

#if SMITHPROXY_OPENSSL_QUIC

unique_ssl make_openssl_quic_client_engine(SSL_CTX* context, int family) {
    if (!context || (family != AF_INET && family != AF_INET6)) return {};
    unique_ssl domain(SSL_new_domain(context, SSL_DOMAIN_FLAG_SINGLE_THREAD));
    if (!domain) return {};
    unique_ssl port(SSL_new_listener_from(domain.get(), 0));
    if (!port) return {};

    // OpenSSL 3.5 supports one port per engine. Use an unconnected datagram
    // socket: the port demultiplexes replies by CID, each child sets its peer.
    auto const fd = ::socket(family, SOCK_DGRAM | SOCK_CLOEXEC | SOCK_NONBLOCK, IPPROTO_UDP);
    if (fd < 0) return {};
    BIO* bio = BIO_new_dgram(fd, BIO_CLOSE);
    if (!bio) { ::close(fd); return {}; }
    SSL_set_bio(port.get(), bio, bio);
    if (SSL_set_blocking_mode(port.get(), 0) != 1) return {};
    // No SSL_listen/accept: this port creates outgoing children only. Each
    // child retains the port, which retains the domain and owns the socket.
    return port;
}

struct openssl_connection::stream_state {
    stream_state(multiflow::flow_handle flow_handle, unique_ssl ssl_stream,
                 multiflow::direction stream_direction)
        : handle(flow_handle), stream(std::move(ssl_stream)), direction(stream_direction),
          read_terminal_reported(stream_direction == multiflow::direction::send_only),
          write_terminal_reported(stream_direction == multiflow::direction::receive_only) {}

    multiflow::flow_handle handle;       // Stable public identity for this SSL stream.
    unique_ssl stream;                   // Must be destroyed before the parent connection.
    multiflow::direction direction;      // Capabilities from this endpoint's perspective.
    // OpenSSL retains terminal state indefinitely. These flags make FIN/reset
    // edge-triggered to MFProxy and avoid unsafe repeated state queries.
    bool read_terminal_reported = false;
    bool write_terminal_reported = false;
};

struct openssl_listener::observer_state {
    datagram_observer observer;          // Service callback receiving copied metadata.
};

struct openssl_listener::dispatcher_state {
    using packet = datagram_packet;
    datagram_source source;              // Optional receiver-to-worker inbox.
    ~dispatcher_state() { BIO_free(application_bio); }

    BIO* application_bio = nullptr;       // Owned application half of the datagram pair.
    int socket_fd = -1;                   // Borrowed transparent UDP socket.
    std::deque<packet> pending_input;     // Waiting for capacity in the OpenSSL BIO.
    std::deque<packet> pending_output;    // Waiting for socket writability.
    detail::datagram_route_table routes;  // Bounded CID-to-transparent-tuple map.
    unsigned active_ingress_ifindex = 0;
    datagram_endpoint active_peer;        // Tuple scoped to one synchronous operation.
    datagram_endpoint active_local;       // Local half paired with active_peer.
    std::uint64_t active_association = 0; // CID family scoped to the same operation.
    std::uint64_t next_association = 1;   // Zero means unknown/unroutable.
    bool input_active = false;            // The active tuple is currently safe to use.
    bool route_failed = false;            // Callback allocation failure must not cross C frames.
};

openssl_listener::openssl_listener(std::unique_ptr<observer_state> observer,
                                   std::shared_ptr<dispatcher_state> dispatcher,
                                   unique_ssl listener, bool local_address_enabled)
    : observer_state_(std::move(observer)), dispatcher_state_(std::move(dispatcher)),
      listener_(std::move(listener)),
      local_address_enabled_(local_address_enabled) {}

openssl_listener::~openssl_listener() = default;

namespace {

datagram_endpoint endpoint_from_bio(const BIO_ADDR* address) {
    datagram_endpoint result;
    if (!address) return result;
    auto const family = BIO_ADDR_family(address);
    if (family == AF_INET) {
        sockaddr_in value {};
        value.sin_family = AF_INET;
        std::size_t size = sizeof(value.sin_addr);
        if (BIO_ADDR_rawaddress(address, &value.sin_addr, &size) != 1) return {};
        value.sin_port = BIO_ADDR_rawport(address);
        std::memcpy(&result.address, &value, sizeof(value));
        result.size = sizeof(value);
    } else if (family == AF_INET6) {
        sockaddr_in6 value {};
        value.sin6_family = AF_INET6;
        std::size_t size = sizeof(value.sin6_addr);
        if (BIO_ADDR_rawaddress(address, &value.sin6_addr, &size) != 1) return {};
        value.sin6_port = BIO_ADDR_rawport(address);
        std::memcpy(&result.address, &value, sizeof(value));
        result.size = sizeof(value);
    }
    return result;
}

struct bio_addr_deleter {
    void operator()(BIO_ADDR* value) const { BIO_ADDR_free(value); }
};
using unique_bio_addr = std::unique_ptr<BIO_ADDR, bio_addr_deleter>;

unique_bio_addr endpoint_to_bio(datagram_endpoint const& endpoint) {
    unique_bio_addr result(BIO_ADDR_new());
    if (!result || !endpoint.valid()) return {};
    int made = 0;
    if (endpoint.address.ss_family == AF_INET) {
        auto const* address = reinterpret_cast<sockaddr_in const*>(&endpoint.address);
        made = BIO_ADDR_rawmake(result.get(), AF_INET, &address->sin_addr,
                                sizeof(address->sin_addr), address->sin_port);
    } else if (endpoint.address.ss_family == AF_INET6) {
        auto const* address = reinterpret_cast<sockaddr_in6 const*>(&endpoint.address);
        made = BIO_ADDR_rawmake(result.get(), AF_INET6, &address->sin6_addr,
                                sizeof(address->sin6_addr), address->sin6_port);
    }
    return made == 1 ? std::move(result) : unique_bio_addr {};
}

bool same_endpoint(datagram_endpoint const& lhs, datagram_endpoint const& rhs) {
    return lhs.size == rhs.size && lhs.size != 0
        && std::memcmp(&lhs.address, &rhs.address, lhs.size) == 0;
}

} // namespace

void detail::datagram_route_table::remember(
    std::vector<std::uint8_t> const& connection_id, datagram_route const& route) {
    if (connection_id.empty() || maximum_routes_ == 0) return;

    auto [entry, inserted] = routes_.emplace(connection_id, route);
    if (!inserted) {
        // A CID is not globally unique across independent clients. Retain an
        // unroutable tombstone on a collision rather than redirecting the old
        // connection. Its entry still obeys the ordinary bounded eviction.
        if (!same_endpoint(entry->second.peer, route.peer)
            || !same_endpoint(entry->second.local, route.local)
            || entry->second.association != route.association) entry->second = {};
        return;
    }

    insertion_order_.push_back(connection_id);
    while (insertion_order_.size() > maximum_routes_) {
        routes_.erase(insertion_order_.front());
        insertion_order_.pop_front();
    }
}

bool detail::datagram_route_table::learn(
    unsigned char const* data, std::size_t size, datagram_route const& route) {
    auto const parsed = parse_header(data, size);
    if (!parsed || parsed.value.form != packet_form::long_header) return false;

    auto const conflicts = [&](std::vector<std::uint8_t> const& id) {
        if(id.empty()) return false;
        auto const existing = routes_.find(id);
        return existing != routes_.end() &&
            (!same_endpoint(existing->second.peer, route.peer) ||
             !same_endpoint(existing->second.local, route.local) ||
             existing->second.association != route.association);
    };
    if(conflicts(parsed.value.destination_connection_id) ||
       conflicts(parsed.value.source_connection_id)) {
        return false;
    }

    remember(parsed.value.destination_connection_id, route);
    remember(parsed.value.source_connection_id, route);
    return true;
}

bool detail::datagram_route_table::learn_new_connection_id(
    unsigned char const* data, std::size_t size, datagram_route const& route) {
    // Only OpenSSL's authenticated frame callback feeds this parser. Frame
    // type, sequence and retire_prior_to are varints; CID length is one byte.
    if (!data || !route.peer.valid() || !route.local.valid()) return false;
    std::uint64_t values[3] {};
    for (auto& value : values) {
        auto const decoded = parse_varint(data, size);
        if (!decoded) return false;
        value = decoded.value;
        data += decoded.encoded_size;
        size -= decoded.encoded_size;
    }
    if (values[0] != 0x18 || values[2] > values[1] || size == 0) return false;
    auto const length = *data++;
    --size;
    // The remaining bytes are the CID and its 16-byte stateless-reset token.
    if (length == 0 || length > 20 || size != std::size_t(length) + 16) return false;
    remember(std::vector<std::uint8_t>(data, data + length), route);
    return true;
}

std::optional<detail::datagram_route> detail::datagram_route_table::resolve(
    unsigned char const* data, std::size_t size) const {
    auto const parsed = parse_header(data, size);
    if (!parsed) return std::nullopt;

    if (parsed.value.form == packet_form::long_header) {
        auto const found = routes_.find(parsed.value.destination_connection_id);
        return found == routes_.end() ? std::nullopt : std::optional(found->second);
    }

    // The short header does not carry a CID length. Match the known CID bytes
    // immediately following its first byte and reject an ambiguous match.
    std::optional<datagram_route> result;
    for (auto const& [connection_id, route] : routes_) {
        if (connection_id.empty() || size < connection_id.size() + 1
            || !std::equal(connection_id.begin(), connection_id.end(), data + 1)) {
            continue;
        }
        if (result && (!same_endpoint(result->peer, route.peer)
                       || !same_endpoint(result->local, route.local)
                       || result->association != route.association)) {
            return std::nullopt;
        }
        result = route;
    }
    return result;
}

std::optional<detail::datagram_route> detail::datagram_route_table::resolve_peer(
    datagram_endpoint const& peer) const {
    std::optional<datagram_route> result;
    if (!peer.valid()) return result;
    for (auto const& [cid, route] : routes_) {
        if (!same_endpoint(peer, route.peer)) continue;
        if (result) {
            if (!same_endpoint(result->local, route.local)) return std::nullopt;
            // Reused UDP tuples can retain old CID families. The wire route
            // remains unambiguous, but its capture association does not.
            if (result->association != route.association) result->association = 0;
        } else {
            result = route;
        }
    }
    return result;
}

namespace {

struct connection_route_observer {
    std::weak_ptr<openssl_listener::dispatcher_state> dispatcher;
    detail::datagram_route route;
};

/** The SSL owns the callback argument, even if it outlives its listener adapter. */
int connection_route_index() {
    static int const index = SSL_get_ex_new_index(0, nullptr, nullptr, nullptr,
        [](void*, void* pointer, CRYPTO_EX_DATA*, int, long, void*) {
            delete static_cast<connection_route_observer*>(pointer);
        });
    return index;
}

/** Keep CID routing exact after either side rotates its connection ID. */
void observe_connection_id(int, int, int content_type, void const* data,
                           std::size_t size, SSL*, void* argument) noexcept {
    if (content_type != SSL3_RT_QUIC_FRAME_FULL || !data || size == 0) return;
    auto const type = parse_varint(static_cast<unsigned char const*>(data), size);
    if (!type || type.value != 0x18) return;
    auto* observer = static_cast<connection_route_observer*>(argument);
    if (auto state = observer->dispatcher.lock()) {
        try {
            state->routes.learn_new_connection_id(
                static_cast<unsigned char const*>(data), size, observer->route);
        } catch (...) {
            state->route_failed = true;
        }
    }
}

void learn_packet_route(openssl_listener::dispatcher_state& state,
                        openssl_listener::dispatcher_state::packet const& packet) {
    state.routes.learn(packet.data.data(), packet.data.size(),
                       {packet.peer, packet.local, packet.association});
}

bool associate_input_packet(openssl_listener::dispatcher_state& state,
                            openssl_listener::dispatcher_state::packet& packet) {
    // Only a valid long header can introduce a new CID family. Unknown short
    // headers and non-QUIC datagrams must never acquire somebody else's state.
    auto const parsed = parse_header(packet.data.data(), packet.data.size());
    if (!parsed) return true;
    auto const route = state.routes.resolve(packet.data.data(), packet.data.size());
    if (!route && parsed.value.form != packet_form::long_header) return true;
    packet.association = route ? route->association : state.next_association++;
    if (packet.association == 0) packet.association = state.next_association++;
    if(parsed.value.form != packet_form::long_header) return true;
    return state.routes.learn(packet.data.data(), packet.data.size(),
                              {packet.peer, packet.local, packet.association});
}

bool receive_socket_datagram(int fd, openssl_listener::dispatcher_state::packet& packet) {
    // Allocate only the received payload when handing a packet to a worker.
    // Initialising a fresh 64KiB vector per 1200-byte datagram wastes bandwidth.
    std::array<unsigned char, 65536> payload;
    std::array<unsigned char, 256> control {};
    sockaddr_storage peer {};
    iovec vector { payload.data(), payload.size() };
    msghdr message {};
    message.msg_name = &peer;
    message.msg_namelen = sizeof(peer);
    message.msg_iov = &vector;
    message.msg_iovlen = 1;
    message.msg_control = control.data();
    message.msg_controllen = control.size();
    auto const received = detail::retry_on_eintr(
        [&] { return ::recvmsg(fd, &message, MSG_DONTWAIT); });
    if (received < 0) return false;
    if ((message.msg_flags & (MSG_TRUNC | MSG_CTRUNC)) != 0) {
        errno = EMSGSIZE;
        return false;
    }
    packet.data.assign(payload.begin(), payload.begin() + received);
    if (!socle_detail::copy_socket_address(
            packet.peer.address, &peer, message.msg_namelen)) {
        errno = EPROTO;
        return false;
    }
    packet.ingress_ifindex = socle::ancillary_ifindex(message);
    packet.peer.size = packet.peer.address.ss_family == AF_INET
        ? sizeof(sockaddr_in) : sizeof(sockaddr_in6);
    for (auto* item = CMSG_FIRSTHDR(&message); item; item = CMSG_NXTHDR(&message, item)) {
        if (item->cmsg_level == SOL_IP && item->cmsg_type == IP_ORIGDSTADDR) {
            if (!socle_detail::copy_original_destination(packet.local.address, item)) {
                errno = EPROTO;
                return false;
            }
            packet.local.size = sizeof(sockaddr_in);
        } else if (item->cmsg_level == SOL_IP && item->cmsg_type == IP_PKTINFO
                   && !packet.local.valid()) {
            if (item->cmsg_len < CMSG_LEN(sizeof(in_pktinfo))) {
                errno = EPROTO;
                return false;
            }
            in_pktinfo info{};
            std::memcpy(&info, CMSG_DATA(item), sizeof(info));
            sockaddr_in address {};
            address.sin_family = AF_INET;
            address.sin_addr = info.ipi_addr;
            sockaddr_in bound {};
            socklen_t size = sizeof(bound);
            if (::getsockname(fd, reinterpret_cast<sockaddr*>(&bound), &size) == 0) {
                address.sin_port = bound.sin_port;
            }
            std::memcpy(&packet.local.address, &address, sizeof(address));
            packet.local.size = sizeof(address);
        }
#ifdef IPV6_ORIGDSTADDR
        if (item->cmsg_level == SOL_IPV6 && item->cmsg_type == IPV6_ORIGDSTADDR) {
            if (!socle_detail::copy_original_destination(packet.local.address, item)) {
                errno = EPROTO;
                return false;
            }
            packet.local.size = sizeof(sockaddr_in6);
        }
#endif
    }
    return true;
}

bool inject_bio_datagram(BIO* bio, openssl_listener::dispatcher_state::packet const& packet) {
    auto peer = endpoint_to_bio(packet.peer);
    auto local = endpoint_to_bio(packet.local);
    if (!peer || !local) return false;
    // A BIO pair models two endpoints: send.local becomes receive.peer.
    // We inject a packet sent by the client to the intercepted destination.
    BIO_MSG message { const_cast<unsigned char*>(packet.data.data()), packet.data.size(),
                      local.get(), peer.get(), 0 };
    std::size_t processed = 0;
    ERR_clear_error();
    if (BIO_sendmmsg(bio, &message, sizeof(message), 1, 0, &processed) == 1
        && processed == 1) {
        return true;
    }
    auto const error = ERR_peek_last_error();
    if (error != 0 && BIO_err_is_non_fatal(error)) {
        ERR_clear_error();
        return false;
    }
    return false;
}

using send_result = detail::datagram_send_result;

void observe_datagram(openssl_listener::observer_state const* state,
                      datagram_direction direction,
                      openssl_listener::dispatcher_state::packet const& packet) {
    if (!state || !state->observer) return;
    state->observer(datagram_view {
        direction, packet.peer, packet.local,
        packet.association,
        packet.data.data(), packet.data.size(),
    });
}

send_result send_socket_datagram(int fd,
                                 openssl_listener::dispatcher_state::packet const& packet) {
    if (!packet.peer.valid() || !packet.local.valid()) return send_result::failed;
    iovec vector { const_cast<unsigned char*>(packet.data.data()), packet.data.size() };
    std::array<unsigned char, CMSG_SPACE(sizeof(in6_pktinfo))> control {};
    msghdr message {};
    message.msg_name = const_cast<sockaddr*>(
        reinterpret_cast<sockaddr const*>(&packet.peer.address));
    message.msg_namelen = packet.peer.size;
    message.msg_iov = &vector;
    message.msg_iovlen = 1;
    message.msg_control = control.data();
    if (packet.local.address.ss_family == AF_INET) {
        message.msg_controllen = CMSG_SPACE(sizeof(in_pktinfo));
        auto* item = CMSG_FIRSTHDR(&message);
        item->cmsg_level = SOL_IP;
        item->cmsg_type = IP_PKTINFO;
        item->cmsg_len = CMSG_LEN(sizeof(in_pktinfo));
        auto* info = reinterpret_cast<in_pktinfo*>(CMSG_DATA(item));
        *info = {};
        info->ipi_spec_dst = reinterpret_cast<sockaddr_in const*>(
            &packet.local.address)->sin_addr;
    } else if (packet.local.address.ss_family == AF_INET6) {
        message.msg_controllen = CMSG_SPACE(sizeof(in6_pktinfo));
        auto* item = CMSG_FIRSTHDR(&message);
        item->cmsg_level = SOL_IPV6;
        item->cmsg_type = IPV6_PKTINFO;
        item->cmsg_len = CMSG_LEN(sizeof(in6_pktinfo));
        auto* info = reinterpret_cast<in6_pktinfo*>(CMSG_DATA(item));
        *info = {};
        info->ipi6_addr = reinterpret_cast<sockaddr_in6 const*>(
            &packet.local.address)->sin6_addr;
    } else {
        return send_result::failed;
    }
    auto const sent = detail::retry_on_eintr(
        [&] { return ::sendmsg(fd, &message, MSG_DONTWAIT); });
    return detail::classify_datagram_send(sent, errno, packet.data.size());
}

bool drain_bio_output(openssl_listener::dispatcher_state& state) {
    if (state.route_failed) return false;
    // The BIO can return a full UDP payload, but ordinary QUIC packets are
    // much smaller. Reuse scratch space; retain only the actual payload in
    // each queued packet instead of allocating/zeroing 64 KiB per datagram.
    std::array<unsigned char, 65536> payload;
    unique_bio_addr peer(BIO_ADDR_new());
    unique_bio_addr local(BIO_ADDR_new());
    if (!peer || !local) return false;
    while (state.pending_output.size() < 1024) {
        BIO_ADDR_clear(peer.get());
        BIO_ADDR_clear(local.get());
        BIO_MSG message { payload.data(), payload.size(), peer.get(), local.get(), 0 };
        std::size_t processed = 0;
        ERR_clear_error();
        if (BIO_recvmmsg(state.application_bio, &message, sizeof(message), 1, 0,
                         &processed) != 1 || processed == 0) {
            auto const error = ERR_peek_last_error();
            if (error == 0) break;
            if (!BIO_err_is_non_fatal(error)) return false;
            ERR_clear_error();
            break;
        }
        openssl_listener::dispatcher_state::packet packet;
        packet.data.assign(payload.data(), payload.data() + message.data_len);
        // Reading the application half reverses the sender's BIO addresses.
        packet.peer = endpoint_from_bio(local.get());
        packet.local = endpoint_from_bio(peer.get());
        // OpenSSL may leave the outgoing source address unspecified. Recover
        // the intercepted local address from the route, not the last session
        // serviced: one engine tick can produce packets for several clients.
        auto route = state.routes.resolve(packet.data.data(), packet.data.size());
        // OpenSSL may rotate the destination CID without exposing the encrypted
        // NEW_CONNECTION_ID frame. Its output peer still identifies the route
        // when unique; never infer a destination from the last active session.
        if (!route) route = state.routes.resolve_peer(packet.peer);
        if (!packet.peer.valid() && route) packet.peer = route->peer;
        if (!packet.local.valid() && route) packet.local = route->local;
        if (route) packet.association = route->association;
        // A client's first Initial may have an empty source CID, leaving a
        // Retry with no routable destination CID. While processing exactly
        // that input datagram, its tuple is unambiguous and safe to use.
        auto const header = parse_header(packet.data.data(), packet.data.size());
        bool const retry = state.input_active && header && header.value.type == packet_type::retry;
        if (!packet.peer.valid() && retry) packet.peer = state.active_peer;
        if (!packet.local.valid() && retry) packet.local = state.active_local;
        if (packet.association == 0 && !route && retry) {
            packet.association = state.active_association;
        }
        if (!packet.peer.valid() || !packet.local.valid()) {
            // An unroutable control packet must be dropped, never sent to an
            // unrelated client. The peer will retransmit if it was relevant.
            continue;
        }
        learn_packet_route(state, packet);
        state.pending_output.push_back(std::move(packet));
    }
    return true;
}

bool flush_socket_output(openssl_listener::dispatcher_state& state,
                         openssl_listener::observer_state const* observer) {
    while (!state.pending_output.empty()) {
        auto const result = send_socket_datagram(state.socket_fd, state.pending_output.front());
        if (result == send_result::blocked) return true;
        if (result == send_result::failed) return false;
        observe_datagram(observer, datagram_direction::egress,
                         state.pending_output.front());
        state.pending_output.pop_front();
    }
    return true;
}

} // namespace

bool receive_datagram(int fd, datagram_packet& packet) {
    return receive_socket_datagram(fd, packet);
}

datagram_endpoint endpoint_from_bio_address(const BIO_ADDR* address) {
    return endpoint_from_bio(address);
}

openssl_connection::openssl_connection(unique_ssl connection, int owned_udp_fd,
                                       event_driver driver, datagram_endpoint peer)
    : connection_(std::move(connection)), owned_udp_fd_(owned_udp_fd), peer_(peer), driver_(driver) {
    if (connection_) {
        ERR_clear_error();
        // Stream I/O only consumes or queues application bytes. Transport ticks
        // belong to the worker's downstream listener or upstream domain.
        // Standalone adapters retain their own explicit transport driver.
        if(SSL_set_event_handling_mode(connection_.get(),
                SSL_VALUE_EVENT_HANDLING_MODE_EXPLICIT) != 1 ||
           SSL_set_blocking_mode(connection_.get(), 0) != 1 ||
           SSL_set_default_stream_mode(
               connection_.get(), SSL_DEFAULT_STREAM_MODE_NONE) != 1 ||
           SSL_set_incoming_stream_policy(
               connection_.get(), SSL_INCOMING_STREAM_POLICY_ACCEPT, 0) != 1) {
            closed_ = true;
        }
    } else {
        closed_ = true;
    }
}

openssl_connection::~openssl_connection() {
    streams_.clear();
    connection_.reset();
    if (owned_udp_fd_ >= 0) ::close(owned_udp_fd_);
}

bool openssl_connection::handshake_complete() const {
    return connection_ && SSL_is_init_finished(connection_.get());
}

std::string openssl_connection::server_name() const {
    if (!connection_) return {};
    auto const* name = SSL_get_servername(connection_.get(), TLSEXT_NAMETYPE_host_name);
    return name ? std::string(name) : std::string {};
}

std::string openssl_connection::negotiated_alpn() const {
    if (!connection_) return {};
    const unsigned char* data = nullptr;
    unsigned int size = 0;
    SSL_get0_alpn_selected(connection_.get(), &data, &size);
    return data && size != 0
        ? std::string(reinterpret_cast<char const*>(data), size) : std::string {};
}

std::shared_ptr<keylog_store> openssl_connection::keylog() const {
    return ssl_keylog_store(connection_.get(), true);
}

datagram_endpoint openssl_connection::peer_endpoint() const {
    if (peer_.valid()) return peer_;
    if (!connection_) return {};
    BIO_ADDR* address = BIO_ADDR_new();
    if (!address) return {};
    auto const success = BIO_dgram_get_peer(SSL_get_rbio(connection_.get()), address);
    auto result = success > 0 ? endpoint_from_bio_address(address) : datagram_endpoint {};
    BIO_ADDR_free(address);
    return result;
}

multiflow::flow_handle openssl_connection::open_flow(multiflow::direction flow_direction) {
    if (closed_ || !connection_ || flow_direction == multiflow::direction::receive_only) return {};

    auto const flags = flow_direction == multiflow::direction::send_only
        ? SSL_STREAM_FLAG_UNI | SSL_STREAM_FLAG_NO_BLOCK
        : SSL_STREAM_FLAG_NO_BLOCK;
    unique_ssl stream(SSL_new_stream(connection_.get(), flags));
    if (!stream) return {};
    return attach_stream(std::move(stream), false);
}

bool openssl_connection::contains(multiflow::flow_handle flow) const {
    return find(flow) != nullptr;
}

std::optional<multiflow::direction> openssl_connection::direction_of(
    multiflow::flow_handle flow) const {
    auto const* state = find(flow);
    return state ? std::optional<multiflow::direction>(state->direction) : std::nullopt;
}

std::optional<multiflow::flow_id> openssl_connection::wire_flow_id(
    multiflow::flow_handle flow) const {
    auto const* state = find(flow);
    if (!state) return std::nullopt;

    auto const stream_id = SSL_get_stream_id(state->stream.get());
    return stream_id < (std::uint64_t{1} << 62)
        ? std::optional<multiflow::flow_id>(stream_id) : std::nullopt;
}

multiflow::io_result openssl_connection::read(multiflow::flow_handle flow,
                                              void* destination, std::size_t size) {
    if (closed_) return { 0, multiflow::io_status::connection_closed };
    auto* state = find(flow);
    if (!state) return { 0, multiflow::io_status::invalid_handle };
    if (state->direction == multiflow::direction::send_only) {
        return { 0, multiflow::io_status::eof };
    }
    // Match read(2): a zero-length operation on a valid readable flow is a
    // successful no-op. Entering OpenSSL here can otherwise advance QUIC
    // state or surface WANT_READ/WANT_WRITE for an operation with no payload.
    if (size == 0) return { 0, multiflow::io_status::ok };

    std::size_t read_size = 0;
    ERR_clear_error();
    auto const result = SSL_read_ex(state->stream.get(), destination, size, &read_size);
    if (result == 1) {
        // Consuming input can queue MAX_DATA/MAX_STREAM_DATA even when the
        // bridge cannot forward anything yet. Byte-forwarding counters alone
        // therefore cannot decide whether the worker is allowed to sleep.
        application_progress_ |= read_size != 0;
        return { read_size, multiflow::io_status::ok };
    }

    auto const ssl_error = SSL_get_error(state->stream.get(), result);
    if (ssl_error == SSL_ERROR_WANT_READ || ssl_error == SSL_ERROR_WANT_WRITE) {
        // The required network direction need not match the application
        // operation: a read can need to write an ACK or flow-control frame.
        // Do not retry inline. The owner polls SSL_net_*_desired(), progresses
        // the connection on readiness, and then retries this deferred read.
        return { 0, multiflow::io_status::would_block };
    }
    auto const stream_state_value = SSL_get_stream_read_state(state->stream.get());
    if (ssl_error == SSL_ERROR_ZERO_RETURN || stream_state_value == SSL_STREAM_STATE_FINISHED) {
        if (!state->read_terminal_reported) {
            state->read_terminal_reported = true;
            emit(multiflow::event_type::peer_fin, flow);
        }
        return { 0, multiflow::io_status::eof };
    }
    if (stream_state_value == SSL_STREAM_STATE_RESET_REMOTE
        || stream_state_value == SSL_STREAM_STATE_RESET_LOCAL) {
        if (!state->read_terminal_reported) {
            std::uint64_t protocol_error = 0;
            SSL_get_stream_read_error_code(state->stream.get(), &protocol_error);
            state->read_terminal_reported = true;
            emit(multiflow::event_type::reset, flow, protocol_error);
        }
        return { 0, multiflow::io_status::reset };
    }
    if (stream_state_value == SSL_STREAM_STATE_CONN_CLOSED) {
        return { 0, multiflow::io_status::connection_closed };
    }
    return { 0, multiflow::io_status::reset };
}

multiflow::io_result openssl_connection::write(multiflow::flow_handle flow,
                                               const void* source, std::size_t size) {
    if (closed_) return { 0, multiflow::io_status::connection_closed };
    auto* state = find(flow);
    if (!state) return { 0, multiflow::io_status::invalid_handle };
    if (state->direction == multiflow::direction::receive_only) {
        return { 0, multiflow::io_status::eof };
    }
    // A successful FIN or reset makes the OpenSSL stream's sending half
    // terminal. In particular, OpenSSL 3.5 may dereference cleared internal
    // send-stream state if SSL_get_stream_write_state() follows a rejected
    // SSL_write_ex() on that terminal stream. Keep the public operation
    // idempotent and do not re-enter OpenSSL after we reported termination.
    if (state->write_terminal_reported) {
        return { 0, multiflow::io_status::eof };
    }
    // Match write(2) and the other transport adapters. In particular, do not
    // publish a stream or perturb flow-control state for an empty probe.
    if (size == 0) return { 0, multiflow::io_status::ok };

    std::size_t written_size = 0;
    ERR_clear_error();
    auto const result = SSL_write_ex(state->stream.get(), source, size, &written_size);
    application_progress_ |= written_size != 0;
    if (result == 1) return { written_size, multiflow::io_status::ok };
    auto const ssl_error = SSL_get_error(state->stream.get(), result);
    if (ssl_error == SSL_ERROR_WANT_READ || ssl_error == SSL_ERROR_WANT_WRITE) {
        // A write can need inbound acknowledgements just as it can need socket
        // capacity. Preserve the unwritten suffix and let the owner's network
        // poll defer the retry; an immediate loop here would busy-spin.
        return { written_size, multiflow::io_status::would_block };
    }
    auto const stream_state_value = SSL_get_stream_write_state(state->stream.get());
    if (stream_state_value == SSL_STREAM_STATE_FINISHED) {
        return { written_size, multiflow::io_status::eof };
    }
    if (stream_state_value == SSL_STREAM_STATE_RESET_REMOTE
        || stream_state_value == SSL_STREAM_STATE_RESET_LOCAL) {
        if (!state->write_terminal_reported) {
            std::uint64_t protocol_error = 0;
            SSL_get_stream_write_error_code(state->stream.get(), &protocol_error);
            state->write_terminal_reported = true;
            emit(multiflow::event_type::reset, flow, protocol_error);
        }
        return { written_size, multiflow::io_status::reset };
    }
    if (stream_state_value == SSL_STREAM_STATE_CONN_CLOSED) {
        return { written_size, multiflow::io_status::connection_closed };
    }
    return { written_size, multiflow::io_status::reset };
}

multiflow::io_status openssl_connection::finish(multiflow::flow_handle flow) {
    auto* state = find(flow);
    if (!state) return closed_ ? multiflow::io_status::connection_closed
                               : multiflow::io_status::invalid_handle;
    if (state->direction == multiflow::direction::receive_only
        || state->write_terminal_reported) {
        return multiflow::io_status::ok;
    }
    ERR_clear_error();
    auto const result = SSL_stream_conclude(state->stream.get(), 0);
    if (result == 1) {
        state->write_terminal_reported = true;
        application_progress_ = true; // A FIN needs output even without payload.
        return multiflow::io_status::ok;
    }
    auto const error = SSL_get_error(state->stream.get(), result);
    return error == SSL_ERROR_WANT_READ || error == SSL_ERROR_WANT_WRITE
        ? multiflow::io_status::would_block
        : multiflow::io_status::reset;
}

multiflow::io_status openssl_connection::reset(multiflow::flow_handle flow,
                                               std::uint64_t protocol_error) {
    auto* state = find(flow);
    if (!state) return closed_ ? multiflow::io_status::connection_closed
                               : multiflow::io_status::invalid_handle;
    SSL_STREAM_RESET_ARGS args { protocol_error };
    if (SSL_stream_reset(state->stream.get(), &args, sizeof(args)) == 1) {
        // The proxy treats reset as terminal for the logical flow. Do not ask
        // OpenSSL for either half's state after a local reset; some 3.5 builds
        // cannot safely query the opposite half during reset processing.
        state->read_terminal_reported = true;
        state->write_terminal_reported = true;
        emit(multiflow::event_type::reset, flow, protocol_error);
        return multiflow::io_status::ok;
    }
    return multiflow::io_status::reset;
}

void openssl_connection::close(std::uint64_t protocol_error) {
    if (closed_ || closing_ || !connection_) return;
    SSL_SHUTDOWN_EX_ARGS args { protocol_error, nullptr };
    auto const result = SSL_shutdown_ex(connection_.get(), SSL_SHUTDOWN_FLAG_NO_BLOCK,
                                        &args, sizeof(args));
    closing_ = result != 1;
    closed_ = result == 1;
    emit(multiflow::event_type::connection_close, std::nullopt, protocol_error);
}

bool openssl_connection::readable(multiflow::flow_handle flow) const {
    auto const* state = find(flow);
    return state && poll_stream(*state, SSL_POLL_EVENT_RE);
}

bool openssl_connection::writable(multiflow::flow_handle flow) const {
    auto const* state = find(flow);
    return state && poll_stream(*state, SSL_POLL_EVENT_WE);
}

void openssl_connection::progress_transport() {
    if (!connection_ || closed_) return;

    // OpenSSL QUIC is explicitly nonblocking. WANT_READ/WANT_WRITE is a normal
    // scheduling result; the caller will invoke us again after socket readiness
    // or the next timer deadline.
    if (closing_) {
        SSL_SHUTDOWN_EX_ARGS args { 0, nullptr };
        if (SSL_shutdown_ex(connection_.get(), SSL_SHUTDOWN_FLAG_NO_BLOCK,
                            &args, sizeof(args)) == 1) {
            closing_ = false;
            closed_ = true;
        } else if (driver_ == event_driver::connection) {
            SSL_handle_events(connection_.get());
        }
        return;
    } else if (driver_ == event_driver::connection && !SSL_is_init_finished(connection_.get())) {
        ERR_clear_error();
        auto const result = SSL_do_handshake(connection_.get());
        if (result != 1) {
            auto const error = SSL_get_error(connection_.get(), result);
            if (error != SSL_ERROR_WANT_READ && error != SSL_ERROR_WANT_WRITE
                && error != SSL_ERROR_WANT_X509_LOOKUP) {
                closed_ = true;
                emit(multiflow::event_type::connection_close, std::nullopt,
                     static_cast<std::uint64_t>(error));
            }
        }
    }
    if (!closed_ && driver_ == event_driver::connection) SSL_handle_events(connection_.get());
    SSL_CONN_CLOSE_INFO close_info {};
    if (SSL_get_conn_close_info(connection_.get(), &close_info, sizeof(close_info)) == 1) {
        closed_ = true;
        emit(multiflow::event_type::connection_close, std::nullopt,
             close_info.error_code);
    }
}

std::vector<multiflow::event> openssl_connection::drain_events() {
    std::vector<multiflow::event> result;
    if (!connection_ || closed_) {
        for (auto const& pending : events_) result.push_back(pending.second);
        events_.clear();
        return result;
    }

    bool const entered_during_handshake = !SSL_is_init_finished(connection_.get());
    progress_transport();

    if (closed_) {
        for (auto const& pending : events_) result.push_back(pending.second);
        events_.clear();
        return result;
    }
    // Keep streams queued in OpenSSL when this call crossed the handshake
    // boundary. Listener code may legitimately discard handshake-progress
    // events before its MFProxy exists; accepting streams here would make
    // early application data disappear in that narrow transition window.
    if (entered_during_handshake) {
        for (auto const& pending : events_) result.push_back(pending.second);
        events_.clear();
        return result;
    }
    while (unique_ssl stream { SSL_accept_stream(connection_.get(), SSL_ACCEPT_STREAM_NO_BLOCK) }) {
        attach_stream(std::move(stream), true);
    }

    for (auto const& item : streams_) {
        auto& state = *item.second;
        auto const read_state = state.read_terminal_reported
            ? SSL_STREAM_STATE_NONE : SSL_get_stream_read_state(state.stream.get());
        if (read_state == SSL_STREAM_STATE_RESET_REMOTE) {
            std::uint64_t protocol_error = 0;
            SSL_get_stream_read_error_code(state.stream.get(), &protocol_error);
            state.read_terminal_reported = true;
            state.write_terminal_reported = true;
            emit(multiflow::event_type::reset, state.handle, protocol_error);
            continue;
        }
        auto const write_state = state.write_terminal_reported
            ? SSL_STREAM_STATE_NONE : SSL_get_stream_write_state(state.stream.get());
        if (write_state == SSL_STREAM_STATE_RESET_REMOTE) {
            std::uint64_t protocol_error = 0;
            SSL_get_stream_write_error_code(state.stream.get(), &protocol_error);
            state.write_terminal_reported = true;
            state.read_terminal_reported = true;
            emit(multiflow::event_type::reset, state.handle, protocol_error);
            continue;
        }
        if (poll_stream(state, SSL_POLL_EVENT_RE)) {
            emit(multiflow::event_type::readable, state.handle);
        }
        if (poll_stream(state, SSL_POLL_EVENT_WE)) {
            emit(multiflow::event_type::writable, state.handle);
        }
    }

    result.reserve(events_.size());
    for (auto const& pending : events_) result.push_back(pending.second);
    events_.clear();

    // Once both halves are terminal, the returned lifecycle event is the last
    // externally observable use of this handle.  Keeping the child SSL object
    // until the whole QUIC connection closes lets a peer grow this map with a
    // long sequence of reset or completed streams despite the bridge's live
    // stream limit.  Erase only after copying pending events so reset/FIN is
    // still delivered exactly once.
    for (auto current = streams_.begin(); current != streams_.end();) {
        auto const& state = *current->second;
        if (state.read_terminal_reported && state.write_terminal_reported) {
            current = streams_.erase(current);
        } else {
            ++current;
        }
    }
    return result;
}

bool openssl_connection::inject_datagram(const unsigned char* data, std::size_t size,
                                         const BIO_ADDR* peer, const BIO_ADDR* local) {
    return !closed_ && connection_ && data && size != 0
        && SSL_inject_net_dgram(connection_.get(), data, size, peer, local) == 1;
}

std::unique_ptr<openssl_connection> connect_openssl_quic(
    SSL_CTX* context, const sockaddr* peer, socklen_t peer_size,
    std::string const& server_name, std::string* error) {
    return connect_openssl_quic(context, peer, peer_size, server_name, "h3", error);
}

std::unique_ptr<openssl_connection> connect_openssl_quic(
    SSL_CTX* context, const sockaddr* peer, socklen_t peer_size,
    std::string const& server_name, std::string const& alpn, std::string* error,
    HookEvent const* offer, std::function<bool(SSL*)> const& configure, SSL* port) {
    auto fail = [error](std::string message) {
        if (error) *error = std::move(message);
        return std::unique_ptr<openssl_connection> {};
    };
    if (!context || !peer || peer_size == 0 || alpn.empty() || alpn.size() > 255) {
        return fail("invalid QUIC peer or ALPN");
    }

    // Production children share the worker's outgoing port/socket. Standalone
    // adapters keep their own connected socket for tests and independent use.
    int fd = -1;
    auto close_and_fail = [&fd, &fail](std::string message) {
        if (fd >= 0) ::close(fd);
        return fail(std::move(message));
    };
    if (port) {
        if (!SSL_is_listener(port) || SSL_get_SSL_CTX(port) != context)
            return fail("QUIC port/context mismatch");
    } else {
        fd = ::socket(peer->sa_family, SOCK_DGRAM | SOCK_CLOEXEC | SOCK_NONBLOCK, IPPROTO_UDP);
        if (fd < 0) return fail(std::string("socket: ") + std::strerror(errno));
        if (detail::retry_on_eintr([&] { return ::connect(fd, peer, peer_size); }) != 0)
            return close_and_fail(std::string("connect: ") + std::strerror(errno));
    }
    unique_ssl ssl(port ? SSL_new_from_listener(port, 0) : SSL_new(context));
    if (!ssl) return close_and_fail("SSL_new: " + openssl_error_stack());
    datagram_endpoint endpoint;
    if (peer_size > sizeof(endpoint.address)) return close_and_fail("invalid QUIC peer size");
    std::memcpy(&endpoint.address, peer, peer_size);
    endpoint.size = peer_size;
    auto initial_peer = endpoint_to_bio(endpoint);
    std::array<unsigned char, sizeof(in6_addr)> binary_address {};
    auto const numeric_identity = !server_name.empty()
        && (::inet_pton(AF_INET, server_name.c_str(), binary_address.data()) == 1
            || ::inet_pton(AF_INET6, server_name.c_str(), binary_address.data()) == 1);
    if ((!port && SSL_set_fd(ssl.get(), fd) != 1)
        || !initial_peer || SSL_set1_initial_peer_addr(ssl.get(), initial_peer.get()) != 1
        || SSL_set_blocking_mode(ssl.get(), 0) != 1
        || (!server_name.empty() && numeric_identity
            && X509_VERIFY_PARAM_set1_ip_asc(
                   SSL_get0_param(ssl.get()), server_name.c_str()) != 1)
        || (!server_name.empty() && !numeric_identity
            && (SSL_set_tlsext_host_name(ssl.get(), server_name.c_str()) != 1
                || SSL_set1_host(ssl.get(), server_name.c_str()) != 1))) {
        return close_and_fail("configure outgoing QUIC: " + openssl_error_stack());
    }
    std::vector<unsigned char> encoded_alpn;
    encoded_alpn.reserve(alpn.size() + 1);
    encoded_alpn.push_back(static_cast<unsigned char>(alpn.size()));
    encoded_alpn.insert(encoded_alpn.end(), alpn.begin(), alpn.end());
    if (SSL_set_alpn_protos(ssl.get(), encoded_alpn.data(), encoded_alpn.size()) != 0) {
        return close_and_fail("configure QUIC ALPN: " + openssl_error_stack());
    }

    if(offer && !apply_hook_offer(ssl.get(), *offer, server_name)) {
        return close_and_fail("configure QUIC hook settings: " + openssl_error_stack());
    }

    if (configure && !configure(ssl.get())) return close_and_fail("QUIC certificate policy setup failed");

    auto connection = std::make_unique<openssl_connection>(std::move(ssl), fd,
        port ? openssl_connection::event_driver::owner
               : openssl_connection::event_driver::connection, endpoint);
    if (port && !connection->closed()) {
        // Bootstrap once after policy/hooks are installed. OpenSSL starts the
        // channel here; subsequent transport ticks belong to the worker.
        ERR_clear_error();
        auto const result = SSL_do_handshake(connection->native_handle());
        if (result != 1) {
            auto const reason = SSL_get_error(connection->native_handle(), result);
            if (reason != SSL_ERROR_WANT_READ && reason != SSL_ERROR_WANT_WRITE
                && reason != SSL_ERROR_WANT_X509_LOOKUP)
                return fail("start shared QUIC handshake: " + openssl_error_stack());
        }
    }
    connection->drain_events();
    if (connection->closed()) return fail("start QUIC handshake: " + openssl_error_stack());
    if (error) error->clear();
    return connection;
}

openssl_connection::stream_state* openssl_connection::find(multiflow::flow_handle flow) {
    auto found = streams_.find(flow.id);
    if (found == streams_.end() || found->second->handle.generation != flow.generation) return nullptr;
    return found->second.get();
}

openssl_connection::stream_state const* openssl_connection::find(multiflow::flow_handle flow) const {
    auto found = streams_.find(flow.id);
    if (found == streams_.end() || found->second->handle.generation != flow.generation) return nullptr;
    return found->second.get();
}

multiflow::flow_handle openssl_connection::attach_stream(unique_ssl stream, bool incoming) {
    // MFFlowCom has socket write semantics: report consumed bytes immediately.
    // OpenSSL's default all-or-nothing retry retains the original buffer/length,
    // while the proxy can append to or compact its queue under backpressure.
    SSL_set_mode(stream.get(), SSL_MODE_ENABLE_PARTIAL_WRITE);
    auto const stream_type = SSL_get_stream_type(stream.get());
    auto const stream_direction = stream_type == SSL_STREAM_TYPE_BIDI
        ? multiflow::direction::bidirectional
        : (stream_type == SSL_STREAM_TYPE_READ
            ? multiflow::direction::receive_only
            : multiflow::direction::send_only);
    multiflow::flow_handle handle { next_internal_id_++, next_generation_++ };
    streams_.emplace(handle.id,
                     std::make_unique<stream_state>(handle, std::move(stream), stream_direction));
    emit(multiflow::event_type::flow_open, handle);
    if (!incoming) emit(multiflow::event_type::writable, handle);
    return handle;
}

bool openssl_connection::poll_stream(stream_state const& stream, std::uint64_t events) const {
    SSL_POLL_ITEM item { SSL_as_poll_descriptor(stream.stream.get()), events, 0 };
    timeval timeout { 0, 0 };
    std::size_t result_count = 0;
    // Readiness is a snapshot; the connection/listener owner drives transport.
    // A normal SSL_poll() ticks the engine again, including sibling connections
    // on a shared listener. Doing that for every stream multiplies I/O work.
    if (SSL_poll(&item, 1, sizeof(item), &timeout,
                 SSL_POLL_FLAG_NO_HANDLE_EVENTS, &result_count) != 1) return false;
    return result_count != 0 && (item.revents & events) != 0;
}

void openssl_connection::emit(multiflow::event_type type,
                              std::optional<multiflow::flow_handle> flow,
                              std::uint64_t protocol_error) {
    event_key key { type, flow ? flow->id : 0 };
    events_.emplace(key, multiflow::event { type, flow, protocol_error });
    // Readable/writable are level-triggered observations, not completed work.
    // In particular, an idle writable stream must not keep its worker spinning.
    if (type != multiflow::event_type::readable && type != multiflow::event_type::writable)
        application_progress_ = true;
}

std::unique_ptr<openssl_listener> openssl_listener::create(SSL_CTX* context, int udp_fd,
                                                           bool enable_local_address,
                                                           datagram_observer observer, datagram_source source) {
    if (!context || udp_fd < 0) return nullptr;

    // The dispatcher, not the optional observer, requires the original local
    // address. Configure its socket contract here so standalone users cannot
    // accidentally create a transparent listener without tuple metadata.
    if (enable_local_address) {
        sockaddr_storage bound {};
        socklen_t bound_size = sizeof(bound);
        if (sx::quic::detail::retry_on_eintr([&] {
                return ::getsockname(udp_fd, reinterpret_cast<sockaddr*>(&bound),
                                     &bound_size);
            }) != 0) return nullptr;
        int enabled = 1;
        int const level = bound.ss_family == AF_INET ? SOL_IP : SOL_IPV6;
        int const option = bound.ss_family == AF_INET
            ? IP_RECVORIGDSTADDR : IPV6_RECVORIGDSTADDR;
        if ((bound.ss_family != AF_INET && bound.ss_family != AF_INET6)
            || sx::quic::detail::retry_on_eintr([&] {
                return ::setsockopt(udp_fd, level, option, &enabled,
                                    sizeof(enabled));
            }) != 0) return nullptr;
    }

    // Interface identity belongs to the received datagram, not its destination
    // address. Request pktinfo alongside original-destination ancillary data.
    if(enable_local_address) {
        sockaddr_storage bound {};
        socklen_t size = sizeof(bound);
        if(::getsockname(udp_fd, reinterpret_cast<sockaddr*>(&bound), &size) != 0) return nullptr;
        const int enabled = 1;
        const int level = bound.ss_family == AF_INET ? SOL_IP : SOL_IPV6;
        const int option = bound.ss_family == AF_INET ? IP_PKTINFO : IPV6_RECVPKTINFO;
        if(::setsockopt(udp_fd, level, option, &enabled, sizeof(enabled)) != 0) return nullptr;
    }

    BIO* network_bio = nullptr;
    auto dispatcher = std::shared_ptr<openssl_listener::dispatcher_state> {};
    bool local_address_enabled = false;
    if (enable_local_address) {
        BIO* application_bio = nullptr;
        BIO* ssl_bio = nullptr;
        if (BIO_new_bio_dgram_pair(&application_bio, 1U << 20, &ssl_bio, 1U << 20) != 1) {
            return nullptr;
        }
        auto fail_pair = [&]() {
            BIO_free(application_bio);
            BIO_free(ssl_bio);
            return std::unique_ptr<openssl_listener> {};
        };
        // Both users preserve both addresses on every datagram: the dispatcher
        // supplies the received peer/local tuple and honours the tuple emitted
        // by OpenSSL. Capabilities are advertised to the opposite BIO half, so
        // declaring the complete contract on both ends also permits peer-aware
        // BIO_sendmmsg() injection in either direction.
        constexpr std::uint32_t address_capabilities =
            BIO_DGRAM_CAP_HANDLES_SRC_ADDR | BIO_DGRAM_CAP_HANDLES_DST_ADDR
            | BIO_DGRAM_CAP_PROVIDES_SRC_ADDR | BIO_DGRAM_CAP_PROVIDES_DST_ADDR;
        if (BIO_dgram_set_caps(ssl_bio, address_capabilities) != 1
            || BIO_dgram_set_caps(application_bio, address_capabilities) != 1
            || BIO_dgram_set_local_addr_enable(ssl_bio, 1) != 1
            || BIO_dgram_set_local_addr_enable(application_bio, 1) != 1
            || BIO_dgram_set_mtu(application_bio, 1500) != 1) {
            return fail_pair();
        }
        dispatcher = std::make_shared<openssl_listener::dispatcher_state>();
        dispatcher->application_bio = application_bio;
        dispatcher->socket_fd = udp_fd;
        dispatcher->source = std::move(source);
        network_bio = ssl_bio;
        local_address_enabled = true;
    } else {
        network_bio = BIO_new_dgram(udp_fd, BIO_NOCLOSE);
        if (!network_bio) return nullptr;
    }
    auto observer_state = std::make_unique<openssl_listener::observer_state>();
    observer_state->observer = std::move(observer);
    unique_ssl listener(SSL_new_listener(context, 0));
    if (!listener) {
        BIO_free(network_bio);
        return nullptr;
    }
    // Capability negotiation occurs when the BIO is attached. Transparent mode
    // therefore uses a datagram pair configured above, while this adapter owns
    // all socket I/O and preserves the original source/destination tuple.
    SSL_set_bio(listener.get(), network_bio, network_bio);
    if (SSL_set_blocking_mode(listener.get(), 0) != 1) return nullptr;
    if (SSL_listen(listener.get()) != 1) return nullptr;
    return std::unique_ptr<openssl_listener>(
        new openssl_listener(std::move(observer_state), std::move(dispatcher),
                             std::move(listener),
                             local_address_enabled));
}

std::unique_ptr<openssl_connection> openssl_listener::accept() {
    if (!listener_) return nullptr;
    // SSL_accept_connection(NO_BLOCK) still ticks the whole engine when its
    // queue is empty. The worker already drove input/timers in handle_events();
    // accepting must only dequeue connections, not run every sibling again.
    if (SSL_get_accept_connection_queue_len(listener_.get()) == 0) return nullptr;
    unique_ssl connection(SSL_accept_connection(listener_.get(),
                                                SSL_ACCEPT_CONNECTION_NO_BLOCK));
    if (!connection) return nullptr;
    return std::make_unique<openssl_connection>(std::move(connection), -1,
        openssl_connection::event_driver::owner);
}

bool openssl_listener::handle_events() {
    last_error_.clear();
    if (!listener_) return fail_operation("listener is not initialized");

    // A normal socket BIO already owns the entire transport pump.
    if (!dispatcher_state_) {
        ERR_clear_error();
        return SSL_handle_events(listener_.get()) == 1
            || fail_operation("SSL_handle_events on socket BIO");
    }

    // Transparent mode owns recvmsg/sendmsg so the original destination and
    // selected source address stay attached to every individual datagram.
    if (!flush_dispatcher_socket()) return false;
    if (!receive_input_batch()) return false;
    bool const received = !dispatcher_state_->pending_input.empty();
    while (!dispatcher_state_->pending_input.empty()) {
        if (!progress_input_packet()) return false;
    }
    // Processing a batch already ticks the entire engine, including timers.
    // Only an empty receive pass needs a separate timer/output tick here.
    return received || progress_listener_timers();
}

bool openssl_listener::finish_events() {
    // Stream writes only enqueue bytes. Tick once after all sessions have run,
    // otherwise queued data can wait for a peer packet which will never arrive.
    if (!listener_) return fail_operation("listener is not initialized");
    if (dispatcher_state_) return progress_listener_timers();
    return SSL_handle_events(listener_.get()) == 1
        || fail_operation("SSL_handle_events after stream output");
}

bool openssl_listener::fail_operation(std::string operation) {
    auto detail = openssl_error_stack();
    last_error_ = std::move(operation);
    if (!detail.empty()) last_error_ += ": " + detail;
    return false;
}

bool openssl_listener::flush_dispatcher_socket() {
    if (flush_socket_output(*dispatcher_state_, observer_state_.get())) return true;
    last_error_ = std::string("sendmsg: ") + std::strerror(errno);
    return false;
}

bool openssl_listener::progress_input_packet() {
    auto& dispatcher = *dispatcher_state_;
    auto& packet = dispatcher.pending_input.front();

    // Scope the fallback tuple to this one input operation. OpenSSL 3.5 can
    // omit addresses on synchronously generated Retry packets when the client
    // Initial has a zero-length source CID. A process-global "last peer" would
    // leak output across sessions; this narrow scope cannot cross a packet.
    dispatcher.active_ingress_ifindex = packet.ingress_ifindex;
    dispatcher.active_peer = packet.peer;
    dispatcher.active_local = packet.local;
    dispatcher.active_association = packet.association;
    dispatcher.input_active = true;
    auto clear_active = [&dispatcher]() { dispatcher.input_active = false; };

    // Established short-header packets carry their own BIO addresses and can
    // share one engine tick across connections. No last-packet fallback is safe
    // for that batch. Initial/Handshake packets retain one-packet scope for
    // certificate/Retry callbacks. Keep each batch below the BIO capacity.
    auto const can_batch = [](dispatcher_state::packet const& input) {
        return input.association != 0 && !input.data.empty()
            && (input.data.front() & 0x80) == 0;
    };
    bool const batch = can_batch(packet);
    if (batch) dispatcher.input_active = false;
    std::size_t bytes = 0;
    do {
        auto const& input = dispatcher.pending_input.front();
        if (!inject_bio_datagram(dispatcher.application_bio, input)) {
            clear_active();
            return fail_operation("BIO_sendmmsg into listener");
        }
        bytes += input.data.size();
        dispatcher.pending_input.pop_front();
        if (!batch || dispatcher.pending_input.empty()) break;

        auto const& next = dispatcher.pending_input.front();
        if (!can_batch(next) || bytes + next.data.size() > 65536) break;
    } while (true);

    ERR_clear_error();
    if (SSL_handle_events(listener_.get()) != 1) {
        clear_active();
        return fail_operation("SSL_handle_events after input");
    }
    if (!drain_bio_output(dispatcher)) {
        clear_active();
        return fail_operation("BIO_recvmmsg from listener");
    }

    clear_active();
    return flush_dispatcher_socket();
}

bool openssl_listener::receive_input_batch() {
    auto& dispatcher = *dispatcher_state_;

    // Bound each pass so a hot UDP socket cannot starve established streams,
    // certificate futures, shutdown, or management snapshots.
    for (std::size_t count = 0; count < 64; ++count) {
        dispatcher_state::packet packet;
        if (dispatcher.source) {
            if (!dispatcher.source(packet)) break;
        } else if (!receive_socket_datagram(dispatcher.socket_fd, packet)) {
            if (detail::datagram_receive_would_block(errno)) break;
            last_error_ = std::string("recvmsg: ") + std::strerror(errno);
            return false;
        }
        if (!packet.peer.valid() || !packet.local.valid()) {
            last_error_ = "recvmsg returned a datagram without a complete UDP tuple";
            return false;
        }

        if(!associate_input_packet(dispatcher, packet)) {
            // CID ownership is established before this unauthenticated packet
            // reaches OpenSSL. Never let a spoofed tuple redirect subsequent
            // listener output for an existing connection.
            continue;
        }
        observe_datagram(observer_state_.get(), datagram_direction::ingress, packet);

        dispatcher.pending_input.push_back(std::move(packet));
    }
    return true;
}

bool openssl_listener::progress_listener_timers() {
    auto& dispatcher = *dispatcher_state_;

    // Tick timer-driven QUIC work even if the socket had no readable datagram.
    ERR_clear_error();
    if (SSL_handle_events(listener_.get()) != 1) {
        return fail_operation("SSL_handle_events timer tick");
    }
    if (!drain_bio_output(dispatcher)) {
        return fail_operation("BIO_recvmmsg after timer tick");
    }
    return flush_dispatcher_socket();
}

bool openssl_listener::flush_output(datagram_endpoint const& peer,
                                    datagram_endpoint const& local) {
    return flush_output(peer, local, 0);
}

bool openssl_listener::flush_output(datagram_endpoint const& peer,
                                    datagram_endpoint const& local,
                                    std::uint64_t association) {
    if (!listener_ || !peer.valid() || !local.valid()) return false;
    if (!dispatcher_state_) return true;
    auto& dispatcher = *dispatcher_state_;
    dispatcher.active_peer = peer;
    dispatcher.active_local = local;
    dispatcher.active_association = association;
    dispatcher.input_active = true;
    auto const drained = drain_bio_output(dispatcher);
    dispatcher.input_active = false;
    if (!drained) {
        auto detail = openssl_error_stack();
        last_error_ = "BIO_recvmmsg while flushing connection output";
        if (!detail.empty()) last_error_ += ": " + detail;
        return false;
    }
    if (!flush_socket_output(dispatcher, observer_state_.get())) {
        last_error_ = std::string("sendmsg: ") + std::strerror(errno);
        return false;
    }
    return true;
}

short openssl_listener::desired_socket_events() const {
    if (!listener_) return 0;
    if (dispatcher_state_) {
        return POLLIN | (dispatcher_state_->pending_output.empty() ? 0 : POLLOUT);
    }
    short events = 0;
    if (SSL_net_read_desired(listener_.get()) > 0) events |= POLLIN;
    if (SSL_net_write_desired(listener_.get()) > 0) events |= POLLOUT;
    return events;
}

datagram_endpoint openssl_listener::current_peer() const {
    return dispatcher_state_ ? dispatcher_state_->active_peer : datagram_endpoint {};
}

datagram_endpoint openssl_listener::current_local() const {
    return dispatcher_state_ ? dispatcher_state_->active_local : datagram_endpoint {};
}

unsigned openssl_listener::current_ingress_ifindex() const {
    return dispatcher_state_ && dispatcher_state_->input_active
        ? dispatcher_state_->active_ingress_ifindex : 0;
}

std::uint64_t openssl_listener::current_association() const {
    return dispatcher_state_ && dispatcher_state_->input_active
        ? dispatcher_state_->active_association : 0;
}

bool openssl_listener::bind_connection_route(SSL* connection) {
    if (!dispatcher_state_) return true;
    if (!connection || SSL_is_connection(connection) != 1
        || !dispatcher_state_->input_active || current_association() == 0) return false;
    int const index = connection_route_index();
    if (index < 0) return false;
    auto* existing = static_cast<connection_route_observer*>(SSL_get_ex_data(connection, index));
    if (existing) return existing->route.association == current_association();

    auto observer = std::make_unique<connection_route_observer>(connection_route_observer {
        dispatcher_state_, {current_peer(), current_local(), current_association()}});
    if (SSL_set_ex_data(connection, index, observer.get()) != 1) return false;
    SSL_set_msg_callback_arg(connection, observer.get());
    SSL_set_msg_callback(connection, observe_connection_id);
    observer.release();
    return true;
}

#endif // SMITHPROXY_OPENSSL_QUIC

} // namespace sx::quic
