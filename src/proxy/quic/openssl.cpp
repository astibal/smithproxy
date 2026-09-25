#include "proxy/quic/openssl.hpp"
#include "proxy/quic/wire.hpp"

#include <openssl/err.h>

#include <algorithm>
#include <array>
#include <cerrno>
#include <cstring>
#include <deque>
#include <fcntl.h>
#include <map>
#include <netinet/in.h>
#include <poll.h>
#include <sstream>
#include <sys/socket.h>
#include <unistd.h>
#include <utility>

namespace sx::quic {

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
    return unique_ssl_ctx(SSL_CTX_new(server ? OSSL_QUIC_server_method()
                                             : OSSL_QUIC_client_method()));
#else
    (void)server;
    return nullptr;
#endif
}

#if SMITHPROXY_OPENSSL_QUIC

struct openssl_connection::stream_state {
    stream_state(multiflow::flow_handle flow_handle, unique_ssl ssl_stream,
                 multiflow::direction stream_direction)
        : handle(flow_handle), stream(std::move(ssl_stream)), direction(stream_direction) {}

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
    struct packet {
        std::vector<unsigned char> data;
        datagram_endpoint peer;
        datagram_endpoint local;
    };
    ~dispatcher_state() { BIO_free(application_bio); }

    BIO* application_bio = nullptr;       // Owned application half of the datagram pair.
    int socket_fd = -1;                   // Borrowed transparent UDP socket.
    std::deque<packet> pending_input;     // Waiting for capacity in the OpenSSL BIO.
    std::deque<packet> pending_output;    // Waiting for socket writability.
    detail::datagram_route_table routes;  // Bounded CID-to-transparent-tuple map.
    datagram_endpoint active_peer;        // Tuple scoped to one synchronous operation.
    datagram_endpoint active_local;       // Local half paired with active_peer.
    bool input_active = false;            // The active tuple is currently safe to use.
};

openssl_listener::openssl_listener(std::unique_ptr<observer_state> observer,
                                   std::unique_ptr<dispatcher_state> dispatcher,
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
        entry->second = route;
        return;
    }

    insertion_order_.push_back(connection_id);
    while (insertion_order_.size() > maximum_routes_) {
        routes_.erase(insertion_order_.front());
        insertion_order_.pop_front();
    }
}

void detail::datagram_route_table::learn(
    unsigned char const* data, std::size_t size, datagram_route const& route) {
    auto const parsed = parse_header(data, size);
    if (!parsed || parsed.value.form != packet_form::long_header) return;

    remember(parsed.value.destination_connection_id, route);
    remember(parsed.value.source_connection_id, route);
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
                       || !same_endpoint(result->local, route.local))) {
            return std::nullopt;
        }
        result = route;
    }
    return result;
}

namespace {

void learn_packet_route(openssl_listener::dispatcher_state& state,
                        openssl_listener::dispatcher_state::packet const& packet) {
    state.routes.learn(packet.data.data(), packet.data.size(),
                       {packet.peer, packet.local});
}

bool receive_socket_datagram(int fd, openssl_listener::dispatcher_state::packet& packet) {
    packet.data.resize(65536);
    std::array<unsigned char, 256> control {};
    sockaddr_storage peer {};
    iovec vector { packet.data.data(), packet.data.size() };
    msghdr message {};
    message.msg_name = &peer;
    message.msg_namelen = sizeof(peer);
    message.msg_iov = &vector;
    message.msg_iovlen = 1;
    message.msg_control = control.data();
    message.msg_controllen = control.size();
    auto const received = ::recvmsg(fd, &message, MSG_DONTWAIT);
    if (received < 0) return false;
    packet.data.resize(static_cast<std::size_t>(received));
    std::memcpy(&packet.peer.address, &peer, message.msg_namelen);
    packet.peer.size = message.msg_namelen;
    for (auto* item = CMSG_FIRSTHDR(&message); item; item = CMSG_NXTHDR(&message, item)) {
        if (item->cmsg_level == SOL_IP && item->cmsg_type == IP_ORIGDSTADDR) {
            auto const* address = reinterpret_cast<sockaddr_in*>(CMSG_DATA(item));
            std::memcpy(&packet.local.address, address, sizeof(*address));
            packet.local.size = sizeof(*address);
        } else if (item->cmsg_level == SOL_IP && item->cmsg_type == IP_PKTINFO
                   && !packet.local.valid()) {
            auto const* info = reinterpret_cast<in_pktinfo*>(CMSG_DATA(item));
            sockaddr_in address {};
            address.sin_family = AF_INET;
            address.sin_addr = info->ipi_addr;
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
            auto const* address = reinterpret_cast<sockaddr_in6*>(CMSG_DATA(item));
            std::memcpy(&packet.local.address, address, sizeof(*address));
            packet.local.size = sizeof(*address);
        }
#endif
    }
    return true;
}

bool inject_bio_datagram(BIO* bio, openssl_listener::dispatcher_state::packet const& packet) {
    auto peer = endpoint_to_bio(packet.peer);
    auto local = endpoint_to_bio(packet.local);
    if (!peer || !local) return false;
    BIO_MSG message { const_cast<unsigned char*>(packet.data.data()), packet.data.size(),
                      peer.get(), local.get(), 0 };
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

enum class send_result { sent, blocked, failed };

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
    auto const sent = ::sendmsg(fd, &message, MSG_DONTWAIT);
    if (sent == static_cast<ssize_t>(packet.data.size())) return send_result::sent;
    if (sent < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) return send_result::blocked;
    return send_result::failed;
}

bool drain_bio_output(openssl_listener::dispatcher_state& state) {
    while (state.pending_output.size() < 1024) {
        openssl_listener::dispatcher_state::packet packet;
        packet.data.resize(65536);
        unique_bio_addr peer(BIO_ADDR_new());
        unique_bio_addr local(BIO_ADDR_new());
        if (!peer || !local) return false;
        BIO_MSG message { packet.data.data(), packet.data.size(), peer.get(), local.get(), 0 };
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
        packet.data.resize(message.data_len);
        packet.peer = endpoint_from_bio(peer.get());
        packet.local = endpoint_from_bio(local.get());
        // OpenSSL 3.5 may omit the peer on listener-generated packets. A global
        // last-peer fallback is unsafe with concurrent connections, so recover
        // the tuple from the destination Connection ID learned on input.
        auto const route = state.routes.resolve(packet.data.data(), packet.data.size());
        if (!packet.peer.valid() && route) packet.peer = route->peer;
        if (!packet.local.valid() && route) packet.local = route->local;
        // A client's first Initial may have an empty source CID, leaving a
        // Retry with no routable destination CID. While processing exactly
        // that input datagram, its tuple is unambiguous and safe to use.
        if (!packet.peer.valid() && state.input_active) packet.peer = state.active_peer;
        if (!packet.local.valid() && state.input_active) packet.local = state.active_local;
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

bool flush_socket_output(openssl_listener::dispatcher_state& state) {
    while (!state.pending_output.empty()) {
        auto const result = send_socket_datagram(state.socket_fd, state.pending_output.front());
        if (result == send_result::blocked) return true;
        if (result == send_result::failed) return false;
        state.pending_output.pop_front();
    }
    return true;
}

} // namespace

datagram_endpoint endpoint_from_bio_address(const BIO_ADDR* address) {
    return endpoint_from_bio(address);
}

openssl_connection::openssl_connection(unique_ssl connection, int owned_udp_fd)
    : connection_(std::move(connection)), owned_udp_fd_(owned_udp_fd) {
    if (connection_) {
        SSL_set_blocking_mode(connection_.get(), 0);
        SSL_set_default_stream_mode(connection_.get(), SSL_DEFAULT_STREAM_MODE_NONE);
        SSL_set_incoming_stream_policy(connection_.get(),
                                       SSL_INCOMING_STREAM_POLICY_ACCEPT, 0);
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

datagram_endpoint openssl_connection::peer_endpoint() const {
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

multiflow::io_result openssl_connection::read(multiflow::flow_handle flow,
                                              void* destination, std::size_t size) {
    if (closed_) return { 0, multiflow::io_status::connection_closed };
    auto* state = find(flow);
    if (!state) return { 0, multiflow::io_status::invalid_handle };
    if (state->direction == multiflow::direction::send_only) {
        return { 0, multiflow::io_status::eof };
    }

    std::size_t read_size = 0;
    auto const result = SSL_read_ex(state->stream.get(), destination, size, &read_size);
    if (result == 1) return { read_size, multiflow::io_status::ok };

    auto const ssl_error = SSL_get_error(state->stream.get(), result);
    if (ssl_error == SSL_ERROR_WANT_READ || ssl_error == SSL_ERROR_WANT_WRITE) {
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

    std::size_t written_size = 0;
    auto const result = SSL_write_ex(state->stream.get(), source, size, &written_size);
    if (result == 1) return { written_size, multiflow::io_status::ok };
    auto const ssl_error = SSL_get_error(state->stream.get(), result);
    if (ssl_error == SSL_ERROR_WANT_READ || ssl_error == SSL_ERROR_WANT_WRITE) {
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
    auto const result = SSL_stream_conclude(state->stream.get(), 0);
    if (result == 1) {
        state->write_terminal_reported = true;
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
        } else {
            SSL_handle_events(connection_.get());
        }
        return;
    } else if (!SSL_is_init_finished(connection_.get())) {
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
    if (!closed_) SSL_handle_events(connection_.get());
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
    std::string const& server_name, std::string const& alpn, std::string* error) {
    auto fail = [error](std::string message) {
        if (error) *error = std::move(message);
        return std::unique_ptr<openssl_connection> {};
    };
    if (!context || !peer || peer_size == 0 || alpn.empty() || alpn.size() > 255) {
        return fail("invalid QUIC peer or ALPN");
    }

    auto const fd = ::socket(peer->sa_family, SOCK_DGRAM, IPPROTO_UDP);
    if (fd < 0) return fail(std::string("socket: ") + std::strerror(errno));
    auto close_and_fail = [fd, &fail](std::string message) {
        ::close(fd);
        return fail(std::move(message));
    };
    auto const flags = ::fcntl(fd, F_GETFL, 0);
    if (flags < 0 || ::fcntl(fd, F_SETFL, flags | O_NONBLOCK) != 0) {
        return close_and_fail(std::string("O_NONBLOCK: ") + std::strerror(errno));
    }
    if (::connect(fd, peer, peer_size) != 0) {
        return close_and_fail(std::string("connect: ") + std::strerror(errno));
    }

    unique_ssl ssl(SSL_new(context));
    if (!ssl) return close_and_fail("SSL_new: " + openssl_error_stack());
    if (SSL_set_fd(ssl.get(), fd) != 1
        || SSL_set_blocking_mode(ssl.get(), 0) != 1
        || (!server_name.empty()
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

    auto connection = std::make_unique<openssl_connection>(std::move(ssl), fd);
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
    if (SSL_poll(&item, 1, sizeof(item), &timeout, 0, &result_count) != 1) return false;
    return result_count != 0 && (item.revents & events) != 0;
}

void openssl_connection::emit(multiflow::event_type type,
                              std::optional<multiflow::flow_handle> flow,
                              std::uint64_t protocol_error) {
    event_key key { type, flow ? flow->id : 0 };
    events_.emplace(key, multiflow::event { type, flow, protocol_error });
}

std::unique_ptr<openssl_listener> openssl_listener::create(SSL_CTX* context, int udp_fd,
                                                           bool enable_local_address,
                                                           datagram_observer observer) {
    if (!context || udp_fd < 0) return nullptr;

    // The dispatcher, not the optional observer, requires the original local
    // address. Configure its socket contract here so standalone users cannot
    // accidentally create a transparent listener without tuple metadata.
    if (enable_local_address) {
        int enabled = 1;
        if (::setsockopt(udp_fd, SOL_IP, IP_RECVORIGDSTADDR,
                         &enabled, sizeof(enabled)) != 0) return nullptr;
    }

    BIO* network_bio = nullptr;
    auto dispatcher = std::unique_ptr<openssl_listener::dispatcher_state> {};
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
        dispatcher = std::make_unique<openssl_listener::dispatcher_state>();
        dispatcher->application_bio = application_bio;
        dispatcher->socket_fd = udp_fd;
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
    unique_ssl connection(SSL_accept_connection(listener_.get(),
                                                SSL_ACCEPT_CONNECTION_NO_BLOCK));
    if (!connection) return nullptr;
    return std::make_unique<openssl_connection>(std::move(connection));
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
    while (!dispatcher_state_->pending_input.empty()) {
        if (!progress_input_packet()) return false;
    }
    if (!receive_input_batch()) return false;
    return progress_listener_timers();
}

bool openssl_listener::fail_operation(std::string operation) {
    auto detail = openssl_error_stack();
    last_error_ = std::move(operation);
    if (!detail.empty()) last_error_ += ": " + detail;
    return false;
}

bool openssl_listener::flush_dispatcher_socket() {
    if (flush_socket_output(*dispatcher_state_)) return true;
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
    dispatcher.active_peer = packet.peer;
    dispatcher.active_local = packet.local;
    dispatcher.input_active = true;
    auto clear_active = [&dispatcher]() { dispatcher.input_active = false; };

    if (!inject_bio_datagram(dispatcher.application_bio, packet)) {
        clear_active();
        return fail_operation("BIO_sendmmsg into listener");
    }
    dispatcher.pending_input.pop_front();

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
        if (!receive_socket_datagram(dispatcher.socket_fd, packet)) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) break;
            last_error_ = std::string("recvmsg: ") + std::strerror(errno);
            return false;
        }
        if (!packet.peer.valid() || !packet.local.valid()) {
            last_error_ = "recvmsg returned a datagram without a complete UDP tuple";
            return false;
        }

        learn_packet_route(dispatcher, packet);
        if (observer_state_ && observer_state_->observer) {
            observer_state_->observer(packet.peer, packet.local);
        }

        dispatcher.pending_input.push_back(std::move(packet));
        if (!progress_input_packet()) return false;
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
    if (!listener_ || !peer.valid() || !local.valid()) return false;
    if (!dispatcher_state_) return true;
    auto& dispatcher = *dispatcher_state_;
    dispatcher.active_peer = peer;
    dispatcher.active_local = local;
    dispatcher.input_active = true;
    auto const drained = drain_bio_output(dispatcher);
    dispatcher.input_active = false;
    if (!drained) {
        auto detail = openssl_error_stack();
        last_error_ = "BIO_recvmmsg while flushing connection output";
        if (!detail.empty()) last_error_ += ": " + detail;
        return false;
    }
    if (!flush_socket_output(dispatcher)) {
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

#endif // SMITHPROXY_OPENSSL_QUIC

} // namespace sx::quic
