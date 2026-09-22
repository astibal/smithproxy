#include "proxy/quic/openssl.hpp"

#include <openssl/err.h>

#include <array>
#include <cerrno>
#include <cstring>
#include <fcntl.h>
#include <netinet/in.h>
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

    multiflow::flow_handle handle;
    unique_ssl stream;
    multiflow::direction direction;
};

struct openssl_listener::observer_state {
    datagram_observer observer;
    datagram_endpoint pending_local;
};

openssl_listener::openssl_listener(std::unique_ptr<observer_state> state,
                                   unique_ssl listener, bool local_address_enabled)
    : observer_state_(std::move(state)), listener_(std::move(listener)),
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

datagram_endpoint peek_original_destination(int fd) {
    datagram_endpoint result;
    std::array<unsigned char, 1> byte {};
    std::array<unsigned char, 256> control {};
    sockaddr_storage peer {};
    iovec vector { byte.data(), byte.size() };
    msghdr message {};
    message.msg_name = &peer;
    message.msg_namelen = sizeof(peer);
    message.msg_iov = &vector;
    message.msg_iovlen = 1;
    message.msg_control = control.data();
    message.msg_controllen = control.size();
    if (::recvmsg(fd, &message, MSG_PEEK | MSG_DONTWAIT) < 0) return result;
    for (auto* item = CMSG_FIRSTHDR(&message); item; item = CMSG_NXTHDR(&message, item)) {
        if (item->cmsg_level == SOL_IP && item->cmsg_type == IP_ORIGDSTADDR) {
            auto const* address = reinterpret_cast<sockaddr_in*>(CMSG_DATA(item));
            std::memcpy(&result.address, address, sizeof(*address));
            result.size = sizeof(*address);
            break;
        }
#ifdef IPV6_ORIGDSTADDR
        if (item->cmsg_level == SOL_IPV6 && item->cmsg_type == IPV6_ORIGDSTADDR) {
            auto const* address = reinterpret_cast<sockaddr_in6*>(CMSG_DATA(item));
            std::memcpy(&result.address, address, sizeof(*address));
            result.size = sizeof(*address);
            break;
        }
#endif
    }
    return result;
}

long observe_datagrams(BIO* bio, int operation, const char* argument,
                       std::size_t, int, long, int result, std::size_t*) {
    auto* state = reinterpret_cast<openssl_listener::observer_state*>(
        BIO_get_callback_arg(bio));
    if (!state) return result;
    if (operation == BIO_CB_RECVMMSG) {
        state->pending_local = peek_original_destination(BIO_get_fd(bio, nullptr));
    } else if (operation == (BIO_CB_RECVMMSG | BIO_CB_RETURN) && result > 0
               && state->pending_local.valid() && state->observer) {
        auto const* arguments = reinterpret_cast<BIO_MMSG_CB_ARGS const*>(argument);
        if (arguments && arguments->msgs_processed && *arguments->msgs_processed != 0) {
            auto const peer = endpoint_from_bio(arguments->msg[0].peer);
            if (peer.valid()) state->observer(peer, state->pending_local);
        }
        state->pending_local = {};
    }
    return result;
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
        return { 0, multiflow::io_status::eof };
    }
    if (stream_state_value == SSL_STREAM_STATE_RESET_REMOTE
        || stream_state_value == SSL_STREAM_STATE_RESET_LOCAL) {
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
    auto const result = SSL_stream_conclude(state->stream.get(), 0);
    if (result == 1) return multiflow::io_status::ok;
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
        emit(multiflow::event_type::reset, flow, protocol_error);
        return multiflow::io_status::ok;
    }
    return multiflow::io_status::reset;
}

void openssl_connection::close(std::uint64_t protocol_error) {
    if (closed_ || !connection_) return;
    SSL_SHUTDOWN_EX_ARGS args { protocol_error, nullptr };
    SSL_shutdown_ex(connection_.get(), SSL_SHUTDOWN_FLAG_NO_BLOCK, &args, sizeof(args));
    closed_ = true;
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

std::vector<multiflow::event> openssl_connection::drain_events() {
    std::vector<multiflow::event> result;
    if (!connection_ || closed_) {
        for (auto const& pending : events_) result.push_back(pending.second);
        events_.clear();
        return result;
    }

    if (!SSL_is_init_finished(connection_.get())) {
        auto const result = SSL_do_handshake(connection_.get());
        if (result != 1) {
            auto const error = SSL_get_error(connection_.get(), result);
            if (error != SSL_ERROR_WANT_READ && error != SSL_ERROR_WANT_WRITE) {
                closed_ = true;
                emit(multiflow::event_type::connection_close, std::nullopt,
                     static_cast<std::uint64_t>(error));
            }
        }
    }
    SSL_handle_events(connection_.get());
    SSL_CONN_CLOSE_INFO close_info {};
    if (SSL_get_conn_close_info(connection_.get(), &close_info, sizeof(close_info)) == 1) {
        closed_ = true;
        emit(multiflow::event_type::connection_close, std::nullopt,
             close_info.error_code);
    }
    if (closed_) {
        for (auto const& pending : events_) result.push_back(pending.second);
        events_.clear();
        return result;
    }
    while (unique_ssl stream { SSL_accept_stream(connection_.get(), SSL_ACCEPT_STREAM_NO_BLOCK) }) {
        attach_stream(std::move(stream), true);
    }

    for (auto const& item : streams_) {
        auto const& state = *item.second;
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
    auto fail = [error](std::string message) {
        if (error) *error = std::move(message);
        return std::unique_ptr<openssl_connection> {};
    };
    if (!context || !peer || peer_size == 0) return fail("invalid QUIC peer");

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
    static constexpr unsigned char h3[] = { 2, 'h', '3' };
    if (SSL_set_alpn_protos(ssl.get(), h3, sizeof(h3)) != 0) {
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
    if (observer) {
        int enabled = 1;
        if (::setsockopt(udp_fd, SOL_IP, IP_RECVORIGDSTADDR,
                         &enabled, sizeof(enabled)) != 0) return nullptr;
    }

    unique_ssl listener(SSL_new_listener(context, 0));
    if (!listener) return nullptr;
    if (SSL_set_fd(listener.get(), udp_fd) != 1) return nullptr;
    if (SSL_set_blocking_mode(listener.get(), 0) != 1) return nullptr;

    bool local_address_enabled = false;
    if (enable_local_address) {
        auto* read_bio = SSL_get_rbio(listener.get());
        local_address_enabled = read_bio
            && BIO_dgram_set_local_addr_enable(read_bio, 1) == 1;
    }
    auto observer_state = std::make_unique<openssl_listener::observer_state>();
    observer_state->observer = std::move(observer);
    if (observer_state->observer) {
        auto* read_bio = SSL_get_rbio(listener.get());
        BIO_set_callback_arg(read_bio, reinterpret_cast<char*>(observer_state.get()));
        BIO_set_callback_ex(read_bio, observe_datagrams);
    }
    if (SSL_listen(listener.get()) != 1) return nullptr;
    return std::unique_ptr<openssl_listener>(
        new openssl_listener(std::move(observer_state), std::move(listener),
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
    return listener_ && SSL_handle_events(listener_.get()) == 1;
}

#endif // SMITHPROXY_OPENSSL_QUIC

} // namespace sx::quic
