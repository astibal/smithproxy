#include "connection.hpp"
#include <openssl/rand.h>
#include <algorithm>
#include <chrono>
#include <cstring>
#include <iostream>
#include <stdexcept>
#include <limits>

namespace sx::quic::experiment {
namespace mf = multiflow;

// One monotonic timestamp per worker pass is reused by receive, timers and TX.
timestamp now() {
    return std::chrono::duration_cast<std::chrono::nanoseconds>(
        std::chrono::steady_clock::now().time_since_epoch()).count();
}

ngtcp2_callbacks connection::callbacks(bool server) {
    ngtcp2_callbacks cb {};
    if (server) cb.recv_client_initial = ngtcp2_crypto_recv_client_initial_cb;
    else cb.client_initial = ngtcp2_crypto_client_initial_cb;
    cb.recv_crypto_data = ngtcp2_crypto_recv_crypto_data_cb;
    cb.encrypt = ngtcp2_crypto_encrypt_cb;
    cb.decrypt = ngtcp2_crypto_decrypt_cb;
    cb.hp_mask = ngtcp2_crypto_hp_mask_cb;
    cb.recv_stream_data = recv_stream;
    cb.acked_stream_data_offset = ack_stream;
    cb.stream_open = opened_stream;
    cb.stream_close = closed_stream;
    cb.stream_reset = reset_stream;
    cb.recv_retry = ngtcp2_crypto_recv_retry_cb;
    cb.rand = [](uint8_t* output, size_t size, ngtcp2_rand_ctx const*) {
        if (RAND_bytes(output, static_cast<int>(size)) != 1) std::terminate();
    };
    cb.get_new_connection_id = new_cid;
    cb.remove_connection_id = remove_cid;
    cb.update_key = ngtcp2_crypto_update_key_cb;
    cb.delete_crypto_aead_ctx = ngtcp2_crypto_delete_crypto_aead_ctx_cb;
    cb.delete_crypto_cipher_ctx = ngtcp2_crypto_delete_crypto_cipher_ctx_cb;
    cb.get_path_challenge_data = ngtcp2_crypto_get_path_challenge_data_cb;
    cb.version_negotiation = ngtcp2_crypto_version_negotiation_cb;
    return cb;
}

connection::connection(SSL_CTX* tls, bool server, datagram_endpoint local,
                       datagram_endpoint remote, ngtcp2_pkt_hd const* initial,
                       cid_router route, timestamp started)
    : server_(server), local_(local), remote_(remote), route_(std::move(route)) {
    ngtcp2_cid scid {}, dcid {};
    scid.datalen = 16;
    dcid.datalen = 16;
    if (RAND_bytes(scid.data, scid.datalen) != 1 || RAND_bytes(dcid.data, dcid.datalen) != 1)
        throw std::runtime_error("CID random generation failed");
    if (server) dcid = initial->scid;
    ngtcp2_path path {{reinterpret_cast<sockaddr*>(&local_.address), local_.size},
                      {reinterpret_cast<sockaddr*>(&remote_.address), remote_.size}, nullptr};
    ngtcp2_settings settings;
    ngtcp2_settings_default(&settings);
    settings.initial_ts = started;
    settings.handshake_timeout = 10 * NGTCP2_SECONDS;
    settings.max_tx_udp_payload_size = 1350;
    settings.no_pmtud = 1;
    ngtcp2_transport_params params;
    ngtcp2_transport_params_default(&params);
    params.initial_max_data = 16 * 1024 * 1024;
    params.initial_max_stream_data_bidi_local = stream_buffer_limit;
    params.initial_max_stream_data_bidi_remote = stream_buffer_limit;
    params.initial_max_stream_data_uni = stream_buffer_limit;
    params.initial_max_streams_bidi = 256;
    params.initial_max_streams_uni = 16;
    params.active_connection_id_limit = 4;
    params.max_idle_timeout = 30 * NGTCP2_SECONDS;
    if (server) {
        params.original_dcid = initial->dcid;
        params.original_dcid_present = 1;
    }
    auto cb = callbacks(server);
    auto rc = server
        ? ngtcp2_conn_server_new(&conn_, &dcid, &scid, &path, initial->version,
                                &cb, &settings, &params, nullptr, this)
        : ngtcp2_conn_client_new(&conn_, &dcid, &scid, &path, NGTCP2_PROTO_VER_V1,
                                &cb, &settings, &params, nullptr, this);
    if (rc) throw std::runtime_error(ngtcp2_strerror(rc));
    try {
        ssl_ = SSL_new(tls);
        if (!ssl_ || ngtcp2_crypto_ossl_ctx_new(&crypto_, ssl_) != 0)
            throw std::runtime_error("TLS allocation failed");
        reference_.user_data = this;
        reference_.get_conn = [](ngtcp2_crypto_conn_ref* ref) {
            return static_cast<connection*>(ref->user_data)->conn_;
        };
        SSL_set_app_data(ssl_, &reference_);
        auto configured = server ? ngtcp2_crypto_ossl_configure_server_session(ssl_)
                                 : ngtcp2_crypto_ossl_configure_client_session(ssl_);
        if (configured != 0) throw std::runtime_error("ngtcp2 TLS setup failed");
        if (server) SSL_set_accept_state(ssl_);
        else {
            SSL_set_connect_state(ssl_);
            static constexpr unsigned char alpn[] {2, 'h', '3'};
            SSL_set_alpn_protos(ssl_, alpn, sizeof(alpn));
            SSL_set_tlsext_host_name(ssl_, "origin.runner.lab");
        }
        ngtcp2_conn_set_tls_native_handle(conn_, crypto_);
        route_(scid, true);
        if (initial) route_(initial->dcid, true);
    } catch (...) {
        if (ssl_) { SSL_set_app_data(ssl_, nullptr); SSL_free(ssl_); }
        ngtcp2_crypto_ossl_ctx_del(crypto_);
        ngtcp2_conn_del(conn_);
        throw;
    }
}

connection::~connection() {
    SSL_set_app_data(ssl_, nullptr);
    SSL_free(ssl_);
    ngtcp2_conn_del(conn_);
    ngtcp2_crypto_ossl_ctx_del(crypto_);
}

// A remote FIN becomes visible only after the application consumed its bytes.
void connection::notify_fin(int64_t id, stream& value) {
    if (value.peer_fin && value.rx.empty() && !value.fin_notified) {
        value.fin_notified = true;
        events_.push_back({mf::event_type::peer_fin, mf::flow_handle{uint64_t(id), 1}});
    }
}

connection::stream& connection::ensure_stream(int64_t id, bool incoming) {
    auto [it, inserted] = streams_.try_emplace(id);
    if (inserted) {
        it->second.direction = (id & 2)
            ? (incoming ? mf::direction::receive_only : mf::direction::send_only)
            : mf::direction::bidirectional;
        if (incoming) events_.push_back({mf::event_type::flow_open, mf::flow_handle{uint64_t(id), 1}});
    }
    return it->second;
}

int connection::recv_stream(ngtcp2_conn*, uint32_t flags, int64_t id, uint64_t offset,
                            uint8_t const* data, size_t size, void* self, void*) {
    auto& c = *static_cast<connection*>(self);
    auto& s = c.ensure_stream(id, true);
    if (offset != s.received) return NGTCP2_ERR_CALLBACK_FAILURE;
    if (size) s.rx.push_back({std::vector<unsigned char>(data, data + size), offset, 0});
    s.received += size;
    s.peer_fin |= (flags & NGTCP2_STREAM_DATA_FLAG_FIN) != 0;
    c.notify_fin(id, s);
    return 0;
}

// Release complete immutable chunks only after ngtcp2 acknowledges their range.
int connection::ack_stream(ngtcp2_conn*, int64_t id, uint64_t offset, uint64_t size,
                           void* self, void*) {
    auto& s = static_cast<connection*>(self)->streams_.at(id);
    s.acknowledged = offset + size;
    while (!s.tx.empty() && s.tx.front().offset + s.tx.front().bytes.size() <= s.acknowledged)
        s.tx.pop_front();
    return 0;
}

int connection::opened_stream(ngtcp2_conn*, int64_t id, void* self) {
    static_cast<connection*>(self)->ensure_stream(id, true);
    return 0;
}

int connection::closed_stream(ngtcp2_conn* conn, uint32_t flags, int64_t id,
                              uint64_t error, void* self, void*) {
    auto& c = *static_cast<connection*>(self);
    auto& s = c.ensure_stream(id, true);
    s.tx_closed = true;
    s.tx.clear();
    if (flags & NGTCP2_STREAM_CLOSE_FLAG_APP_ERROR_CODE_SET) {
        s.reset = true;
        c.events_.push_back({mf::event_type::reset, mf::flow_handle{uint64_t(id), 1}, error});
    }
    if (((id & 1) != 0) != c.server_) {
        if (id & 2) ngtcp2_conn_extend_max_streams_uni(conn, 1);
        else ngtcp2_conn_extend_max_streams_bidi(conn, 1);
    }
    return 0;
}

int connection::reset_stream(ngtcp2_conn*, int64_t id, uint64_t, uint64_t error,
                             void* self, void*) {
    auto& c = *static_cast<connection*>(self);
    c.ensure_stream(id, true).reset = true;
    c.events_.push_back({mf::event_type::reset, mf::flow_handle{uint64_t(id), 1}, error});
    return 0;
}

int connection::new_cid(ngtcp2_conn*, ngtcp2_cid* cid, uint8_t* token, size_t size, void* self) {
    cid->datalen = size;
    if (RAND_bytes(cid->data, size) != 1 || RAND_bytes(token, NGTCP2_STATELESS_RESET_TOKENLEN) != 1)
        return NGTCP2_ERR_CALLBACK_FAILURE;
    static_cast<connection*>(self)->route_(*cid, true);
    return 0;
}

int connection::remove_cid(ngtcp2_conn*, ngtcp2_cid const* cid, void* self) {
    static_cast<connection*>(self)->route_(*cid, false);
    return 0;
}

void connection::receive(datagram_packet const& packet, timestamp ts) {
    if (closed_) return;
    ngtcp2_path path {{const_cast<sockaddr*>(reinterpret_cast<sockaddr const*>(&packet.local.address)), packet.local.size},
                      {const_cast<sockaddr*>(reinterpret_cast<sockaddr const*>(&packet.peer.address)), packet.peer.size}, nullptr};
    ngtcp2_pkt_info info {};
    if (auto rc = ngtcp2_conn_read_pkt(conn_, &path, &info, packet.data.data(), packet.data.size(), ts))
        fail(rc, "receive");
}

void connection::expire(timestamp ts) {
    if (!closed_ && ngtcp2_conn_get_expiry(conn_) <= ts) {
        if (auto rc = ngtcp2_conn_handle_expiry(conn_, ts)) fail(rc, "timer");
    }
}

timestamp connection::deadline() const {
    return closed_ ? std::numeric_limits<timestamp>::max() : ngtcp2_conn_get_expiry(conn_);
}

bool connection::established() const { return !closed_ && ngtcp2_conn_get_handshake_completed(conn_); }

void connection::fail(int error, char const* operation) {
    if (closed_) return;
    closed_ = true;
    events_.push_back({mf::event_type::connection_close, std::nullopt, 0});
    if (error != NGTCP2_ERR_DRAINING && error != NGTCP2_ERR_IDLE_CLOSE)
        std::cerr << "ngtcp2 " << (server_ ? "A " : "B ") << operation << ": " << ngtcp2_strerror(error) << '\n';
}

mf::flow_handle connection::open_flow(mf::direction direction) {
    if (closed_ || direction == mf::direction::receive_only) return {};
    int64_t id;
    auto rc = direction == mf::direction::send_only
        ? ngtcp2_conn_open_uni_stream(conn_, &id, nullptr)
        : ngtcp2_conn_open_bidi_stream(conn_, &id, nullptr);
    if (rc) return {};
    ensure_stream(id, false);
    return {uint64_t(id), 1};
}

bool connection::contains(mf::flow_handle f) const { return f.generation == 1 && streams_.contains(f.id); }
std::optional<mf::direction> connection::direction_of(mf::flow_handle f) const {
    return contains(f) ? std::optional(streams_.at(f.id).direction) : std::nullopt;
}

mf::io_result connection::read(mf::flow_handle f, void* destination, size_t size) {
    if (!contains(f)) return {0, mf::io_status::invalid_handle};
    auto& s = streams_.at(f.id);
    size_t copied = 0;
    while (copied < size && !s.rx.empty()) {
        auto& head = s.rx.front();
        auto count = std::min(size - copied, head.bytes.size() - head.used);
        std::memcpy(static_cast<unsigned char*>(destination) + copied, head.bytes.data() + head.used, count);
        head.used += count;
        copied += count;
        if (head.used == head.bytes.size()) s.rx.pop_front();
    }
    if (copied && !closed_) {
        ngtcp2_conn_extend_max_stream_offset(conn_, f.id, copied);
        ngtcp2_conn_extend_max_offset(conn_, copied);
    }
    notify_fin(f.id, s);
    return {copied, copied ? mf::io_status::ok : s.reset ? mf::io_status::reset
                          : s.peer_fin ? mf::io_status::eof : mf::io_status::would_block};
}

mf::io_result connection::write(mf::flow_handle f, void const* source, size_t size) {
    if (!contains(f)) return {0, mf::io_status::invalid_handle};
    if (!writable(f)) return {0, mf::io_status::would_block};
    auto& s = streams_.at(f.id);
    auto count = std::min<uint64_t>(size, stream_buffer_limit - (s.queued - s.acknowledged));
    auto bytes = static_cast<unsigned char const*>(source);
    if (count) {
        s.tx.push_back({std::vector<unsigned char>(bytes, bytes + count), s.queued, 0});
        s.queued += count;
    }
    return {count, count ? mf::io_status::ok : mf::io_status::would_block};
}

mf::io_status connection::finish(mf::flow_handle f) {
    if (!contains(f)) return mf::io_status::invalid_handle;
    streams_.at(f.id).fin_requested = true;
    return mf::io_status::ok;
}

mf::io_status connection::reset(mf::flow_handle f, uint64_t error) {
    if (!contains(f)) return mf::io_status::invalid_handle;
    ngtcp2_conn_shutdown_stream(conn_, 0, f.id, error);
    streams_.at(f.id).reset = true;
    return mf::io_status::ok;
}

void connection::close(uint64_t error) {
    if (closed_) return;
    closed_ = true;
    close_error_ = error;
    send_close_ = true;
}

bool connection::readable(mf::flow_handle f) const {
    return contains(f) && !streams_.at(f.id).rx.empty();
}

bool connection::writable(mf::flow_handle f) const {
    if (closed_ || !contains(f)) return false;
    auto& s = streams_.at(f.id);
    return !s.reset && !s.tx_closed && !s.fin_requested && s.direction != mf::direction::receive_only
        && s.queued - s.acknowledged < stream_buffer_limit;
}

std::vector<mf::event> connection::drain_events() { return std::exchange(events_, {}); }

// Preserve the packet generated by ngtcp2 if the kernel socket is full. The
// source address is part of the path: downstream replies retain original IP.
bool connection::send_pending(int fd) {
    if (!pending_size_) return true;
    iovec iov {pending_.data(), pending_size_};
    msghdr message {};
    message.msg_name = pending_path_.path.remote.addr;
    message.msg_namelen = pending_path_.path.remote.addrlen;
    message.msg_iov = &iov;
    message.msg_iovlen = 1;
    std::array<unsigned char, CMSG_SPACE(sizeof(in6_pktinfo))> control {};
    message.msg_control = control.data();
    auto* local = pending_path_.path.local.addr;
    if (local->sa_family == AF_INET) {
        message.msg_controllen = CMSG_SPACE(sizeof(in_pktinfo));
        auto* cmsg = CMSG_FIRSTHDR(&message);
        cmsg->cmsg_level = IPPROTO_IP; cmsg->cmsg_type = IP_PKTINFO;
        cmsg->cmsg_len = CMSG_LEN(sizeof(in_pktinfo));
        auto* pkt = reinterpret_cast<in_pktinfo*>(CMSG_DATA(cmsg));
        pkt->ipi_spec_dst = reinterpret_cast<sockaddr_in*>(local)->sin_addr;
    } else {
        message.msg_controllen = CMSG_SPACE(sizeof(in6_pktinfo));
        auto* cmsg = CMSG_FIRSTHDR(&message);
        cmsg->cmsg_level = IPPROTO_IPV6; cmsg->cmsg_type = IPV6_PKTINFO;
        cmsg->cmsg_len = CMSG_LEN(sizeof(in6_pktinfo));
        auto* pkt = reinterpret_cast<in6_pktinfo*>(CMSG_DATA(cmsg));
        pkt->ipi6_addr = reinterpret_cast<sockaddr_in6*>(local)->sin6_addr;
    }
    auto sent = ::sendmsg(fd, &message, MSG_DONTWAIT);
    if (sent < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) return false;
    if (sent != static_cast<ssize_t>(pending_size_)) throw std::runtime_error("ngtcp2 sendmsg failed");
    pending_size_ = 0;
    return true;
}

size_t connection::transmit(int fd, timestamp ts) {
    if (!send_pending(fd)) return 0;
    size_t packets = 0;
    while (packets < 64) {
        ngtcp2_path_storage_zero(&pending_path_);
        ngtcp2_pkt_info info {};
        ngtcp2_ssize count = 0;
        if (send_close_) {
            ngtcp2_ccerr error;
            ngtcp2_ccerr_default(&error);
            ngtcp2_ccerr_set_application_error(&error, close_error_, nullptr, 0);
            count = ngtcp2_conn_write_connection_close(conn_, &pending_path_.path, &info,
                pending_.data(), pending_.size(), &error, ts);
            send_close_ = false;
        } else if (closed_) break;
        else {
            int64_t id = -1;
            stream* selected = nullptr;
            chunk* data = nullptr;
            // Round-robin streams, retaining submitted chunks until ACK.
            auto it = streams_.lower_bound(next_tx_);
            for (size_t visited = 0; visited < streams_.size(); ++visited) {
                if (it == streams_.end()) it = streams_.begin();
                auto& s = it->second;
                if (!s.tx_closed && !s.reset) {
                    for (auto& ch : s.tx) if (ch.used != ch.bytes.size()) { data = &ch; break; }
                    if (data || (s.fin_requested && !s.fin_submitted)) {
                        id = it->first; selected = &s; next_tx_ = id + 1; break;
                    }
                }
                ++it;
            }
            ngtcp2_vec vec {data ? data->bytes.data() + data->used : nullptr,
                           data ? data->bytes.size() - data->used : 0};
            bool fin = selected && selected->fin_requested
                && (!data || data->offset + data->bytes.size() == selected->queued);
            ngtcp2_ssize accepted = -1;
            count = ngtcp2_conn_writev_stream(conn_, &pending_path_.path, &info,
                pending_.data(), 1350, &accepted, fin ? NGTCP2_WRITE_STREAM_FLAG_FIN : 0,
                id, &vec, data ? 1 : 0, ts);
            if (accepted >= 0) {
                if (data) data->used += accepted;
                if (fin && size_t(accepted) == vec.len) selected->fin_submitted = true;
            }
            if (count == NGTCP2_ERR_STREAM_DATA_BLOCKED || count == NGTCP2_ERR_STREAM_SHUT_WR) {
                // Still permit control/ACK frames when stream credit is exhausted.
                count = ngtcp2_conn_write_pkt(conn_, &pending_path_.path, &info,
                    pending_.data(), 1350, ts);
            }
        }
        if (count < 0) { fail(count, "transmit"); break; }
        if (count == 0) break;
        pending_size_ = count;
        ++packets;
        if (!send_pending(fd)) break;
    }
    if (packets) ngtcp2_conn_update_pkt_tx_time(conn_, ts);
    return packets;
}

} // namespace sx::quic::experiment
