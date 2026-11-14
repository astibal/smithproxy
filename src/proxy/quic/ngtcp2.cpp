#include "proxy/quic/error_stats.hpp"
#include "proxy/quic/ngtcp2.hpp"
#include "proxy/quic/socket_io_detail.hpp"
#include <openssl/rand.h>
#include <algorithm>
#include <chrono>
#include <cstring>
#include "proxy/quic/log.hpp"
#include <stdexcept>
#include <limits>

namespace sx::quic::ng {
namespace mf = multiflow;

// One monotonic timestamp per worker pass is reused by receive, timers and TX.
timestamp now() {
    return std::chrono::duration_cast<std::chrono::nanoseconds>(
        std::chrono::steady_clock::now().time_since_epoch()).count();
}

// Wire TLS helpers and stream notifications into the worker-owned connection.
ngtcp2_callbacks connection::callbacks(bool server) {
    ngtcp2_callbacks handlers {};
    if (server) handlers.recv_client_initial = ngtcp2_crypto_recv_client_initial_cb;
    else handlers.client_initial = ngtcp2_crypto_client_initial_cb;
    handlers.recv_crypto_data = recv_crypto;
    handlers.encrypt = ngtcp2_crypto_encrypt_cb;
    handlers.decrypt = ngtcp2_crypto_decrypt_cb;
    handlers.hp_mask = ngtcp2_crypto_hp_mask_cb;
    handlers.recv_stream_data = recv_stream;
    handlers.acked_stream_data_offset = ack_stream;
    handlers.stream_open = opened_stream;
    handlers.stream_close = closed_stream;
    handlers.stream_reset = reset_stream;
    handlers.recv_retry = ngtcp2_crypto_recv_retry_cb;
    handlers.rand = [](uint8_t* output, size_t size, ngtcp2_rand_ctx const*) {
        if (RAND_bytes(output, static_cast<int>(size)) != 1) {
            ++stats.errors.ngtcp2_random_failure;
            std::terminate();
        }
    };
    handlers.get_new_connection_id = new_cid;
    handlers.remove_connection_id = remove_cid;
    handlers.update_key = ngtcp2_crypto_update_key_cb;
    handlers.delete_crypto_aead_ctx = ngtcp2_crypto_delete_crypto_aead_ctx_cb;
    handlers.delete_crypto_cipher_ctx = ngtcp2_crypto_delete_crypto_cipher_ctx_cb;
    handlers.get_path_challenge_data = ngtcp2_crypto_get_path_challenge_data_cb;
    handlers.version_negotiation = ngtcp2_crypto_version_negotiation_cb;
    return handlers;
}

// Create a single A or B transport; the worker registers its receive CIDs.
connection::connection(SSL_CTX* tls, bool server, datagram_endpoint local,
                       datagram_endpoint remote, ngtcp2_pkt_hd const* initial,
                       cid_router route, timestamp started,
                       std::function<bool(SSL*)> configure, datagram_observer observer,
                       std::function<void()> activate)
    : server_(server), local_(local), remote_(remote), route_(std::move(route)),
      observer_(std::move(observer)), activate_(std::move(activate)),
      keylog_(server ? std::make_shared<keylog_store>() : nullptr) {
    ngtcp2_cid scid {}, dcid {};
    scid.datalen = 16;
    dcid.datalen = 16;
    if (RAND_bytes(scid.data, scid.datalen) != 1 || RAND_bytes(dcid.data, dcid.datalen) != 1) {
        ++stats.errors.connection_create_cid_random_generation_failed;
        throw std::runtime_error("CID random generation failed");
    }
    if (server && !initial) {
        ++stats.errors.connection_create_server_connection_requires_initial_metadata;
        throw std::invalid_argument("server connection requires Initial metadata");
    }
    if (server) dcid = initial->scid;
    ngtcp2_path path {{reinterpret_cast<sockaddr*>(&local_.address), local_.size},
                      {reinterpret_cast<sockaddr*>(&remote_.address), remote_.size}, nullptr};
    ngtcp2_settings settings;
    ngtcp2_settings_default(&settings);
    settings.initial_ts = started;
    // Keep the default unlimited library deadline: the shared service owns
    // the configured handshake timeout and its diagnostic counter.
    settings.max_tx_udp_payload_size = max_udp_payload;
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
    // Tuple changes require coordinated transparent routing and are not enabled.
    params.disable_active_migration = 1;
    params.max_idle_timeout = 30 * NGTCP2_SECONDS;
    if (server) {
        params.original_dcid = initial->dcid;
        params.original_dcid_present = 1;
    }
    auto handlers = callbacks(server);
    ngtcp2_conn* created = nullptr;
    auto rc = server
        ? ngtcp2_conn_server_new(&created, &dcid, &scid, &path, initial->version,
                                &handlers, &settings, &params, nullptr, this)
        : ngtcp2_conn_client_new(&created, &dcid, &scid, &path, NGTCP2_PROTO_VER_V1,
                                &handlers, &settings, &params, nullptr, this);
    conn_.value = created;
    if (rc) {
        ++stats.errors.connection_create_throw;
        throw std::runtime_error(ngtcp2_strerror(rc));
    }
    initialize_tls(tls, configure);
    route_(scid, true);
    if (initial) route_(initial->dcid, true);
}

// Bind the TLS-only OpenSSL session to this transport before policy callbacks run.
// Allocation failures are unwound by the constructor, whose RAII members release partial state.
void connection::initialize_tls(SSL_CTX* tls, std::function<bool(SSL*)> const& configure) {
    ssl_.value = SSL_new(tls);
    if (!ssl_.value) {
        ++stats.errors.connection_initialize_tls_tls_allocation_failed;
        throw std::runtime_error("TLS allocation failed");
    }
    ngtcp2_crypto_ossl_ctx* created = nullptr;
    auto const crypto_result = ngtcp2_crypto_ossl_ctx_new(&created, ssl_.value);
    crypto_.value = created;
    if (crypto_result != 0) {
        ++stats.errors.connection_initialize_tls_tls_crypto_allocation_failed;
        throw std::runtime_error("TLS crypto allocation failed");
    }
    reference_.user_data = this;
    reference_.get_conn = [](ngtcp2_crypto_conn_ref* ref) {
        return ref && ref->user_data ? static_cast<connection*>(ref->user_data)->conn_.value : nullptr;
    };
    SSL_set_app_data(ssl_.value, &reference_);
    auto configured = server_ ? ngtcp2_crypto_ossl_configure_server_session(ssl_.value)
                             : ngtcp2_crypto_ossl_configure_client_session(ssl_.value);
    if (configured != 0) {
        ++stats.errors.connection_initialize_tls_ngtcp2_tls_setup_failed;
        throw std::runtime_error("ngtcp2 TLS setup failed");
    }
    if (server_) {
        SSL_set_accept_state(ssl_.value);
    } else {
        SSL_set_connect_state(ssl_.value);
        static constexpr unsigned char alpn[] {2, 'h', '3'};
        if (SSL_set_alpn_protos(ssl_.value, alpn, sizeof(alpn)) != 0) {
            ++stats.errors.connection_initialize_tls_alpn_failed;
            throw std::runtime_error("ngtcp2 ALPN setup failed");
        }
    }
    if (configure && !configure(ssl_.value)) {
        ++stats.errors.connection_initialize_tls_quic_tls_policy_setup_rejected;
        throw std::runtime_error("QUIC TLS policy setup rejected");
    }
    ngtcp2_conn_set_tls_native_handle(conn_.value, crypto_.value);
}

// Clear the callback back-reference before releasing TLS and transport state.
connection::~connection() = default;

// The certificate callback suspends A while the shared service authenticates B.
// A paused TLS handshake is successful packet processing, not a crypto failure.
int connection::recv_crypto(ngtcp2_conn* conn, ngtcp2_encryption_level level,
                            uint64_t, uint8_t const* data, size_t size, void* self) {
    if (!self || !conn) {
        ++stats.errors.connection_recv_crypto_failure;
        return NGTCP2_ERR_CALLBACK_FAILURE;
    }
    auto& owner = *static_cast<connection*>(self);
    try {
        auto rc = ngtcp2_crypto_read_write_crypto_data(conn, level, data, size);
        bool const paused = rc == NGTCP2_CRYPTO_OSSL_ERR_TLS_WANT_X509_LOOKUP;
        if (paused != owner.tls_paused_) {
            logging::info().deb("ngtcp2 conn=%p %s certificate callback %s",
                                self, owner.server_ ? "A" : "B", paused ? "paused" : "resumed");
        }
        owner.tls_paused_ = paused;
        if (*logging::message().level() >= DUM) {
            logging::message().dum("ngtcp2 conn=%p CRYPTO level=%d bytes=%zu result=%d",
                                   self, static_cast<int>(level), size, rc);
        }
        if (owner.tls_paused_ || rc == 0) return 0;
        ++stats.errors.connection_recv_crypto_tls_failure;
        ngtcp2_conn_set_tls_error(conn, rc);
        return NGTCP2_ERR_CRYPTO;
    } catch (...) {
        ++stats.errors.connection_recv_crypto_exception;
        return NGTCP2_ERR_CALLBACK_FAILURE;
    }
}

// Resume only a suspended TLS operation; packet/timer processing belongs to the
// worker transport. The service can therefore inspect B without ticking it twice.
void connection::progress_transport() {
    if (closed_ || !tls_paused_) return;
    activate_();
    auto rc = recv_crypto(conn_.value, NGTCP2_ENCRYPTION_LEVEL_INITIAL, 0, nullptr, 0, this);
    if (rc) {
        ++stats.errors.connection_progress_transport_certificate_resume;
        fail(rc, "certificate resume");
    }
    if (!tls_paused_) progress_ = true;
}

// Return the ClientHello SNI, or an empty name before it is available.
std::string connection::server_name() const {
    auto* value = SSL_get_servername(ssl_.value, TLSEXT_NAMETYPE_host_name);
    return value ? value : "";
}

// Copy the negotiated ALPN without retaining OpenSSL-owned storage.
std::string connection::negotiated_alpn() const {
    unsigned char const* value = nullptr;
    unsigned size = 0;
    SSL_get0_alpn_selected(ssl_.value, &value, &size);
    return size ? std::string(reinterpret_cast<char const*>(value), size) : "";
}

// Attach downstream secrets to the common capture journal, never a global sink.
void connection::record_keylog(SSL const* ssl, char const* line) {
    if (!ssl || !line) {
        ++stats.errors.ngtcp2_keylog_missing_argument;
        return;
    }
    auto* ref = static_cast<ngtcp2_crypto_conn_ref*>(SSL_get_app_data(ssl));
    if (!ref || !ref->user_data) {
        ++stats.errors.ngtcp2_keylog_missing_connection;
        return;
    }

    auto* self = static_cast<connection*>(ref->user_data);
    try {
        if (self->keylog_) self->keylog_->append(line);
    } catch (...) {
        ++stats.errors.connection_record_keylog_exception;
        // Key capture is optional, and no C callback may leak an exception.
    }
}

// A remote FIN becomes visible only after the application consumed its bytes.
void connection::notify_fin(int64_t id, stream& value) {
    if (value.peer_fin && value.rx.empty() && !value.fin_notified) {
        value.fin_notified = true;
        events_.push_back({mf::event_type::peer_fin, mf::flow_handle{uint64_t(id), 1}});
    }
}

// Materialize stream state once and announce only peer-created streams.
connection::stream& connection::ensure_stream(int64_t id, bool incoming) {
    auto [it, inserted] = streams_.try_emplace(id);
    if (inserted) {
        logging::stream().deb("ngtcp2 conn=%p %s stream=%lld opened incoming=%d",
                              static_cast<void*>(this), server_ ? "A" : "B",
                              static_cast<long long>(id), incoming);
        it->second.direction = (id & 2)
            ? (incoming ? mf::direction::receive_only : mf::direction::send_only)
            : mf::direction::bidirectional;
        if (incoming) events_.push_back({mf::event_type::flow_open, mf::flow_handle{uint64_t(id), 1}});
    }
    return it->second;
}

// ngtcp2 delivers ordered stream bytes; grant receive credit only in read().
int connection::recv_stream(ngtcp2_conn*, uint32_t flags, int64_t id, uint64_t offset,
                            uint8_t const* data, size_t size, void* self, void*) {
    if (!self || (size > 0 && !data)) {
        ++stats.errors.connection_recv_stream_failure;
        return NGTCP2_ERR_CALLBACK_FAILURE;
    }
    try {
        auto& owner = *static_cast<connection*>(self);
        auto& state = owner.ensure_stream(id, true);
        if (offset != state.received) {
            ++stats.errors.connection_recv_stream_offset_mismatch;
            return NGTCP2_ERR_CALLBACK_FAILURE;
        }
        if (size) state.rx.push_back({buffer(data, size), offset, 0});
        state.received += size;
        if (*logging::stream().level() >= DUM) {
            logging::stream().dum("ngtcp2 conn=%p stream=%lld RX offset=%llu bytes=%zu flags=%u",
                                  self, static_cast<long long>(id),
                                  static_cast<unsigned long long>(offset), size, flags);
        }
        if (flags & NGTCP2_STREAM_DATA_FLAG_FIN) state.peer_fin = true;
        owner.notify_fin(id, state);
        return 0;
    } catch (...) {
        ++stats.errors.connection_recv_stream_exception;
        return NGTCP2_ERR_CALLBACK_FAILURE;
    }
}

// Release complete immutable chunks only after ngtcp2 acknowledges their range.
int connection::ack_stream(ngtcp2_conn*, int64_t id, uint64_t offset, uint64_t size,
                           void* self, void*) {
    if (!self) {
        ++stats.errors.connection_ack_stream_failure;
        return NGTCP2_ERR_CALLBACK_FAILURE;
    }
    try {
        auto& state = static_cast<connection*>(self)->streams_.at(id);
        state.acknowledged = offset + size;
        if (*logging::stream().level() >= DUM) {
            logging::stream().dum("ngtcp2 conn=%p stream=%lld ACK offset=%llu bytes=%llu",
                                  self, static_cast<long long>(id),
                                  static_cast<unsigned long long>(offset), static_cast<unsigned long long>(size));
        }
        while (!state.tx.empty() && state.tx.front().offset + state.tx.front().bytes.size() <= state.acknowledged) {
            state.tx.pop_front();
            --state.tx_submitted;
        }
        return 0;
    } catch (...) {
        ++stats.errors.connection_ack_stream_exception;
        return NGTCP2_ERR_CALLBACK_FAILURE;
    }
}

// Announce peer streams even when their first frame carries no application bytes.
int connection::opened_stream(ngtcp2_conn*, int64_t id, void* self) {
    if (!self) {
        ++stats.errors.connection_opened_stream_failure;
        return NGTCP2_ERR_CALLBACK_FAILURE;
    }
    try {
        static_cast<connection*>(self)->ensure_stream(id, true);
        return 0;
    } catch (...) {
        ++stats.errors.connection_opened_stream_exception;
        return NGTCP2_ERR_CALLBACK_FAILURE;
    }
}

// End TX ownership and replenish peer stream-count credit after transport close.
int connection::closed_stream(ngtcp2_conn* conn, uint32_t flags, int64_t id,
                              uint64_t error, void* self, void*) {
    if (!self) {
        ++stats.errors.connection_closed_stream_failure;
        return NGTCP2_ERR_CALLBACK_FAILURE;
    }
    try {
        auto& owner = *static_cast<connection*>(self);
        auto& state = owner.ensure_stream(id, true);
        state.tx_closed = true;
        state.tx.clear();
        state.tx_submitted = 0;
        if (flags & NGTCP2_STREAM_CLOSE_FLAG_APP_ERROR_CODE_SET) {
            state.reset = true;
            owner.events_.push_back({mf::event_type::reset, mf::flow_handle{uint64_t(id), 1}, error});
        }
        if (((id & 1) != 0) != owner.server_) {
            if (id & 2) ngtcp2_conn_extend_max_streams_uni(conn, 1);
            else ngtcp2_conn_extend_max_streams_bidi(conn, 1);
        }
        return 0;
    } catch (...) {
        ++stats.errors.connection_closed_stream_exception;
        return NGTCP2_ERR_CALLBACK_FAILURE;
    }
}

// Surface the peer reset through the common multiflow event contract.
int connection::reset_stream(ngtcp2_conn*, int64_t id, uint64_t, uint64_t error,
                             void* self, void*) {
    if (!self) {
        ++stats.errors.connection_reset_stream_failure;
        return NGTCP2_ERR_CALLBACK_FAILURE;
    }
    try {
        auto& owner = *static_cast<connection*>(self);
        owner.ensure_stream(id, true).reset = true;
        owner.events_.push_back({mf::event_type::reset, mf::flow_handle{uint64_t(id), 1}, error});
        return 0;
    } catch (...) {
        ++stats.errors.connection_reset_stream_exception;
        return NGTCP2_ERR_CALLBACK_FAILURE;
    }
}

// Issue an unpredictable CID/reset token and register it with this worker.
int connection::new_cid(ngtcp2_conn*, ngtcp2_cid* cid, uint8_t* token, size_t size, void* self) {
    if (!self || !cid || !token || size > sizeof(cid->data)) {
        ++stats.errors.connection_new_cid_failure;
        return NGTCP2_ERR_CALLBACK_FAILURE;
    }
    try {
        cid->datalen = size;
        if (RAND_bytes(cid->data, size) != 1 || RAND_bytes(token, NGTCP2_STATELESS_RESET_TOKENLEN) != 1) {
            ++stats.errors.connection_new_cid_random_failure;
            return NGTCP2_ERR_CALLBACK_FAILURE;
        }
        static_cast<connection*>(self)->route_(*cid, true);
        return 0;
    } catch (...) {
        ++stats.errors.connection_new_cid_exception;
        return NGTCP2_ERR_CALLBACK_FAILURE;
    }
}

// Retire one routing alias; the connection can still have other active CIDs.
int connection::remove_cid(ngtcp2_conn*, ngtcp2_cid const* cid, void* self) {
    if (!self || !cid) {
        ++stats.errors.connection_remove_cid_failure;
        return NGTCP2_ERR_CALLBACK_FAILURE;
    }
    try {
        static_cast<connection*>(self)->route_(*cid, false);
        return 0;
    } catch (...) {
        ++stats.errors.connection_remove_cid_exception;
        return NGTCP2_ERR_CALLBACK_FAILURE;
    }
}

// Feed the actual packet path to QUIC under the correct service callback owner.
void connection::receive(datagram_packet const& packet, timestamp ts) {
    if (closed_) return;
    if (*logging::transport().level() >= EXT) {
        logging::transport().ext("ngtcp2 conn=%p %s RX bytes=%zu",
                                 static_cast<void*>(this), server_ ? "A" : "B", packet.data.size());
    }
    activate_();
    ngtcp2_path path {{const_cast<sockaddr*>(reinterpret_cast<sockaddr const*>(&packet.local.address)), packet.local.size},
                      {const_cast<sockaddr*>(reinterpret_cast<sockaddr const*>(&packet.peer.address)), packet.peer.size}, nullptr};
    ngtcp2_pkt_info info {};
    if (auto rc = ngtcp2_conn_read_pkt(conn_.value, &path, &info, packet.data.data(), packet.data.size(), ts)) {
        ++stats.errors.connection_receive_receive;
        fail(rc, "receive");
    }
}

// Service due protocol timers without imposing a second handshake timeout.
void connection::expire(timestamp ts) {
    if (!closed_ && ngtcp2_conn_get_expiry(conn_.value) <= ts) {
        if (*logging::transport().level() >= DUM) {
            logging::transport().dum("ngtcp2 conn=%p timer expired", static_cast<void*>(this));
        }
        if (auto rc = ngtcp2_conn_handle_expiry(conn_.value, ts)) {
            ++stats.errors.connection_expire_timer;
            fail(rc, "timer");
        }
    }
}

// Closed transports have no protocol deadline; worker retirement is separate.
timestamp connection::deadline() const {
    return closed_ ? std::numeric_limits<timestamp>::max() : ngtcp2_conn_get_expiry(conn_.value);
}

// Report live handshake completion to the shared A:B lifecycle gate.
bool connection::established() const { return !closed_ && ngtcp2_conn_get_handshake_completed(conn_.value); }

// Translate transport/TLS failure into a wire close and one service notification.
void connection::fail(int error, char const* operation) {
    if (closed_) return;
    closed_ = true;
    progress_ = true;
    send_close_ = error != NGTCP2_ERR_DRAINING && error != NGTCP2_ERR_IDLE_CLOSE;
    // Preserve TLS alerts and transport errors on the wire; policy/application
    // closes use their separate application-error namespace in close().
    ngtcp2_ccerr_default(&close_error_);
    if (error == NGTCP2_ERR_CRYPTO)
        ngtcp2_ccerr_set_tls_alert(&close_error_, ngtcp2_conn_get_tls_alert(conn_.value), nullptr, 0);
    else
        ngtcp2_ccerr_set_liberr(&close_error_, error, nullptr, 0);
    events_.push_back({mf::event_type::connection_close, std::nullopt, 0});
    if (error != NGTCP2_ERR_DRAINING && error != NGTCP2_ERR_IDLE_CLOSE) {
        logging::transport().war("ngtcp2 conn=%p %s %s: %s",
                                 static_cast<void*>(this), server_ ? "A" : "B",
                                 operation, ngtcp2_strerror(error));
    } else if (error == NGTCP2_ERR_DRAINING) {
        // ERR_DRAINING describes our state, not the peer's reason for closing.
        // Retain the received error namespace: H3 codes are application errors.
        auto const* peer = ngtcp2_conn_get_ccerr(conn_.value);
        std::string reason;
        if (peer->reason) {
            reason.assign(reinterpret_cast<char const*>(peer->reason), peer->reasonlen);
            for (auto& character : reason) {
                auto const byte = static_cast<unsigned char>(character);
                if (byte < 0x20 || byte == 0x7f) character = '?';
            }
        }

        logging::transport().dia(
            "ngtcp2 conn=%p %s closed: %s peer_type=%s peer_code=0x%llx frame=0x%llx reason='%s'",
            static_cast<void*>(this), server_ ? "A" : "B", ngtcp2_strerror(error),
            peer->type == NGTCP2_CCERR_TYPE_APPLICATION ? "application" : "transport",
            static_cast<unsigned long long>(peer->error_code),
            static_cast<unsigned long long>(peer->frame_type), reason.c_str());
    } else {
        logging::transport().dia("ngtcp2 conn=%p %s closed: %s",
                                 static_cast<void*>(this), server_ ? "A" : "B", ngtcp2_strerror(error));
    }
}

// Allocate a local stream; flow-control exhaustion is reported as no handle.
mf::flow_handle connection::open_flow(mf::direction direction) {
    if (closed_ || direction == mf::direction::receive_only) return {};
    int64_t id;
    auto rc = direction == mf::direction::send_only
        ? ngtcp2_conn_open_uni_stream(conn_.value, &id, nullptr)
        : ngtcp2_conn_open_bidi_stream(conn_.value, &id, nullptr);
    if (rc) return {};
    ensure_stream(id, false);
    return {uint64_t(id), 1};
}

// QUIC stream IDs never recycle within this connection, so generation stays one.
bool connection::contains(mf::flow_handle flow) const {
    return flow.generation == 1 && streams_.find(flow.id) != streams_.end();
}
// Expose a known stream direction without creating state for invalid handles.
std::optional<mf::direction> connection::direction_of(mf::flow_handle flow) const {
    return contains(flow) ? std::optional(streams_.at(flow.id).direction) : std::nullopt;
}

// Return buffered bytes and replenish only the credit consumed by the bridge.
mf::io_result connection::read(mf::flow_handle flow, void* destination, size_t size) {
    if (!contains(flow)) return {0, mf::io_status::invalid_handle};
    auto& state = streams_.at(flow.id);
    size_t copied = 0;
    while (copied < size && !state.rx.empty()) {
        auto& head = state.rx.front();
        auto count = std::min(size - copied, head.bytes.size() - head.used);
        std::memcpy(static_cast<unsigned char*>(destination) + copied, head.bytes.data() + head.used, count);
        head.used += count;
        copied += count;
        if (head.used == head.bytes.size()) state.rx.pop_front();
    }
    if (copied != 0) progress_ = true;
    if (copied && !closed_) {
        ngtcp2_conn_extend_max_stream_offset(conn_.value, flow.id, copied);
        ngtcp2_conn_extend_max_offset(conn_.value, copied);
    }
    notify_fin(flow.id, state);
    if (copied) return {copied, mf::io_status::ok};
    if (state.reset) return {0, mf::io_status::reset};
    if (state.peer_fin) return {0, mf::io_status::eof};
    return {0, mf::io_status::would_block};
}

// Copy into bounded, stable TX chunks; ngtcp2 may reference them until ACK.
mf::io_result connection::write(mf::flow_handle flow, void const* source, size_t size) {
    if (!contains(flow)) return {0, mf::io_status::invalid_handle};
    if (!writable(flow)) return {0, mf::io_status::would_block};
    auto& state = streams_.at(flow.id);
    auto count = std::min<uint64_t>(size, stream_buffer_limit - (state.queued - state.acknowledged));
    auto bytes = static_cast<unsigned char const*>(source);
    if (count) {
        state.tx.push_back({buffer(bytes, count), state.queued, 0});
        state.queued += count;
        progress_ = true;
    }
    return {count, count ? mf::io_status::ok : mf::io_status::would_block};
}

// Queue FIN behind all accepted application bytes rather than sending it early.
mf::io_status connection::finish(mf::flow_handle flow) {
    if (!contains(flow)) return mf::io_status::invalid_handle;
    streams_.at(flow.id).fin_requested = true;
    progress_ = true;
    return mf::io_status::ok;
}

// Stop both transport directions and prevent further writes from the bridge.
mf::io_status connection::reset(mf::flow_handle flow, uint64_t error) {
    if (!contains(flow)) return mf::io_status::invalid_handle;
    ngtcp2_conn_shutdown_stream(conn_.value, 0, flow.id, error);
    streams_.at(flow.id).reset = true;
    progress_ = true;
    return mf::io_status::ok;
}

// Schedule an application close for the next worker TX pass; this performs no I/O.
void connection::close(uint64_t error) {
    if (closed_) return;
    closed_ = true;
    progress_ = true;
    ngtcp2_ccerr_default(&close_error_);
    ngtcp2_ccerr_set_application_error(&close_error_, error, nullptr, 0);
    send_close_ = true;
}

// Readability means buffered payload; FIN/reset arrive through separate events.
bool connection::readable(mf::flow_handle flow) const {
    return contains(flow) && !streams_.at(flow.id).rx.empty();
}

// Bound outstanding storage, including bytes submitted but not yet acknowledged.
bool connection::writable(mf::flow_handle flow) const {
    if (closed_ || !contains(flow)) return false;
    auto& state = streams_.at(flow.id);
    return !state.reset && !state.tx_closed && !state.fin_requested && state.direction != mf::direction::receive_only
        && state.queued - state.acknowledged < stream_buffer_limit;
}

// Transfer accumulated notifications to the service exactly once per drain.
std::vector<mf::event> connection::drain_events() { return std::exchange(events_, {}); }

// Send a bounded batch with per-packet source metadata. A positive return
// acknowledges only that prefix; errno is meaningful only on total failure.
size_t connection::send_packets(int fd, output_packet* const* packets, size_t count) {
    std::array<mmsghdr, packet_batch_limit> messages {};
    std::array<iovec, packet_batch_limit> vectors;
    struct ancillary {
        alignas(cmsghdr) unsigned char bytes[CMSG_SPACE(sizeof(in6_pktinfo))];
    };
    std::array<ancillary, packet_batch_limit> control {};
    for (size_t i = 0; i < count; ++i) {
        auto& packet = *packets[i];
        auto& message = messages[i].msg_hdr;
        vectors[i] = {packet.bytes.data(), packet.size};
        message.msg_name = &packet.remote.address;
        message.msg_namelen = packet.remote.size;
        message.msg_iov = &vectors[i];
        message.msg_iovlen = 1;
        message.msg_control = control[i].bytes;
        auto* local = reinterpret_cast<sockaddr const*>(&packet.local.address);
        if (local->sa_family == AF_INET) {
            message.msg_controllen = CMSG_SPACE(sizeof(in_pktinfo));
            auto* cmsg = CMSG_FIRSTHDR(&message);
            cmsg->cmsg_level = IPPROTO_IP;
            cmsg->cmsg_type = IP_PKTINFO;
            cmsg->cmsg_len = CMSG_LEN(sizeof(in_pktinfo));
            auto* pkt = reinterpret_cast<in_pktinfo*>(CMSG_DATA(cmsg));
            pkt->ipi_spec_dst = reinterpret_cast<sockaddr_in const*>(local)->sin_addr;
        } else {
            message.msg_controllen = CMSG_SPACE(sizeof(in6_pktinfo));
            auto* cmsg = CMSG_FIRSTHDR(&message);
            cmsg->cmsg_level = IPPROTO_IPV6;
            cmsg->cmsg_type = IPV6_PKTINFO;
            cmsg->cmsg_len = CMSG_LEN(sizeof(in6_pktinfo));
            auto* pkt = reinterpret_cast<in6_pktinfo*>(CMSG_DATA(cmsg));
            pkt->ipi6_addr = reinterpret_cast<sockaddr_in6 const*>(local)->sin6_addr;
        }
    }
    auto sent = detail::retry_on_eintr([&] {
        return ::sendmmsg(fd, messages.data(), count, MSG_DONTWAIT);
    });
    if (sent < 0) {
        if (detail::classify_datagram_send(sent, errno, 0) == detail::datagram_send_result::blocked)
            return 0;
        ++stats.errors.connection_send_packets_ngtcp2_sendmmsg;
        throw std::runtime_error(std::string("ngtcp2 sendmmsg: ") + std::strerror(errno));
    }
    if (*logging::transport().level() >= EXT) {
        logging::transport().ext("ngtcp2 conn=%p TX batch sent=%ld requested=%zu",
                                 static_cast<void*>(this), static_cast<long>(sent), count);
    }
    for (ssize_t i = 0; i < sent; ++i) {
        auto const& packet = *packets[i];
        if (messages[i].msg_len != packet.size) {
            ++stats.errors.connection_send_packets_ngtcp2_incomplete_udp_datagram_send;
            throw std::runtime_error("ngtcp2 incomplete UDP datagram send");
        }
        if (observer_) observer_({datagram_direction::egress, packet.remote, packet.local,
                                  0, packet.bytes.data(), packet.size});
    }
    return static_cast<size_t>(sent);
}

// Retry only the unsent suffix, preserving ciphertext and transparent paths.
// No new packets are generated while an earlier batch remains socket-blocked.
bool connection::send_pending(int fd) {
    if (pending_output_.empty()) return true;
    std::array<output_packet*, packet_batch_limit> packets;
    size_t count = 0;
    for (auto& packet : pending_output_) packets[count++] = &packet;
    auto sent = send_packets(fd, packets.data(), count);
    for (size_t i = 0; i < sent; ++i) pending_output_.pop_front();
    return pending_output_.empty();
}

// Visit each stream at most once. Submitted chunks remain in the queue for
// retransmission; only their unused suffix is eligible for a new submission.
connection::transmit_selection connection::select_transmit_stream() {
    auto it = streams_.lower_bound(next_tx_);
    for (size_t visited = 0; visited < streams_.size(); ++visited, ++it) {
        if (it == streams_.end()) it = streams_.begin();
        auto& state = it->second;
        if (state.tx_closed || state.reset) continue;

        bool has_data = state.tx_submitted < state.tx.size();
        auto* data = has_data ? &state.tx[state.tx_submitted] : nullptr;
        bool has_fin = state.fin_requested && !state.fin_submitted;
        if (!has_data && !has_fin) continue;

        next_tx_ = it->first + 1;
        return {it->first, &state, data};
    }
    // Stream -1 asks ngtcp2 to produce only transport/control frames.
    return {};
}

// Submit one stream slice, then fall back to control output if flow control
// blocks that stream. FIN is offered only with its last queued bytes.
ngtcp2_ssize connection::write_stream_packet(ngtcp2_path_storage& path, unsigned char* output,
                                              ngtcp2_pkt_info& info, timestamp ts) {
    auto selected = select_transmit_stream();
    auto* state = selected.state;
    auto* data = selected.data;
    ngtcp2_vec slice {
        data ? data->bytes.data() + data->used : nullptr,
        data ? data->bytes.size() - data->used : 0
    };
    bool fin = state && state->fin_requested
        && (!data || data->offset + data->bytes.size() == state->queued);
    ngtcp2_ssize accepted = -1;
    auto count = ngtcp2_conn_writev_stream(conn_.value, &path.path, &info,
        output, max_udp_payload, &accepted,
        fin ? NGTCP2_WRITE_STREAM_FLAG_FIN : 0, selected.id, &slice, data ? 1 : 0, ts);

    // Accepted bytes are retained until ACK; acceptance alone does not free
    // buffer capacity. ngtcp2 may accept only part of the offered final slice.
    if (accepted >= 0) {
        if (data) {
            data->used += accepted;
            if (data->used == data->bytes.size()) ++state->tx_submitted;
        }
        if (fin && size_t(accepted) == slice.len) state->fin_submitted = true;
    }
    if (count == NGTCP2_ERR_STREAM_DATA_BLOCKED || count == NGTCP2_ERR_STREAM_SHUT_WR) {
        return ngtcp2_conn_write_pkt(conn_.value, &path.path, &info,
            output, max_udp_payload, ts);
    }
    return count;
}

// Flush a retained suffix first, then generate a bounded batch. Socket pressure
// preserves the encrypted packet and path for the next writable notification.
size_t connection::transmit(int fd, timestamp ts) {
    if (!send_pending(fd)) return 0;

    std::array<output_packet, packet_batch_limit> batch;
    std::array<output_packet*, packet_batch_limit> packets;
    size_t count = 0;
    while (count < packet_batch_limit) {
        auto& packet = batch[count];
        ngtcp2_path_storage path;
        ngtcp2_path_storage_zero(&path);
        ngtcp2_pkt_info info {};
        ngtcp2_ssize size = 0;
        if (send_close_) {
            size = ngtcp2_conn_write_connection_close(conn_.value, &path.path, &info,
                packet.bytes.data(), packet.bytes.size(), &close_error_, ts);
            send_close_ = false;
        } else if (closed_) {
            break;
        } else {
            size = write_stream_packet(path, packet.bytes.data(), info, ts);
        }
        if (size < 0) {
            ++stats.errors.connection_transmit_transmit;
            fail(size, "transmit");
            break;
        }
        if (!size) break;
        packet.size = size;
        packet.local.size = path.path.local.addrlen;
        packet.remote.size = path.path.remote.addrlen;
        std::memcpy(&packet.local.address, path.path.local.addr, packet.local.size);
        std::memcpy(&packet.remote.address, path.path.remote.addr, packet.remote.size);
        packets[count++] = &packet;
    }
    if (count) {
        auto sent = send_packets(fd, packets.data(), count);
        for (size_t i = sent; i < count; ++i) pending_output_.push_back(std::move(batch[i]));
        ngtcp2_conn_update_pkt_tx_time(conn_.value, ts);
    }
    if (count == packet_batch_limit) progress_ = true;
    return count;
}

} // namespace sx::quic::ng
