#pragma once

// ngtcp2 transport for the shared QUIC service. TLS verification and certificate
// selection are configured by the same service callbacks as the OpenSSL backend.
#include "proxy/quic/openssl.hpp"
#include <ngtcp2/ngtcp2.h>
#include <ngtcp2/ngtcp2_crypto.h>
#include <ngtcp2/ngtcp2_crypto_ossl.h>
#include <array>
#include <deque>
#include <functional>
#include <map>

namespace sx::quic::ng {

using timestamp = ngtcp2_tstamp;
// Shared scheduling budget keeps either leg from monopolizing a worker pass.
inline constexpr size_t packet_batch_limit = 64;
timestamp now();
using cid_router = std::function<void(ngtcp2_cid const&, bool)>;

/** One A or B connection; stream bytes pass through the existing MFProxy. */
class connection final : public transport_connection {
public:
    connection(SSL_CTX* tls, bool server, datagram_endpoint local,
               datagram_endpoint remote, ngtcp2_pkt_hd const* initial,
               cid_router route, timestamp started,
               std::function<bool(SSL*)> configure, datagram_observer observer,
               std::function<void()> activate);
    ~connection() override;
    connection(connection const&) = delete;
    connection& operator=(connection const&) = delete;

    /** Process a complete datagram, preserving its actual local/remote tuple. */
    void receive(datagram_packet const& packet, timestamp ts);
    /** Expire due protocol timers; deadline() supplies the next absolute expiry. */
    void expire(timestamp ts);
    timestamp deadline() const;
    /** Produce bounded output; EAGAIN retains the exact encrypted packet. */
    size_t transmit(int fd, timestamp ts);
    bool send_blocked() const { return pending_size_ != 0; }
    bool established() const;
    bool ended() const { return closed_; }
    ngtcp2_conn* native() const { return conn_; }
    SSL* native_handle() const override { return ssl_; }
    datagram_endpoint peer_endpoint() const override { return remote_; }
    bool handshake_complete() const override { return established(); }
    bool closed() const override { return closed_; }
    std::string server_name() const override;
    std::string negotiated_alpn() const override;
    std::shared_ptr<keylog_store> keylog() const override { return keylog_; }
    void progress_transport() override;
    bool take_application_progress() override { return std::exchange(progress_, false); }
    /** TLS secrets belong to this downstream connection's existing capture journal. */
    static void record_keylog(SSL const*, char const*);

    multiflow::flow_handle open_flow(multiflow::direction direction) override;
    bool contains(multiflow::flow_handle flow) const override;
    std::optional<multiflow::direction> direction_of(multiflow::flow_handle flow) const override;
    multiflow::outer_transport policy_transport() const override { return multiflow::outer_transport::udp; }
    multiflow::io_result read(multiflow::flow_handle flow, void* destination, size_t size) override;
    multiflow::io_result write(multiflow::flow_handle flow, void const* source, size_t size) override;
    multiflow::io_status finish(multiflow::flow_handle flow) override;
    multiflow::io_status reset(multiflow::flow_handle flow, uint64_t error) override;
    void close(uint64_t error = 0) override;
    bool readable(multiflow::flow_handle flow) const override;
    bool writable(multiflow::flow_handle flow) const override;
    std::vector<multiflow::event> drain_events() override;

private:
    // RX uses used as a read cursor; TX uses it as a submission cursor. TX
    // storage remains immutable and alive until the acknowledged range covers it.
    struct chunk {
        std::vector<unsigned char> bytes;
        uint64_t offset = 0;
        size_t used = 0;
    };
    struct stream {
        multiflow::direction direction;
        std::deque<chunk> rx;
        std::deque<chunk> tx;
        // Fully submitted chunks stay alive for retransmission until ACK. Keep
        // their count, not an iterator: deque append may invalidate iterators.
        size_t tx_submitted = 0;
        uint64_t received = 0;
        uint64_t queued = 0;
        uint64_t acknowledged = 0;
        bool peer_fin = false;
        bool fin_notified = false;
        bool fin_requested = false;
        bool fin_submitted = false;
        bool tx_closed = false;
        bool reset = false;
    };
    // A borrowed view valid during one packet submission; queues own the storage.
    struct transmit_selection {
        int64_t id = -1;
        stream* state = nullptr;
        chunk* data = nullptr;
    };
    static constexpr size_t max_udp_payload = 1350;
    static constexpr size_t stream_buffer_limit = 1024 * 1024;
    void initialize_tls(SSL_CTX* tls, std::function<bool(SSL*)> const& configure);
    transmit_selection select_transmit_stream();
    ngtcp2_ssize write_stream_packet(ngtcp2_pkt_info& info, timestamp ts);
    stream& ensure_stream(int64_t id, bool incoming);
    void notify_fin(int64_t id, stream& value);
    void fail(int error, char const* operation);
    bool send_pending(int fd);
    static ngtcp2_callbacks callbacks(bool server);

    // Callbacks only change worker-owned state. Transport calls never re-enter
    // either connection from a callback or invoke the application bridge.
    static int recv_crypto(ngtcp2_conn*, ngtcp2_encryption_level, uint64_t, uint8_t const*, size_t, void*);
    static int recv_stream(ngtcp2_conn*, uint32_t, int64_t, uint64_t,
                           uint8_t const*, size_t, void*, void*);
    static int ack_stream(ngtcp2_conn*, int64_t, uint64_t, uint64_t, void*, void*);
    static int opened_stream(ngtcp2_conn*, int64_t, void*);
    static int closed_stream(ngtcp2_conn*, uint32_t, int64_t, uint64_t, void*, void*);
    static int reset_stream(ngtcp2_conn*, int64_t, uint64_t, uint64_t, void*, void*);
    static int new_cid(ngtcp2_conn*, ngtcp2_cid*, uint8_t*, size_t, void*);
    static int remove_cid(ngtcp2_conn*, ngtcp2_cid const*, void*);

    bool progress_ = true;
    bool tls_paused_ = false;
    bool server_;
    bool closed_ = false;
    bool send_close_ = false;
    ngtcp2_ccerr close_error_ {};
    datagram_endpoint local_, remote_;
    cid_router route_;
    datagram_observer observer_;
    std::function<void()> activate_;
    std::shared_ptr<keylog_store> keylog_;
    ngtcp2_conn* conn_ = nullptr;
    SSL* ssl_ = nullptr;
    ngtcp2_crypto_ossl_ctx* crypto_ = nullptr;
    ngtcp2_crypto_conn_ref reference_ {};
    std::map<int64_t, stream> streams_;
    std::vector<multiflow::event> events_;
    int64_t next_tx_ = 0;
    std::array<unsigned char, 1500> pending_ {};
    size_t pending_size_ = 0;
    ngtcp2_path_storage pending_path_ {};
};

} // namespace sx::quic::ng
