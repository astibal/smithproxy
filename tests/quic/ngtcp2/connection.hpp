#pragma once

// Laboratory transport adapter. The benchmark owns all connections on one
// worker and deliberately uses fixed credentials without upstream verification.
#include "proxy/quic/openssl.hpp"
#include <ngtcp2/ngtcp2.h>
#include <ngtcp2/ngtcp2_crypto.h>
#include <ngtcp2/ngtcp2_crypto_ossl.h>
#include <array>
#include <deque>
#include <functional>
#include <map>

namespace sx::quic::experiment {

using timestamp = ngtcp2_tstamp;
timestamp now();
using cid_router = std::function<void(ngtcp2_cid const&, bool)>;

/** One A or B connection; stream bytes pass through the existing MFProxy. */
class connection final : public multiflow::connection {
public:
    connection(SSL_CTX* tls, bool server, datagram_endpoint local,
               datagram_endpoint remote, ngtcp2_pkt_hd const* initial,
               cid_router route, timestamp started);
    ~connection() override;
    connection(connection const&) = delete;
    connection& operator=(connection const&) = delete;

    /** Process a complete datagram, preserving its actual local/remote tuple. */
    void receive(datagram_packet const& packet, timestamp ts);
    /** Expire due protocol timers and return the next absolute deadline. */
    void expire(timestamp ts);
    timestamp deadline() const;
    /** Produce bounded output; EAGAIN retains the exact encrypted packet. */
    size_t transmit(int fd, timestamp ts);
    bool send_blocked() const { return pending_size_ != 0; }
    bool established() const;
    bool ended() const { return closed_; }
    ngtcp2_conn* native() const { return conn_; }

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
    struct chunk {
        std::vector<unsigned char> bytes;
        uint64_t offset = 0;
        size_t used = 0;
    };
    struct stream {
        multiflow::direction direction;
        std::deque<chunk> rx, tx;
        uint64_t received = 0, queued = 0, acknowledged = 0;
        bool peer_fin = false, fin_notified = false;
        bool fin_requested = false, fin_submitted = false, tx_closed = false, reset = false;
    };
    static constexpr size_t stream_buffer_limit = 1024 * 1024;
    stream& ensure_stream(int64_t id, bool incoming);
    void notify_fin(int64_t id, stream& value);
    void fail(int error, char const* operation);
    bool send_pending(int fd);
    static ngtcp2_callbacks callbacks(bool server);

    // Callbacks only change worker-owned state. Transport calls never re-enter
    // either connection from a callback or invoke the application bridge.
    static int recv_stream(ngtcp2_conn*, uint32_t, int64_t, uint64_t,
                           uint8_t const*, size_t, void*, void*);
    static int ack_stream(ngtcp2_conn*, int64_t, uint64_t, uint64_t, void*, void*);
    static int opened_stream(ngtcp2_conn*, int64_t, void*);
    static int closed_stream(ngtcp2_conn*, uint32_t, int64_t, uint64_t, void*, void*);
    static int reset_stream(ngtcp2_conn*, int64_t, uint64_t, uint64_t, void*, void*);
    static int new_cid(ngtcp2_conn*, ngtcp2_cid*, uint8_t*, size_t, void*);
    static int remove_cid(ngtcp2_conn*, ngtcp2_cid const*, void*);

    bool server_, closed_ = false, send_close_ = false;
    uint64_t close_error_ = 0;
    datagram_endpoint local_, remote_;
    cid_router route_;
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

} // namespace sx::quic::experiment
