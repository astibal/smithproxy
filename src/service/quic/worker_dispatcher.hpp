#ifndef SMITHPROXY_QUIC_WORKER_DISPATCHER_HPP
#define SMITHPROXY_QUIC_WORKER_DISPATCHER_HPP

#include "proxy/quic/openssl.hpp"

#if SMITHPROXY_OPENSSL_QUIC
#include <atomic>
#include <deque>
#include <memory>
#include <mutex>
#include <thread>
#include <vector>

namespace sx::quic {

/**
 * UDP receiver for one address family, following the receiver/worker split.
 * Only this thread reads the shared socket. It routes owned packets to bounded
 * inboxes; SSL, CID tables and session lifecycle remain entirely worker-owned.
 * A destination keeps its worker for this receiver's lifetime, including drain.
 */
class worker_dispatcher final {
public:
    explicit worker_dispatcher(std::size_t workers);
    ~worker_dispatcher();
    worker_dispatcher(worker_dispatcher const&) = delete;
    worker_dispatcher& operator=(worker_dispatcher const&) = delete;

    /** Borrow the prepared ingress socket; duplicate it when first attached. */
    bool attach_socket(int fd);
    int socket_fd() const { return socket_fd_; }
    std::size_t size() const { return inboxes_.size(); }
    /** Select by original destination IP, independent of ports and client IP. */
    std::size_t owner(datagram_endpoint const& destination) const;
    /** Start once after every worker has been prepared; safe from worker threads. */
    bool start();
    /** Stop receiving and join before destroying any inbox or socket. */
    void stop();
    /** Retire an owner without moving its traffic to another worker. */
    void retire(std::size_t worker);
    /** Level-triggered notification, readable while this inbox has packets. */
    int wake_fd(std::size_t worker) const;
    /** Move one packet out, clearing the wakeup only when the inbox is empty. */
    bool pop(std::size_t worker, datagram_packet& packet);
    /** Move at most capacity packets under one lock, then process outside it. */
    std::size_t pop_batch(std::size_t worker, datagram_packet* packets, std::size_t capacity);
    /** Route one packet; false records overload or an already retired owner. */
    bool enqueue(datagram_packet packet);
    /** Route at most datagram_batch_limit packets, locking each owner once.
     * Returns accepted packets; rejected packets increment that owner's drops.
     */
    std::size_t enqueue_batch(datagram_packet* packets, std::size_t count);
    std::uint64_t dropped(std::size_t worker) const;
    int error() const { return error_.load(); }

private:
    struct inbox;
    /** Poll ingress and drain bounded batches; never call OpenSSL here. */
    void run();
    /** Publish fatal receive errors and wake every worker to leave its poll. */
    void fail(int error);

    std::vector<std::unique_ptr<inbox>> inboxes_;
    int socket_fd_ = -1;
    int stop_fd_ = -1;
    std::mutex lifecycle_lock_;
    std::thread thread_;
    std::atomic_bool stopping_ {false};
    std::atomic_int error_ {0};
    std::atomic_size_t retired_ {0};
};

} // namespace sx::quic
#endif
#endif
