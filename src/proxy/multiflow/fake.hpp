#ifndef SMITHPROXY_MULTIFLOW_FAKE_HPP
#define SMITHPROXY_MULTIFLOW_FAKE_HPP

#include <algorithm>
#include <cstring>
#include <deque>
#include <limits>
#include <map>
#include <set>
#include <utility>

#include "proxy/multiflow/multiflow.hpp"

namespace sx::multiflow {

/**
 * Deterministic, in-memory implementation used to prove multiflow lifetime and
 * backpressure semantics independently of a network or QUIC library. Production
 * code does not use this class; tests drive its peer-facing helper methods to
 * reproduce FIN, reset, and blocked-write transitions exactly.
 */
class fake_connection final : public connection {
public:
    explicit fake_connection(std::size_t send_high_watermark = 64 * 1024)
        : send_high_watermark_(send_high_watermark) {}

    flow_handle open_flow(direction flow_direction) override {
        flow_handle handle { next_flow_id_, next_generation_++ };
        next_flow_id_ += 4;

        flows_.emplace(handle.id, flow_state { handle, flow_direction });
        emit(event_type::flow_open, handle);
        emit(event_type::writable, handle);
        return handle;
    }

    bool contains(flow_handle handle) const override {
        return find(handle) != nullptr;
    }

    std::optional<direction> direction_of(flow_handle handle) const override {
        auto const* flow = find(handle);
        return flow ? std::optional<direction>(flow->flow_direction) : std::nullopt;
    }

    io_result read(flow_handle handle, void* destination, std::size_t size) override {
        if (closed_) return { 0, io_status::connection_closed };
        auto* flow = find(handle);
        if (!flow) return { 0, io_status::invalid_handle };
        if (flow->reset) return { 0, io_status::reset };

        auto const copied = std::min(size, flow->receive.size());
        auto* output = static_cast<unsigned char*>(destination);
        for (std::size_t i = 0; i < copied; ++i) {
            output[i] = flow->receive.front();
            flow->receive.pop_front();
        }

        if (!flow->receive.empty()) emit(event_type::readable, handle);
        if (copied != 0) return { copied, io_status::ok };
        if (flow->peer_finished) return { 0, io_status::eof };
        return { 0, io_status::would_block };
    }

    io_result write(flow_handle handle, const void* source, std::size_t size) override {
        if (closed_) return { 0, io_status::connection_closed };
        auto* flow = find(handle);
        if (!flow) return { 0, io_status::invalid_handle };
        if (flow->reset) return { 0, io_status::reset };
        if (flow->local_finished || flow->flow_direction == direction::receive_only) {
            return { 0, io_status::eof };
        }

        auto const available = send_high_watermark_ - std::min(send_high_watermark_, flow->send.size());
        auto const copied = std::min(size, available);
        auto const* input = static_cast<unsigned char const*>(source);
        flow->send.insert(flow->send.end(), input, input + copied);

        if (flow->send.size() < send_high_watermark_) emit(event_type::writable, handle);
        return { copied, copied == size ? io_status::ok : io_status::would_block };
    }

    io_status finish(flow_handle handle) override {
        auto* flow = find(handle);
        if (!flow) return closed_ ? io_status::connection_closed : io_status::invalid_handle;
        if (flow->reset) return io_status::reset;
        if (flow->finish_blocked) return io_status::would_block;
        flow->local_finished = true;
        return io_status::ok;
    }

    io_status reset(flow_handle handle, std::uint64_t protocol_error) override {
        auto* flow = find(handle);
        if (!flow) return closed_ ? io_status::connection_closed : io_status::invalid_handle;
        flow->reset = true;
        flow->protocol_error = protocol_error;
        emit(event_type::reset, handle, protocol_error);
        return io_status::ok;
    }

    void close(std::uint64_t protocol_error = 0) override {
        if (closed_) return;
        closed_ = true;
        connection_error_ = protocol_error;
        emit(event_type::connection_close, std::nullopt, protocol_error);
    }

    bool readable(flow_handle handle) const override {
        auto const* flow = find(handle);
        return flow && (!flow->receive.empty() || flow->peer_finished || flow->reset);
    }

    bool writable(flow_handle handle) const override {
        auto const* flow = find(handle);
        return flow && !closed_ && !flow->reset && !flow->local_finished
            && flow->flow_direction != direction::receive_only
            && flow->send.size() < send_high_watermark_;
    }

    std::vector<event> drain_events() override {
        std::vector<event> result;
        result.reserve(events_.size());
        for (auto const& pending : events_) result.push_back(pending.second);
        events_.clear();
        return result;
    }

    /** Append bytes as if they had arrived from the remote endpoint. */
    io_status inject_receive(flow_handle handle, const void* source, std::size_t size) {
        auto* flow = find(handle);
        if (!flow) return closed_ ? io_status::connection_closed : io_status::invalid_handle;
        if (flow->reset) return io_status::reset;
        if (flow->flow_direction == direction::send_only) return io_status::eof;

        auto const* input = static_cast<unsigned char const*>(source);
        flow->receive.insert(flow->receive.end(), input, input + size);
        if (size != 0) emit(event_type::readable, handle);
        return io_status::ok;
    }

    /** Mark the peer's sending half complete and make EOF observable. */
    io_status inject_peer_fin(flow_handle handle) {
        auto* flow = find(handle);
        if (!flow) return closed_ ? io_status::connection_closed : io_status::invalid_handle;
        flow->peer_finished = true;
        emit(event_type::peer_fin, handle);
        emit(event_type::readable, handle);
        return io_status::ok;
    }

    /** Remove bytes queued by local writes, modelling transport transmission. */
    std::vector<unsigned char> consume_send(flow_handle handle,
                                            std::size_t limit = std::numeric_limits<std::size_t>::max()) {
        auto* flow = find(handle);
        if (!flow) return {};

        auto const was_writable = flow->send.size() < send_high_watermark_;
        auto const consumed = std::min(limit, flow->send.size());
        std::vector<unsigned char> result;
        result.reserve(consumed);
        for (std::size_t i = 0; i < consumed; ++i) {
            result.push_back(flow->send.front());
            flow->send.pop_front();
        }
        if (!was_writable && flow->send.size() < send_high_watermark_) {
            emit(event_type::writable, handle);
        }
        return result;
    }

    /** Return whether finish() concluded the local sending half. */
    bool local_finished(flow_handle handle) const {
        auto const* flow = find(handle);
        return flow && flow->local_finished;
    }

    /** Force finish() to report would_block for retry-path tests. */
    void block_finish(flow_handle handle, bool blocked) {
        if (auto* flow = find(handle)) flow->finish_blocked = blocked;
    }

    /** Return the application error recorded by reset(), if any. */
    std::optional<std::uint64_t> reset_code(flow_handle handle) const {
        auto const* flow = find(handle);
        return flow && flow->reset
            ? std::optional<std::uint64_t>(flow->protocol_error) : std::nullopt;
    }

private:
    /** Complete state of one simulated logical stream. */
    struct flow_state {
        flow_state(flow_handle flow, direction direction_value)
            : handle(flow), flow_direction(direction_value) {}

        flow_handle handle;
        direction flow_direction;
        std::deque<unsigned char> receive;
        std::deque<unsigned char> send;
        bool peer_finished = false;
        bool local_finished = false;
        bool finish_blocked = false;
        bool reset = false;
        std::uint64_t protocol_error = 0;
    };

    /** Key used to coalesce repeated readiness events until they are drained. */
    struct event_key {
        event_type type;
        flow_id id;

        friend bool operator<(event_key const& lhs, event_key const& rhs) {
            if (lhs.id != rhs.id) return lhs.id < rhs.id;
            return lhs.type < rhs.type;
        }
    };

    flow_state* find(flow_handle handle) {
        auto found = flows_.find(handle.id);
        if (found == flows_.end() || found->second.handle.generation != handle.generation) return nullptr;
        return &found->second;
    }

    flow_state const* find(flow_handle handle) const {
        auto found = flows_.find(handle.id);
        if (found == flows_.end() || found->second.handle.generation != handle.generation) return nullptr;
        return &found->second;
    }

    void emit(event_type type, std::optional<flow_handle> handle,
              std::uint64_t protocol_error = 0) {
        event_key key { type, handle ? handle->id : 0 };
        events_.emplace(key, event { type, handle, protocol_error });
    }

    std::map<flow_id, flow_state> flows_;       ///< Live simulated streams.
    std::map<event_key, event> events_;         ///< Pending de-duplicated events.
    std::size_t send_high_watermark_;           ///< Per-flow write-buffer limit.
    flow_id next_flow_id_ = 0;
    generation_id next_generation_ = 1;
    bool closed_ = false;                       ///< Connection-wide terminal state.
    std::uint64_t connection_error_ = 0;        ///< Last close application error.
};

} // namespace sx::multiflow

#endif // SMITHPROXY_MULTIFLOW_FAKE_HPP
