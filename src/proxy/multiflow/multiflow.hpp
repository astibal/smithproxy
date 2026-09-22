#ifndef SMITHPROXY_MULTIFLOW_HPP
#define SMITHPROXY_MULTIFLOW_HPP

#include <cstddef>
#include <cstdint>
#include <memory>
#include <optional>
#include <vector>

namespace sx::multiflow {

using flow_id = std::uint64_t;
using generation_id = std::uint64_t;

enum class direction {
    bidirectional,
    send_only,
    receive_only,
};

enum class event_type {
    flow_open,
    readable,
    writable,
    peer_fin,
    reset,
    connection_close,
};

enum class io_status {
    ok,
    would_block,
    eof,
    reset,
    connection_closed,
    invalid_handle,
};

struct flow_handle {
    flow_id id = 0;
    generation_id generation = 0;

    friend bool operator==(flow_handle const& lhs, flow_handle const& rhs) {
        return lhs.id == rhs.id && lhs.generation == rhs.generation;
    }
};

struct event {
    event_type type;
    std::optional<flow_handle> flow;
    std::uint64_t protocol_error = 0;
};

struct io_result {
    std::size_t size = 0;
    io_status status = io_status::ok;
};

/**
 * One multiplexed connection.
 *
 * The connection owns its flow state. A flow_handle is deliberately a value,
 * not an owning pointer: users must tolerate a handle becoming invalid after a
 * reset or connection close.
 */
class connection {
public:
    virtual ~connection() = default;

    virtual flow_handle open_flow(direction flow_direction) = 0;
    virtual bool contains(flow_handle flow) const = 0;
    virtual std::optional<direction> direction_of(flow_handle flow) const = 0;

    virtual io_result read(flow_handle flow, void* destination, std::size_t size) = 0;
    virtual io_result write(flow_handle flow, const void* source, std::size_t size) = 0;

    virtual io_status finish(flow_handle flow) = 0;
    virtual io_status reset(flow_handle flow, std::uint64_t protocol_error) = 0;
    virtual void close(std::uint64_t protocol_error = 0) = 0;

    virtual bool readable(flow_handle flow) const = 0;
    virtual bool writable(flow_handle flow) const = 0;

    /** Drain currently pending, de-duplicated readiness/lifecycle events. */
    virtual std::vector<event> drain_events() = 0;
};

using connection_ptr = std::shared_ptr<connection>;

} // namespace sx::multiflow

#endif // SMITHPROXY_MULTIFLOW_HPP
