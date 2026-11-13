#ifndef SX_PROTOCOL_INPUT_HPP
#define SX_PROTOCOL_INPUT_HPP

#include <buffer.hpp>
#include <tuple>
#include <cstdint>
#include <optional>

namespace sx::engine {

enum class ProtocolEndpoint { Client, Server };
enum class ProtocolEvent { Data, Fin, Reset, ConnectionClose };

// Session-local logical identity. The transport maps it to each leg's wire ID;
// both endpoint views must use the same key even when those wire IDs differ.
struct ProtocolStream {
    std::uint64_t id = 0;
    std::uint64_t generation = 0;
    bool operator<(ProtocolStream const& other) const {
        return std::tie(id, generation) < std::tie(other.id, other.generation);
    }
};

// A synchronous borrowed input, not a payload owner. Adapters retain their own
// copies of incomplete fragments. An empty buffer is valid for lifecycle events.
struct ProtocolInput {
    ProtocolEndpoint sender;
    buffer const& bytes;
    std::optional<ProtocolStream> stream = std::nullopt;
    ProtocolEvent event = ProtocolEvent::Data;
    std::optional<std::uint64_t> error_code = std::nullopt;
};

} // namespace sx::engine
#endif
