/*
 * Exclusive stream ownership for protocol-specific proxy handlers.
 */

#ifndef SMITHPROXY_STREAMHANDLER_HPP
#define SMITHPROXY_STREAMHANDLER_HPP

#include <cstdint>
#include <functional>
#include <string>
#include <string_view>

class MitmProxy;

namespace sx {

enum class stream_direction { upstream, downstream };

class StreamHandler {
public:
    using plaintext_observer = std::function<void(stream_direction, std::string_view)>;
    using event_observer = std::function<void(stream_direction, std::string_view)>;

    enum class result {
        progress,
        wait,
        finished,
        blocked,
        failed,
    };

    virtual ~StreamHandler() = default;

    // Called exactly once after MitmProxy has tapped its host contexts.
    // Implementations may retain a non-owning pointer to proxy; the proxy
    // always owns and outlives its handler.
    virtual bool attach(MitmProxy& proxy) = 0;
    virtual result drive() = 0;
    virtual void shutdown() noexcept = 0;
    // Reports application bytes after protocol decoding, before re-encoding.
    virtual void observe_plaintext(plaintext_observer observer) = 0;
    virtual void observe_events(event_observer observer) = 0;

    // A committed handler owns the stream until close. Raw forwarding must
    // never be restored after this becomes true.
    [[nodiscard]] virtual bool committed() const noexcept = 0;
    // Protocol name used by session-list presentation. The underlying
    // communication object may still correctly be a TCP socket.
    [[nodiscard]] virtual std::string_view session_protocol() const noexcept = 0;
    [[nodiscard]] virtual std::uint64_t bytes_up() const noexcept { return 0; }
    [[nodiscard]] virtual std::uint64_t bytes_down() const noexcept { return 0; }
    [[nodiscard]] virtual std::string state() const = 0;
    [[nodiscard]] virtual std::string error() const = 0;
    // Protocol-specific, human-readable session details for diagnostics.
    [[nodiscard]] virtual std::string diagnostics() const { return {}; }
};

inline std::string session_protocol_names(std::string text, std::string_view protocol) {
    if (protocol.empty()) return text;

    for (auto const transport : {std::string_view{"tcp_"}, std::string_view{"ssli_"}}) {
        std::size_t pos = 0;
        while ((pos = text.find(transport, pos)) != std::string::npos) {
            const bool endpoint_boundary = pos == 0 || text[pos - 1] == ':'
                                           || text[pos - 1] == '<'
                                           || text[pos - 1] == '+' || text[pos - 1] == ' ';
            if (endpoint_boundary) {
                text.replace(pos, transport.size(), protocol);
                text.insert(pos + protocol.size(), 1, '_');
                pos += protocol.size() + 1;
            } else {
                pos += transport.size();
            }
        }
    }
    return text;
}

} // namespace sx

#endif
