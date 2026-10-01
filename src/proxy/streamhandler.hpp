/*
 * Exclusive stream ownership for protocol-specific proxy handlers.
 */

#ifndef SMITHPROXY_STREAMHANDLER_HPP
#define SMITHPROXY_STREAMHANDLER_HPP

#include <string>
#include <string_view>

class MitmProxy;

namespace sx {

class StreamHandler {
public:
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

    // A committed handler owns the stream until close. Raw forwarding must
    // never be restored after this becomes true.
    [[nodiscard]] virtual bool committed() const noexcept = 0;
    // Protocol name used by session-list presentation. The underlying
    // communication object may still correctly be a TCP socket.
    [[nodiscard]] virtual std::string_view session_protocol() const noexcept = 0;
    [[nodiscard]] virtual std::string state() const = 0;
    [[nodiscard]] virtual std::string error() const = 0;
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
