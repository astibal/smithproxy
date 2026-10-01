/*
 * Exclusive stream ownership for protocol-specific proxy handlers.
 */

#ifndef SMITHPROXY_STREAMHANDLER_HPP
#define SMITHPROXY_STREAMHANDLER_HPP

#include <string>

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
    [[nodiscard]] virtual std::string state() const = 0;
    [[nodiscard]] virtual std::string error() const = 0;
};

} // namespace sx

#endif
