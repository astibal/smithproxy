#ifndef SMITHPROXY_TRAFFICCAPTURE_HPP
#define SMITHPROXY_TRAFFICCAPTURE_HPP

#include <memory>

#include <traflog/basetraflog.hpp>

namespace sx {

/**
 * Optional per-session transformation applied to a configured traffic logger.
 *
 * The proxy core owns logger creation and capture policy. Protocol adapters may
 * decorate a compatible logger without exposing transport-specific state to
 * MitmProxy, baseCom, or the packet-capture implementation.
 */
class traffic_log_adapter {
public:
    virtual ~traffic_log_adapter() = default;

    virtual std::unique_ptr<socle::baseTrafficLogger> wrap(
        std::unique_ptr<socle::baseTrafficLogger> output) = 0;
};

} // namespace sx

#endif // SMITHPROXY_TRAFFICCAPTURE_HPP
