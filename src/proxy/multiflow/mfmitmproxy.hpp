#ifndef SMITHPROXY_MFMITMPROXY_HPP
#define SMITHPROXY_MFMITMPROXY_HPP

#include "proxy/multiflow/mfproxy.hpp"
#include "proxy/trafficcapture.hpp"

#include <functional>
#include <string>
#include <sys/socket.h>

namespace sx::multiflow {

/** Endpoint and extension hooks used to construct one proxy per logical flow. */
struct flow_proxy_context {
    std::string source_host;
    std::string source_port;
    std::string target_host;
    std::string target_port;
    int address_family = AF_INET;
    /** Create an optional capture adapter for a downstream-visible flow ID. */
    std::function<std::unique_ptr<sx::traffic_log_adapter>(flow_id)>
        make_traffic_log_adapter;
};

/**
 * Build the production bridge used by multiplexed transports.
 *
 * Unlike the direct MFProxy test bridge, this implementation represents every
 * logical flow by its own ordinary MitmProxy child. The physical connection
 * remains shared; only flow state, policy, inspection, accounting,
 * and session lifetime are split.
 */
std::unique_ptr<flow_proxy> make_mitm_flow_proxy(
    std::shared_ptr<connection> downstream,
    std::shared_ptr<connection> upstream,
    proxy_limits limits,
    flow_proxy_context context);

} // namespace sx::multiflow

#endif // SMITHPROXY_MFMITMPROXY_HPP
