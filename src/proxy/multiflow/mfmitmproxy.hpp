#ifndef SMITHPROXY_MFMITMPROXY_HPP
#define SMITHPROXY_MFMITMPROXY_HPP

#include "proxy/multiflow/mfproxy.hpp"
#include "service/quic/quicservice.hpp"

namespace sx::multiflow {

/**
 * Build the production MultiFlow bridge used by the QUIC listener.
 *
 * Unlike the direct MFProxy test bridge, this implementation represents every
 * logical stream by its own ordinary MitmProxy child. The physical QUIC
 * connection remains shared; only stream state, policy, inspection, accounting,
 * and session lifetime are split.
 */
std::unique_ptr<flow_proxy> make_mitm_flow_proxy(
    std::shared_ptr<connection> downstream,
    std::shared_ptr<connection> upstream,
    proxy_limits limits,
    quic::flow_proxy_context context);

} // namespace sx::multiflow

#endif // SMITHPROXY_MFMITMPROXY_HPP
