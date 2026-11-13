#ifndef SX_HTTP_DIAGNOSTICS_HPP
#define SX_HTTP_DIAGNOSTICS_HPP

#include <inspect/protocol_views.hpp>
#include <nlohmann/json.hpp>

namespace sx::engine::http {

// Owner-thread snapshot of retained metadata only. Never selects a stream,
// advances an inspector, or retains additional traffic for diagnostics.
nlohmann::json diagnostics(ProtocolViews const& views,
                           std::optional<ProtocolStream> stream = std::nullopt);

} // namespace sx::engine::http
#endif
