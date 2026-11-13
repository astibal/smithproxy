#ifndef SX_HTTP3_ADAPTER_HPP
#define SX_HTTP3_ADAPTER_HPP

#include <inspect/protocol_adapter.hpp>
#include <nlohmann/json.hpp>
#include <inspect/protocol_views.hpp>

namespace sx::engine::http::v3 {
ProtocolAdapter const& protocol_adapter();
// Fixed ASCII keys; invalid UTF-8 values become tagged, lossless base64 objects.
void encode_metadata_bytes(nlohmann::json& value);
nlohmann::json diagnostics(ProtocolViews const& views, std::uint64_t stream_id);
nlohmann::json metadata(EngineCtx const& ctx, std::uint64_t stream_id, ProtocolEndpoint sender);
} // namespace sx::engine::http::v3
#endif
