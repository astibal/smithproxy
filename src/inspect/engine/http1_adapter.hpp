#ifndef SX_ENGINE_HTTP1_ADAPTER_HPP
#define SX_ENGINE_HTTP1_ADAPTER_HPP

namespace sx::engine {
class ProtocolAdapter;

namespace http::v1 {

// Reuse the native H1 framing state for independent endpoint observations.
ProtocolAdapter const& protocol_adapter();

} // namespace http::v1
} // namespace sx::engine

#endif
