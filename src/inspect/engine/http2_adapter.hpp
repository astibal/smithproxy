#ifndef SX_ENGINE_HTTP2_ADAPTER_HPP
#define SX_ENGINE_HTTP2_ADAPTER_HPP

namespace sx::engine {
class ProtocolAdapter;

namespace http::v2 {

// Process-lifetime adapter. Its implementation and H2 state stay protocol-local.
ProtocolAdapter const& protocol_adapter();

} // namespace http::v2
} // namespace sx::engine

#endif
