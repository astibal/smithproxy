#ifndef SX_HTTP3_RESPONSE_HPP
#define SX_HTTP3_RESPONSE_HPP

#include <buffer.hpp>
#include <optional>
#include <string_view>

namespace sx::engine::http::v3 {

// A local response uses only literal/static QPACK fields. It does not change
// the peer's dynamic table or require a QPACK encoder stream.
std::optional<buffer> make_response(std::string_view body, unsigned status = 403,
                                    bool head_only = false);

} // namespace sx::engine::http::v3
#endif
