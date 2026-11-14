#pragma once

#include <nlohmann/json.hpp>

#include <sslcom.hpp>

namespace sx::capture {

[[nodiscard]] nlohmann::json tls_leg(SSLCom const& com, bool include_verify);
[[nodiscard]] nlohmann::json tls_payload(nlohmann::json identity,
                                         std::string transport,
                                         nlohmann::json left,
                                         nlohmann::json right);

} // namespace sx::capture
