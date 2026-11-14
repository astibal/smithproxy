#pragma once

#include <nlohmann/json.hpp>
#include <openssl/x509.h>

#include <sslcom.hpp>

namespace sx::capture {

[[nodiscard]] nlohmann::json peer_certificate(X509 const* certificate);
[[nodiscard]] nlohmann::json tls_leg(SSLCom const& com, bool include_verify);
[[nodiscard]] nlohmann::json tls_payload(nlohmann::json identity,
                                         std::string transport,
                                         nlohmann::json left,
                                         nlohmann::json right);

} // namespace sx::capture
