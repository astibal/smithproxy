#pragma once

#include <nlohmann/json.hpp>
#include <openssl/x509.h>

namespace jsonize {

// Legacy diagnostics schema and verbosity remain unchanged.
[[nodiscard]] nlohmann::json from(X509 const* certificate, int verbosity);
// Structured public certificate metadata; no DER, PEM or private key material.
[[nodiscard]] nlohmann::json certificate_summary(X509 const* certificate);

} // namespace jsonize
