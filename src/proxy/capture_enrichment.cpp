#include <proxy/capture_enrichment.hpp>

namespace sx::capture {

nlohmann::json tls_payload(nlohmann::json identity, std::string transport,
                           nlohmann::json left, nlohmann::json right) {
    identity["schema"] = "smithproxy.tls.v1";
    identity["transport"] = std::move(transport);
    identity["L"] = std::move(left);
    identity["R"] = std::move(right);
    return identity;
}

} // namespace sx::capture
