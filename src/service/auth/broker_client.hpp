#pragma once

#include "pap.hpp"

namespace sx::auth {

// This transport has a bounded synchronous deadline. The PAP interface also
// admits future asynchronous clients without adding backend libraries here.
class BrokerPapBackend final : public PapBackend {
public:
    explicit BrokerPapBackend(std::string socket_path, long timeout_ms = 1500);
    std::optional<Result> verify_pap(
        PapCredentials credentials, completion_type completion) override;

private:
    std::string socket_path_;
    long timeout_ms_;
};

// Set once at startup, before proxy workers are created. No local backend or
// credentials database exists in the Smithproxy process.
void configure_proxy_auth(std::string socket_path);
Result verify_proxy_credentials(std::string_view username, std::string_view password);
std::optional<PapCredentials> http_basic_credentials(std::string_view headers);

} // namespace sx::auth
