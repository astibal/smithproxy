#pragma once

#include "pap.hpp"

namespace sx::auth {

// Backend policy belongs to the daemon. A future LDAP or RADIUS backend can
// implement PapBackend without being linked into the proxy process.
class LinuxPamBackend final : public PapBackend {
public:
    LinuxPamBackend(std::string service, std::string allowed_group, std::string config_directory = {});
    std::optional<PapResult> verify_pap(
        PapCredentials credentials, completion_type completion) override;

private:
    std::string service_;
    std::string allowed_group_;
    std::string config_directory_;
};

} // namespace sx::auth
