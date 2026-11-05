#pragma once

#include <string>

#include <nlohmann/json.hpp>

struct MHD_Connection;

namespace sx::webserver {

// Return configuration bytes and their revision identity from one protected
// read. A client can safely use revision as the base of a later transaction.
nlohmann::json cfg_state(MHD_Connection* connection,
                         std::string const& method,
                         std::string const& request);

}  // namespace sx::webserver
