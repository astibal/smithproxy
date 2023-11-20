
#pragma once

#include <nlohmann/json.hpp>

struct ObjAPI {
    nlohmann::json proxy_session_list_json(uint64_t oid, bool active_only, bool tls_info, bool verbose);
};