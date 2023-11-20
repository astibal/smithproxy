
#pragma once

#include <nlohmann/json.hpp>

class MitmMproxy;
struct ObjAPI {
    void for_each_proxy(std::function<void(MitmProxy*)> callable);

    std::string instance_OID();
    nlohmann::json proxy_session_connid_list();
    nlohmann::json proxy_session_list_json(uint64_t oid, bool active_only, bool tls_info, bool verbose);
};

