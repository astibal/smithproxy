
#pragma once

#include <nlohmann/json.hpp>

class MitmMproxy;
struct ObjAPI {
    void for_each_proxy(std::function<void(MitmProxy*)> callable);

    std::string instance_OID();
    nlohmann::json proxy_session_connid_list();
    nlohmann::json proxy_session_connid_list_plus(); // list, but append also session label
    nlohmann::json proxy_session_list_json(uint64_t oid, bool active_only, bool tls_info, bool verbose);

    nlohmann::json neighbor_list(bool flag_raw, unsigned  int last_n_days);
    nlohmann::json neighbor_update(std::string const& request);
};

