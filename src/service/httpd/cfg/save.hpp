#pragma once

#include <string>

#include <nlohmann/json.hpp>

#include <service/cfgapi/cfg_tx.hpp>

struct MHD_Connection;

namespace sx::webserver::cfg_save_api {

struct Request {
    std::string expected_revision;
};

sx::cfg::tx::Result<Request> decode_request(nlohmann::json const& body);

}  // namespace sx::webserver::cfg_save_api

namespace sx::webserver {

struct Http_JsonResponseParams;

Http_JsonResponseParams cfg_save(
    MHD_Connection* connection, std::string const& method, std::string const& request);

}  // namespace sx::webserver
