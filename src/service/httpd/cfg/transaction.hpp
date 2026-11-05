#pragma once

#include <cstdint>
#include <string>
#include <vector>

#include <nlohmann/json.hpp>

#include <service/cfgapi/cfg_tx.hpp>

struct MHD_Connection;

namespace sx::webserver::cfg_tx_api {

sx::cfg::tx::Result<std::vector<sx::cfg::tx::Op>> decode_operations(
    nlohmann::json const& value);

}  // namespace sx::webserver::cfg_tx_api

namespace sx::webserver {

struct Http_JsonResponseParams;

Http_JsonResponseParams cfg_transaction_begin(
    MHD_Connection* connection, std::string const& method, std::string const& request);
Http_JsonResponseParams cfg_transaction_prepare(
    MHD_Connection* connection, std::string const& method, std::string const& request);
Http_JsonResponseParams cfg_transaction_commit(
    MHD_Connection* connection, std::string const& method, std::string const& request);
Http_JsonResponseParams cfg_transaction_abort(
    MHD_Connection* connection, std::string const& method, std::string const& request);

}  // namespace sx::webserver
