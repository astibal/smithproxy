#include "archive.hpp"

#include <microhttpd.h>

#include <service/cfgapi/cfgapi.hpp>
#include <service/httpd/httpd.hpp>
#include <utils/crypto.hpp>

namespace sx::webserver {
namespace {

template<class Reader>
Http_JsonResponseParams download(Reader&& reader, std::string filename) {
    Http_JsonResponseParams response;
    try {
        response.response_code = MHD_HTTP_OK;
        response.binary = reader();
        response.content_type = "application/vnd.smithproxy.cftar";
        response.headers.emplace_back(
            "Content-Disposition", "attachment; filename=\"" + filename + "\"");
    }
    catch (const std::exception& error) {
        response.response_code = MHD_HTTP_CONFLICT;
        response.response = {
            {"state", "error"},
            {"error", {
                {"code", "native_archive_unavailable"},
                {"detail", error.what()},
            }},
        };
        response.content_type = "application/json";
    }
    return response;
}

}  // namespace

Http_JsonResponseParams cfg_archive_download(
    [[maybe_unused]] MHD_Connection* connection,
    [[maybe_unused]] std::string const& method,
    [[maybe_unused]] std::string const& request) {
    return download(
        [] { return CfgFactory::get()->archive_payload(); },
        "smithproxy.cftar");
}

Http_JsonResponseParams cfg_archive_previous_download(
    [[maybe_unused]] MHD_Connection* connection,
    [[maybe_unused]] std::string const& method,
    [[maybe_unused]] std::string const& request) {
    return download(
        [] { return CfgFactory::get()->previous_archive_payload(); },
        "smithproxy.previous.cftar");
}

Http_JsonResponseParams cfg_archive_validate(
    [[maybe_unused]] MHD_Connection* connection,
    [[maybe_unused]] std::string const& method,
    std::string const& request) {
    Http_JsonResponseParams response;
    try {
        const auto info = sx::cfg::CfgSource::inspect_archive(request);
        const auto hash = sx::crypto::sha256(request);
        if (!hash) throw sx::cfg::CfgTarError("cannot hash configuration archive");

        nlohmann::json entries = nlohmann::json::array();
        for (const auto& entry : info.entries) {
            entries.push_back({
                {"path", entry.path},
                {"size", entry.size},
                {"executable", entry.executable},
            });
        }
        response.response_code = MHD_HTTP_OK;
        response.response = {
            {"state", "valid"},
            {"content_hash", "sha256:" + *hash},
            {"archive_size", request.size()},
            {"payload_size", info.payload_size},
            {"format_version", info.format_version},
            {"entries", std::move(entries)},
        };
    }
    catch (const std::exception& error) {
        response.response_code = MHD_HTTP_UNPROCESSABLE_ENTITY;
        response.response = {
            {"state", "invalid"},
            {"error", {
                {"code", "invalid_archive"},
                {"detail", error.what()},
            }},
        };
    }
    response.content_type = "application/json";
    return response;
}

}  // namespace sx::webserver
