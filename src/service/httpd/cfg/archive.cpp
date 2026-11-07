#include "archive.hpp"

#include <microhttpd.h>

#include <service/cfgapi/cfgapi.hpp>
#include <service/httpd/httpd.hpp>

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

}  // namespace sx::webserver
