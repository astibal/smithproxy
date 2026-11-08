#include "archive.hpp"

#include <microhttpd.h>

#include <service/cfgapi/cfgapi.hpp>
#include <service/httpd/httpd.hpp>
#include <utils/crypto.hpp>

namespace sx::webserver {
namespace {

const char* header(MHD_Connection* connection, const char* name) {
    return MHD_lookup_connection_value(connection, MHD_HEADER_KIND, name);
}

Http_JsonResponseParams resource_error(
    std::string code, std::string detail, unsigned int status) {
    Http_JsonResponseParams response;
    response.response_code = status;
    response.content_type = "application/json";
    response.response = {
        {"state", "error"},
        {"error", {{"code", std::move(code)}, {"detail", std::move(detail)}}},
    };
    return response;
}

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
        const auto info = sx::cfg::CfgArchive::inspect_archive(request);
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

Http_JsonResponseParams cfg_archive_restore(
    MHD_Connection* connection,
    [[maybe_unused]] std::string const& method,
    std::string const& request) {
    // Keep the body as exact CFtar bytes; preconditions travel in headers.
    const auto* revision = MHD_lookup_connection_value(
        connection, MHD_HEADER_KIND, "X-Smithproxy-Expected-Revision");
    const auto* hash = MHD_lookup_connection_value(
        connection, MHD_HEADER_KIND, "X-Smithproxy-Archive-SHA256");

    Http_JsonResponseParams response;
    response.content_type = "application/json";

    // Restore is never blind: state and archive must have been inspected first.
    if(!revision || !*revision || !hash || !*hash) {
        response.response_code = MHD_HTTP_BAD_REQUEST;
        response.response = {
            {"state", "error"},
            {"error", {
                {"code", "missing_restore_precondition"},
                {"detail", "restore requires expected revision and archive SHA-256 headers"},
            }},
        };
        return response;
    }

    const auto result = CfgFactory::restore_startup_archive(revision, hash, request);

    // Success means durable startup replacement, not live reload.
    if(result.ok()) {
        response.response_code = MHD_HTTP_OK;
        response.response = {
            {"state", "restored"},
            {"revision", result.revision.current_id},
            {"content_hash", result.content_hash},
            {"restart_required", true},
        };
        return response;
    }

    // Preserve domain-specific failures so the GUI can offer the right remedy.
    std::string code;
    unsigned int status = MHD_HTTP_CONFLICT;
    using Status = sx::cfg::ArchiveRestoreStatus;
    switch(result.status) {
        case Status::invalid_archive:
            code = "invalid_archive";
            status = MHD_HTTP_UNPROCESSABLE_ENTITY;
            break;
        case Status::hash_mismatch:
            code = "archive_hash_mismatch";
            status = MHD_HTTP_UNPROCESSABLE_ENTITY;
            break;
        case Status::lease_busy: code = "write_lease_busy"; break;
        case Status::stale_revision: code = "stale_revision"; break;
        case Status::unsaved_running: code = "unsaved_running_config"; break;
        case Status::native_unavailable: code = "native_archive_unavailable"; break;
        case Status::restart_pending: code = "restart_already_required"; break;
        case Status::write_failed:
            code = "archive_install_failed";
            status = MHD_HTTP_INTERNAL_SERVER_ERROR;
            break;
        case Status::restored: break;
    }

    response.response_code = status;
    response.response = {
        {"state", "error"},
        {"revision", result.revision.current_id},
        {"content_hash", result.content_hash},
        {"error", {
            {"code", std::move(code)},
            {"detail", result.detail},
        }},
    };
    return response;
}

Http_JsonResponseParams cfg_archive_resources(
    [[maybe_unused]] MHD_Connection* connection,
    [[maybe_unused]] std::string const& method,
    [[maybe_unused]] std::string const& request) {
    try {
        const auto info = CfgFactory::get()->archive_info();
        if(!info.native) throw sx::cfg::CfgTarError("native archive is unavailable");

        nlohmann::json resources = nlohmann::json::array();
        for(const auto& entry : info.entries) {
            if(!sx::cfg::CfgManifest::is_resource_path(entry.path)) continue;
            resources.push_back({
                {"path", entry.path}, {"size", entry.size},
                {"executable", entry.executable},
            });
        }
        Http_JsonResponseParams response;
        response.response = {
            {"state", "ready"}, {"content_hash", info.content_hash},
            {"resources", std::move(resources)},
        };
        return response;
    }
    catch(const std::exception& error) {
        return resource_error("native_archive_unavailable", error.what(), MHD_HTTP_CONFLICT);
    }
}

Http_JsonResponseParams cfg_archive_resource(
    MHD_Connection* connection,
    std::string const& method,
    std::string const& request) {
    const auto* path = MHD_lookup_connection_value(
        connection, MHD_GET_ARGUMENT_KIND, "path");
    if(!path || !*path) {
        return resource_error("missing_resource_path", "resource path is required",
                              MHD_HTTP_BAD_REQUEST);
    }

    if(method == "GET") {
        try {
            Http_JsonResponseParams response;
            response.binary = CfgFactory::get()->archive_resource(path);
            response.content_type = "application/octet-stream";
            return response;
        }
        catch(const std::exception& error) {
            return resource_error("resource_unavailable", error.what(), MHD_HTTP_NOT_FOUND);
        }
    }

    const auto* revision = header(connection, "X-Smithproxy-Expected-Revision");
    const auto* hash = header(connection, "X-Smithproxy-Archive-SHA256");
    if(!revision || !*revision || !hash || !*hash) {
        return resource_error("missing_resource_precondition",
            "resource write requires expected revision and archive SHA-256 headers",
            MHD_HTTP_BAD_REQUEST);
    }
    const bool executable = header(connection, "X-Smithproxy-Executable") &&
                            std::string_view(header(connection, "X-Smithproxy-Executable")) == "true";
    const auto result = CfgFactory::write_archive_resource(
        revision, hash, path, method == "DELETE" ? std::nullopt
                                                   : std::optional<std::string>(request),
        executable);
    if(result.ok()) {
        Http_JsonResponseParams response;
        response.response = {
            {"state", "written"}, {"content_hash", result.archive_hash},
            {"restart_required", true},
        };
        return response;
    }

    using Status = sx::cfg::ResourceWriteStatus;
    const bool invalid = result.status == Status::invalid_resource;
    const bool failed = result.status == Status::write_failed;
    std::string code = "resource_write_conflict";
    if(invalid) code = "invalid_resource";
    else if(failed) code = "resource_write_failed";
    return resource_error(std::move(code), result.detail,
        invalid ? MHD_HTTP_UNPROCESSABLE_ENTITY
                : failed ? MHD_HTTP_INTERNAL_SERVER_ERROR : MHD_HTTP_CONFLICT);
}

}  // namespace sx::webserver
