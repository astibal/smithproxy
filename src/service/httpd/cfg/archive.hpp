#pragma once

#include <string>

struct MHD_Connection;

namespace sx::webserver {

struct Http_JsonResponseParams;

// Download the complete active CFtar. Authentication is supplied by the
// dispatcher, exactly as for the rest of the protected configuration API.
Http_JsonResponseParams cfg_archive_download(
    MHD_Connection* connection, std::string const& method, std::string const& request);

Http_JsonResponseParams cfg_archive_previous_download(
    MHD_Connection* connection, std::string const& method, std::string const& request);

Http_JsonResponseParams cfg_archive_validate(
    MHD_Connection* connection, std::string const& method, std::string const& request);

// Install a previously validated CFtar as the next startup configuration.
// The running process remains untouched and reports restart_required.
Http_JsonResponseParams cfg_archive_restore(
    MHD_Connection* connection, std::string const& method, std::string const& request);

Http_JsonResponseParams cfg_archive_resources(
    MHD_Connection* connection, std::string const& method, std::string const& request);
Http_JsonResponseParams cfg_archive_resource(
    MHD_Connection* connection, std::string const& method, std::string const& request);

}  // namespace sx::webserver
