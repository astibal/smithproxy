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

}  // namespace sx::webserver
