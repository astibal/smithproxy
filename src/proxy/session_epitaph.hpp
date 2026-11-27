#pragma once

#include <cstdint>
#include <optional>
#include <string>

namespace sx::proxy {

// Session-owned terminal snapshot captured before transport contexts disappear.
// Hooks may enrich and publish it, but they do not own its lifetime or identity.
struct SessionEpitaph {
    std::string connection_id;
    std::string connection_label;
    int policy = 0;
    std::uint64_t bytes_up = 0;
    std::uint64_t bytes_down = 0;
    std::string ja4_client_hello;
    std::string ja4_client_hello_standard;
    std::string ja4_client_hello_no_sni;
    bool ja4_client_hello_ignore_sni = false;
    std::string ja4_server_hello;
    std::optional<std::string> parent_connection_id;
    std::optional<std::uint64_t> stream_id;
};

} // namespace sx::proxy
