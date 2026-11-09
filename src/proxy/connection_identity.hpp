#pragma once

#include <cstdint>
#include <string>

#include <common/stringformat.hpp>

namespace sx::proxy {

inline std::string connection_id(std::uint32_t boot_id,
                                 std::uint64_t session_id) {
    return string_format("Proxy-%lX-SID-%llX",
                         static_cast<unsigned long>(boot_id),
                         static_cast<unsigned long long>(session_id));
}

} // namespace sx::proxy
