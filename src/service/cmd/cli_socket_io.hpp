#pragma once

#include <service/libcli/fd_transport.hpp>

#include <cerrno>
#include <poll.h>
#include <string_view>

namespace sx::cli {

inline bool write_all(libcli2::FdTransport& transport, std::string_view text,
                      int stall_timeout_ms = 1000) {
    std::size_t written = 0;
    while(written < text.size()) {
        const auto count = transport.write_some(
            text.data() + written, text.size() - written);
        if(count > 0) {
            written += static_cast<std::size_t>(count);
            continue;
        }
        if(count < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
            pollfd descriptor {transport.output_fd(), POLLOUT, 0};
            int ready;
            do {
                ready = ::poll(&descriptor, 1, stall_timeout_ms);
            } while(ready < 0 && errno == EINTR);
            if(ready > 0 && (descriptor.revents & POLLOUT) != 0) continue;
        }
        return false;
    }
    return true;
}

} // namespace sx::cli
