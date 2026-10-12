#pragma once

#include <cerrno>
#include <sys/types.h>

namespace sx::explicit_proxy::io_detail {

template<class Operation>
ssize_t retry_on_eintr(Operation&& operation) {
    ssize_t result;
    do {
        result = operation();
    } while(result < 0 && errno == EINTR);
    return result;
}

inline bool send_would_block(int error) noexcept {
    return error == EAGAIN || error == EWOULDBLOCK || error == ENOBUFS;
}

} // namespace sx::explicit_proxy::io_detail
