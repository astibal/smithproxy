#pragma once

#include <cerrno>
#include <sys/types.h>

namespace sx::dns::io_detail {

template<class Operation>
ssize_t retry_on_eintr(Operation&& operation) {
    ssize_t result;
    do {
        result = operation();
    } while(result < 0 && errno == EINTR);
    return result;
}

} // namespace sx::dns::io_detail
