#pragma once

#include <cerrno>
#include <cstddef>
#include <sys/types.h>

namespace sx::quic::detail {

enum class datagram_send_result { sent, blocked, failed };

template<class Operation>
ssize_t retry_on_eintr(Operation&& operation) {
    ssize_t result;
    do {
        result = operation();
    } while(result < 0 && errno == EINTR);
    return result;
}

inline datagram_send_result classify_datagram_send(
        ssize_t result, int error, std::size_t expected) noexcept {
    if(result == static_cast<ssize_t>(expected))
        return datagram_send_result::sent;
    if(result < 0 && (error == EAGAIN || error == EWOULDBLOCK ||
                      error == ENOBUFS || error == ENOMEM))
        return datagram_send_result::blocked;
    return datagram_send_result::failed;
}

inline bool datagram_receive_would_block(int error) noexcept {
    return error == EAGAIN || error == EWOULDBLOCK ||
           error == ENOBUFS || error == ENOMEM;
}

} // namespace sx::quic::detail
