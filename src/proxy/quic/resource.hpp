#pragma once

#include <vars.hpp>
#include <cerrno>
#include <utility>
#include <unistd.h>

namespace sx::quic {

// Runtime deleter for owned sockets/eventfds. Invalidate before closing so the
// same operation also supports preparation retries; never retry close on EINTR.
// Preserve the failure being reported by the caller during RAII unwinding.
inline void close_descriptor(int& fd) noexcept {
    if (fd < 0) return;
    int const saved_errno = errno;
    ::close(std::exchange(fd, -1));
    errno = saved_errno;
}

} // namespace sx::quic
