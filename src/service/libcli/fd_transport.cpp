#include "fd_transport.hpp"

#include <cerrno>
#include <sys/socket.h>
#include <unistd.h>

namespace libcli2 {

FdTransport::~FdTransport() {
    close_owned();
}

FdTransport::FdTransport(FdTransport&& other) noexcept : fds_(other.release()) {}

FdTransport& FdTransport::operator=(FdTransport&& other) noexcept {
    if (this != &other) reset(other.release());
    return *this;
}

void FdTransport::reset(FdPair replacement) noexcept {
    close_owned();
    fds_ = replacement;
}

FdPair FdTransport::release() noexcept {
    const FdPair result = fds_;
    fds_ = FdPair{};
    return result;
}

void FdTransport::close_owned() noexcept {
    // Invalidate first, and coalesce a shared input/output descriptor into one close.
    const FdPair old = release();
    const bool own_input = old.input_ownership == FdOwnership::owned;
    const bool own_output = old.output_ownership == FdOwnership::owned;
    if (old.input >= 0 && (own_input || (old.input == old.output && own_output)))
        ::close(old.input);
    if (old.output >= 0 && old.output != old.input && own_output)
        ::close(old.output);
}

ssize_t FdTransport::read_some(void* destination, std::size_t size) const noexcept {
    ssize_t result;
    do {
        result = ::read(fds_.input, destination, size);
    } while (result < 0 && errno == EINTR);
    return result;
}

ssize_t FdTransport::write_some(const void* source, std::size_t size) const noexcept {
    ssize_t result;
    do {
        result = ::send(fds_.output, source, size, MSG_NOSIGNAL);
        if (result < 0 && errno == ENOTSOCK) result = ::write(fds_.output, source, size);
    } while (result < 0 && errno == EINTR);
    return result;
}

}  // namespace libcli2
