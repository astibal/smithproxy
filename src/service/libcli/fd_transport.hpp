#pragma once

#include <cstddef>
#include <sys/types.h>

namespace libcli2 {

enum class FdOwnership {
    borrowed,
    owned,
};

struct FdPair {
    explicit FdPair(int input = -1, int output = -1,
                    FdOwnership ownership = FdOwnership::owned) noexcept
        : input(input), output(output), input_ownership(ownership), output_ownership(ownership) {}

    FdPair(int input, int output, FdOwnership input_ownership,
           FdOwnership output_ownership) noexcept
        : input(input), output(output), input_ownership(input_ownership),
          output_ownership(output_ownership) {}

    static FdPair borrowed(int input, int output) noexcept {
        return FdPair(input, output, FdOwnership::borrowed);
    }

    int input = -1;
    int output = -1;
    FdOwnership input_ownership = FdOwnership::owned;
    FdOwnership output_ownership = FdOwnership::owned;
};

// Movable, non-copyable ownership wrapper for a duplex descriptor pair.
// Owned descriptors must not be closed externally; use release() to transfer them.
class FdTransport {
public:
    FdTransport() noexcept = default;
    explicit FdTransport(FdPair fds) noexcept : fds_(fds) {}
    ~FdTransport();

    FdTransport(const FdTransport&) = delete;
    FdTransport& operator=(const FdTransport&) = delete;
    FdTransport(FdTransport&& other) noexcept;
    FdTransport& operator=(FdTransport&& other) noexcept;

    int input_fd() const noexcept { return fds_.input; }
    int output_fd() const noexcept { return fds_.output; }
    bool valid() const noexcept { return fds_.input >= 0 || fds_.output >= 0; }

    // Close the old owned pair and optionally install another one.
    void reset(FdPair replacement = FdPair()) noexcept;

    // Relinquish ownership without closing the descriptors.
    [[nodiscard]] FdPair release() noexcept;

    ssize_t read_some(void* destination, std::size_t size) const noexcept;
    ssize_t write_some(const void* source, std::size_t size) const noexcept;

private:
    void close_owned() noexcept;
    FdPair fds_;
};

}  // namespace libcli2
