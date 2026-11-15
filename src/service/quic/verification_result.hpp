#pragma once

#include "proxy/quic/resource.hpp"
#include <atomic>
#include <fcntl.h>
#include <sys/eventfd.h>
#include <system_error>

namespace sx::quic {

// Shared between the SSL-owned verifier and its asynchronous revocation task.
// The duplicated eventfd owns a reference to the original wakeup object, so a
// late completion cannot signal a descriptor recycled after listener teardown.
class verification_result {
public:
    explicit verification_result(int wake_fd = -1) {
        if (wake_fd >= 0) {
            wake_.value = ::fcntl(wake_fd, F_DUPFD_CLOEXEC, 0);
            if (wake_.value < 0) {
                throw std::system_error(errno, std::generic_category(), "duplicate QUIC verification wakeup");
            }
        }
    }

    int load() const { return verdict_.load(std::memory_order_acquire); }

    // Synchronous decisions already run on the listener; no wakeup is needed.
    void store(int verdict) { verdict_.store(verdict, std::memory_order_release); }

    void complete(int verdict) {
        // Publish the evidence/verdict before waking ppoll. The listener reads
        // with acquire semantics and still makes the normal admission decision.
        store(verdict);

        if (wake_.value >= 0) {
            while (::eventfd_write(wake_.value, 1) < 0 && errno == EINTR) {}
            // EAGAIN means the counter is full: the listener is already awake.
        }
    }

private:
    std::atomic_int verdict_ {0};
    socle::raw::var<int> wake_ {-1, close_descriptor};
};

} // namespace sx::quic
