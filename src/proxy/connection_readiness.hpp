#pragma once

#include <cstdint>

namespace sx::proxy {

// Notification bookkeeping only; the transport remains the authority on readiness.
struct ConnectionReadiness {
    int descriptor = 0;
    const void* communication = nullptr;
    std::uint64_t attempt = 0;
    bool connected = false;
    bool ready = false;

    void observe_context(int fd, const void* com, std::uint64_t& sequence) {
        if(descriptor != fd) {
            descriptor = fd;
            attempt = ++sequence;
            connected = false;
            ready = false;
        }
        // STARTTLS replaces com on the same TCP socket. Keep the transport
        // identity, but wait for the new layer before announcing readiness.
        if(communication != com) {
            communication = com;
            ready = false;
        }
    }
};

} // namespace sx::proxy
