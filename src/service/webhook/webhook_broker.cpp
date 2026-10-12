#include <service/webhook/webhook_broker.hpp>

#include <cerrno>
#include <mutex>

namespace {
std::mutex transport_mutex;
std::string configured_path;
}

namespace sx::comm::webhook {

int configure_transport(const std::string& path) {
    if(path.empty()) { errno = EINVAL; return -1; }
    std::lock_guard lock(transport_mutex);
    configured_path = path;
    return 0;
}

void clear_transport() noexcept {
    std::lock_guard lock(transport_mutex);
    configured_path.clear();
}

bool enabled() noexcept {
    std::lock_guard lock(transport_mutex);
    return !configured_path.empty();
}

std::string transport_path() {
    std::lock_guard lock(transport_mutex);
    return configured_path;
}

} // namespace sx::comm::webhook
