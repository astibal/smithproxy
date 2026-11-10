#pragma once

#include <service/helper_debug.hpp>
#include <log/logan.hpp>
#include <array>
#include <unistd.h>

namespace sx::helper_debug {

inline auto &loggers() {
    static std::array<logan_lite, static_cast<std::size_t>(Service::count)> values{
        logan_lite{"sys.comm"},    logan_lite{"sys.files"}, logan_lite{"sys.gre"},
        logan_lite{"sys.webhook"}, logan_lite{"sys.sift"},  logan_lite{"sys.auth"}};
    return values;
}

inline logan_lite &common_logger() {
    static logan_lite value{"sys.helpers"};
    return value;
}

inline void install_logging() {
    // Register before traffic so debug set also works on an idle proxy.
    for (auto &logger : loggers())
        (void)logger.level();
    (void)common_logger().level();

    filter.store(
        +[](Service service, int level) {
            return loggers().at(static_cast<std::size_t>(service)).level()->level() >=
                       static_cast<unsigned>(level) ||
                   common_logger().level()->level() >= static_cast<unsigned>(level);
        },
        std::memory_order_release);

    sink.store(
        +[](Service service, int level, std::uint64_t id, std::string_view event,
            std::string_view detail) {
            auto &specific = loggers().at(static_cast<std::size_t>(service));
            auto &logger = specific.level()->level() >= static_cast<unsigned>(level)
                               ? specific
                               : common_logger();

            logger.log(loglevel(level), logger.topic(), "helper=%s pid=%d exchange=%llu %.*s %.*s",
                       specific.topic().c_str(), static_cast<int>(::getpid()),
                       static_cast<unsigned long long>(id), static_cast<int>(event.size()),
                       event.data(), static_cast<int>(detail.size()),
                       detail.empty() ? "" : detail.data());
        },
        std::memory_order_release);
}
} // namespace sx::helper_debug
