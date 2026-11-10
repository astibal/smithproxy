#pragma once

#include <log/logan.hpp>

namespace sx::cfg {

// Share one diagnostic topic across the complete configuration lifecycle.
// Configuration content, credentials, and physical filesystem paths must not
// be included in messages emitted through this logger.
inline logan_lite& config_log() {
    static logan_lite logger("config");
    return logger;
}

}  // namespace sx::cfg
