#pragma once

// This isolated HTTP worker test supplies only the daemon's shutdown flag.
// RequestTask, the thread pool, libcurl and the receiving socket are real.
#define SMITHPROXY_SMITHPROXY_HPP
#include <atomic>
#include <smithlog.hpp>
#include <common/timeops.hpp>

class SmithProxy {
public:
    std::atomic_bool terminate_flag{false};

    static SmithProxy& instance() {
        static SmithProxy runtime;
        return runtime;
    }
};
