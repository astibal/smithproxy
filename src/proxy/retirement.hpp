#pragma once

#include <utility>

namespace sx::proxy {

// Retirement is irreversible: an optional callback must not skip the remaining
// cleanup/notifications. Even error reporting is allowed to fail during teardown.
template<class Operation, class Failure>
bool retirement_step(Operation&& operation, Failure&& failure) noexcept {
    try {
        std::forward<Operation>(operation)();
        return true;
    }
    catch(...) {
        try { std::forward<Failure>(failure)(); }
        catch(...) {}
        return false;
    }
}

} // namespace sx::proxy
