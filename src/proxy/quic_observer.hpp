#pragma once

#include <array>
#include <string>
#include <proxy/quic/hooks.hpp>

namespace sx::proxy {

// One observer per parent QUIC session, not per HTTP/3 stream. Certificate
// verification completes before the forwarding worker invokes this observer.
class QuicObserver {
public:
    QuicObserver(std::string id, bool strict, bool start, bool meta = false)
        : id_(std::move(id)), meta_(meta), strict_(strict), start_(start) {}

    static void register_callbacks();
    bool outcome_pending(bool client) const { return !outcomes_[client ? 0 : 1]; }

private:
    static bool dispatch(proxymaker::SessionSetup& setup, quic::HookEvent& event) noexcept;
    bool observe(quic::HookEvent& event);

    std::string id_;
    bool meta_ = false;
    bool strict_ = false;
    bool start_ = false;
    std::array<bool, 2> outcomes_ {};
    std::array<unsigned int, 2> attempts_ {1, 0};
    bool terminated_ = false;
};

} // namespace sx::proxy
