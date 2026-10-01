/*
 * StreamHandler adapter for the libssh MITM transport.
 */

#include <proxy/ssh/sshstream.hpp>

#include <utility>

#include <proxy/mitmproxy.hpp>

namespace sx::ssh {

stream_handler::stream_handler(transport_options options)
    : options_(std::move(options)) {}

stream_handler::~stream_handler() {
    shutdown();
}

bool stream_handler::attach(MitmProxy& proxy) {
    if (transport_) {
        final_error_ = "SSH stream handler is already attached";
        return false;
    }

    auto* left = proxy.first_left();
    auto* right = proxy.first_right();
    if (!left || !right) {
        final_error_ = "SSH stream handler requires both proxy legs";
        return false;
    }

    transport_ = std::make_unique<mitm_transport>(options_);
    if (!transport_->attach(left->real_socket(), right->real_socket())) {
        final_error_ = transport_->error();
        transport_.reset();
        return false;
    }

    // From this point forward failure is terminal. We deliberately never
    // untap and fall back to forwarding a partially processed SSH stream.
    committed_ = true;
    return true;
}

sx::StreamHandler::result stream_handler::drive() {
    if (!transport_) {
        final_error_ = "SSH stream handler is detached";
        return result::failed;
    }

    switch (transport_->drive()) {
        case drive_result::progress:             return result::progress;
        case drive_result::again:                return result::wait;
        case drive_result::authentication_ready: return result::progress;
        case drive_result::blocked:              return result::blocked;
        case drive_result::failed:               return result::failed;
    }
    return result::failed;
}

void stream_handler::shutdown() noexcept {
    if (transport_) {
        final_state_ = state();
        final_error_ = error();
        transport_.reset();
    }
}

std::string stream_handler::state() const {
    return transport_ ? state_name(transport_->state()) : final_state_;
}

std::string stream_handler::error() const {
    return transport_ ? transport_->error() : final_error_;
}

} // namespace sx::ssh
