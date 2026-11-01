#include "pap.hpp"

#include <exception>
#include <utility>

namespace sx::auth {

struct PapExchange::State {
    State(action_type tap_action, action_type untap_action)
        : tap(std::move(tap_action)), untap(std::move(untap_action)) {}

    std::uint64_t begin(completion_type next_completion) {
        std::lock_guard lock(mutex);
        if(active) {
            return 0;
        }
        active = true;
        completion = std::move(next_completion);
        return ++generation;
    }

    bool is_pending() const {
        std::lock_guard lock(mutex);
        return active;
    }

    void finish(std::uint64_t expected_generation, PapResult result) {
        completion_type notify;
        {
            std::lock_guard lock(mutex);
            if(!active || generation != expected_generation) {
                return;
            }

            // Resume before publishing the idle state. A new request must not
            // tap its transport while the previous untap is still running.
            if(untap) {
                untap();
            }
            active = false;
            notify = std::move(completion);
        }
        if(notify) {
            notify(std::move(result));
        }
    }

    void cancel() {
        std::lock_guard lock(mutex);
        if(!active) {
            return;
        }
        if(untap) {
            untap();
        }
        active = false;
        ++generation;
        completion = {};
    }

    mutable std::recursive_mutex mutex;
    bool active = false;
    std::uint64_t generation = 0;
    action_type tap;
    action_type untap;
    completion_type completion;
};

PapExchange::PapExchange(action_type tap, action_type untap)
    : state_(std::make_shared<State>(std::move(tap), std::move(untap))) {}

PapExchange::~PapExchange() {
    cancel();
}

bool PapExchange::verify(PapBackend& backend, std::string_view username,
                         std::string_view password, completion_type completion) {
    std::lock_guard operation_guard(operation_lock_);
    auto const generation = state_->begin(std::move(completion));
    if(generation == 0) {
        return false;
    }

    if(state_->tap) {
        state_->tap();
    }

    std::weak_ptr<State> weak_state = state_;
    auto finish = [weak_state, generation](PapResult result) {
        if(auto state = weak_state.lock()) {
            state->finish(generation, std::move(result));
        }
    };

    try {
        auto immediate = backend.verify_pap(
            PapCredentials{std::string(username), std::string(password)}, finish);
        if(immediate) {
            finish(std::move(*immediate));
        }
    } catch(std::exception const& exception) {
        finish(PapResult{PapStatus::error, {}, exception.what()});
    } catch(...) {
        finish(PapResult{PapStatus::error, {}, "PAP backend threw an unknown exception"});
    }
    return true;
}

bool PapExchange::pending() const {
    return state_->is_pending();
}

void PapExchange::cancel() {
    std::lock_guard operation_guard(operation_lock_);
    state_->cancel();
}

} // namespace sx::auth
