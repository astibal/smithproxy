#pragma once

#include <cstdint>
#include <functional>
#include <memory>
#include <mutex>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace sx::auth {

enum class PapStatus {
    accepted,
    rejected,
    error,
};

struct PapResult {
    PapStatus status = PapStatus::error;
    std::string identity;
    std::string error;
    std::vector<std::string> groups{};

    explicit operator bool() const noexcept { return status == PapStatus::accepted; }
};

struct PapCredentials {
    std::string username;
    std::string password;
};

class PapBackend {
public:
    using completion_type = std::function<void(PapResult)>;

    virtual ~PapBackend() = default;

    // A value means that verification completed synchronously. nullopt means
    // that completion will be called later, exactly once. Implementations may
    // invoke completion before verify_pap() returns; PapExchange handles that
    // race. Credentials must not be retained beyond completion.
    virtual std::optional<PapResult> verify_pap(
        PapCredentials credentials, completion_type completion) = 0;
};

// Own one PAP exchange for a connection. The transport is paused before the
// backend is entered, so both synchronous and future asynchronous backends use
// the same, tested control path. Tap/untap hooks must not throw or start an
// exchange; the completion callback may start the next exchange.
class PapExchange {
public:
    using action_type = std::function<void()>;
    using completion_type = PapBackend::completion_type;

    PapExchange(action_type tap, action_type untap);
    ~PapExchange();

    PapExchange(PapExchange const&) = delete;
    PapExchange& operator=(PapExchange const&) = delete;

    bool verify(PapBackend& backend, std::string_view username,
                std::string_view password, completion_type completion);
    bool pending() const;
    void cancel();

private:
    struct State;
    // Serializes request startup with cancel/destruction. recursive_mutex also
    // permits an immediate completion callback to start the next exchange.
    mutable std::recursive_mutex operation_lock_;
    std::shared_ptr<State> state_;
};

} // namespace sx::auth
