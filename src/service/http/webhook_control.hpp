#pragma once

#include <atomic>
#include <cstdint>
#include <functional>
#include <memory>
#include <nlohmann/json.hpp>
#include <optional>
#include <string>
#include <utility>
#include <vector>

namespace sx::http::webhooks {

// Per-connection policy, shared with asynchronous replies without owning a proxy.
struct webhook_control_t {
    enum class mode_t { regular, strict };
    std::atomic<mode_t> mode{mode_t::regular};
    std::atomic<std::uint64_t> content_sequence{0};

    bool strict() const { return mode.load() == mode_t::strict; }

    void apply(nlohmann::json const& reply) {
        if(!reply.is_object()) return;
        auto control = reply.find("control");
        if(control == reply.end() || !control->is_object()) return;

        auto value = control->find("mode");
        if(value == control->end() || !value->is_string()) return;

        if(*value == "strict") mode.store(mode_t::strict);
        else if(*value == "regular") mode.store(mode_t::regular);
        // Missing/unknown options never silently downgrade an active policy.
    }
};

// A parsed operation keeps its imperative name separate from its arguments.
// Protocol-specific code receives this neutral form and decides whether it
// can prepare the requested engine or proxy operation.
struct webhook_control_operation_t {
    std::string operation;
    nlohmann::json arguments;
};

// All validation and fallible resource acquisition must finish before an
// operation reaches this interface.  The owning proxy can then publish the
// whole prepared control block without recovering from a partial commit.
class prepared_webhook_operation_t {
public:
    virtual ~prepared_webhook_operation_t() = default;
    virtual void commit() noexcept = 0;
};

// The consumer validates one operation and returns its infallible commit step.
// Returning an empty pointer rejects the complete control block.
using webhook_operation_preparer_t = std::function<
    std::unique_ptr<prepared_webhook_operation_t>(
        webhook_control_operation_t const&, std::string& error)>;

// A prepared block owns the policy update and ordered operation commits.  It
// is move-only so the result cannot accidentally be copied to another proxy
// or committed through two independent owners.
class prepared_webhook_control_t {
public:
    prepared_webhook_control_t(
            std::optional<webhook_control_t::mode_t> mode,
            std::vector<std::unique_ptr<prepared_webhook_operation_t>> operations)
        : mode_(mode), operations_(std::move(operations)) {}

    prepared_webhook_control_t(prepared_webhook_control_t&&) noexcept = default;
    prepared_webhook_control_t& operator=(prepared_webhook_control_t&&) noexcept = default;
    prepared_webhook_control_t(prepared_webhook_control_t const&) = delete;
    prepared_webhook_control_t& operator=(prepared_webhook_control_t const&) = delete;

    [[nodiscard]] std::size_t operation_count() const noexcept {
        return operations_.size();
    }

    void commit(webhook_control_t& state) && noexcept {
        // Preserve existing control.mode semantics, then execute operations in
        // their original JSON array order at the same proxy commit boundary.
        if(mode_) state.mode.store(*mode_);

        for(auto& operation : operations_) operation->commit();
        operations_.clear();
    }

private:
    std::optional<webhook_control_t::mode_t> mode_;
    std::vector<std::unique_ptr<prepared_webhook_operation_t>> operations_;
};

// Preparation returns either a complete commit plan or one diagnostic error.
struct webhook_control_prepare_result_t {
    std::unique_ptr<prepared_webhook_control_t> prepared;
    std::string error;

    [[nodiscard]] explicit operator bool() const noexcept {
        return static_cast<bool>(prepared);
    }
};

// Keep operation names readable and safe to use in diagnostics and dispatch.
inline bool valid_webhook_operation_name(std::string const& name) {
    if(name.empty() || name.size() > 64) return false;
    if(name.front() < 'a' || name.front() > 'z') return false;

    for(unsigned char character : name) {
        if((character >= 'a' && character <= 'z') ||
           (character >= '0' && character <= '9') || character == '-') {
            continue;
        }
        return false;
    }
    return true;
}

// Build an immutable control plan without touching connection or proxy state.
// Parsing the generic envelope is kept here; concrete targets and arguments
// belong to the supplied proxy/engine preparer.  This separation lets all
// operations succeed or fail together before the caller stages its byte
// action and enters the FlowCtx commit path.
inline webhook_control_prepare_result_t prepare_webhook_control(
        nlohmann::json const& reply,
        webhook_operation_preparer_t const& prepare_operation = {}) {

    // Validate the reply envelope before extracting any policy or operation.
    if(!reply.is_object()) return {nullptr, "Webhook reply must be an object"};

    std::optional<webhook_control_t::mode_t> mode;
    std::vector<std::unique_ptr<prepared_webhook_operation_t>> prepared_operations;

    // Absence of control is a valid no-op plan.  This keeps ordinary webhook
    // replies on the same preparation and commit path.
    auto const control = reply.find("control");
    if(control == reply.end()) {
        return {std::make_unique<prepared_webhook_control_t>(
                    mode, std::move(prepared_operations)), {}};
    }
    if(!control->is_object()) return {nullptr, "control must be an object"};

    // Stage the connection policy update.  Unknown values intentionally leave
    // the current mode unchanged instead of downgrading a strict connection.
    auto const mode_value = control->find("mode");
    if(mode_value != control->end() && mode_value->is_string()) {
        if(*mode_value == "strict") mode = webhook_control_t::mode_t::strict;
        else if(*mode_value == "regular") mode = webhook_control_t::mode_t::regular;
    }

    // Validate the generic ordered list before asking protocol-specific code
    // to allocate or resolve anything for individual operations.
    auto const operations = control->find("operations");
    if(operations == control->end()) {
        return {std::make_unique<prepared_webhook_control_t>(
                    mode, std::move(prepared_operations)), {}};
    }
    if(!operations->is_array()) return {nullptr, "control.operations must be an array"};
    if(operations->size() > 64)
        return {nullptr, "control.operations exceeds the 64-operation limit"};
    if(!prepare_operation && !operations->empty())
        return {nullptr, "This callback does not support control operations"};

    prepared_operations.reserve(operations->size());

    // Prepare every operation in wire order.  Nothing in prepared_operations
    // is published when a later item fails validation or preparation.
    for(std::size_t index = 0; index < operations->size(); ++index) {
        auto const& item = (*operations)[index];
        if(!item.is_object()) {
            return {nullptr, "control.operations[" + std::to_string(index) +
                             "] must be an object"};
        }

        auto const operation_value = item.find("operation");
        if(operation_value == item.end() || !operation_value->is_string()) {
            return {nullptr, "control.operations[" + std::to_string(index) +
                             "].operation must be a string"};
        }

        auto const operation_name = operation_value->get<std::string>();
        if(!valid_webhook_operation_name(operation_name)) {
            return {nullptr, "control.operations[" + std::to_string(index) +
                             "].operation has an invalid name"};
        }

        // Remove the dispatch tag before handing arguments to the concrete
        // preparer, which owns the operation-specific schema and limits.
        auto arguments = item;
        arguments.erase("operation");
        webhook_control_operation_t operation{operation_name, std::move(arguments)};
        std::string error;
        auto prepared = prepare_operation(operation, error);

        if(!prepared) {
            if(error.empty()) error = "Unsupported control operation: " + operation_name;
            return {nullptr, "control.operations[" + std::to_string(index) + "]: " + error};
        }
        prepared_operations.push_back(std::move(prepared));
    }

    // Only a fully prepared list becomes visible as a committable result.
    return {std::make_unique<prepared_webhook_control_t>(
                mode, std::move(prepared_operations)), {}};
}

}
