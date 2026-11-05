#pragma once

#include <cstddef>
#include <cstdint>
#include <memory>
#include <optional>
#include <string>
#include <variant>
#include <vector>

#include <libconfig.h++>

namespace sx::cfg::tx {

// The wire/API value keeps its type instead of relying on text conversion.
// Arrays are homogeneous by construction, matching libconfig's TypeArray.
using Value = std::variant<
    std::int64_t,
    double,
    bool,
    std::string,
    std::vector<std::int64_t>,
    std::vector<double>,
    std::vector<bool>,
    std::vector<std::string>>;

struct Set {
    // Full path of an existing setting or of a new leaf below an existing group.
    std::string path;
    Value value;
};

struct Add {
    // Collection receiving the new entry. Groups use name; lists ignore it.
    std::string path;
    std::string name;
};

struct Remove {
    // Group entry names or decimal list indices removed as one operation.
    std::string path;
    std::vector<std::string> entries;
};

enum class Position {
    before,
    after,
};

struct Move {
    // Reorder one entry in an unnamed libconfig list.
    std::string path;
    std::size_t source {0};
    Position position {Position::before};
    std::size_t target {0};
};

using Op = std::variant<Set, Add, Remove, Move>;

struct Request {
    // Revision whose complete snapshot becomes the candidate input.
    std::string base_revision;

    // Human-readable client identity recorded with the future commit lease.
    std::string owner;

    // Ordered changes; later operations see results of all earlier ones.
    std::vector<Op> operations;
};

struct Issue {
    // Zero-based position in Request::operations which produced the error.
    std::size_t operation {0};

    // Stable machine-readable category suitable for an API response.
    std::string code;

    // Configuration path involved in the failure, when one is available.
    std::string path;

    // Human-readable explanation intended for CLI and GUI diagnostics.
    std::string detail;
};

// C++17 counterpart of std::expected used only by the transaction layer.
// Keeping errors as values makes operation failures explicit at every call site.
template <class T>
class Result {
public:
    Result(T value) : data_(std::move(value)) {}
    Result(Issue error) : data_(std::move(error)) {}

    [[nodiscard]] explicit operator bool() const noexcept {
        return std::holds_alternative<T>(data_);
    }

    T& operator*() { return std::get<T>(data_); }
    T const& operator*() const { return std::get<T>(data_); }
    T* operator->() { return &std::get<T>(data_); }
    T const* operator->() const { return &std::get<T>(data_); }

    Issue& error() { return std::get<Issue>(data_); }
    Issue const& error() const { return std::get<Issue>(data_); }

private:
    std::variant<T, Issue> data_;
};

template <>
class Result<void> {
public:
    Result() = default;
    Result(Issue error) : error_(std::move(error)) {}

    [[nodiscard]] explicit operator bool() const noexcept {
        return !error_.has_value();
    }

    Issue& error() { return *error_; }
    Issue const& error() const { return *error_; }

private:
    std::optional<Issue> error_;
};

// A complete, isolated libconfig object built from one revision snapshot.
// Mutating a candidate never changes the running Smithproxy configuration.
class Candidate {
public:
    using ApplyResult = Result<void>;
    using LoadResult = Result<Candidate>;
    using SnapshotResult = Result<std::string>;

    Candidate(Candidate&&) noexcept = default;
    Candidate& operator=(Candidate&&) noexcept = default;
    Candidate(Candidate const&) = delete;
    Candidate& operator=(Candidate const&) = delete;

    static LoadResult load(std::string const& snapshot);

    // Apply one operation to this candidate only. The index is carried into
    // Issue so a caller can identify the failing item in an operation chain.
    ApplyResult apply(Op const& operation, std::size_t operation_index);

    // Serialize and parse the result once more. Success means the complete
    // candidate can be persisted and reconstructed by libconfig.
    SnapshotResult snapshot();

    [[nodiscard]] libconfig::Config const& config() const noexcept;

private:
    explicit Candidate(std::unique_ptr<libconfig::Config> config);

    std::unique_ptr<libconfig::Config> config_;
};

}  // namespace sx::cfg::tx
