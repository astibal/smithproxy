#pragma once

#include <cstddef>
#include <cstdint>
#include <deque>
#include <functional>
#include <mutex>
#include <optional>
#include <string>
#include <vector>

namespace sx::cfg {

// One successful running-config change creates one immutable revision.
// The snapshot is kept in full so it can later be compared or restored.
struct CfgRevision {
    // Unique ID of this running-config revision.
    std::string id;

    // Revision that was current immediately before this one; empty for the
    // first recorded snapshot.
    std::string parent_id;

    // SHA-256 of snapshot. Equal hashes mean equal configuration content even
    // when the revisions were created at different times.
    std::string content_hash;

    // Wall-clock creation time expressed as microseconds since Unix epoch.
    std::int64_t timestamp_us {0};

    // Component that created the revision, for example "cli", "gui", or
    // "startup".
    std::string source;

    // Short human-readable summary of the change.
    std::string description;

    // Complete serialized running configuration used for diff and restore.
    std::string snapshot;
};

// Keeps the newest running-config revisions in insertion order.
// The history is bounded by entry count only. Smithproxy configurations are
// small, and retaining complete snapshots keeps restore behavior predictable.
class CfgRevHistory {
public:
    static constexpr std::size_t default_capacity = 100;

    // Injectable generators keep revision tests deterministic. Production
    // callers use the random-ID and system-clock defaults.
    using IdGenerator = std::function<std::string()>;
    using TimestampGenerator = std::function<std::int64_t()>;

    explicit CfgRevHistory(
        std::size_t capacity = default_capacity,
        IdGenerator id_generator = {},
        TimestampGenerator timestamp_generator = {});

    CfgRevision append(std::string snapshot, std::string source, std::string description);
    [[nodiscard]] std::optional<CfgRevision> find(std::string const& id) const;

    // Return a point-in-time copy. Callers never retain references that can be
    // invalidated when the ring buffer evicts its oldest entry.
    [[nodiscard]] std::vector<CfgRevision> entries() const;
    [[nodiscard]] std::size_t size() const;
    [[nodiscard]] std::size_t capacity() const noexcept;

private:
    // The caller must hold history_mutex_.
    [[nodiscard]] bool contains_id(std::string const& id) const;

    std::size_t capacity_;
    IdGenerator id_generator_;
    TimestampGenerator timestamp_generator_;
    mutable std::mutex history_mutex_;
    std::deque<CfgRevision> entries_;
};

}  // namespace sx::cfg
