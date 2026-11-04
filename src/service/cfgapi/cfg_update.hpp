#pragma once

#include <cstdint>
#include <memory>
#include <mutex>
#include <string>
#include <unordered_map>
#include <vector>

#include "cfg_revision.hpp"

class UpdateBoard {
public:
    static constexpr std::uint64_t starting_num = 1000;

    struct UpdateInfo {
        std::uint64_t seen_current {starting_num};
        std::uint64_t seen_saved {starting_num};
    };

    struct UpdateNotice {
        bool current_changed {false};
        bool saved_changed {false};
        std::string updater;

        [[nodiscard]] bool changed() const noexcept {
            return current_changed || saved_changed;
        }
    };

    struct RevisionView {
        std::string current_id;
        std::string saved_id;
        std::vector<sx::cfg::CfgRevision> entries;
    };

    explicit UpdateBoard(std::size_t history_capacity = sx::cfg::CfgRevHistory::default_capacity);

    void subscribe(std::string const& subscriber);
    void unsubscribe(std::string const& subscriber);

    [[nodiscard]] bool differs_current(std::string const& subscriber);
    [[nodiscard]] bool differs_saved(std::string const& subscriber);
    [[nodiscard]] bool differs(std::string const& subscriber);
    [[nodiscard]] std::int64_t current_delta(std::string const& subscriber);
    [[nodiscard]] std::int64_t saved_delta(std::string const& subscriber);

    // Read and acknowledge both update counters as one atomic board operation.
    [[nodiscard]] UpdateNotice poll_updates(std::string const& subscriber);

    void ack_current(std::string const& subscriber);
    void ack_saved(std::string const& subscriber);

    // Transitional counter-only update. Configuration writers will move to
    // the snapshot overload as transaction support is connected.
    std::uint64_t upgrade(std::string const& source);

    // Record the initial running and startup configuration.
    sx::cfg::CfgRevision init_revision(std::string snapshot, std::string source);

    // Record one successful running-config change and advance the legacy
    // update counter used by existing CLI subscribers.
    sx::cfg::CfgRevision upgrade(
        std::string const& source,
        std::string snapshot,
        std::string description);

    std::uint64_t rollback(std::string const& source);
    std::uint64_t save(std::string const& source);

    [[nodiscard]] std::string updater() const;
    [[nodiscard]] std::uint64_t version_current() const;
    [[nodiscard]] std::uint64_t version_saved() const;
    [[nodiscard]] bool unsaved() const;
    [[nodiscard]] std::string revision_current() const;
    [[nodiscard]] std::string revision_saved() const;
    [[nodiscard]] std::vector<sx::cfg::CfgRevision> revisions() const;
    [[nodiscard]] RevisionView revision_view() const;

private:
    using SubscriberMap = std::unordered_map<std::string, UpdateInfo>;

    // The caller must hold board_mutex_. Unknown subscribers start at the
    // board's current state so their first read is not reported as a change.
    UpdateInfo& subscriber_locked(std::string const& subscriber);

    mutable std::mutex board_mutex_;
    SubscriberMap subscribers_;
    std::uint64_t current_version_ {starting_num};
    std::uint64_t saved_version_ {starting_num};
    std::string current_revision_;
    std::string saved_revision_;
    std::string updater_;
    sx::cfg::CfgRevHistory history_;
};

class UpdateBoardSubscriber {
public:
    UpdateBoardSubscriber() = delete;
    UpdateBoardSubscriber(std::string subscriber, std::shared_ptr<UpdateBoard> board);
    ~UpdateBoardSubscriber();

    [[nodiscard]] std::shared_ptr<UpdateBoard> board() const;

private:
    std::string subscriber_;
    std::weak_ptr<UpdateBoard> board_;
};
