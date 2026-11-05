#include "cfg_update.hpp"

#include <stdexcept>
#include <utility>

UpdateBoard::UpdateBoard(std::size_t history_capacity)
    : history_(history_capacity) {}

void UpdateBoard::subscribe(std::string const& subscriber) {
    std::scoped_lock lock(board_mutex_);
    subscribers_[subscriber] = {current_version_, saved_version_};
}

void UpdateBoard::unsubscribe(std::string const& subscriber) {
    std::scoped_lock lock(board_mutex_);
    subscribers_.erase(subscriber);
}

bool UpdateBoard::differs_current(std::string const& subscriber) {
    std::scoped_lock lock(board_mutex_);
    return subscriber_locked(subscriber).seen_current != current_version_;
}

bool UpdateBoard::differs_saved(std::string const& subscriber) {
    std::scoped_lock lock(board_mutex_);
    return subscriber_locked(subscriber).seen_saved != saved_version_;
}

bool UpdateBoard::differs(std::string const& subscriber) {
    std::scoped_lock lock(board_mutex_);
    auto const& state = subscriber_locked(subscriber);
    return state.seen_current != current_version_ || state.seen_saved != saved_version_;
}

std::int64_t UpdateBoard::current_delta(std::string const& subscriber) {
    std::scoped_lock lock(board_mutex_);
    auto const seen = subscriber_locked(subscriber).seen_current;
    return static_cast<std::int64_t>(current_version_) - static_cast<std::int64_t>(seen);
}

std::int64_t UpdateBoard::saved_delta(std::string const& subscriber) {
    std::scoped_lock lock(board_mutex_);
    auto const seen = subscriber_locked(subscriber).seen_saved;
    return static_cast<std::int64_t>(saved_version_) - static_cast<std::int64_t>(seen);
}

UpdateBoard::UpdateNotice UpdateBoard::poll_updates(std::string const& subscriber) {
    std::scoped_lock lock(board_mutex_);
    auto& state = subscriber_locked(subscriber);

    UpdateNotice notice;
    notice.current_changed = state.seen_current != current_version_;
    notice.saved_changed = state.seen_saved != saved_version_;
    notice.updater = updater_;

    state.seen_current = current_version_;
    state.seen_saved = saved_version_;
    return notice;
}

void UpdateBoard::ack_current(std::string const& subscriber) {
    std::scoped_lock lock(board_mutex_);
    subscriber_locked(subscriber).seen_current = current_version_;
}

void UpdateBoard::ack_saved(std::string const& subscriber) {
    std::scoped_lock lock(board_mutex_);
    subscriber_locked(subscriber).seen_saved = saved_version_;
}

std::uint64_t UpdateBoard::upgrade(std::string const& source) {
    std::scoped_lock lock(board_mutex_);
    updater_ = source;
    return ++current_version_;
}

sx::cfg::CfgRevision UpdateBoard::init_revision(std::string snapshot, std::string source) {
    std::scoped_lock lock(board_mutex_);
    if(!current_revision_.empty()) {
        throw std::logic_error("configuration revision history is already initialized");
    }

    auto revision = history_.append(std::move(snapshot), std::move(source), "initial configuration");
    current_revision_ = revision.id;
    saved_revision_ = revision.id;
    return revision;
}

sx::cfg::CfgRevision UpdateBoard::upgrade(
    std::string const& source,
    std::string snapshot,
    std::string description) {
    std::scoped_lock lock(board_mutex_);
    auto revision = history_.append(std::move(snapshot), source, std::move(description));
    current_revision_ = revision.id;
    updater_ = source;
    ++current_version_;
    return revision;
}

sx::cfg::CfgRevision UpdateBoard::reload(
    std::string const& source,
    std::string snapshot,
    std::string description) {
    std::scoped_lock lock(board_mutex_);
    auto revision = history_.append(std::move(snapshot), source, std::move(description));
    updater_ = source;
    current_revision_ = revision.id;
    saved_revision_ = revision.id;
    ++current_version_;
    saved_version_ = current_version_;
    return revision;
}

std::uint64_t UpdateBoard::save(std::string const& source) {
    std::scoped_lock lock(board_mutex_);
    updater_ = source;
    saved_revision_ = current_revision_;
    saved_version_ = current_version_;
    return saved_version_;
}

std::string UpdateBoard::updater() const {
    std::scoped_lock lock(board_mutex_);
    return updater_;
}

std::uint64_t UpdateBoard::version_current() const {
    std::scoped_lock lock(board_mutex_);
    return current_version_;
}

std::uint64_t UpdateBoard::version_saved() const {
    std::scoped_lock lock(board_mutex_);
    return saved_version_;
}

bool UpdateBoard::unsaved() const {
    std::scoped_lock lock(board_mutex_);
    return current_version_ != saved_version_;
}

std::string UpdateBoard::revision_current() const {
    std::scoped_lock lock(board_mutex_);
    return current_revision_;
}

std::string UpdateBoard::revision_saved() const {
    std::scoped_lock lock(board_mutex_);
    return saved_revision_;
}

std::optional<sx::cfg::CfgRevision> UpdateBoard::revision(
    std::string const& id) const {
    return history_.find(id);
}

std::vector<sx::cfg::CfgRevision> UpdateBoard::revisions() const {
    return history_.entries();
}

UpdateBoard::RevisionView UpdateBoard::revision_view() const {
    std::scoped_lock lock(board_mutex_);
    return {current_revision_, saved_revision_, history_.entries()};
}

UpdateBoard::UpdateInfo& UpdateBoard::subscriber_locked(std::string const& subscriber) {
    auto [position, inserted] = subscribers_.try_emplace(
        subscriber,
        UpdateInfo {current_version_, saved_version_});
    return position->second;
}

UpdateBoardSubscriber::UpdateBoardSubscriber(
    std::string subscriber,
    std::shared_ptr<UpdateBoard> board)
    : subscriber_(std::move(subscriber)), board_(board) {
    if(board) {
        board->subscribe(subscriber_);
    }
}

UpdateBoardSubscriber::~UpdateBoardSubscriber() {
    if(auto board = board_.lock()) {
        board->unsubscribe(subscriber_);
    }
}

std::shared_ptr<UpdateBoard> UpdateBoardSubscriber::board() const {
    return board_.lock();
}
