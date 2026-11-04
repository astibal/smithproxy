#include "cfg_revision.hpp"

#include <chrono>
#include <stdexcept>
#include <utility>

#include <utils/crypto.hpp>

namespace sx::cfg {
namespace {

std::string random_revision_id() {
    auto id = sx::crypto::random_hex(16);
    if(!id) {
        throw std::runtime_error("cannot generate configuration revision ID");
    }
    return std::move(*id);
}

std::int64_t current_timestamp_us() {
    auto const now = std::chrono::system_clock::now().time_since_epoch();
    return std::chrono::duration_cast<std::chrono::microseconds>(now).count();
}

std::string content_hash(std::string const& snapshot) {
    auto hash = sx::crypto::sha256(snapshot);
    if(!hash) {
        throw std::runtime_error("cannot hash configuration snapshot");
    }
    return "sha256:" + std::move(*hash);
}

}  // namespace

CfgRevHistory::CfgRevHistory(
    std::size_t capacity,
    IdGenerator id_generator,
    TimestampGenerator timestamp_generator)
    : capacity_(capacity),
      id_generator_(id_generator ? std::move(id_generator) : random_revision_id),
      timestamp_generator_(timestamp_generator ? std::move(timestamp_generator) : current_timestamp_us) {
    if(capacity_ == 0) {
        throw std::invalid_argument("configuration revision history capacity must be positive");
    }
}

CfgRevision CfgRevHistory::append(
    std::string snapshot,
    std::string source,
    std::string description) {
    std::scoped_lock lock(history_mutex_);

    std::string id;
    for(unsigned int attempt = 0; attempt < 16 && id.empty(); ++attempt) {
        auto candidate = id_generator_();
        if(!candidate.empty() && !contains_id(candidate)) {
            id = std::move(candidate);
        }
    }
    if(id.empty()) {
        throw std::runtime_error("cannot allocate a unique configuration revision ID");
    }

    CfgRevision revision;
    revision.id = std::move(id);
    revision.parent_id = entries_.empty() ? std::string {} : entries_.back().id;
    revision.content_hash = content_hash(snapshot);
    revision.timestamp_us = timestamp_generator_();
    revision.source = std::move(source);
    revision.description = std::move(description);
    revision.snapshot = std::move(snapshot);

    entries_.push_back(revision);
    if(entries_.size() > capacity_) {
        entries_.pop_front();
    }
    return revision;
}

std::optional<CfgRevision> CfgRevHistory::find(std::string const& id) const {
    std::scoped_lock lock(history_mutex_);
    for(auto const& revision : entries_) {
        if(revision.id == id) {
            return revision;
        }
    }
    return std::nullopt;
}

std::vector<CfgRevision> CfgRevHistory::entries() const {
    std::scoped_lock lock(history_mutex_);
    return {entries_.begin(), entries_.end()};
}

std::size_t CfgRevHistory::size() const {
    std::scoped_lock lock(history_mutex_);
    return entries_.size();
}

std::size_t CfgRevHistory::capacity() const noexcept {
    return capacity_;
}

bool CfgRevHistory::contains_id(std::string const& id) const {
    for(auto const& revision : entries_) {
        if(revision.id == id) {
            return true;
        }
    }
    return false;
}

}  // namespace sx::cfg
