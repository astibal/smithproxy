#include "proxy/multiflow/mfproxy.hpp"

#include <algorithm>
#include <array>
#include <vector>

namespace sx::multiflow {

MFProxy::MFProxy(std::shared_ptr<connection> left, std::shared_ptr<connection> right,
                 limits resource_limits)
    : left_(std::move(left)), right_(std::move(right)), limits_(resource_limits) {}

std::size_t MFProxy::pump_once(std::size_t chunk_size) {
    if (!left_ || !right_ || chunk_size == 0 || closed_) return 0;
    process_events(true, left_->drain_events());
    if (closed_) return 0;
    process_events(false, right_->drain_events());
    if (closed_) return 0;
    chunk_size = std::min(chunk_size, limits_.buffer_per_direction);
    if (chunk_size == 0) return 0;

    std::size_t moved = 0;
    for (auto& item : pairs_) {
        auto& current = *item.second;
        moved += pump_direction(*current.left, *current.right,
                                current.left_to_right, chunk_size);
        moved += pump_direction(*current.right, *current.left,
                                current.right_to_left, chunk_size);
        propagate_fin(current);
    }
    for (auto id : retired_) pairs_.erase(id);
    retired_.clear();
    return moved;
}

void MFProxy::process_events(bool from_left, std::vector<event> events) {
    for (auto const& current : events) {
        if (current.type == event_type::connection_close) {
            (from_left ? right_ : left_)->close(current.protocol_error);
            closed_ = true;
            continue;
        }
        if (!current.flow) continue;

        if (current.type == event_type::flow_open && !paired(from_left, *current.flow)) {
            pair_new_flow(from_left, *current.flow);
            continue;
        }

        auto* matched = find_pair(from_left, *current.flow);
        if (!matched) continue;
        if (current.type == event_type::peer_fin) {
            if (from_left) matched->left_peer_fin = true;
            else matched->right_peer_fin = true;
        } else if (current.type == event_type::reset) {
            auto& destination_connection = from_left ? right_ : left_;
            auto const destination_flow = from_left
                ? matched->right_handle : matched->left_handle;
            destination_connection->reset(destination_flow, current.protocol_error);
            retired_.insert(matched->left_handle.id);
        }
    }
}

void MFProxy::pair_new_flow(bool from_left, flow_handle source) {
    auto& source_connection = from_left ? left_ : right_;
    auto& destination_connection = from_left ? right_ : left_;
    auto const source_direction = source_connection->direction_of(source);
    if (!source_direction) return;
    if (pairs_.size() >= limits_.max_flows) {
        source_connection->reset(source, 0x107);
        ++limit_rejections_;
        return;
    }

    auto destination_direction = *source_direction;
    if (*source_direction == direction::send_only) destination_direction = direction::receive_only;
    if (*source_direction == direction::receive_only) destination_direction = direction::send_only;

    // A receive-only local flow cannot be opened. It represents a peer-created
    // unidirectional stream, so the opposite endpoint must create send-only.
    auto destination = destination_connection->open_flow(destination_direction);
    if (destination.generation == 0) return;

    auto created = std::make_unique<pair>();
    created->left_handle = from_left ? source : destination;
    created->right_handle = from_left ? destination : source;
    created->left = std::make_unique<MFFlowCom>(left_, created->left_handle);
    created->right = std::make_unique<MFFlowCom>(right_, created->right_handle);
    pairs_.emplace(created->left_handle.id, std::move(created));
}

std::size_t MFProxy::pump_direction(MFFlowCom& source, MFFlowCom& destination,
                                    std::deque<unsigned char>& pending,
                                    std::size_t chunk_size) {
    std::size_t moved = 0;
    if (pending.empty() && source.readable(source.token())) {
        std::vector<unsigned char> buffer(chunk_size);
        auto const count = source.read(source.token(), buffer.data(), buffer.size(), 0);
        if (count > 0) {
            pending.insert(pending.end(), buffer.begin(), buffer.begin() + count);
        }
    }

    if (!pending.empty() && destination.writable(destination.token())) {
        auto const contiguous = std::min(chunk_size, pending.size());
        std::vector<unsigned char> buffer;
        buffer.reserve(contiguous);
        auto iterator = pending.begin();
        for (std::size_t i = 0; i < contiguous; ++i, ++iterator) buffer.push_back(*iterator);
        auto const count = destination.write(destination.token(), buffer.data(), buffer.size(), 0);
        if (count > 0) {
            pending.erase(pending.begin(), pending.begin() + count);
            moved += static_cast<std::size_t>(count);
        }
    }
    return moved;
}

bool MFProxy::paired(bool left_side, flow_handle flow) const {
    for (auto const& item : pairs_) {
        auto const& current = *item.second;
        auto const candidate = left_side ? current.left_handle : current.right_handle;
        if (candidate == flow) return true;
    }
    return false;
}

MFProxy::pair* MFProxy::find_pair(bool left_side, flow_handle flow) {
    for (auto& item : pairs_) {
        auto& current = *item.second;
        auto const candidate = left_side ? current.left_handle : current.right_handle;
        if (candidate == flow) return &current;
    }
    return nullptr;
}

void MFProxy::propagate_fin(pair& current) {
    if (current.left_peer_fin && current.left_to_right.empty()
        && !current.right_finish_sent) {
        auto const status = right_->finish(current.right_handle);
        current.right_finish_sent = status != io_status::would_block;
    }
    if (current.right_peer_fin && current.right_to_left.empty()
        && !current.left_finish_sent) {
        auto const status = left_->finish(current.left_handle);
        current.left_finish_sent = status != io_status::would_block;
    }
    if (current.left_peer_fin && current.right_peer_fin
        && current.left_to_right.empty() && current.right_to_left.empty()) {
        retired_.insert(current.left_handle.id);
    }
}

} // namespace sx::multiflow
