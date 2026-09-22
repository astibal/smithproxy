#include "proxy/multiflow/mfproxy.hpp"

#include <algorithm>
#include <array>
#include <vector>

namespace sx::multiflow {

MFProxy::MFProxy(std::shared_ptr<connection> left, std::shared_ptr<connection> right)
    : left_(std::move(left)), right_(std::move(right)) {}

std::size_t MFProxy::pump_once(std::size_t chunk_size) {
    if (!left_ || !right_ || chunk_size == 0) return 0;
    process_events(true, left_->drain_events());
    process_events(false, right_->drain_events());

    std::size_t moved = 0;
    for (auto& item : pairs_) {
        auto& current = *item.second;
        moved += pump_direction(*current.left, *current.right,
                                current.left_to_right, chunk_size);
        moved += pump_direction(*current.right, *current.left,
                                current.right_to_left, chunk_size);
    }
    return moved;
}

void MFProxy::process_events(bool from_left, std::vector<event> events) {
    for (auto const& current : events) {
        if (current.type == event_type::flow_open && current.flow
            && !paired(from_left, *current.flow)) {
            pair_new_flow(from_left, *current.flow);
        }
    }
}

void MFProxy::pair_new_flow(bool from_left, flow_handle source) {
    auto& source_connection = from_left ? left_ : right_;
    auto& destination_connection = from_left ? right_ : left_;
    auto const source_direction = source_connection->direction_of(source);
    if (!source_direction) return;

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

} // namespace sx::multiflow
