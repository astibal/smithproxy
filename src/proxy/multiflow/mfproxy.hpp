#ifndef SMITHPROXY_MFPROXY_HPP
#define SMITHPROXY_MFPROXY_HPP

#include <deque>
#include <map>
#include <memory>
#include <set>

#include "proxy/multiflow/mfflowcom.hpp"

namespace sx::multiflow {

/** Connection-level coordinator which pairs and pumps logical flows. */
class MFProxy {
public:
    MFProxy(std::shared_ptr<connection> left, std::shared_ptr<connection> right);

    /** Process lifecycle events and move at most one chunk per direction/flow. */
    std::size_t pump_once(std::size_t chunk_size = 16 * 1024);
    std::size_t pair_count() const { return pairs_.size(); }

private:
    struct pair {
        flow_handle left_handle;
        flow_handle right_handle;
        std::unique_ptr<MFFlowCom> left;
        std::unique_ptr<MFFlowCom> right;
        std::deque<unsigned char> left_to_right;
        std::deque<unsigned char> right_to_left;
        bool left_peer_fin = false;
        bool right_peer_fin = false;
        bool left_finish_sent = false;
        bool right_finish_sent = false;
    };

    void process_events(bool from_left, std::vector<event> events);
    void pair_new_flow(bool from_left, flow_handle source);
    std::size_t pump_direction(MFFlowCom& source, MFFlowCom& destination,
                               std::deque<unsigned char>& pending, std::size_t chunk_size);
    bool paired(bool left_side, flow_handle flow) const;
    pair* find_pair(bool left_side, flow_handle flow);
    void propagate_fin(pair& current);

    std::shared_ptr<connection> left_;
    std::shared_ptr<connection> right_;
    std::map<flow_id, std::unique_ptr<pair>> pairs_;
    std::set<flow_id> retired_;
    bool closed_ = false;
};

} // namespace sx::multiflow

#endif // SMITHPROXY_MFPROXY_HPP
