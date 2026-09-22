#ifndef SMITHPROXY_MFPROXY_HPP
#define SMITHPROXY_MFPROXY_HPP

#include <deque>
#include <map>
#include <memory>
#include <set>

#include "proxy/multiflow/mfflowcom.hpp"

namespace sx::multiflow {

/** Resource bounds applied independently to one paired connection. */
struct proxy_limits {
    std::size_t max_flows = 256;                 ///< Maximum simultaneously paired flows.
    std::size_t buffer_per_direction = 16 * 1024; ///< Maximum queued chunk per direction.
};

/**
 * Pairs logical flows from two multiplexed connections and pumps their bytes.
 *
 * A flow opened by either endpoint creates a corresponding flow on the other
 * endpoint. The coordinator preserves directionality, backpressure, FIN, reset
 * codes, and connection close without assigning ownership of the physical
 * connections to individual MFFlowCom objects. All methods are worker-affine;
 * the class does not provide internal locking.
 */
class MFProxy {
public:
    using limits = proxy_limits;

    /** Construct a bridge between two live multiplexed connections. */
    MFProxy(std::shared_ptr<connection> left, std::shared_ptr<connection> right,
            limits resource_limits = {});

    /** Process lifecycle events and move at most one chunk per direction/flow. */
    std::size_t pump_once(std::size_t chunk_size = 16 * 1024);
    std::size_t pair_count() const { return pairs_.size(); } ///< Current paired flows.
    /** Cumulative streams reset because max_flows was reached. */
    std::size_t limit_rejections() const { return limit_rejections_; }

private:
    /** Bidirectional bookkeeping for one left/right flow association. */
    struct pair {
        flow_handle left_handle;
        flow_handle right_handle;
        std::unique_ptr<MFFlowCom> left;
        std::unique_ptr<MFFlowCom> right;
        std::deque<unsigned char> left_to_right; ///< Bytes blocked by the right side.
        std::deque<unsigned char> right_to_left; ///< Bytes blocked by the left side.
        bool left_peer_fin = false;
        bool right_peer_fin = false;
        bool left_finish_sent = false;
        bool right_finish_sent = false;
    };

    /** Apply one endpoint's readiness and lifecycle notifications. */
    void process_events(bool from_left, std::vector<event> events);
    /** Mirror a newly observed flow onto the opposite connection. */
    void pair_new_flow(bool from_left, flow_handle source);
    /** Move at most one bounded chunk while retaining unwritten bytes. */
    std::size_t pump_direction(MFFlowCom& source, MFFlowCom& destination,
                               std::deque<unsigned char>& pending, std::size_t chunk_size);
    bool paired(bool left_side, flow_handle flow) const;
    pair* find_pair(bool left_side, flow_handle flow);
    /** Forward FIN only after all bytes preceding it have been written. */
    void propagate_fin(pair& current);

    std::shared_ptr<connection> left_;           ///< First physical connection.
    std::shared_ptr<connection> right_;          ///< Second physical connection.
    std::map<flow_id, std::unique_ptr<pair>> pairs_; ///< Associations keyed by left ID.
    std::set<flow_id> retired_;                  ///< Pairs erased after iteration.
    bool closed_ = false;                        ///< A connection close was propagated.
    limits limits_;                              ///< Per-connection resource policy.
    std::size_t limit_rejections_ = 0;           ///< Monotonic diagnostic counter.
};

} // namespace sx::multiflow

#endif // SMITHPROXY_MFPROXY_HPP
