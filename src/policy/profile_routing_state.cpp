#include <policy/profiles.hpp>

std::vector<std::shared_ptr<CidrAddress>> ProfileRouting::lb_candidates(int family) const {
    auto l_ = std::scoped_lock(lb_state.lock_);
    return family == CIDR_IPV6 ? lb_state.candidates_v6 : lb_state.candidates_v4;
}

size_t ProfileRouting::lb_index_rr(size_t sz) const {
    if (sz == 0) return 0;
    return lb_state.rr_counter.fetch_add(1, std::memory_order_relaxed) % sz;
}
