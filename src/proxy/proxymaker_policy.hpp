#pragma once

#include <policy/policy.hpp>
#include <utility>

namespace sx::proxymaker {
// The single ordered policy selector.
// The caller owns a stable rules view (currently the configuration lock).
class PolicyMatcher final {
public:
    template<class... Context>
    static int select(const std::vector<std::shared_ptr<PolicyRule>>& rules, Context&&... context) {
        for(std::size_t i = 0; i < rules.size(); ++i) {
            if(rules[i] && rules[i]->match(std::forward<Context>(context)...))
                return static_cast<int>(i);
        }
        return -1;
    }
};
} // namespace sx::proxymaker
