#include <policy/profiles.hpp>
#include <cfgapi.hpp>




bool ProfileRouting::LbState::expand_candidates(std::vector<std::string> const& addresses) {

    if(auto now = time(nullptr); now - last_refresh > refresh_interval) {
        last_refresh = now;

        // get a fresh, expanded list of all IP addresses
        std::vector<std::shared_ptr<CidrAddress>> update4 = CfgFactory::get()->expand_to_cidr(addresses, AF_INET);
        std::vector<std::shared_ptr<CidrAddress>> update6 = CfgFactory::get()->expand_to_cidr(addresses, AF_INET6);

        auto l_ = std::scoped_lock(lock_);
        candidates_v4 = update4;
        candidates_v6 = update6;
    }

    return false;
}