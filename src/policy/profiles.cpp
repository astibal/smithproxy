#include <policy/profiles.hpp>
#include <service/cfgapi/cfgapi.hpp>

#include <proxy/mitmproxy.hpp>
#include <crc32.hpp>

void ProfileRouting::update() {
    lb_state.expand_candidates(dnat_addresses);
}


static uint32_t crc32_proxy_key(MitmProxy const* proxy, bool add_port) {
    std::stringstream ss;

    if(auto const* l = proxy->first_left(); l) {
        ss << l->host();
    }
    if(auto const* r = proxy->first_right(); r) {
        ss << r->host();
        if(add_port) {
            ss << r->port();
        }
    }

    auto key = ss.str();

    return socle::tools::crc32::compute(0, key.data(), key.size());
}

size_t ProfileRouting::lb_index_l3 (MitmProxy const* proxy, size_t sz) const {

    return sz == 0 || !proxy ? 0 : crc32_proxy_key(proxy, false) % sz;
}

size_t ProfileRouting::lb_index_l4(MitmProxy const* proxy, size_t sz) const {

    return sz == 0 || !proxy ? 0 : crc32_proxy_key(proxy, true) % sz;
}


bool ProfileRouting::LbState::expand_candidates(std::vector<std::string> const& addresses) {

    const auto now = time(nullptr);
    {
        auto l_ = std::scoped_lock(lock_);
        if (refresh_in_progress || now - last_refresh <= refresh_interval) {
            return false;
        }
        refresh_in_progress = true;
    }

    try {
        // get a fresh, expanded list of all IP addresses
        const std::vector<std::shared_ptr<CidrAddress>> update4 = CfgFactory::get()->expand_to_cidr(addresses, AF_INET);
        const std::vector<std::shared_ptr<CidrAddress>> update6 = CfgFactory::get()->expand_to_cidr(addresses, AF_INET6);

        auto l_ = std::scoped_lock(lock_);
        candidates_v4 = update4;
        candidates_v6 = update6;
        last_refresh = now;
        refresh_in_progress = false;
    }
    catch (...) {
        auto l_ = std::scoped_lock(lock_);
        refresh_in_progress = false;
        throw;
    }

    return true;
}
