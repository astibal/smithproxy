#include <policy/profiles.hpp>
#include <service/cfgapi/cfgapi.hpp>

#include <proxy/mitmproxy.hpp>
#include <crc32.hpp>

void ProfileRouting::update() {
    lb_state.expand_candidates(dnat_addresses);
    lb_state.rr_counter++;
}

std::vector<std::shared_ptr<CidrAddress>> ProfileRouting::lb_candidates(int family) const {
    return family == CIDR_IPV6 ? lb_state.candidates_v6 : lb_state.candidates_v4;
}

size_t ProfileRouting::lb_index_rr(size_t sz) const {
    return sz == 0 ? 0 : lb_state.rr_counter % sz;
}


static uint32_t crc32_proxy_key(MitmProxy* proxy, bool add_port) {
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

size_t ProfileRouting::lb_index_l3 (MitmProxy* proxy, size_t sz) const {

    return sz == 0 ? 0 : crc32_proxy_key(proxy, false) % sz;
}

size_t ProfileRouting::lb_index_l4(MitmProxy* proxy, size_t sz) const {

    return sz == 0 ? 0 : crc32_proxy_key(proxy, proxy) % sz;
}


bool ProfileRouting::LbState::expand_candidates(std::vector<std::string> const& addresses) {

    if(auto now = time(nullptr); now - last_refresh > refresh_interval) {
        last_refresh = now;

        // get a fresh, expanded list of all IP addresses
        const std::vector<std::shared_ptr<CidrAddress>> update4 = CfgFactory::get()->expand_to_cidr(addresses, AF_INET);
        const std::vector<std::shared_ptr<CidrAddress>> update6 = CfgFactory::get()->expand_to_cidr(addresses, AF_INET6);

        auto l_ = std::scoped_lock(lock_);
        candidates_v4 = update4;
        candidates_v6 = update6;
    }

    return false;
}