/*
    Smithproxy- transparent proxy with SSL inspection capabilities.
    Copyright (c) 2014, Ales Stibal <astib@mag0.net>, All rights reserved.

    Smithproxy is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    Smithproxy is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with Smithproxy.  If not, see <http://www.gnu.org/licenses/>.

    Linking Smithproxy statically or dynamically with other modules is
    making a combined work based on Smithproxy. Thus, the terms and
    conditions of the GNU General Public License cover the whole combination.

    In addition, as a special exception, the copyright holders of Smithproxy
    give you permission to combine Smithproxy with free software programs
    or libraries that are released under the GNU LGPL and with code
    included in the standard release of OpenSSL under the OpenSSL's license
    (or modified versions of such code, with unchanged license).
    You may copy and distribute such a system following the terms
    of the GNU GPL for Smithproxy and the licenses of the other code
    concerned, provided that you include the source code of that other code
    when and as the GNU GPL requires distribution of source code.

    Note that people who make modified versions of Smithproxy are not
    obligated to grant this special exception for their modified versions;
    it is their choice whether to do so. The GNU General Public License
    gives permission to release a modified version without this exception;
    this exception also makes it possible to release a modified version
    which carries forward this exception.
*/

#include <thread>
#include <vector>
#include <set>
#include <ctime>

#include <policy/addrobj.hpp>
#include <inspect/dns.hpp>
#include <inspect/dnsinspector.hpp>
#include <service/cfgapi/cfgapi.hpp>

#include <service/core/smithproxy.hpp>

// returns sleep time for the next cleanup
unsigned int dns_cache_cleanup() {

    logan_lite log = logan_lite("com.dns.cleaner");

    auto& cache = DNS::get_dns_cache();
    auto lc_ = std::scoped_lock(DNS::get_dns_lock());

    int min_ttl = 300;
    int processed = 0;
    int removed = 0;

    for(auto it = cache.cache().begin(); it != cache.cache().end(); ) {
        processed++;

        _deb("dns_cache_cleanup: %s", it->first.c_str());

        auto ttl = it->second->ptr()->current_ttl().value_or(-1);
        if(ttl < 0) {
            _deb("dns_cache_cleanup:     ttl %d -- removing", ttl);
            it = cache.erase(it);
            removed++;
        } else {
            _deb("dns_cache_cleanup:     ttl %d -- keeping", ttl);

            // find time to sleep for a next call
            if( ttl < min_ttl) {
                min_ttl = ttl;
                _deb("dns_cache_cleanup:     ttl %d -- setting up new minttl", ttl);
            }

            ++it;
        }


    }

    // cap max waiting time to ~5 minutes
    if(min_ttl > 300) {
        min_ttl = 300;
    }

    auto ret = 10 + min_ttl;


    _dia("dns_cache_cleanup: processed %d entries, removed %d, next scan in %ds", processed, removed, ret);

    // wait at least 10 seconds to next laundry
    return ret;
}



struct DNS_Resolver : DNS_Setup {

    static inline logan_lite log = logan_lite("com.dns.resolver");
    static inline time_t requery_ttl = 60;
    static inline std::set<std::string, std::less<>> record_blacklist;

    static std::vector<std::string> refresh_candidates() {
        std::vector<std::string> ret;

        auto lc_ = std::scoped_lock(CfgFactory::lock());
        for (auto const &a: CfgFactory::get()->db_address) {
            auto fa = std::dynamic_pointer_cast<CfgAddress>(a.second);
            if (fa) {

                auto fa_obj = std::dynamic_pointer_cast<FqdnAddress>(fa->value());
                if (fa_obj) {
                    ret.push_back("A:" + fa_obj->fqdn());
                    ret.push_back("AAAA:" + fa_obj->fqdn());
                }
            }
        }

        return ret;
    }

    static std::vector<std::string> check_cache_expiry(std::vector<std::string> const& request_candidates) {

        std::vector<std::string> to_refresh;

        auto ll_ = std::scoped_lock(DNS::get_dns_lock());

        for (auto const& candidate: request_candidates) {
            auto dns_response = DNS::get_dns_cache().get(candidate);
            if (dns_response) {
                const long ttl = (dns_response->loaded_at + dns_response->answers().at(0).ttl_) - ::time(nullptr);

                _dia("fqdn %s ttl %d", candidate.c_str(), ttl);

                //re-query only about-to-expire existing DNS entries for FQDN addresses
                if (ttl < requery_ttl) {
                    to_refresh.push_back(candidate);
                }
            } else {
                // query FQDNs without DNS cache entry
                if (record_blacklist.find(candidate) == record_blacklist.end()) {
                    to_refresh.push_back(candidate);
                } else {
                    _dia("fqdn %s is blacklisted", candidate.c_str());
                }
            }
        }

        return to_refresh;
    }



    static void requery_records(std::vector<std::string> const& records) {
        for(const auto& t_a: records) {
            _dia("refreshing fqdn: %s",t_a.c_str());

            std::string a;
            DNS_Record_Type t;

            if(t_a.size() < 5) continue;

            if(t_a.find("A:") == 0) {
                t = A; a = t_a.substr(2,-1);
            }
            else if (t_a.find("AAAA:") == 0) {
                t = AAAA;
                a = t_a.substr(5, -1);
            }
            else {
                continue;
            }

            auto const& nameserver = DNS_Resolver::choose_dns_server(0);

            auto resp = std::shared_ptr<DNS_Response>(DNSFactory::get().resolve_dns_s(a, t, nameserver));

            if(resp) {
                if(DNS_Inspector::store(resp)) {
                    _dia("Entry successfully stored in cache.");
                } else {
                    _war("entry for %s was not stored, blacklisted!",t_a.c_str());
                    DNS_Resolver::record_blacklist.insert(t_a);
                }
            }
        }
    }
};

void dns_updater_thread_fn() {

    auto const& log = DNS_Resolver::log;

    const unsigned int sleep_time = 10;
    const unsigned int blacklist_timeout = 120;

    unsigned int dns_cache_laundry_delta = 0;
    unsigned int dns_cache_laundry_ttl = 0;


    for(unsigned int i = 1; ; i++) {

        if(Service::abort_sleep(sleep_time)) {
            break;
        }

        _dia("dns_updater: refresh round %d", i);

        const auto request_candidates = DNS_Resolver::refresh_candidates();
        const auto to_refresh = DNS_Resolver::check_cache_expiry(request_candidates);
        DNS_Resolver::requery_records(to_refresh);

        dns_cache_laundry_delta += sleep_time;
        if(dns_cache_laundry_delta > dns_cache_laundry_ttl) {
            dns_cache_laundry_delta = 0;

            _dia("dns cache laundry executed");
            dns_cache_laundry_ttl = dns_cache_cleanup();
            _dia("next dns cache laundry in %ds", dns_cache_laundry_ttl);
        }


        // do some rescans of blacklisted entries
        if((i*sleep_time) % blacklist_timeout == 0) {
            DNS_Resolver::record_blacklist.clear();
        }

    }
}

std::thread* create_dns_updater() {
    return new std::thread(dns_updater_thread_fn);
}
