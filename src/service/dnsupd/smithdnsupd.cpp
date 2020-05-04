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
#include <cfgapi.hpp>

#include <service/core/smithproxy.hpp>


std::thread* create_dns_updater() {
    auto* dns_thread = new std::thread([]() {

    logan_lite log = logan_lite("com.dns.updater");

    unsigned int sleep_time = 3;
    int requery_ttl = 60;
    std::set<std::string> record_blacklist;

    for(unsigned int i = 1; ; i++) {

        if(Service::abort_sleep(sleep_time)) {
            break;
        }

        _dia("dns_updater: refresh round %d", i);

        std::vector<std::string> fqdns;

        {
            std::lock_guard<std::recursive_mutex> l_(CfgFactory::lock());
            for (auto const& a: CfgFactory::get().db_address) {
                auto fa = std::dynamic_pointer_cast<FqdnAddress>(a.second);
                if (fa) {
                    std::vector<std::string> recs;
                    recs.push_back("A:" + fa->fqdn());
                    recs.push_back("AAAA:" + fa->fqdn());

                    std::scoped_lock<std::recursive_mutex> ll_(DNS::get_dns_lock());
                    for (auto const& rec: recs) {
                        auto dns_response = DNS::get_dns_cache().get(rec);
                        if (dns_response) {
                            long ttl = (dns_response->loaded_at + dns_response->answers().at(0).ttl_) - ::time(nullptr);

                            _dia("fqdn %s ttl %d", rec.c_str(), ttl);

                            //re-query only about-to-expire existing DNS entries for FQDN addresses
                            if (ttl < requery_ttl) {
                                fqdns.push_back(rec);
                            }
                        } else {
                            // query FQDNs without DNS cache entry
                            if (record_blacklist.find(rec) == record_blacklist.end()) {
                                fqdns.push_back(rec);
                            } else {
                                _dia("fqdn %s is blacklisted", rec.c_str());
                            }
                        }
                    }
                }
            }
        }

        std::string nameserver = "8.8.8.8";
        if(! CfgFactory::get().db_nameservers.empty() ) {
            nameserver = CfgFactory::get().db_nameservers.at(i % CfgFactory::get().db_nameservers.size());
        }

        DNS_Inspector di;
        for(const auto& t_a: fqdns) {
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



            DNS_Response* resp = DNSFactory::get().resolve_dns_s(a, t, nameserver);
            if(resp) {
                if(di.store(resp)) {
                    _dia("Entry successfully stored in cache.");
                } else {
                    _war("entry for %s was not stored, blacklisted!",t_a.c_str());
                    record_blacklist.insert(t_a);
                    delete resp;
                }
            }
        }

        // do some rescans of blacklisted entries
        if(i % (20*sleep_time) == 0) {
            record_blacklist.clear();
        }

    } } );
      
    
    return dns_thread;
}
