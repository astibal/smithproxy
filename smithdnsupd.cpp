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
#include <sys/socket.h>
#include <openssl/rand.h>

#include <thread>
#include <vector>
#include <set>
#include <time.h>

#include <addrobj.hpp>
#include <dns.hpp>
#include <inspectors.hpp>
#include <cfgapi.hpp>
#include <smithdnsupd.hpp>


int send_dns_request (std::string const& hostname, DNS_Record_Type t, std::string const& nameserver) {
    if (nameserver.empty()) {
        ERR_("resolve_dns_s: query %s for type %s: missing nameserver", hostname.c_str(), dns_record_type_str(t));
    }

    buffer b(256);

    unsigned char rand_pool[2];
    RAND_bytes(rand_pool, 2);
    unsigned short id = *(unsigned short *) rand_pool;

    int s = generate_dns_request(id, b, hostname, t);
    DUM_("DNS generated request: size %db\n%s", s, hex_dump(b).c_str());

    // create UDP socket
    int send_socket = ::socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    struct sockaddr_storage addr;
    memset(&addr, 0, sizeof(struct sockaddr_storage));
    addr.ss_family = AF_INET;
    ((sockaddr_in *) &addr)->sin_addr.s_addr = inet_addr(nameserver.c_str());
    ((sockaddr_in *) &addr)->sin_port = htons(53);

    ::connect(send_socket, (sockaddr *) &addr, sizeof(sockaddr_storage));

    if (::send(send_socket, b.data(), b.size(), 0) < 0) {
        std::string r = string_format("resolve_dns_s: cannot write remote socket: %d", send_socket);
        DIA_("%s", r.c_str());
        return -1;
    }

    return send_socket;
}


std::pair<DNS_Response*,int>  recv_dns_response(int send_socket, unsigned int timeout_sec){
    DNS_Response *ret = nullptr;
    int l = 0;

    if(send_socket <= 0) {
        return {nullptr,-1};
    }

    int rv = 1;

    if(timeout_sec > 0) {
        struct timeval tv;
        tv.tv_usec = 0;
        tv.tv_sec = timeout_sec;

        fd_set confds;
        FD_ZERO(&confds);
        FD_SET(send_socket, &confds);
        rv = select(send_socket + 1, &confds, NULL, NULL, &tv);
    } else {

    }
    if(rv == 1) {
        buffer r(1500);
        l = ::recv(send_socket,r.data(),r.capacity(), timeout_sec > 0 ? 0 : MSG_DONTWAIT);
        DEB_("recv_dns_response(%d,%d): recv() returned %d",send_socket, timeout_sec, l);

        DEB_("buffer: ptr=0x%x, size=%d, capacity=%d",r.data(),r.size(),r.capacity());

        if(l > 0) {
            int parsed = -1;

            r.size(l);

            DEB_("received %d bytes",l);
            DUM_("\n%s\n",hex_dump(r).c_str());


            DNS_Response* resp = new DNS_Response();
            parsed = resp->load(&r);
            DIA_("parsed %d bytes (0 means all)",parsed);
            DIA_("DNS response: \n %s",resp->to_string().c_str());

            // save only fully parsed messages
            if(parsed == 0) {
                ret = resp;

            } else {
                ret = resp;
                ERRS_("Something went wrong with parsing DNS response (keeping response)");
                //delete resp;
            }

        }

    } else {
        DIAS_("synchronous mode: timeout, or an error occurred.");
    }

    return {ret,l};
}

DNS_Response* resolve_dns_s (std::string hostname, DNS_Record_Type t, std::string nameserver, unsigned int timeout_s) {

    int send_socket = send_dns_request(hostname, t, nameserver);
    auto resp = recv_dns_response(send_socket,timeout_s);

    ::close(send_socket);
    return resp.first;

}



#pragma clang diagnostic ignored "-Wmissing-noreturn"

std::thread* create_dns_updater() {
    std::thread * dns_thread = new std::thread([]() {

    int sleep_time = 3;
    int requery_ttl = 60;
    std::set<std::string> record_blacklist;

    for(unsigned int i = 1; ; i++) {

        DIA_("dns_updater: refresh round %d",i);

        std::vector<std::string> fqdns;
        CfgFactory::get().cfgapi_write_lock.lock();
        for (auto a: CfgFactory::get().cfgapi_obj_address) {
            FqdnAddress* fa = dynamic_cast<FqdnAddress*>(a.second);
            if(fa) {
                std::vector<std::string> recs;
                recs.push_back("A:" + fa->fqdn());
                recs.push_back("AAAA:" + fa->fqdn());

                std::lock_guard<std::recursive_mutex> l_(inspect_dns_cache.getlock());
                for(auto rec: recs) {
                    DNS_Response* r = inspect_dns_cache.get(rec);
                    if(r) {
                        int ttl = (r->loaded_at + r->answers().at(0).ttl_) - ::time(nullptr);

                        DIA_("fqdn %s ttl %d",rec.c_str(),ttl);

                        //re-query only about-to-expire existing DNS entries for FQDN addresses
                        if(ttl < requery_ttl) {
                            fqdns.push_back(rec);
                        }
                    }
                    else {
                        // query FQDNs without DNS cache entry
                        if(record_blacklist.find(rec) == record_blacklist.end()) {
                            fqdns.push_back(rec);
                        } else {
                            DIA_("fqdn %s is blacklisted",rec.c_str());
                        }
                    }
                }
            }
        }
        CfgFactory::get().cfgapi_write_lock.unlock();


        std::string nameserver = "8.8.8.8";
        if(CfgFactory::get().cfgapi_obj_nameservers.size()) {
            nameserver = CfgFactory::get().cfgapi_obj_nameservers.at(i % CfgFactory::get().cfgapi_obj_nameservers.size());
        }

        DNS_Inspector di;
        for(const auto& t_a: fqdns) {
            DIA_("refreshing fqdn: %s",t_a.c_str());

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



            DNS_Response* resp = resolve_dns_s(a, t, nameserver);
            if(resp) {
                if(di.store(resp)) {
                    DIAS_("Entry successfully stored in cache.");
                } else {
                    WAR_("entry for %s was not stored, blacklisted!",t_a.c_str());
                    record_blacklist.insert(t_a);
                    delete resp;
                }
            }
        }

        // do some rescans of blacklisted entries
        if(i % (20*sleep_time) == 0) {
            record_blacklist.clear();
        }


        ::sleep(sleep_time);
    } } );
      
    
    return dns_thread;
}
