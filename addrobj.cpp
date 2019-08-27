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

#include <addrobj.hpp>
#include <dns.hpp>
#include <sstream>

int CidrAddress::contains(CIDR* other) {
    return cidr_contains(c_,other);
}


std::string FqdnAddress::to_string(int verbosity) {

    std::stringstream ret;

    ret << "FqdnAddress: " + fqdn_;
 
    bool cached_a = false;
    bool cached_4a= false;
    if(verbosity > INF) {

        std::scoped_lock<std::recursive_mutex> l_(DNS::get_dns_lock());

        if(DNS::get_dns_cache().get("A:"+fqdn_) != nullptr) {
            cached_a = true;
        }
        if(DNS::get_dns_cache().get("AAAA:"+fqdn_) != nullptr) {
            cached_4a = true;
        }

        if(cached_4a or cached_a) {
            ret << " (cached";
            if(cached_a) ret << " A";
            if(cached_4a) ret << " AAAA";
            ret << ")";
        } else {
            ret << " (not cached)";
        }
    }

    if(! prof_name.empty()) {
        ret << string_format(" (name=%s)", prof_name.c_str());
    }

    return ret.str();
}


bool FqdnAddress::match(CIDR* c) {
    bool ret = false;
    
    DNS_Response* r = nullptr;


    {
        std::scoped_lock<std::recursive_mutex> l_(DNS::get_dns_lock());

        if (c->proto == CIDR_IPV4) {
            r = DNS::get_dns_cache().get("A:" + fqdn_);
        } else if (c->proto == CIDR_IPV6) {
            r = DNS::get_dns_cache().get("AAAA:" + fqdn_);
        }
    }

    if(r != nullptr) {
        DEB___("FqdnAddress::match: found in cache: %s",fqdn_.c_str());
        
        std::vector<CidrAddress*> ips = r->get_a_anwsers();
        
        int i = 0;
        for(CidrAddress* ip: ips) {
            if(ip->match(c)) {
                DEB___("FqdnAddress::match: cached %s matches answer[%d] with %s",
                                                fqdn_.c_str(),i,ip->to_string().c_str());
                ret = true;
            } else {
                DEB___("FqdnAddress::match: cached %s DOESN'T match answer[%d] with %s",
                                                fqdn_.c_str(),i,ip->to_string().c_str());
            }
            ++i;
            // delete it straigt away.
            delete ip;
        }
        
    } else {
        DEB___("FqdnAddress::match: NOT found in cache: %s",fqdn_.c_str());
    }
    
    return ret;
}
