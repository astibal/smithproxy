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

#include <service/cfgapi/cfgapi.hpp>
#include <policy/authfactory.hpp>
#include <log/logger.hpp>

int AuthFactory::shm_ip6_table_refresh()  {

    {
        std::scoped_lock<std::recursive_mutex> l_(CfgFactory::lock());

        shm_ip6_map.attach(string_format(AUTH_IP6_MEM_NAME,
                                         CfgFactory::get()->tenant_name.c_str()).c_str(),
                                         AUTH_IP6_MEM_SIZE,
                           string_format(AUTH_IP6_SEM_NAME, CfgFactory::get()->tenant_name.c_str()).c_str());

    }

    _deb("AuthFactory::shm_ip6_table_refresh: acquiring semaphore");
    int rc = shm_ip6_map.acquire();
    _deb("cfgapi_auth_shm_ip6_table_refresh: semaphore acquired");
    if (rc) {
        _war("cfgapi_auth_shm_ip6_table_refresh: cannot acquire semaphore for token table");
        return -1;
    }


    _deb("cfgapi_auth_shm_ip6_table_refresh: loading table");
    int l_ip = shm_ip6_map.load();
    _deb("cfgapi_auth_shm_ip6_table_refresh: loading table: done, releasing semaphore");
    shm_ip6_map.release();
    _deb("cfgapi_auth_shm_ip6_table_refresh: semaphore released");
    
    if(l_ip >= 0) {
        // new data!
        std::scoped_lock<std::recursive_mutex> l_(AuthFactory::get_ip6_lock());
        
        if(l_ip == 0 && ( ! ip6_map_.empty()) ) {
            _dia("cfgapi_auth_shm_ip6_table_refresh: zero sized table received, flushing ip map");
            ip6_map_.clear();
        }
        
        _dia("cfgapi_auth_shm_ip6_table_refresh: new data: version %d, entries %d",shm_ip6_map.header_version(),shm_ip6_map.header_entries());
        for(auto& rt: shm_ip6_map.entries()) {
            
            std::string ip = rt.ip();
            
            auto found = ip6_map_.find(ip);
            if(found != ip6_map_.end()) {
                _dia("Updating identity in database: %s",ip.c_str());
                IdentityInfo6& id = (*found).second;
                id.ip = ip;
                id.last_logon_info = rt;
                id.username = rt.username();
                id.update();
            } else {
                IdentityInfo6 i;
                i.ip = ip;
                i.last_logon_info = rt;
                i.username = rt.username();
                i.update();
                ip6_map_[ip] = i;
                _inf("New identity in database: ip: %s, username: %s, groups: %s ",ip.c_str(),i.username.c_str(),i.groups.c_str());
            }
            _deb("cfgapi_auth_shm_ip6_table_refresh: loaded: %d,%s,%s",ip.c_str(),rt.username().c_str(),rt.groups().c_str());
        }
        
        return l_ip;
    }
    return 0;
}

IdentityInfo6* AuthFactory::ip6_get(std::string& host) {
    IdentityInfo6* ret = nullptr;

    std::scoped_lock<std::recursive_mutex> l_(AuthFactory::get_ip6_lock());
    auto ip = ip6_map_.find(host);

    if (ip != ip6_map_.end()) {
        IdentityInfo6& id = (*ip).second;
        ret  = &id;
    }

    return ret;
}


bool  AuthFactory::ip6_inc_counters(const std::string &host, unsigned int rx, unsigned int tx) {
    bool ret = false;

    std::scoped_lock<std::recursive_mutex> l_(AuthFactory::get_ip6_lock());
    auto ip = ip6_map_.find(host);

    if (ip != ip6_map_.end()) {
        IdentityInfo6& id = (*ip).second;
        id.rx_bytes += rx;
        id.tx_bytes += tx;
        ret = true;
    }
    
    return ret;
}

// remove IP from AUTH IP MAP and synchronize with SHM AUTH IP TABLE (table which is used to communicate with bend daemon)
void AuthFactory::ip6_remove (const std::string &ip6_address) {

    std::scoped_lock<std::recursive_mutex> l_(AuthFactory::get_ip6_lock());
    auto ip = ip6_map_.find(ip6_address);

    if (ip != ip6_map_.end()) {
        // erase internal ip map entry

        _dia("cfgapi_ip_map_remove: auth ip map - removing: %s", ip6_address.c_str());
        ip6_map_.erase(ip);

        // for debug only: print all shm table entries (optimized-out in Release)
        _if_deb {
            _deb(":: - SHM AUTH IP map - before removal::");
            for(auto& x_it: shm_ip6_map.map_entries()) {
                _deb("::  %s::",x_it.first.c_str());
            }
        }
        
        shm_ip6_map.acquire();

        // erase shared ip map entry
        auto sh_it = shm_ip6_map.map_entries().find(ip6_address);

        if(sh_it != shm_ip6_map.map_entries().end()) {
            _dia("cfgapi_ip_map_remove: shm auth ip table  - removing: %s", ip6_address.c_str());
            shm_ip6_map.map_entries().erase(sh_it);

            // optimized-out in Release
            _if_deb {
                _deb(":: - SHM AUTH IP map - after removal::");
                for(auto& x_it: shm_ip6_map.map_entries()) {
                        _deb("::   %s::",x_it.first.c_str());
                }                
                
            }
            shm_ip6_map.save(true);
        }
        shm_ip6_map.release();
    }
}


void AuthFactory::ip6_timeout_check() {
    _deb("cfgapi_ip_auth_timeout_check: started");
    std::scoped_lock<std::recursive_mutex> l_(AuthFactory::get_ip6_lock());
    
    std::set<std::string> to_remove;
    
    for(auto& e: ip6_map_) {
        const std::string&  ip = e.first;
        IdentityInfo6& id = e.second;

        _dia("cfgapi_ip_auth_timeout_check: %s", ip.c_str());
        if(id.i_timeout()) {
            _dia("cfgapi_ip_auth_timeout_check: idle timeout, adding to list %s", ip.c_str());
            to_remove.insert(ip);
        }
    }
    
    for(auto tr: to_remove) {
        ip6_remove(tr);
        _inf("IP address %s identity timed out.", tr.c_str());
    }
}
