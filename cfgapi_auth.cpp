
#include <cfgapi.hpp>
#include <cfgapi_auth.hpp>
#include <logger.hpp>


unsigned int IdentityInfo::global_idle_timeout = 600;

std::unordered_map<std::string,IdentityInfo> auth_ip_map;
//shared_table<logon_info>  auth_shm_ip_map;
shared_ip_map auth_shm_ip_map;
shared_table<shm_logon_token> auth_shm_token_map;

// authentication token cache
std::recursive_mutex cfgapi_identity_token_lock;
std::recursive_mutex cfgapi_identity_ip_lock;
std::unordered_map<std::string,std::pair<unsigned int,std::string>> cfgapi_identity_token_cache; // per-ip token cache. Entry is valid for
unsigned int cfgapi_identity_token_timeout = 20; // token expires _from_cache_ after this timeout (in seconds).

std::string cfgapi_identity_portal_address = "192.168.0.1";
std::string cfgapi_identity_portal_address6 = "";
std::string cfgapi_identity_portal_port_http = "8008";
std::string cfgapi_identity_portal_port_https = "8043";

int cfgapi_auth_shm_ip_table_refresh()  {
    std::lock_guard<std::recursive_mutex> l(cfgapi_write_lock);
    
    auth_shm_ip_map.attach(string_format(AUTH_IP_MEM_NAME,cfgapi_tenant_name.c_str()).c_str(),AUTH_IP_MEM_SIZE,string_format(AUTH_IP_SEM_NAME,cfgapi_tenant_name.c_str()).c_str());
    
    DEBS_("cfgapi_auth_shm_ip_table_refresh: acquring semaphore");
    int rc = auth_shm_ip_map.acquire();
    DIAS_("cfgapi_auth_shm_ip_table_refresh: acquring semaphore: done");
    if(rc) {
        WARS_("cfgapi_auth_shm_ip_table_refresh: cannot acquire semaphore for token table");
        return -1;
    }
    
    DEBS_("cfgapi_auth_shm_ip_table_refresh: loading table");
    int l_ip = auth_shm_ip_map.load();
    DIAS_("cfgapi_auth_shm_ip_table_refresh: loading table: done, releasing semaphore");
    auth_shm_ip_map.release();
    DEBS_("cfgapi_auth_shm_ip_table_refresh: semaphore released");
    
    if(l_ip >= 0) {
        // new data!
        cfgapi_identity_ip_lock.lock();
        
        if(l_ip == 0 && auth_ip_map.size() > 0) {
            DIAS_("cfgapi_auth_shm_ip_table_refresh: zero sized table received, flusing ip map");
            auth_ip_map.clear();
        }
        
        DIA_("cfgapi_auth_shm_ip_table_refresh: new data: version %d, entries %d",auth_shm_ip_map.header_version(),auth_shm_ip_map.header_entries());
        for(typename std::vector<shm_logon_info>::iterator i = auth_shm_ip_map.entries().begin(); i != auth_shm_ip_map.entries().end() ; ++i) {
            shm_logon_info& rt = (*i);
            
            std::string ip = std::string(inet_ntoa(*(in_addr*)&rt.ip));
            
            std::unordered_map <std::string, IdentityInfo >::iterator found = auth_ip_map.find(ip);
            if(found != auth_ip_map.end()) {
                DIA_("Updating identity in database: %s",ip.c_str());
                IdentityInfo& id = (*found).second;
                id.last_logon_info = rt;
                id.username = rt.username;
                id.update_groups_vec();
            } else {
                IdentityInfo i;
                i.last_logon_info = rt;
                i.username = rt.username;
                i.update_groups_vec();
                auth_ip_map[ip] = i;
                INF_("New identity in database: ip: %s, username: %s, groups: %s ",ip.c_str(),i.username.c_str(),i.groups.c_str());
            }
            DIA_("cfgapi_auth_shm_ip_table_refresh: loaded: %d,%s,%s",ip.c_str(),rt.username,rt.groups);
        }
        cfgapi_identity_ip_lock.unlock();
        
        return l_ip;
    }
    return 0;
}

int cfgapi_auth_shm_token_table_refresh()  {
    std::lock_guard<std::recursive_mutex> l(cfgapi_write_lock);
    
    auth_shm_token_map.attach(string_format(AUTH_TOKEN_MEM_NAME,cfgapi_tenant_name.c_str()).c_str(),AUTH_TOKEN_MEM_SIZE,string_format(AUTH_TOKEN_SEM_NAME,cfgapi_tenant_name.c_str()).c_str());

    DEBS_("cfgapi_auth_shm_token_table_refresh: acquring semaphore");
    int rc = auth_shm_token_map.acquire();
    DIAS_("cfgapi_auth_shm_token_table_refresh: acquring semaphore: done");
    if(rc) {
        WARS_("cfgapi_auth_shm_token_table_refresh: cannot acquire semaphore for token table");
        return -1;
    }
    
    DEBS_("cfgapi_auth_shm_token_table_refresh: loading table");
    int l_tok = auth_shm_token_map.load();
    DIAS_("cfgapi_auth_shm_token_table_refresh: loading table: done, releasing semaphore");
    auth_shm_token_map.release();
    DEBS_("cfgapi_auth_shm_token_table_refresh: semaphore released");

    if(l_tok > 0) {
        DIA_("cfgapi_auth_shm_token_table_refresh: new data: version %d, entries %d, rowsize %d",auth_shm_token_map.header_version(),auth_shm_token_map.header_entries(),auth_shm_token_map.header_rowsize());
        return l_tok;
    } else {
        DEB_("cfgapi_auth_shm_token_table_refresh: same data: version %d, entries %d, rowsize %d",auth_shm_token_map.header_version(),auth_shm_token_map.header_entries(),auth_shm_token_map.header_rowsize());
    }
    
    return 0;
};

IdentityInfo* cfgapi_ip_auth_get(std::string& host) {
    IdentityInfo* ret = nullptr;

    cfgapi_identity_ip_lock.lock();    
    auto ip = auth_ip_map.find(host);

    if (ip != auth_ip_map.end()) {
        IdentityInfo& id = (*ip).second;
        ret  = &id;
    }
    
    cfgapi_identity_ip_lock.unlock();
    return ret;
   
}


// remove IP from AUTH IP MAP and synchronize with SHM AUTH IP TABLE (table which is used to communicate with bend daemon)
void cfgapi_ip_auth_remove(std::string& host) {

    cfgapi_identity_ip_lock.lock();    
    auto ip = auth_ip_map.find(host);

    if (ip != auth_ip_map.end()) {
        // erase internal ip map entry

        DIA_("cfgapi_ip_map_remove: auth ip map - removing: %s",host.c_str());
        auth_ip_map.erase(ip);

        // for debug only: print all shm table entries
        if(LEV_(DEB)) {
            DEBS_(":: - SHM AUTH IP map - before removal::");
            for(auto& x_it: auth_shm_ip_map.map_entries()) {
                DEB_("::  %s::",x_it.first.c_str());
            }
        }
        
        auth_shm_ip_map.acquire();

        // erase shared ip map entry
        auto sh_it = auth_shm_ip_map.map_entries().find(host);

        if(sh_it != auth_shm_ip_map.map_entries().end()) {
            DIA_("cfgapi_ip_map_remove: shm auth ip table  - removing: %s",host.c_str());
            auth_shm_ip_map.map_entries().erase(sh_it);
            
            if(LEV_(DEB)) {
                DEBS_(":: - SHM AUTH IP map - after removal::");
                for(auto& x_it: auth_shm_ip_map.map_entries()) {
                        DEB_("::   %s::",x_it.first.c_str());
                }                
                
            }
            auth_shm_ip_map.save(true);
        }
        auth_shm_ip_map.release();
    }
    cfgapi_identity_ip_lock.unlock();
}


void cfgapi_ip_auth_timeout_check(void) {
    DIAS_("cfgapi_ip_auth_timeout_check: started");
    cfgapi_identity_ip_lock.lock();
    
    std::set<std::string> to_remove;
    
    for(auto& e: auth_ip_map) {
        const std::string&  ip = e.first;
        IdentityInfo& id = e.second;
        
        DIA_("cfgapi_ip_auth_timeout_check: %s", ip.c_str());
        if(id.i_timeout()) {
            DIA_("cfgapi_ip_auth_timeout_check: idle timeout, adding to list %s", ip.c_str());
            to_remove.insert(ip);
        }
    }
    
    for(auto tr: to_remove) {
        cfgapi_ip_auth_remove(tr);
        INF_("IP address %s identity timed out.", tr.c_str());
    }
    
    cfgapi_identity_ip_lock.unlock();
}
