
#include <cfgapi.hpp>
#include <cfgapi_auth.hpp>
#include <logger.hpp>


unsigned int IdentityInfo::global_idle_timeout = 3600;

std::unordered_map<std::string,IdentityInfo> auth_ip_map;
//shared_table<logon_info>  auth_shm_ip_map;
shared_ip_map auth_shm_ip_map;
shared_table<logon_token> auth_shm_token_map;

// authentication token cache
std::recursive_mutex cfgapi_identity_token_lock;
std::recursive_mutex cfgapi_identity_ip_lock;
std::unordered_map<std::string,std::pair<unsigned int,std::string>> cfgapi_identity_token_cache; // per-ip token cache. Entry is valid for
unsigned int cfgapi_identity_token_timeout = 20; // token expires _from_cache_ after this timeout (in seconds).

std::string cfgapi_identity_portal_address = "192.168.0.1";
std::string cfgapi_identity_portal_port_http = "8008";
std::string cfgapi_identity_portal_port_https = "8043";

int cfgapi_auth_shm_ip_table_refresh()  {
    std::lock_guard<std::recursive_mutex> l(cfgapi_write_lock);
    
    auth_shm_ip_map.attach(AUTH_IP_MEM_NAME,AUTH_IP_MEM_SIZE,AUTH_IP_SEM_NAME);
    
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
    
    if(l_ip > 0) {
        // new data!
        cfgapi_identity_ip_lock.lock();
        
        DIA_("cfgapi_auth_shm_ip_table_refresh: new data: version %d, entries %d",auth_shm_ip_map.header_version(),auth_shm_ip_map.header_entries());
        for(typename std::vector<logon_info>::iterator i = auth_shm_ip_map.entries().begin(); i != auth_shm_ip_map.entries().end() ; ++i) {
            logon_info& rt = (*i);
            
            std::string ip = std::string(inet_ntoa(*(in_addr*)&rt.ip));
            
            std::unordered_map <std::string, IdentityInfo >::iterator found = auth_ip_map.find(ip);
            if(found != auth_ip_map.end()) {
                INF_("Updating identity in database: %s",ip.c_str());
                IdentityInfo& id = (*found).second;
                id.last_logon_info = rt;
                id.update_groups_vec();
            } else {
                INF_("New identity in database: %s ",ip.c_str());
                IdentityInfo i;
                i.last_logon_info = rt;
                i.update_groups_vec();
                auth_ip_map[ip] = i;
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
    
    auth_shm_token_map.attach(AUTH_TOKEN_MEM_NAME,AUTH_TOKEN_MEM_SIZE,AUTH_TOKEN_SEM_NAME);

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

