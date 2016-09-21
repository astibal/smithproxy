#ifndef CFGAPI_AUTH_HPP
  #define CFGAPI_AUTH_HPP

#include <cstring>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <string>
#include <unordered_map>
#include <cstdlib>
#include <ctime>

#include <shmtable.hpp>


#define AUTH_IP_MEM_NAME "/smithproxy_auth_ok_%s"
#define AUTH_IP_MEM_SIZE 64*1024*1024
#define AUTH_IP_SEM_NAME "/smithproxy_auth_ok_%s.sem"

#define AUTH_IP6_MEM_NAME "/smithproxy_auth6_ok_%s"
#define AUTH_IP6_MEM_SIZE 64*1024*1024
#define AUTH_IP6_SEM_NAME "/smithproxy_auth6_ok_%s.sem"


#define AUTH_TOKEN_MEM_NAME "/smithproxy_auth_token_%s"
#define AUTH_TOKEN_MEM_SIZE AUTH_IP_MEM_SIZE 
#define AUTH_TOKEN_SEM_NAME "/smithproxy_auth_token_%s.sem"    
 
#define LOGON_INFO_IP_SZ           4
#define LOGON_INFO_USERNAME_SZ    64
#define LOGON_INFO_GROUPS_SZ     128 

#define LOGON_TOKEN_TOKEN_SZ      64
#define LOGON_TOKEN_URL_SZ       512

#define INFO_HR_OUT_SZ           256



// structure exchanged with backend daemon
template <int AddressSize>
struct shm_logon_info_ {
    char  ip[AddressSize];
    char  username[LOGON_INFO_USERNAME_SZ];
    char  groups[LOGON_INFO_GROUPS_SZ];
    
    shm_logon_info_() {
        memset(ip,0,AddressSize);
        memset(username,0,LOGON_INFO_USERNAME_SZ);
        memset(groups,0,LOGON_INFO_GROUPS_SZ);
    }
    shm_logon_info_(const char* i,const char* u,const char* g) {
        memset(ip,0,AddressSize);
        memset(username,0,LOGON_INFO_USERNAME_SZ);
        memset(groups,0,LOGON_INFO_GROUPS_SZ);
        
        if(AddressSize == 4) {
            inet_pton(AF_INET,i,ip);
        }
        else if (AddressSize == 16) {
            inet_pton(AF_INET6,i,ip);
        }
        strncpy(username,u,LOGON_INFO_USERNAME_SZ-1);
        strncpy(groups,g,LOGON_INFO_GROUPS_SZ-1);
    }
    
//     std::string hr() { 
//         char out[INFO_HR_OUT_SZ]; memset(out,0,INFO_HR_OUT_SZ);
//         snprintf(out,INFO_HR_OUT_SZ-1,"%s : %16s \t groups: %s\n",inet_ntoa(*(in_addr*)ip),username,groups); 
//         return std::string(out);
//     }
};

typedef shm_logon_info_<4> shm_logon_info;
typedef shm_logon_info_<16> shm_logon_info6;

// structure exchanged with backend daemon
struct shm_logon_token {
    char   token[64];
    char   url[512];
    
    shm_logon_token() {
        memset(token,0,LOGON_TOKEN_TOKEN_SZ);
        memset(url,0,LOGON_TOKEN_URL_SZ);
    }
    
    shm_logon_token(const char* u) {
        memset(token,0,LOGON_TOKEN_TOKEN_SZ);
        memset(url,0,LOGON_TOKEN_URL_SZ);
        
        std::srand(std::time(0));
        unsigned int r = std::rand();
        snprintf(token,LOGON_TOKEN_TOKEN_SZ,"%d",r);
        strncpy(url,u,LOGON_TOKEN_URL_SZ-1);
    }
    
    shm_logon_token(const char* t, const char* u) {
        memset(token,0,LOGON_TOKEN_TOKEN_SZ);
        memset(url,0,LOGON_TOKEN_URL_SZ);
        
        strncpy(token,t,LOGON_TOKEN_TOKEN_SZ-1);
        strncpy(url,u,LOGON_TOKEN_URL_SZ-1);
    }
    
    std::string hr() { 
        char out[INFO_HR_OUT_SZ]; memset(out,0,INFO_HR_OUT_SZ);
        snprintf(out,INFO_HR_OUT_SZ-1,"%s : %16s\n",token,url); 
        return std::string(out);
    };
}; 
 

//structure kept in the smithproxy to track IP address identity and history

template <class ShmLogonType>
struct IdentityInfoType {
    static unsigned int global_idle_timeout;
    
    unsigned int idle_timeout = 0;

    unsigned int created;
    std::string  ip_address;
    std::string  username;
    std::string  groups;
    std::vector<std::string> groups_vec;
    
    unsigned int rx_bytes = 0;
    unsigned int tx_bytes = 0;
    
    unsigned int last_seen_at;
    unsigned int last_seen_policy;
    ShmLogonType last_logon_info;
    
    IdentityInfoType() {
        idle_timeout = global_idle_timeout; 
        created = time(nullptr);
        last_seen_at = created;
    }
    
    inline void touch() { last_seen_at = time(nullptr); }
    inline bool i_timeout() { return ( (time(nullptr) - last_seen_at) > idle_timeout ); }
    void update_groups_vec() {
        groups = last_logon_info.groups;
        groups_vec.clear();
        
        int pos = 0;
        int old_pos = 0;
        while(true) {
            pos = groups.find("+",pos);
            if(pos > old_pos && pos != static_cast<int>(std::string::npos)) {
                std::string x  = groups.substr(old_pos,pos-old_pos);
                groups_vec.push_back(x);
                
                old_pos = pos + 1;
                pos++;
                groups.find('+',pos);
            } else {
                std::string x  = groups.substr(old_pos,groups.size()-old_pos);
                groups_vec.push_back(x);
                break;
            }
        }
    }
};

typedef IdentityInfoType<shm_logon_info> IdentityInfo;
typedef IdentityInfoType<shm_logon_info6> IdentityInfo6;

template<class ShmLogonType,int AddressSize>
class shared_logoninfotype_ntoa_map : public shared_map<std::string,ShmLogonType> {
    virtual std::string get_row_key(ShmLogonType* r) {
        char b[64];
        memset(b,0,64);
        
        if(AddressSize == 4) {
            inet_ntop(AF_INET,r->ip,b,64);
            return std::string(b);
        }
        else if(AddressSize == 16) {
            inet_ntop(AF_INET6,r->ip,b,64);
            return std::string(b);
        }
    }
};

typedef shared_logoninfotype_ntoa_map<shm_logon_info,4> shared_ip_map;
typedef shared_logoninfotype_ntoa_map<shm_logon_info6,16> shared_ip6_map;

// refresh from shared memory
extern int cfgapi_auth_shm_ip_table_refresh();
extern int cfgapi_auth_shm_token_table_refresh(); 

// lookup by ip -> returns pointer IN the auth_ip_map
extern IdentityInfo* cfgapi_ip_auth_get(std::string&);
extern void cfgapi_ip_auth_remove(std::string&);
extern void cfgapi_ip_auth_timeout_check(void);

extern std::recursive_mutex cfgapi_identity_ip_lock;

extern std::unordered_map<std::string,IdentityInfo> auth_ip_map;
extern shared_ip_map  auth_shm_ip_map;

extern std::unordered_map<std::string,IdentityInfo6> auth_ip6_map;
extern shared_ip6_map auth_shm_ip6_map;

extern shared_table<shm_logon_token> auth_shm_token_map;

// authentication token cache
extern std::recursive_mutex cfgapi_identity_token_lock;
extern std::unordered_map<std::string,std::pair<unsigned int,std::string>> cfgapi_identity_token_cache; // per-ip token cache. Entry is valid for
extern unsigned int cfgapi_identity_token_timeout; // token expires _from_cache_ after this timeout (in seconds).

extern std::string cfgapi_identity_portal_address;
extern std::string cfgapi_identity_portal_address6;
extern std::string cfgapi_identity_portal_port_http;
extern std::string cfgapi_identity_portal_port_https;

#endif
