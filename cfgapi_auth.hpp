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


#define AUTH_IP_MEM_NAME "/smithproxy_auth_ok"
#define AUTH_IP_MEM_SIZE 64*1024*1024
#define AUTH_IP_SEM_NAME "/smithproxy_auth_ok.sem"


#define AUTH_TOKEN_MEM_NAME "/smithproxy_auth_token"
#define AUTH_TOKEN_MEM_SIZE AUTH_IP_MEM_SIZE 
#define AUTH_TOKEN_SEM_NAME "/smithproxy_auth_token.sem"    
 
#define LOGON_INFO_IP_SZ           4
#define LOGON_INFO_USERNAME_SZ    64
#define LOGON_INFO_GROUPS_SZ     128 

#define LOGON_TOKEN_TOKEN_SZ      64
#define LOGON_TOKEN_URL_SZ       512

#define INFO_HR_OUT_SZ           256



struct logon_info {
    char  ip[LOGON_INFO_IP_SZ];
    char  username[LOGON_INFO_USERNAME_SZ];
    char  groups[LOGON_INFO_GROUPS_SZ];
    
    logon_info() {
        memset(ip,0,LOGON_INFO_IP_SZ);
        memset(username,0,LOGON_INFO_USERNAME_SZ);
        memset(groups,0,LOGON_INFO_GROUPS_SZ);
    }
    logon_info(const char* i,const char* u,const char* g) {
        memset(ip,0,LOGON_INFO_IP_SZ);
        memset(username,0,LOGON_INFO_USERNAME_SZ);
        memset(groups,0,LOGON_INFO_GROUPS_SZ);
        
        inet_aton(i,(in_addr*)ip);
        strncpy(username,u,LOGON_INFO_USERNAME_SZ-1);
        strncpy(groups,g,LOGON_INFO_GROUPS_SZ-1);
    }
    
    std::string hr() { 
        char out[INFO_HR_OUT_SZ]; memset(out,0,INFO_HR_OUT_SZ);
        snprintf(out,INFO_HR_OUT_SZ-1,"%s : %16s \t groups: %s\n",inet_ntoa(*(in_addr*)ip),username,groups); 
        return std::string(out);
    }
};

struct logon_token {
    char   token[64];
    char   url[512];
    
    logon_token() {
        memset(token,0,LOGON_TOKEN_TOKEN_SZ);
        memset(url,0,LOGON_TOKEN_URL_SZ);
    }
    
    logon_token(const char* u) {
        memset(token,0,LOGON_TOKEN_TOKEN_SZ);
        memset(url,0,LOGON_TOKEN_URL_SZ);
        
        std::srand(std::time(0));
        unsigned int r = std::rand();
        snprintf(token,LOGON_TOKEN_TOKEN_SZ,"%d",r);
        strncpy(url,u,LOGON_TOKEN_URL_SZ-1);
    }
    
    logon_token(const char* t, const char* u) {
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
 
// refresh from shared memory
extern int cfgapi_auth_shm_ip_table_refresh();
extern int cfgapi_auth_shm_token_table_refresh(); 

// lookup by ip -> returns pointer IN the auth_ip_map
extern logon_info* cfgapi_auth_get_ip(std::string&);

extern std::unordered_map<std::string,logon_info> auth_ip_map;
extern shared_table<logon_info>  auth_shm_ip_map;
extern shared_table<logon_token> auth_shm_token_map;

// authentication token cache
extern std::recursive_mutex cfgapi_identity_token_lock;
extern std::unordered_map<std::string,std::pair<unsigned int,std::string>> cfgapi_identity_token_cache; // per-ip token cache. Entry is valid for
extern unsigned int cfgapi_identity_token_timeout; // token expires _from_cache_ after this timeout (in seconds).

extern std::string cfgapi_identity_portal_address;
extern std::string cfgapi_identity_portal_port_http;
extern std::string cfgapi_identity_portal_port_https;

#endif