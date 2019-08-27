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
#include <random>

#include <buffer.hpp>
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


struct shm_logon_info_base {
    
    virtual std::string ip() = 0;
    virtual std::string username() = 0;
    virtual std::string groups() = 0;
    
    virtual shm_logon_info_base* clone() = 0;
    
    virtual ~shm_logon_info_base() = default;
};

// structure exchanged with backend daemon
template <int AddressSize>
struct shm_logon_info_ : public shm_logon_info_base {

    buffer buffer_;
    virtual buffer* data() { return &buffer_; }
    
    ~shm_logon_info_() override = default;

    static unsigned int record_size () {
        return AddressSize+LOGON_INFO_USERNAME_SZ+LOGON_INFO_GROUPS_SZ;
    }

    shm_logon_info_() {
        buffer_.size(record_size());
        buffer_.fill(0);
    }
    
    int load(unsigned char* b) {
        buffer_.assign(b,record_size());
        return buffer_.size();
    };
    
    shm_logon_info_(const char* i,const char* u,const char* g) {
        buffer_.size(record_size());
        buffer_.fill(0);
        
        if(AddressSize == 4) {
            inet_pton(AF_INET,i,buffer_.data());
        }
        else if (AddressSize == 16) {
            inet_pton(AF_INET6,i,buffer_.data());
        }
        strncpy((char*)&buffer_.data()[AddressSize],u,LOGON_INFO_USERNAME_SZ-1);
        strncpy((char*)&buffer_.data()[AddressSize+LOGON_INFO_USERNAME_SZ],g,LOGON_INFO_GROUPS_SZ-1);
    }
    
    std::string ip() override {
        char b[64]; memset(b,0,64);
        
        if(AddressSize == 16) {
            inet_ntop(AF_INET6,buffer_.data(),b,64);
            return std::string(b);
        }
        
        inet_ntop(AF_INET,buffer_.data(),b,64);
        return std::string(b);
    }
    
    std::string username() override {
        return std::string((const char*)&buffer_.data()[AddressSize]);
    }
    
    std::string groups() override {
        return std::string((const char*)&buffer_.data()[AddressSize+LOGON_INFO_USERNAME_SZ]);
    }
    
    shm_logon_info_base* clone() override {
        auto* n =  new shm_logon_info_<AddressSize>(); //return a clone of this object
        *n->data() = *data();
        
        return n;
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
    
    buffer buffer_;
    virtual buffer* data() { return &buffer_; }
    
    std::string token() const { return std::string((const char*)buffer_.data()); };
    std::string url() const { return std::string((const char*)&buffer_.data()[LOGON_TOKEN_TOKEN_SZ]);};

    static unsigned int record_size() { return LOGON_TOKEN_TOKEN_SZ+LOGON_TOKEN_URL_SZ; }
    
    shm_logon_token() {
        buffer_.size(LOGON_TOKEN_TOKEN_SZ+LOGON_TOKEN_URL_SZ);
        buffer_.fill(0);
    }
    
    explicit shm_logon_token(const char* u) {
        buffer_.size(LOGON_TOKEN_TOKEN_SZ+LOGON_TOKEN_URL_SZ);
        buffer_.fill(0);

        std::default_random_engine generator(time(0)+last_random);
        std::uniform_int_distribution<int> distribution(0xCABA1A);

        int number = distribution(generator);
        last_random = number;

        unsigned int r = last_random;
        snprintf((char*)buffer_.data(),LOGON_TOKEN_TOKEN_SZ,"%d",r);
        strncpy((char*)&buffer_.data()[LOGON_TOKEN_TOKEN_SZ],u,LOGON_TOKEN_URL_SZ-1);
    }
    
    shm_logon_token(const char* t, const char* u) {
        strncpy((char*)buffer_.data(),t,LOGON_TOKEN_TOKEN_SZ-1);
        strncpy((char*)&buffer_.data()[LOGON_TOKEN_TOKEN_SZ],u,LOGON_TOKEN_URL_SZ-1);
    }
    
    int load(unsigned char* b) {
        buffer_.assign(b,LOGON_TOKEN_TOKEN_SZ+LOGON_TOKEN_URL_SZ);
        
        return buffer_.size();
    };    
    
    std::string hr() { 
        return string_format("%s : %16s\n",token().c_str(),url().c_str());
    };
private:
    unsigned int last_random = 0;
}; 
 

//structure kept in the smithproxy to track IP address identity and history



struct IdentityInfoBase {
   
    static unsigned int global_idle_timeout;
    
    unsigned int idle_timeout = 0;

    unsigned int created;
    std::string  ip;
    std::string  username;
    std::string  groups;
    
    std::vector<std::string> groups_vec;
    
    unsigned int rx_bytes = 0;
    unsigned int tx_bytes = 0;
    
    unsigned int last_seen_at;
    unsigned int last_seen_policy;
    
    IdentityInfoBase() {
        idle_timeout = global_idle_timeout; 
        created = time(nullptr);
        last_seen_at = created;
    }
    
    inline void touch() { last_seen_at = time(nullptr); }
    inline bool i_timeout() const { return ( (time(nullptr) - last_seen_at) > idle_timeout ); }
    inline int i_time() const { return time(nullptr) - last_seen_at; }
    inline int uptime() const { return time(nullptr) - created; }
    virtual void update() {};
};

template <class ShmLogonType>
struct IdentityInfoType : public IdentityInfoBase {
    ShmLogonType last_logon_info;
    
    IdentityInfoType() : IdentityInfoBase() {}

    virtual void update() {
        groups = last_logon_info.groups();
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
    virtual std::string get_row_key(ShmLogonType* r) { return r->ip(); }
};

typedef shared_logoninfotype_ntoa_map<shm_logon_info,4> shared_ip_map;
typedef shared_logoninfotype_ntoa_map<shm_logon_info6,16> shared_ip6_map;

// refresh from shared memory
extern int cfgapi_auth_shm_token_table_refresh(); 

// lookup by ip -> returns pointer IN the auth_ip_map
extern int cfgapi_auth_shm_ip_table_refresh();
extern IdentityInfo* cfgapi_ip_auth_get(std::string&);
extern bool  cfgapi_ip_auth_inc_counters(std::string& host, unsigned int rx, unsigned int tx);
extern void cfgapi_ip_auth_remove(std::string&);
extern void cfgapi_ip_auth_timeout_check(void);

// lookup by ip -> returns pointer IN the auth_ip_map
extern int cfgapi_auth_shm_ip6_table_refresh();
extern IdentityInfo6* cfgapi_ip6_auth_get(std::string&);
extern bool  cfgapi_ip6_auth_inc_counters(std::string& host, unsigned int rx, unsigned int tx);
extern void cfgapi_ip6_auth_remove(std::string&);
extern void cfgapi_ip6_auth_timeout_check(void);


class baseHostCX;
bool cfgapi_ipX_auth_inc_counters(baseHostCX* cx, unsigned int rx, unsigned int tx);
bool cfgapi_ipX_auth_inc_counters(baseHostCX* cx);


extern std::recursive_mutex cfgapi_identity_ip_lock;
extern std::unordered_map<std::string,IdentityInfo> auth_ip_map;
extern shared_ip_map  auth_shm_ip_map;

extern std::recursive_mutex cfgapi_identity_ip6_lock;
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
