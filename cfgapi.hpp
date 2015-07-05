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
    
*/    

#ifndef CFGAPI_HPP
 #define CFGAPI_HPP

#include <vector>
#include <map>
#include <mutex>
 
#include <libconfig.h++>
#include <cidr.hpp>
#include <ranges.hpp>
#include <policy.hpp>

#include <cfgapi_auth.hpp>

#define PROTO_ICMP 1
#define PROTO_TCP  6
#define PROTO_UDP  17


#define CFGAPI_LOCKED(x)    \
    {                       \
        std::lock_guard<std::recursive_mutex> l(cfgapi_write_lock);\
        (x);                \
    }                       \

using namespace libconfig;
extern Config cfgapi;
extern std::map<std::string,CIDR*> cfgapi_obj_address;
extern std::map<std::string,range> cfgapi_obj_port;
extern std::map<std::string,int> cfgapi_obj_proto;
extern std::vector<PolicyRule*> cfgapi_obj_policy;
extern std::map<std::string,ProfileDetection*> cfgapi_obj_profile_detection;
extern std::map<std::string,ProfileContent*> cfgapi_obj_profile_content;
extern std::map<std::string,ProfileTls*> cfgapi_obj_profile_tls;
extern std::map<std::string,ProfileAuth*> cfgapi_obj_profile_auth;
extern std::map<std::string,ProfileAlgDns*> cfgapi_obj_profile_alg_dns;

extern std::recursive_mutex cfgapi_write_lock;


struct logging_{
    unsigned int level = INF;
    unsigned int cli_init_level = ERR;
} ;

struct cfgapi_table_ {
    logging_ logging;
};


extern struct cfgapi_table_ cfgapi_table;


bool  cfgapi_init(const char* fnm);
void  cfgapi_cleanup();

CIDR* cfgapi_lookup_address(const char* name);
range cfgapi_lookup_port(const char* name);
int   cfgapi_lookup_proto(const char* name);
ProfileDetection* cfgapi_lookup_profile_detection(const char* name);
ProfileContent*   cfgapi_lookup_profile_content(const char* name);
ProfileTls*   cfgapi_lookup_profile_tls(const char* name);
ProfileAuth*   cfgapi_lookup_profile_auth(const char* name);
ProfileAlgDns*   cfgapi_lookup_profile_alg_dns(const char* name);

int  cfgapi_load_obj_address();
int  cfgapi_load_obj_port();
int  cfgapi_load_obj_proto();
int  cfgapi_load_obj_policy();
int  cfgapi_load_obj_profile_content();
int  cfgapi_load_obj_profile_detection();
int  cfgapi_load_obj_profile_tls();
int  cfgapi_load_obj_profile_auth();
int  cfgapi_load_obj_profile_alg_dns();

int  cfgapi_cleanup_obj_address();
int  cfgapi_cleanup_obj_port();
int  cfgapi_cleanup_obj_proto();
int  cfgapi_cleanup_obj_policy();
int  cfgapi_cleanup_obj_profile_content();
int  cfgapi_cleanup_obj_profile_detection();
int  cfgapi_cleanup_obj_profile_tls();
int  cfgapi_cleanup_obj_profile_auth();
int  cfgapi_cleanup_obj_profile_alg_dns();

int cfgapi_obj_policy_match(baseProxy* proxy);
int cfgapi_obj_policy_match(std::vector<baseHostCX*>& left, std::vector<baseHostCX*>& right);
int cfgapi_obj_policy_action(int index);
int cfgapi_obj_policy_apply(baseHostCX* originator, baseProxy* proxy);

bool cfgapi_obj_policy_apply_tls(int policy_num, baseCom* xcom);
bool cfgapi_obj_policy_apply_tls(ProfileTls* pt, baseCom* xcom);

void cfgapi_log_version(bool warn_delay=true);

ProfileContent* cfgapi_obj_policy_profile_content(int index);
ProfileDetection* cfgapi_obj_policy_profile_detection(int index);
ProfileTls* cfgapi_obj_policy_profile_tls(int index);
ProfileAuth* cfgapi_obj_policy_profile_auth(int index);
ProfileAlgDns* cfgapi_obj_policy_profile_alg_dns(int index);

#endif