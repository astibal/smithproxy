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

#include <vector>

#include <cfgapi.hpp>
#include <logger.hpp>
#include <policy.hpp>
#include <mitmproxy.hpp>
#include <mitmhost.hpp>

#include <socle.hpp>
#include <smithproxy.hpp>

#include <shmtable.hpp>

loglevel  args_debug_flag = NON;

std::string cfg_tcp_listen_port = "50080";
std::string cfg_ssl_listen_port = "50443";
std::string cfg_dtls_port = "50443";
std::string cfg_udp_port = "50080";
std::string cfg_socks_port = "1080";

std::string cfg_tcp_listen_port_base = "50080";
std::string cfg_ssl_listen_port_base = "50443";
std::string cfg_dtls_port_base = "50443";
std::string cfg_udp_port_base = "50080";
std::string cfg_socks_port_base = "1080";

std::string config_file;
bool config_file_check_only = false;

std::string cfg_messages_dir = "/etc/smithproxy/msg/en/";


int cfg_tcp_workers   = 0;
int cfg_ssl_workers   = 0;
int cfg_dtls_workers  = 0;
int cfg_udp_workers   = 0;
int cfg_socks_workers = 0;

std::string cfg_tenant_index;
std::string cfg_tenant_name;

std::string cfg_syslog_server   = "";
int         cfg_syslog_port     = 514;
int         cfg_syslog_facility =  23; //local7
loglevel    cfg_syslog_level    = INF;
int         cfg_syslog_family   = 4;


std::string cfg_log_target_base;
std::string cfg_sslkeylog_target_base;

std::string cfg_log_target;
std::string cfg_sslkeylog_target;
bool cfg_log_console;


Config cfgapi;
time_t system_started;

std::map<std::string,AddressObject*> cfgapi_obj_address;
std::map<std::string,range> cfgapi_obj_port;
std::map<std::string,int> cfgapi_obj_proto;
std::vector<PolicyRule*> cfgapi_obj_policy;
std::map<std::string,ProfileDetection*> cfgapi_obj_profile_detection;
std::map<std::string,ProfileContent*> cfgapi_obj_profile_content;
std::map<std::string,ProfileTls*> cfgapi_obj_profile_tls;
std::map<std::string,ProfileAuth*> cfgapi_obj_profile_auth;
std::map<std::string,ProfileAlgDns*> cfgapi_obj_profile_alg_dns;

std::vector<int> cfgapi_obj_udp_quick_ports;
std::vector<std::string> cfgapi_obj_nameservers;

// multi-tenancy support
std::string cfgapi_tenant_name = "default";
unsigned int cfgapi_tenant_index = 0;

//portal variables
std::string cfg_auth_address;
std::string cfg_auth_http;
std::string cfg_auth_https;
std::string cfg_auth_sslkey;
std::string cfg_auth_sslcert;
std::string cfgapi_tenant_magic_ip;


std::string cfg_traflog_dir = "/var/local/smithproxy/data";
std::string cfg_traflog_file_pref = "";
std::string cfg_traflog_file_suff = "smcap";



std::recursive_mutex cfgapi_write_lock;

struct cfgapi_table_ cfgapi_table;

bool cfgapi_init(const char* fnm) {
    
    std::lock_guard<std::recursive_mutex> l(cfgapi_write_lock);
    
    DIAS_("Reading config file");
    
    // Read the file. If there is an error, report it and exit.
    try {
        cfgapi.readFile(fnm);
    }
    catch(const FileIOException &fioex)
    {
        ERR_("I/O error while reading config file: %s",fnm);
        return false;   
    }
    catch(const ParseException &pex)
    {
        ERR_("Parse error in %s at %s:%d - %s", fnm, pex.getFile(), pex.getLine(), pex.getError());
        return false;
    }
    
    system_started = ::time(nullptr);
    
    return true;
}

AddressObject* cfgapi_lookup_address(const char* name) {
    std::lock_guard<std::recursive_mutex> l(cfgapi_write_lock);
    
    if(cfgapi_obj_address.find(name) != cfgapi_obj_address.end()) {
        return cfgapi_obj_address[name];
    }
    
    return nullptr;
}

range cfgapi_lookup_port(const char* name) {
    std::lock_guard<std::recursive_mutex> l(cfgapi_write_lock);
    
    if(cfgapi_obj_port.find(name) != cfgapi_obj_port.end()) {
        return cfgapi_obj_port[name];
    }    
    
    return NULLRANGE;
}

int cfgapi_lookup_proto(const char* name) {
    std::lock_guard<std::recursive_mutex> l(cfgapi_write_lock);
    
    if(cfgapi_obj_proto.find(name) != cfgapi_obj_proto.end()) {
        return cfgapi_obj_proto[name];
    }    
    
    return 0;
}

ProfileContent* cfgapi_lookup_profile_content(const char* name) {
    std::lock_guard<std::recursive_mutex> l(cfgapi_write_lock);
    
    if(cfgapi_obj_profile_content.find(name) != cfgapi_obj_profile_content.end()) {
        return cfgapi_obj_profile_content[name];
    }    
    
    return nullptr;
}

ProfileDetection* cfgapi_lookup_profile_detection(const char* name) {
    std::lock_guard<std::recursive_mutex> l(cfgapi_write_lock);
    
    if(cfgapi_obj_profile_detection.find(name) != cfgapi_obj_profile_detection.end()) {
        return cfgapi_obj_profile_detection[name];
    }    
    
    return nullptr;
}

ProfileTls* cfgapi_lookup_profile_tls(const char* name) {
    std::lock_guard<std::recursive_mutex> l(cfgapi_write_lock);
    
    if(cfgapi_obj_profile_tls.find(name) != cfgapi_obj_profile_tls.end()) {
        return cfgapi_obj_profile_tls[name];
    }    
    
    return nullptr;
}

ProfileAlgDns* cfgapi_lookup_profile_alg_dns(const char* name) {
    std::lock_guard<std::recursive_mutex> l(cfgapi_write_lock);
    
    if(cfgapi_obj_profile_alg_dns.find(name) != cfgapi_obj_profile_alg_dns.end()) {
        return cfgapi_obj_profile_alg_dns[name];
    }    
    
    return nullptr;

}


ProfileAuth* cfgapi_lookup_profile_auth(const char* name) {
    std::lock_guard<std::recursive_mutex> l(cfgapi_write_lock);
    
    if(cfgapi_obj_profile_auth.find(name) != cfgapi_obj_profile_auth.end()) {
        return cfgapi_obj_profile_auth[name];
    }    
    
    return nullptr;
}


int cfgapi_load_obj_address() {
    std::lock_guard<std::recursive_mutex> l(cfgapi_write_lock);
    
    int num = 0;
    
    DIAS_("cfgapi_load_addresses: start");
    
    if(cfgapi.getRoot().exists("address_objects")) {

        num = cfgapi.getRoot()["address_objects"].getLength();
        DIA_("cfgapi_load_addresses: found %d objects",num);
        
        Setting& curr_set = cfgapi.getRoot()["address_objects"];

        for( int i = 0; i < num; i++) {
            std::string name;
            std::string address;
            int type;
            
            Setting& cur_object = curr_set[i];

            if (  ! cur_object.getName() ) {
                DIA_("cfgapi_load_address: unnamed object index %d: not ok", i);
                continue;
            }
            
            name = cur_object.getName();

            DEB_("cfgapi_load_addresses: processing '%s'",name.c_str());
            
            if( cur_object.lookupValue("type",type)) {
                switch(type) {
                    case 0: // CIDR notation
                        if (cur_object.lookupValue("cidr",address)) {
                            CIDR* c = cidr_from_str(address.c_str());
                            cfgapi_obj_address[name] = new CidrAddress(c);
                            cfgapi_obj_address[name]->prof_name = name;
                            DIA_("cfgapi_load_addresses: cidr '%s': ok",name.c_str());
                        }
                    break;
                    case 1: // FQDN notation
                        if (cur_object.lookupValue("fqdn",address))  {
                            FqdnAddress* f = new FqdnAddress(address);
                            cfgapi_obj_address[name] = f;
                            cfgapi_obj_address[name]->prof_name = name;
                            DIA_("cfgapi_load_addresses: fqdn '%s': ok",name.c_str());
                        }
                    break;
                }
            } else {
                DIA_("cfgapi_load_addresses: '%s': not ok",name.c_str());
            }
        }
    }
    
    return num;
}

int cfgapi_load_obj_port() {
    
    std::lock_guard<std::recursive_mutex> l(cfgapi_write_lock);
    
    int num = 0;
    
    DIAS_("cfgapi_load_ports: start");
    
    if(cfgapi.getRoot().exists("port_objects")) {

        num = cfgapi.getRoot()["port_objects"].getLength();
        DIA_("cfgapi_load_ports: found %d objects",num);
        
        Setting& curr_set = cfgapi.getRoot()["port_objects"];

        for( int i = 0; i < num; i++) {
            std::string name;
            int a;
            int b;
            
            Setting& cur_object = curr_set[i];

            if (  ! cur_object.getName() ) {
                DIA_("cfgapi_load_ports: unnamed object index %d: not ok", i);
                continue;
            }

            name = cur_object.getName();

            DEB_("cfgapi_load_ports: processing '%s'",name.c_str());
            
            if( cur_object.lookupValue("start",a) &&
                cur_object.lookupValue("end",b)   ) {
                
                if(a <= b) {
                    cfgapi_obj_port[name] = range(a,b);
                } else {
                    cfgapi_obj_port[name] = range(b,a);
                }
                
                DIA_("cfgapi_load_ports: '%s': ok",name.c_str());
            } else {
                DIA_("cfgapi_load_ports: '%s': not ok",name.c_str());
            }
        }
    }
    
    return num;
}

int cfgapi_load_obj_proto() {
    
    std::lock_guard<std::recursive_mutex> l(cfgapi_write_lock);
    
    int num = 0;
    
    DIAS_("cfgapi_load_proto: start");
    
    if(cfgapi.getRoot().exists("proto_objects")) {

        num = cfgapi.getRoot()["proto_objects"].getLength();
        DIA_("cfgapi_load_proto: found %d objects",num);
        
        Setting& curr_set = cfgapi.getRoot()["proto_objects"];

        for( int i = 0; i < num; i++) {
            std::string name;
            int a;
            
            Setting& cur_object = curr_set[i];

            if (  ! cur_object.getName() ) {
                DIA_("cfgapi_load_proto: unnamed object index %d: not ok", i);
                continue;
            }
            
            name = cur_object.getName();

            DEB_("cfgapi_load_proto: processing '%s'",name.c_str());
            
            if( cur_object.lookupValue("id",a) ) {
                
                cfgapi_obj_proto[name] = a;
                
                DIA_("cfgapi_load_proto: '%s': ok",name.c_str());
            } else {
                DIA_("cfgapi_load_proto: '%s': not ok",name.c_str());
            }
        }
    }
    
    return num;
}


int cfgapi_load_obj_policy() {
    
    std::lock_guard<std::recursive_mutex> l(cfgapi_write_lock);
    
    int num = 0;
    
    DIAS_("cfgapi_load_policy: start");
    
    if(cfgapi.getRoot().exists("policy")) {

        num = cfgapi.getRoot()["policy"].getLength();
        DIA_("cfgapi_load_policy: found %d objects",num);
        
        Setting& curr_set = cfgapi.getRoot()["policy"];

        for( int i = 0; i < num; i++) {
            Setting& cur_object = curr_set[i];
            
            std::string proto;
            std::string dst;
            std::string dport;
            std::string src;
            std::string sport;
            std::string profile_detection;
            std::string profile_content;
            std::string action;
            std::string nat;
            
            bool error = false;
            
            DEB_("cfgapi_load_policy: processing #%d",i);
            
            PolicyRule* rule = new PolicyRule();

            if(cur_object.lookupValue("proto",proto)) {
                int r = cfgapi_lookup_proto(proto.c_str());
                if(r != 0) {
                    rule->proto_name = proto;
                    rule->proto = r;
                    rule->proto_default = false;
                    DIA_("cfgapi_load_policy[#%d]: proto object: %s",i,proto.c_str());
                } else {
                    DIA_("cfgapi_load_policy[#%d]: proto object not found: %s",i,proto.c_str());
                    error = true;
                }
            }
            
            const Setting& sett_src = cur_object["src"];
            if(sett_src.isScalar()) {
                DIA_("cfgapi_load_policy[#%d]: scalar src address object",i);
                if(cur_object.lookupValue("src",src)) {
                    
                    AddressObject* r = cfgapi_lookup_address(src.c_str());
                    if(r != nullptr) {
                        rule->src.push_back(r);
                        rule->src_default = false;
                        DIA_("cfgapi_load_policy[#%d]: src address object: %s",i,src.c_str());
                    } else {
                        DIA_("cfgapi_load_policy[#%d]: src address object not found: %s",i,src.c_str());
                        error = true;
                    }
                }
            } else {
                int sett_src_count = sett_src.getLength();
                DIA_("cfgapi_load_policy[#%d]: src address list",i);
                for(int y = 0; y < sett_src_count; y++) {
                    const char* obj_name = sett_src[y];
                    
                    AddressObject* r = cfgapi_lookup_address(obj_name);
                    if(r != nullptr) {
                        rule->src.push_back(r);
                        rule->src_default = false;
                        DIA_("cfgapi_load_policy[#%d]: src address object: %s",i,obj_name);
                    } else {
                        DIA_("cfgapi_load_policy[#%d]: src address object not found: %s",i,obj_name);
                        error = true;
                    }

                }
            }
            
            const Setting& sett_sport = cur_object["sport"];
            if(sett_sport.isScalar()) {
                if(cur_object.lookupValue("sport",sport)) {
                    range r = cfgapi_lookup_port(sport.c_str());
                    if(r != NULLRANGE) {
                        rule->src_ports.push_back(r);
                        rule->src_ports_names.push_back(sport);
                        rule->src_ports_default = false;
                        DIA_("cfgapi_load_policy[#%d]: src_port object: %s",i,sport.c_str());
                    } else {
                        DIA_("cfgapi_load_policy[#%d]: src_port object not found: %s",i,sport.c_str());
                        error = true;
                    }
                }
            } else {
                int sett_sport_count = sett_sport.getLength();
                DIA_("cfgapi_load_policy[#%d]: sport list",i);
                for(int y = 0; y < sett_sport_count; y++) {
                    const char* obj_name = sett_sport[y];
                    
                    range r = cfgapi_lookup_port(obj_name);
                    if(r != NULLRANGE) {
                        rule->src_ports.push_back(r);
                        rule->src_ports_names.push_back(obj_name);
                        rule->src_ports_default = false;
                        DIA_("cfgapi_load_policy[#%d]: src_port object: %s",i,obj_name);
                    } else {
                        DIA_("cfgapi_load_policy[#%d]: src_port object not found: %s",i,obj_name);
                        error = true;
                    }
                }
            }

            const Setting& sett_dst = cur_object["dst"];
            if(sett_dst.isScalar()) {
                if(cur_object.lookupValue("dst",dst)) {
                    AddressObject* r = cfgapi_lookup_address(dst.c_str());
                    if(r != nullptr) {
                        rule->dst.push_back(r);
                        rule->dst_default = false;
                        DIA_("cfgapi_load_policy[#%d]: dst address object: %s",i,dst.c_str());
                    } else {
                        DIA_("cfgapi_load_policy[#%d]: dst address object not found: %s",i,dst.c_str());
                        error = true;
                    }                
                }
            } else {
                int sett_dst_count = sett_dst.getLength();
                DIA_("cfgapi_load_policy[#%d]: dst list",i);
                for(int y = 0; y < sett_dst_count; y++) {
                    const char* obj_name = sett_dst[y];

                    AddressObject* r = cfgapi_lookup_address(obj_name);
                    if(r != nullptr) {
                        rule->dst.push_back(r);
                        rule->dst_default = false;
                        DIA_("cfgapi_load_policy[#%d]: dst address object: %s",i,obj_name);
                    } else {
                        DIA_("cfgapi_load_policy[#%d]: dst address object not found: %s",i,obj_name);
                        error = true;
                    }                
                }
            }
            
            
            const Setting& sett_dport = cur_object["dport"];
            if(sett_dport.isScalar()) { 
                if(cur_object.lookupValue("dport",dport)) {
                    range r = cfgapi_lookup_port(dport.c_str());
                    if(r != NULLRANGE) {
                        rule->dst_ports.push_back(r);
                        rule->dst_ports_names.push_back(dport);
                        rule->dst_ports_default = false;
                        DIA_("cfgapi_load_policy[#%d]: dst_port object: %s",i,dport.c_str());
                    } else {
                        DIA_("cfgapi_load_policy[#%d]: dst_port object not found: %s",i,dport.c_str());
                        error = true;
                    }
                }
            } else {
                int sett_dport_count = sett_dport.getLength();
                DIA_("cfgapi_load_policy[#%d]: dst_port object list",i);
                for(int y = 0; y < sett_dport_count; y++) {
                    const char* obj_name = sett_dport[y];
                    
                    range r = cfgapi_lookup_port(obj_name);
                    if(r != NULLRANGE) {
                        rule->dst_ports.push_back(r);
                        rule->dst_ports_names.push_back(obj_name);
                        rule->dst_ports_default = false;
                        DIA_("cfgapi_load_policy[#%d]: dst_port object: %s",i,obj_name);
                    } else {
                        DIA_("cfgapi_load_policy[#%d]: dst_port object not found: %s",i,obj_name);
                        error = true;
                    }                    
                }
            }
            
            if(cur_object.lookupValue("action",action)) {
                int r_a = 1;
                if(action == "deny") {
                    DIA_("cfgapi_load_policy[#%d]: action: deny",i);
                    r_a = POLICY_ACTION_DENY;
                    rule->action_name = action;

                } else if (action == "accept"){
                    DIA_("cfgapi_load_policy[#%d]: action: accept",i);
                    r_a = POLICY_ACTION_PASS;
                    rule->action_name = action;
                } else {
                    DIA_("cfgapi_load_policy[#%d]: action: unknown action '%s'",i,action.c_str());
                    r_a  = POLICY_ACTION_DENY;
                    error = true;
                }
                
                rule->action = r_a;
            } else {
                rule->action = POLICY_ACTION_DENY;
                rule->action_name = "deny";
            }

            if(cur_object.lookupValue("nat",nat)) {
                int nat_a = POLICY_NAT_NONE;
                
                if(nat == "none") {
                    DIA_("cfgapi_load_policy[#%d]: nat: none",i);
                    nat_a = POLICY_NAT_NONE;
                    rule->nat_name = nat;

                } else if (nat == "auto"){
                    DIA_("cfgapi_load_policy[#%d]: nat: auto",i);
                    nat_a = POLICY_NAT_AUTO;
                    rule->nat_name = nat;
                } else {
                    DIA_("cfgapi_load_policy[#%d]: nat: unknown nat method '%s'",i,nat.c_str());
                    nat_a  = POLICY_NAT_NONE;
                    rule->nat_name = "none";
                    error = true;
                }
                
                rule->nat = nat_a;
            } else {
                rule->nat = POLICY_NAT_NONE;
            }            
            
            
            /* try to load policy profiles */
            
            if(rule->action == 1) {
                // makes sense to load profiles only when action is accept! 
                std::string name_content;
                std::string name_detection;
                std::string name_tls;
                std::string name_auth;
                std::string name_alg_dns;
                
                if(cur_object.lookupValue("detection_profile",name_detection)) {
                    ProfileDetection* prf  = cfgapi_lookup_profile_detection(name_detection.c_str());
                    if(prf != nullptr) {
                        DIA_("cfgapi_load_policy[#%d]: detect profile %s",i,name_detection.c_str());
                        rule->profile_detection = prf;
                    } else {
                        ERR_("cfgapi_load_policy[#%d]: detect profile %s cannot be loaded",i,name_detection.c_str());
                        error = true;
                    }
                }
                
                if(cur_object.lookupValue("content_profile",name_content)) {
                    ProfileContent* prf  = cfgapi_lookup_profile_content(name_content.c_str());
                    if(prf != nullptr) {
                        DIA_("cfgapi_load_policy[#%d]: content profile %s",i,name_content.c_str());
                        rule->profile_content = prf;
                    } else {
                        ERR_("cfgapi_load_policy[#%d]: content profile %s cannot be loaded",i,name_content.c_str());
                        error = true;
                    }
                }                
                if(cur_object.lookupValue("tls_profile",name_tls)) {
                    ProfileTls* tls  = cfgapi_lookup_profile_tls(name_tls.c_str());
                    if(tls != nullptr) {
                        DIA_("cfgapi_load_policy[#%d]: tls profile %s",i,name_tls.c_str());
                        rule->profile_tls= tls;
                    } else {
                        ERR_("cfgapi_load_policy[#%d]: tls profile %s cannot be loaded",i,name_tls.c_str());
                        error = true;
                    }
                }         
                if(cur_object.lookupValue("auth_profile",name_auth)) {
                    ProfileAuth* auth  = cfgapi_lookup_profile_auth(name_auth.c_str());
                    if(auth != nullptr) {
                        DIA_("cfgapi_load_policy[#%d]: auth profile %s",i,name_auth.c_str());
                        rule->profile_auth= auth;
                    } else {
                        ERR_("cfgapi_load_policy[#%d]: auth profile %s cannot be loaded",i,name_auth.c_str());
                        error = true;
                    }
                }
                if(cur_object.lookupValue("alg_dns_profile",name_alg_dns)) {
                    ProfileAlgDns* dns  = cfgapi_lookup_profile_alg_dns(name_alg_dns.c_str());
                    if(dns != nullptr) {
                        DIA_("cfgapi_load_policy[#%d]: DNS alg profile %s",i,name_alg_dns.c_str());
                        rule->profile_alg_dns = dns;
                    } else {
                        ERR_("cfgapi_load_policy[#%d]: DNS alg %s cannot be loaded",i,name_alg_dns.c_str());
                        error = true;
                    }
                }                    
            }
            
            if(!error){
                DIA_("cfgapi_load_policy[#%d]: ok",i);
                cfgapi_obj_policy.push_back(rule);
            } else {
                ERR_("cfgapi_load_policy[#%d]: not ok (will not process traffic)",i);
            }
        }
    }
    
    return num;
}

int cfgapi_obj_policy_match(baseProxy* proxy) {
    std::lock_guard<std::recursive_mutex> l(cfgapi_write_lock);
    
    int x = 0;
    for( std::vector<PolicyRule*>::iterator i = cfgapi_obj_policy.begin(); i != cfgapi_obj_policy.end(); ++i) {
        PolicyRule* rule = (*i);
        bool r = rule->match(proxy);
        
        if(r) {
            DIA_("cfgapi_obj_policy_match: matched #%d",x);
            return x;
        }
        
        x++;
    }
    
    DIAS_("cfgapi_obj_policy_match: implicit deny");
    return -1;
}

int cfgapi_obj_policy_match(std::vector<baseHostCX*>& left, std::vector<baseHostCX*>& right) {
    std::lock_guard<std::recursive_mutex> l(cfgapi_write_lock);
    
    int x = 0;
    for( std::vector<PolicyRule*>::iterator i = cfgapi_obj_policy.begin(); i != cfgapi_obj_policy.end(); ++i) {
        PolicyRule* rule = (*i);
        bool r = rule->match(left,right);
        
        if(r) {
            DIA_("cfgapi_obj_policy_match_lr: matched #%d",x);
            return x;
        }
        
        x++;
    }
    
    DIAS_("cfgapi_obj_policy_match_lr: implicit deny");
    return -1;
}    

int cfgapi_obj_policy_action(int index) {
    std::lock_guard<std::recursive_mutex> l(cfgapi_write_lock);
    
    if(index < 0) {
        return -1;
    }
    
    if(index < (signed int)cfgapi_obj_policy.size()) {
        return cfgapi_obj_policy.at(index)->action;
    } else {
        DIA_("cfg_obj_policy_action[#%d]: out of bounds, deny",index);
        return POLICY_ACTION_DENY;
    }
}

ProfileContent* cfgapi_obj_policy_profile_content(int index) {
    std::lock_guard<std::recursive_mutex> l(cfgapi_write_lock);
    
    if(index < 0) {
        return nullptr;
    }
    
    if(index < (signed int)cfgapi_obj_policy.size()) {
        return cfgapi_obj_policy.at(index)->profile_content;
    } else {
        DIA_("cfgapi_obj_policy_profile_content[#%d]: out of bounds, nullptr",index);
        return nullptr;
    }
}

ProfileDetection* cfgapi_obj_policy_profile_detection(int index) {
    std::lock_guard<std::recursive_mutex> l(cfgapi_write_lock);
    
    if(index < 0) {
        return nullptr;
    }
    
    if(index < (signed int)cfgapi_obj_policy.size()) {
        return cfgapi_obj_policy.at(index)->profile_detection;
    } else {
        DIA_("cfgapi_obj_policy_profile_detection[#%d]: out of bounds, nullptr",index);
        return nullptr;
    }
}

ProfileTls* cfgapi_obj_policy_profile_tls(int index) {
    std::lock_guard<std::recursive_mutex> l(cfgapi_write_lock);
    
    if(index < 0) {
        return nullptr;
    }
    
    if(index < (signed int)cfgapi_obj_policy.size()) {
        return cfgapi_obj_policy.at(index)->profile_tls;
    } else {
        DIA_("cfgapi_obj_policy_profile_tls[#%d]: out of bounds, nullptr",index);
        return nullptr;
    }
}


ProfileAlgDns* cfgapi_obj_policy_profile_alg_dns(int index) {
    std::lock_guard<std::recursive_mutex> l(cfgapi_write_lock);
    
    if(index < 0) {
        return nullptr;
    }
    
    if(index < (signed int)cfgapi_obj_policy.size()) {
        return cfgapi_obj_policy.at(index)->profile_alg_dns;
    } else {
        DIA_("cfgapi_obj_policy_profile_alg_dns[#%d]: out of bounds, nullptr",index);
        return nullptr;
    }
}


ProfileAuth* cfgapi_obj_policy_profile_auth(int index) {
    std::lock_guard<std::recursive_mutex> l(cfgapi_write_lock);
    
    if(index < 0) {
        return nullptr;
    }
    
    if(index < (signed int)cfgapi_obj_policy.size()) {
        return cfgapi_obj_policy.at(index)->profile_auth;
    } else {
        DIA_("cfgapi_obj_policy_profile_auth[#%d]: out of bounds, nullptr",index);
        return nullptr;
    }
}



int cfgapi_load_obj_profile_detection() {
    std::lock_guard<std::recursive_mutex> l(cfgapi_write_lock);
    
    int num = 0;
    
    DIAS_("cfgapi_load_obj_profile_detect: start");
    
    if(cfgapi.getRoot().exists("detection_profiles")) {

        num = cfgapi.getRoot()["detection_profiles"].getLength();
        DIA_("cfgapi_load_obj_profile_detect: found %d objects",num);
        
        Setting& curr_set = cfgapi.getRoot()["detection_profiles"];
        
        for( int i = 0; i < num; i++) {
            std::string name;
            ProfileDetection* a = new ProfileDetection;
            
            Setting& cur_object = curr_set[i];

            if (  ! cur_object.getName() ) {
                DIA_("cfgapi_load_obj_profile_detect: unnamed object index %d: not ok", i);
                continue;
            }

            name = cur_object.getName();
           
            DIA_("cfgapi_load_obj_profile_detect: processing '%s'",name.c_str());
            
            if( cur_object.lookupValue("mode",a->mode) ) {
                
                a->prof_name = name;
                cfgapi_obj_profile_detection[name] = a;
                
                DIA_("cfgapi_load_obj_profile_detect: '%s': ok",name.c_str());
            } else {
                DIA_("cfgapi_load_obj_profile_detect: '%s': not ok",name.c_str());
            }
        }
    }
    
    return num;
}


int cfgapi_load_obj_profile_content() {
    std::lock_guard<std::recursive_mutex> l(cfgapi_write_lock);
    
    int num = 0;
    
    DIAS_("cfgapi_load_obj_profile_content: start");
    
    if(cfgapi.getRoot().exists("content_profiles")) {

        num = cfgapi.getRoot()["content_profiles"].getLength();
        DIA_("cfgapi_load_obj_profile_content: found %d objects",num);
        
        Setting& curr_set = cfgapi.getRoot()["content_profiles"];

        for( int i = 0; i < num; i++) {
            std::string name;
            ProfileContent* a = new ProfileContent;
            
            Setting& cur_object = curr_set[i];

            if (  ! cur_object.getName() ) {
                DIA_("cfgapi_load_obj_profile_content: unnamed object index %d: not ok", i);
                continue;
            }

            name = cur_object.getName();

            DEB_("cfgapi_load_obj_profile_content: processing '%s'",name.c_str());
            
            if( cur_object.lookupValue("write_payload",a->write_payload) ) {
                
                a->prof_name = name;
                cfgapi_obj_profile_content[name] = a;
                
                if(cur_object.exists("content_rules")) {
                    int jnum = cur_object["content_rules"].getLength();
                    DIA_("replace rules in profile '%s', size %d",name.c_str(),jnum);
                    for (int j = 0; j < jnum; j++) {
                        Setting& cur_replace_rule = cur_object["content_rules"][j];

                        std::string m;
                        std::string r;
                        bool action_defined = false;
                        
                        bool fill_length = false;
                        int replace_each_nth = 0;
                        
                        cur_replace_rule.lookupValue("match",m);
                        
                        if(cur_replace_rule.lookupValue("replace",r)) {
                            action_defined = true;
                        }
                        
                        //optional
                        cur_replace_rule.lookupValue("fill_length",fill_length);
                        cur_replace_rule.lookupValue("replace_each_nth",replace_each_nth);
                        
                        if(m.size() > 0 && action_defined) {
                            DIA_("    [%d] match '%s' and replace with '%s'",j,m.c_str(),r.c_str());
                            ProfileContentRule p;
                            p.match = m;
                            p.replace = r;
                            p.fill_length = fill_length;
                            p.replace_each_nth = replace_each_nth;

                            a->content_rules.push_back(p);
                            
                        } else {
                            ERR_("    [%d] unfinished replace policy",j);
                        }
                    }
                }
                
                
                DIA_("cfgapi_load_obj_profile_content: '%s': ok",name.c_str());
            } else {
                DIA_("cfgapi_load_obj_profile_content: '%s': not ok",name.c_str());
            }
        }
    }
    
    return num;
}

int cfgapi_load_obj_profile_tls() {
    std::lock_guard<std::recursive_mutex> l(cfgapi_write_lock);
    
    int num = 0;
    
    DIAS_("cfgapi_load_obj_profile_tls: start");
    
    if(cfgapi.getRoot().exists("tls_profiles")) {

        num = cfgapi.getRoot()["tls_profiles"].getLength();
        DIA_("cfgapi_load_obj_profile_tls: found %d objects",num);
        
        Setting& curr_set = cfgapi.getRoot()["tls_profiles"];

        for( int i = 0; i < num; i++) {
            std::string name;
            ProfileTls* a = new ProfileTls;
            
            Setting& cur_object = curr_set[i];

            if (  ! cur_object.getName() ) {
                DIA_("cfgapi_load_obj_profile_tls: unnamed object index %d: not ok", i);
                continue;
            }

            name = cur_object.getName();

            DEB_("cfgapi_load_obj_profile_tls: processing '%s'",name.c_str());
            
            if( cur_object.lookupValue("inspect",a->inspect) ) {
                
                a->prof_name = name;
                cur_object.lookupValue("allow_untrusted_issuers",a->allow_untrusted_issuers);
                cur_object.lookupValue("allow_invalid_certs",a->allow_invalid_certs);
                cur_object.lookupValue("allow_self_signed",a->allow_self_signed);
                cur_object.lookupValue("use_pfs",a->use_pfs);
                cur_object.lookupValue("left_use_pfs",a->left_use_pfs);
                cur_object.lookupValue("right_use_pfs",a->right_use_pfs);
                cur_object.lookupValue("left_disable_reuse",a->left_disable_reuse);
                cur_object.lookupValue("right_disable_reuse",a->right_disable_reuse);
                
                cur_object.lookupValue("ocsp_mode",a->ocsp_mode);
                cur_object.lookupValue("ocsp_stapling",a->ocsp_stapling);
                cur_object.lookupValue("ocsp_stapling_mode",a->ocsp_stapling_mode);
                cur_object.lookupValue("failed_certcheck_replacement",a->failed_certcheck_replacement);
                cur_object.lookupValue("failed_certcheck_override",a->failed_certcheck_override);
                cur_object.lookupValue("failed_certcheck_override_timout",a->failed_certcheck_override_timeout);
                
                if(cur_object.exists("sni_filter_bypass")) {
                        Setting& sni_filter = cur_object["sni_filter_bypass"];
                        
                        //init only when there is something
                        int sni_filter_len = sni_filter.getLength();
                        if(sni_filter_len > 0) {
                                a->sni_filter_bypass.ptr(new std::vector<std::string>);
                                for(int j = 0; j < sni_filter_len; ++j) {
                                    const char* elem = sni_filter[j];
                                    a->sni_filter_bypass.ptr()->push_back(elem);
                                }
                        }
                }
                

                if(cur_object.exists("redirect_warning_ports")) {
                        Setting& rwp = cur_object["redirect_warning_ports"];
                        
                        //init only when there is something
                        int rwp_len = rwp.getLength();
                        if(rwp_len > 0) {
                                a->redirect_warning_ports.ptr(new std::set<int>);
                                for(int j = 0; j < rwp_len; ++j) {
                                    int elem = rwp[j];
                                    a->redirect_warning_ports.ptr()->insert(elem);
                                }
                        }
                }
                cur_object.lookupValue("sslkeylog",a->sslkeylog);
                
                cfgapi_obj_profile_tls[name] = a;
                
                DIA_("cfgapi_load_obj_profile_tls: '%s': ok",name.c_str());
            } else {
                DIA_("cfgapi_load_obj_profile_tls: '%s': not ok",name.c_str());
            }
        }
    }
    
    return num;
}

int cfgapi_load_obj_profile_alg_dns() {
    std::lock_guard<std::recursive_mutex> l(cfgapi_write_lock);

    int num = 0;
    DIAS_("cfgapi_load_obj_alg_dns_profile: start");
    if(cfgapi.getRoot().exists("alg_dns_profiles")) {
        num = cfgapi.getRoot()["alg_dns_profiles"].getLength();
        DIA_("cfgapi_load_obj_alg_dns_profile: found %d objects",num);
        
        Setting& curr_set = cfgapi.getRoot()["alg_dns_profiles"];

        for( int i = 0; i < num; i++) {
            std::string name;
            ProfileAlgDns* a = new ProfileAlgDns;
            
            Setting& cur_object = curr_set[i];

            if (  ! cur_object.getName() ) {
                DIA_("cfgapi_load_obj_alg_dns_profile: unnamed object index %d: not ok", i);
                continue;
            }
            
            name = cur_object.getName();

            DEB_("cfgapi_load_obj_alg_dns_profile: processing '%s'",name.c_str());
            
            a->prof_name = name;
            cur_object.lookupValue("match_request_id",a->match_request_id);
            cur_object.lookupValue("randomize_id",a->randomize_id);
            cur_object.lookupValue("cached_responses",a->cached_responses);
            
            cfgapi_obj_profile_alg_dns[name] = a;
        }
    }
    
    return num;
}


int cfgapi_load_obj_profile_auth() {
    std::lock_guard<std::recursive_mutex> l(cfgapi_write_lock);
    
    int num = 0;
    
    DIAS_("cfgapi_load_obj_profile_auth: start");
    
    DIAS_("cfgapi_load_obj_profile_auth: portal settings");
    cfgapi.getRoot()["settings"]["auth_portal"].lookupValue("address",cfgapi_identity_portal_address);
    cfgapi.getRoot()["settings"]["auth_portal"].lookupValue("address6",cfgapi_identity_portal_address6);
    cfgapi.getRoot()["settings"]["auth_portal"].lookupValue("http_port",cfgapi_identity_portal_port_http);
    cfgapi.getRoot()["settings"]["auth_portal"].lookupValue("https_port",cfgapi_identity_portal_port_https);    
    
    DIAS_("cfgapi_load_obj_profile_auth: profiles");
    if(cfgapi.getRoot().exists("auth_profiles")) {

        num = cfgapi.getRoot()["auth_profiles"].getLength();
        DIA_("cfgapi_load_obj_profile_auth: found %d objects",num);
        
        Setting& curr_set = cfgapi.getRoot()["auth_profiles"];

        for( int i = 0; i < num; i++) {
            std::string name;
            ProfileAuth* a = new ProfileAuth;
            
            Setting& cur_object = curr_set[i];

            if (  ! cur_object.getName() ) {
                DIA_("cfgapi_load_obj_profile_auth: unnamed object index %d: not ok", i);
                continue;
            }
            
            name = cur_object.getName();

            DEB_("cfgapi_load_obj_profile_auth: processing '%s'",name.c_str());
            
            a->prof_name = name;
            cur_object.lookupValue("authenticate",a->authenticate);
            cur_object.lookupValue("resolve",a->resolve);
            
            if(cur_object.exists("identities")) {
                DIAS_("cfgapi_load_obj_profile_auth: profiles: subpolicies exists");
                int sub_pol_num = cur_object["identities"].getLength();
                DIA_("cfgapi_load_obj_profile_auth: profiles: %d subpolicies detected",sub_pol_num);
                for (int j = 0; j < sub_pol_num; j++) {
                    Setting& cur_subpol = cur_object["identities"][j];
                    
                    ProfileSubAuth* n_subpol = new ProfileSubAuth();

                    if (  ! cur_subpol.getName() ) {
                        DIA_("cfgapi_load_obj_profile_auth: profiles: unnamed object index %d: not ok", j);
                        continue;
                    }

                    n_subpol->name = cur_subpol.getName();
                    
                    std::string name_content;
                    std::string name_detection;
                    std::string name_tls;
                    std::string name_auth;
                    std::string name_alg_dns;
                    
                    if(cur_subpol.lookupValue("detection_profile",name_detection)) {
                        ProfileDetection* prf  = cfgapi_lookup_profile_detection(name_detection.c_str());
                        if(prf != nullptr) {
                            DIA_("cfgapi_load_obj_profile_auth[sub-profile:%s]: detect profile %s",n_subpol->name.c_str(),name_detection.c_str());
                            n_subpol->profile_detection = prf;
                        } else {
                            ERR_("cfgapi_load_obj_profile_auth[sub-profile:%s]: detect profile %s cannot be loaded",n_subpol->name.c_str(),name_detection.c_str());
                        }
                    }
                    
                    if(cur_subpol.lookupValue("content_profile",name_content)) {
                        ProfileContent* prf  = cfgapi_lookup_profile_content(name_content.c_str());
                        if(prf != nullptr) {
                            DIA_("cfgapi_load_obj_profile_auth[sub-profile:%s]: content profile %s",n_subpol->name.c_str(),name_content.c_str());
                            n_subpol->profile_content = prf;
                        } else {
                            ERR_("cfgapi_load_obj_profile_auth[sub-profile:%s]: content profile %s cannot be loaded",n_subpol->name.c_str(),name_content.c_str());
                        }
                    }                
                    if(cur_subpol.lookupValue("tls_profile",name_tls)) {
                        ProfileTls* tls  = cfgapi_lookup_profile_tls(name_tls.c_str());
                        if(tls != nullptr) {
                            DIA_("cfgapi_load_obj_profile_auth[sub-profile:%s]: tls profile %s",n_subpol->name.c_str(),name_tls.c_str());
                            n_subpol->profile_tls= tls;
                        } else {
                            ERR_("cfgapi_load_obj_profile_auth[sub-profile:%s]: tls profile %s cannot be loaded",n_subpol->name.c_str(),name_tls.c_str());
                        }
                    }         

                    // we don't need auth profile in auth sub-profile
                    
                    if(cur_subpol.lookupValue("alg_dns_profile",name_alg_dns)) {
                        ProfileAlgDns* dns  = cfgapi_lookup_profile_alg_dns(name_alg_dns.c_str());
                        if(dns != nullptr) {
                            DIA_("cfgapi_load_obj_profile_auth[sub-profile:%s]: DNS alg profile %s",n_subpol->name.c_str(),name_alg_dns.c_str());
                            n_subpol->profile_alg_dns = dns;
                        } else {
                            ERR_("cfgapi_load_obj_profile_auth[sub-profile:%s]: DNS alg %s cannot be loaded",n_subpol->name.c_str(),name_alg_dns.c_str());
                        }
                    }                    

                    
                    a->sub_policies.push_back(n_subpol);
                    DIA_("cfgapi_load_obj_profile_auth: profiles: %d:%s",j,n_subpol->name.c_str());
                }
            }
            cfgapi_obj_profile_auth[name] = a;
            
            DIA_("cfgapi_load_obj_profile_auth: '%s': ok",name.c_str());
        }
    }
    
    return num;
}




int cfgapi_cleanup_obj_address() {
    std::lock_guard<std::recursive_mutex> l(cfgapi_write_lock);
    
    int r = cfgapi_obj_address.size();
    
    for (std::map<std::string,AddressObject*>::iterator i = cfgapi_obj_address.begin(); i != cfgapi_obj_address.end(); ++i)
    {
        std::pair<std::string,AddressObject*> a = (*i);
        AddressObject* c = a.second;
        if (c != nullptr) delete c;

        a.second = nullptr;
    }
    
    cfgapi_obj_address.clear();
    
    DEB_("cfgapi_cleanup_obj_address: %d objects freed",r);
    return r;
}

int cfgapi_cleanup_obj_policy() {
    std::lock_guard<std::recursive_mutex> l(cfgapi_write_lock);
    
    int r = cfgapi_obj_policy.size();
    for(std::vector<PolicyRule*>::iterator i = cfgapi_obj_policy.begin(); i < cfgapi_obj_policy.end(); ++i) {
        PolicyRule* ptr = (*i);
        if (ptr != nullptr) delete ptr;
        (*i) = nullptr;
    }
    
    cfgapi_obj_policy.clear();
    
    DEB_("cfgapi_cleanup_obj_policy: %d objects freed",r);
    return r;
}

int cfgapi_cleanup_obj_port() {
    std::lock_guard<std::recursive_mutex> l(cfgapi_write_lock);
    
    int r = cfgapi_obj_port.size();
    cfgapi_obj_port.clear();
    
    return r;
}

int cfgapi_cleanup_obj_proto() {
    std::lock_guard<std::recursive_mutex> l(cfgapi_write_lock);
    
    int r = cfgapi_obj_proto.size();
    cfgapi_obj_proto.clear();
    
    return r;
}


int cfgapi_cleanup_obj_profile_content() {
    std::lock_guard<std::recursive_mutex> l(cfgapi_write_lock);
    
    int r = cfgapi_obj_profile_content.size();
    for(std::map<std::string, ProfileContent*>::iterator i = cfgapi_obj_profile_content.begin(); i != cfgapi_obj_profile_content.end(); ++i) {
        std::pair<std::string,ProfileContent*> t = (*i);
        ProfileContent* c = t.second;
        if (c != nullptr) delete c;
    }
    cfgapi_obj_profile_content.clear();
    
    return r;
}
int cfgapi_cleanup_obj_profile_detection() {
    std::lock_guard<std::recursive_mutex> l(cfgapi_write_lock);
    
    int r = cfgapi_obj_profile_detection.size();
    for(std::map<std::string, ProfileDetection*>::iterator i = cfgapi_obj_profile_detection.begin(); i != cfgapi_obj_profile_detection.end(); ++i) {
        std::pair<std::string,ProfileDetection*> t = (*i);
        ProfileDetection* c = t.second;
        if (c != nullptr) delete c;
    }
    cfgapi_obj_profile_detection.clear();
    
    return r;
}
int cfgapi_cleanup_obj_profile_tls() {
    std::lock_guard<std::recursive_mutex> l(cfgapi_write_lock);
    
    int r = cfgapi_obj_profile_tls.size();
    for(std::map<std::string, ProfileTls*>::iterator i = cfgapi_obj_profile_tls.begin(); i != cfgapi_obj_profile_tls.end(); ++i) {
        std::pair<std::string,ProfileTls*> t = (*i);
        ProfileTls* c = t.second;
        if (c != nullptr) delete c;
    }
    cfgapi_obj_profile_tls.clear();
    
    return r;
}

int cfgapi_cleanup_obj_profile_alg_dns() {
    std::lock_guard<std::recursive_mutex> l(cfgapi_write_lock);
    
    int r = cfgapi_obj_profile_alg_dns.size();
    for(std::map<std::string, ProfileAlgDns*>::iterator i = cfgapi_obj_profile_alg_dns.begin(); i != cfgapi_obj_profile_alg_dns.end(); ++i) {
        std::pair<std::string,ProfileAlgDns*> t = (*i);
        ProfileAlgDns* c = t.second;
        if (c != nullptr) delete c;
    }
    cfgapi_obj_profile_alg_dns.clear();
    
    return r;
}



int cfgapi_cleanup_obj_profile_auth() {
    std::lock_guard<std::recursive_mutex> l(cfgapi_write_lock);
    
    int r = cfgapi_obj_profile_auth.size();
    for(std::map<std::string, ProfileAuth*>::iterator i = cfgapi_obj_profile_auth.begin(); i != cfgapi_obj_profile_auth.end(); ++i) {
        std::pair<std::string,ProfileAuth*> t = (*i);
        ProfileAuth* c = t.second;
        
        for(auto j: c->sub_policies) {
            delete j;
        }
        
        if (c != nullptr) delete c;
    }
    cfgapi_obj_profile_auth.clear();
    
    return r;
}


bool cfgapi_obj_profile_content_apply(baseHostCX* originator, baseProxy* new_proxy, ProfileContent* pc) {
    
    MitmProxy* mitm_proxy = static_cast<MitmProxy*>(new_proxy); 
    AppHostCX* mitm_originator = static_cast<AppHostCX*>(originator);
    
    bool ret = true;
    
    bool cfg_wrt;

    const char* pc_name = "none";
    const char* pc_global_no = "global_no";
    const char* pc_global_yes = "global_yes";
    const char* pc_global = pc_global_no;
    
    if(mitm_proxy != nullptr) {
        if(pc != nullptr) {
            pc_name = pc->prof_name.c_str();
            DIA_("cfgapi_obj_policy_apply: policy content profile[%s]: write payload: %d", pc_name, pc->write_payload);
            mitm_proxy->write_payload(pc->write_payload);
    
            if(pc->content_rules.size() > 0) {
                DIA_("cfgapi_obj_policy_apply: policy content profile[%s]: applying content rules, size %d", pc_name, pc->content_rules.size());
                mitm_proxy->init_content_replace();
                mitm_proxy->content_replace(pc->content_rules);
            }
        }
        else if(cfgapi.getRoot()["settings"].lookupValue("default_write_payload",cfg_wrt)) {
            DIA_("cfgapi_obj_policy_apply: global content profile: %d", cfg_wrt);
            mitm_proxy->write_payload(cfg_wrt);
            if(cfg_wrt) {
                pc_global = pc_global_yes;
            }
            
            pc_name = pc_global;
        }
        
        if(mitm_proxy->write_payload()) {
            mitm_proxy->toggle_tlog();
            mitm_proxy->tlog()->left_write("Connection start\n");
        }
    } else {
        WARS_("cfgapi_obj_policy_apply: cannot apply content profile: cast to MitmProxy failed.");
        ret = false;
    } 
    
    return ret;
}


bool cfgapi_obj_profile_detect_apply(baseHostCX* originator, baseProxy* new_proxy, ProfileDetection* pd) {

    MitmProxy* mitm_proxy = static_cast<MitmProxy*>(new_proxy); 
    AppHostCX* mitm_originator = static_cast<AppHostCX*>(originator);
    
    const char* pd_name = "none";
    bool ret = true;
    
    // we scan connection on client's side
    if(mitm_originator != nullptr) {
        mitm_originator->mode(AppHostCX::MODE_NONE);
        if(pd != nullptr)  {
            pd_name = pd->prof_name.c_str();
            DIA_("cfgapi_obj_policy_apply[%s]: policy detection profile: mode: %d", pd_name, pd->mode);
            mitm_originator->mode(pd->mode);
        }
    } else {
        WARS_("cfgapi_obj_policy_apply: cannot apply detection profile: cast to AppHostCX failed.");
        ret = false;
    }    
    
    return ret;
}

bool cfgapi_obj_profile_tls_apply(baseHostCX* originator, baseProxy* new_proxy, ProfileTls* ps) {
    
    MitmProxy* mitm_proxy = static_cast<MitmProxy*>(new_proxy); 
    AppHostCX* mitm_originator = static_cast<AppHostCX*>(originator);
    
    bool tls_applied = false;
    
    if(ps != nullptr) {
        // we should also apply tls profile to originating side! Verification is not in effect, but BYPASS is!
        if (cfgapi_obj_policy_apply_tls(ps,mitm_originator->com())) {
            
            for( cx_iterator i = mitm_proxy->rs().begin(); i != mitm_proxy->rs().end() ; ++i ) {
                baseHostCX* cx = (*i);
                baseCom* xcom = cx->com();
                
                tls_applied = cfgapi_obj_policy_apply_tls(ps,xcom);
                if(!tls_applied) {
                    ERR_("%s: cannot apply TLS profile to target connection %s",new_proxy->c_name(), cx->c_name());
                } else {
                    
                    //applying bypass based on DNS cache
                    
                    SSLCom* sslcom = dynamic_cast<SSLCom*>(xcom);
                    if(sslcom && ps->sni_filter_bypass.valid()) {
                        if(ps->sni_filter_bypass.ptr()->size() > 0 && ps->sni_filter_use_dns_cache) {
                        
                            bool interrupt = false;
                            for(std::string& filter_element: *ps->sni_filter_bypass) {
                                FqdnAddress f(filter_element);
                                CIDR* c = cidr_from_str(xcom->owner_cx()->host().c_str());
                                
                                if(f.match(c)) {
                                    if(sslcom->bypass_me_and_peer()) {
                                        INF_("Connection %s bypassed: IP in DNS cache matching TLS bypass list (%s).",originator->full_name('L').c_str(),filter_element.c_str());
                                        interrupt = true;
                                    } else {
                                        WAR_("Connection %s: cannot be bypassed.",originator->full_name('L').c_str());
                                    }
                                } else if (ps->sni_filter_use_dns_domain_tree) {
                                    domain_cache.lock();
                                    //INF_("FQDN doesn't match SNI element, looking for sub-domains of %s", filter_element.c_str());
                                    //FIXME: we assume flter is 2nd level domain... 
                                    
                                    auto subdomain_cache = domain_cache.get(filter_element);
                                    if(subdomain_cache != nullptr) {
                                        for(auto subdomain: subdomain_cache->cache()) {
                                            
                                            std::vector<std::string> prefix_n_domainname = string_split(subdomain.first,':');
                                            if(prefix_n_domainname.size() < 2) continue; // don't continue if we can't strip A: or AAAA:
                                            
                                            FqdnAddress f(prefix_n_domainname.at(1)+"."+filter_element);
                                            DEB_("Connection %s: subdomain check: test if %s matches %s",originator->full_name('L').c_str(),f.to_string().c_str(),xcom->owner_cx()->host().c_str());
                                            
                                            if(f.match(c)) {
                                                if(sslcom->bypass_me_and_peer()) {
                                                    INF_("Connection %s bypassed: IP in DNS subdomain cache matching TLS bypass list (%s).",originator->full_name('L').c_str(),filter_element.c_str());
                                                } else {
                                                    WAR_("Connection %s: cannot be bypassed.",originator->full_name('L').c_str());                                                    
                                                }
                                                interrupt = true; //exit also from main loop
                                                break;
                                            }
                                        }
                                    }
                                    
                                    domain_cache.unlock();
                                }
                                
                                delete c;
                                
                                if(interrupt) 
                                    break;
                            }                        
                            
                        }
                    }
                }
            }
        }
    } 
    
    return tls_applied;
}

bool cfgapi_obj_alg_dns_apply(baseHostCX* originator, baseProxy* new_proxy, ProfileAlgDns* p_alg_dns) {
    
    AppHostCX* mitm_originator = static_cast<AppHostCX*>(originator);    
    MitmHostCX* mh = dynamic_cast<MitmHostCX*>(mitm_originator);

    bool ret = false;
    
    if(mh != nullptr) {

        if(p_alg_dns != nullptr) {
            DNS_Inspector* n = new DNS_Inspector();
            if(n->l4_prefilter(mh)) {
                n->opt_match_id = p_alg_dns->match_request_id;
                n->opt_randomize_id = p_alg_dns->randomize_id;
                n->opt_cached_responses = p_alg_dns->cached_responses;
                mh->inspectors_.push_back(n);
                ret = true;
            }
            else {
                delete n;
            }
        }
        
    } else {
        NOT_("Connection %s cannot be inspected by ALGs",originator->full_name('L').c_str());
    }    
    
    return ret;
}

int cfgapi_obj_policy_apply(baseHostCX* originator, baseProxy* new_proxy) {
    std::lock_guard<std::recursive_mutex> l(cfgapi_write_lock);
    
    int policy_num = cfgapi_obj_policy_match(new_proxy);
    int verdict = cfgapi_obj_policy_action(policy_num);
    if(verdict == POLICY_ACTION_PASS) {

        ProfileContent* pc  = cfgapi_obj_policy_profile_content(policy_num);
        ProfileDetection* pd = cfgapi_obj_policy_profile_detection(policy_num);
        ProfileTls* pt = cfgapi_obj_policy_profile_tls(policy_num);
        ProfileAuth* pa = cfgapi_obj_policy_profile_auth(policy_num);
        ProfileAlgDns* p_alg_dns  = cfgapi_obj_policy_profile_alg_dns(policy_num);
        
        
        const char* pc_name = "none";
        const char* pd_name = "none";
        const char* pt_name = "none";
        const char* pa_name = "none";
        
        //Algs will be list of single letter abreviations
        // DNS alg: D
        std::string algs_name = ""; 
        
        /* Processing content profile */
        if(pc)
        if(cfgapi_obj_profile_content_apply(originator,new_proxy,pc)) {
            pc_name = pc->prof_name.c_str();
        }
        
        
        /* Processing detection profile */
        if(pd)
        if(cfgapi_obj_profile_detect_apply(originator,new_proxy,pd)) {
            pd_name = pd->prof_name.c_str();
        }        
        
        /* Processing TLS profile*/
        if(pt)
        if(cfgapi_obj_profile_tls_apply(originator,new_proxy,pt)) {
            pt_name = pt->prof_name.c_str();
        }        
        
        /* Processing ALG : DNS*/
        if(p_alg_dns)
        if(cfgapi_obj_alg_dns_apply(originator,new_proxy,p_alg_dns)) {
            algs_name += p_alg_dns->prof_name.c_str();
        }        

        
        MitmProxy* mitm_proxy = static_cast<MitmProxy*>(new_proxy); 
        AppHostCX* mitm_originator = static_cast<AppHostCX*>(originator);
        
        /* Processing Auth profile */
        if(pa) {
            // auth is applied on proxy
            mitm_proxy->opt_auth_authenticate = pa->authenticate;
            mitm_proxy->opt_auth_resolve = pa->resolve;
            
            pa_name = pa->prof_name.c_str();
        } 
        
        // ALGS can operate only on MitmHostCX classes

        
        INF_("Connection %s accepted: policy=%d cont=%s det=%s tls=%s auth=%s algs=%s",originator->full_name('L').c_str(),policy_num,pc_name,pd_name,pt_name,pa_name,algs_name.c_str());
        
    } else {
        INF_("Connection %s denied: policy=%d",originator->full_name('L').c_str(),policy_num);
    }
    
    return policy_num;
}


bool cfgapi_obj_policy_apply_tls(int policy_num, baseCom* xcom) {
    ProfileTls* pt = cfgapi_obj_policy_profile_tls(policy_num);
    return cfgapi_obj_policy_apply_tls(pt,xcom);
}

bool should_redirect_warning_port(ProfileTls* pt, SSLCom* com) {
    
    bool ret = false;
    
    DEB_("should_redirect_warning_port[%s]",com->hr());
    
    if(com && com->owner_cx()) {
        
        try {
            int num_port = std::stoi(com->owner_cx()->port());
            DEB_("should_redirect_warning_port[%s]: owner port %d",com->hr(), num_port);
            
            
            if(pt->redirect_warning_ports.ptr()) {
                // we have port redirection list (which ports should be redirected/replaced for cert issue warning)
                DEB_("should_redirect_warning_port[%s]: checking port list present",com->hr());
                
                auto it = pt->redirect_warning_ports.ptr()->find(num_port);
                
                if(it != pt->redirect_warning_ports.ptr()->end()) {
                    DIA_("should_redirect_warning_port[%s]: port %d in redirect list",com->hr(),num_port);
                    ret = true;
                }
            }
            else {
                // if we have list empty (uninitialized), we assume only 443 should be redirected
                if(num_port == 443) {
                    DEB_("should_redirect_warning_port[%s]: implicit 443 redirection allowed (no port list)",com->hr());
                    ret = true;
                }
            }
        }
        catch(std::invalid_argument) {}
        catch(std::out_of_range) {}
    }
    
    return ret;
}

bool cfgapi_obj_policy_apply_tls(ProfileTls* pt, baseCom* xcom) {

    bool tls_applied = false;     
    
    if(pt != nullptr) {
        SSLCom* sslcom = dynamic_cast<SSLCom*>(xcom);
        if(sslcom != nullptr) {
            sslcom->opt_bypass = !pt->inspect;
            sslcom->opt_allow_unknown_issuer = pt->allow_untrusted_issuers;
            sslcom->opt_allow_self_signed_chain = pt->allow_untrusted_issuers;
            sslcom->opt_allow_not_valid_cert = pt->allow_invalid_certs;
            sslcom->opt_allow_self_signed_cert = pt->allow_self_signed;

            
            if(pt->failed_certcheck_replacement && should_redirect_warning_port(pt,sslcom)) {
                sslcom->opt_failed_certcheck_replacement = pt->failed_certcheck_replacement;
                sslcom->opt_failed_certcheck_override = pt->failed_certcheck_override;
                sslcom->opt_failed_certcheck_override_timeout = pt->failed_certcheck_override_timeout;
            }
            
            // set accordingly if general "use_pfs" is specified, more conrete settings come later
            sslcom->opt_left_kex_dh = pt->use_pfs;
            sslcom->opt_right_kex_dh = pt->use_pfs;
            
            sslcom->opt_left_kex_dh = pt->left_use_pfs;
            sslcom->opt_right_kex_dh = pt->right_use_pfs;
            
            sslcom->opt_left_no_tickets = pt->left_disable_reuse;
            sslcom->opt_right_no_tickets = pt->right_disable_reuse;
            
            sslcom->opt_ocsp_mode = pt->ocsp_mode;
            sslcom->opt_ocsp_stapling_enabled = pt->ocsp_stapling;
            sslcom->opt_ocsp_stapling_mode = pt->ocsp_stapling_mode;
       
            if(pt->sni_filter_bypass.valid()) {
                if(pt->sni_filter_bypass.ptr()->size() > 0) {
                    sslcom->sni_filter_to_bypass().ref(pt->sni_filter_bypass);
                }
            }
            
            sslcom->sslkeylog = pt->sslkeylog;
            
            tls_applied = true;
        }        
    }
    
    return tls_applied;
}


void cfgapi_cleanup()
{
  cfgapi_cleanup_obj_policy();
  cfgapi_cleanup_obj_address();
  cfgapi_cleanup_obj_port();
  cfgapi_cleanup_obj_proto();
  cfgapi_cleanup_obj_profile_content();
  cfgapi_cleanup_obj_profile_detection();
  cfgapi_cleanup_obj_profile_tls();
  cfgapi_cleanup_obj_profile_auth();
  cfgapi_cleanup_obj_profile_alg_dns();
}


void cfgapi_log_version(bool warn_delay)
{
    CRI_("Starting Smithproxy %s (socle %s)",SMITH_VERSION,SOCLE_VERSION);
    
    if(SOCLE_DEVEL || SMITH_DEVEL) {
        WARS_("");
        if(SOCLE_DEVEL) {
            WAR_("Socle library version %s (dev)",SOCLE_VERSION);
        }
#ifdef SOCLE_MEM_PROFILE
        WARS_("*** PERFORMANCE: Socle library has extra memory profiling enabled! ***");
#endif
        if(SMITH_DEVEL) {
            WAR_("Smithproxy version %s (dev)",SMITH_VERSION);
        }        
        WARS_("");
        
        if(warn_delay) {
            WARS_("  ... start will continue in 3 sec.");
            sleep(3);
        }
    }
}


