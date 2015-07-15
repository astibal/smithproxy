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

#include <vector>

#include <cfgapi.hpp>
#include <logger.hpp>
#include <policy.hpp>
#include <mitmproxy.hpp>
#include <mitmhost.hpp>

#include <socle.hpp>
#include <smithproxy.hpp>

#include <shmtable.hpp>

Config cfgapi;
std::map<std::string,CIDR*> cfgapi_obj_address;
std::map<std::string,range> cfgapi_obj_port;
std::map<std::string,int> cfgapi_obj_proto;
std::vector<PolicyRule*> cfgapi_obj_policy;
std::map<std::string,ProfileDetection*> cfgapi_obj_profile_detection;
std::map<std::string,ProfileContent*> cfgapi_obj_profile_content;
std::map<std::string,ProfileTls*> cfgapi_obj_profile_tls;
std::map<std::string,ProfileAuth*> cfgapi_obj_profile_auth;
std::map<std::string,ProfileAlgDns*> cfgapi_obj_profile_alg_dns;

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
    
    return true;
}

CIDR* cfgapi_lookup_address(const char* name) {
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
            
            name = cur_object.getName();

            DEB_("cfgapi_load_addresses: processing '%s'",name.c_str());
            
            if( cur_object.lookupValue("type",type) &&
                cur_object.lookupValue("cidr",address)   ) {
                
                CIDR* c = cidr_from_str(address.c_str());
                cfgapi_obj_address[name] = c;
                DIA_("cfgapi_load_addresses: '%s': ok",name.c_str());
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
                    rule->proto = r;
                    rule->proto_default = false;
                    DIA_("cfgapi_load_policy[#%d]: proto object: %s",i,proto.c_str());
                } else {
                    DIA_("cfgapi_load_policy[#%d]: proto object not found: %s",i,proto.c_str());
                    error = true;
                }
            }
            
            if(cur_object.lookupValue("src",src)) {
                CIDR* r = cfgapi_lookup_address(src.c_str());
                if(r != nullptr) {
                    rule->src.push_back(r);
                    rule->src_default = false;
                    DIA_("cfgapi_load_policy[#%d]: src address object: %s",i,src.c_str());
                } else {
                    DIA_("cfgapi_load_policy[#%d]: src address object not found: %s",i,src.c_str());
                    error = true;
                }
            }
            
            if(cur_object.lookupValue("sport",sport)) {
               range r = cfgapi_lookup_port(sport.c_str());
               if(r != NULLRANGE) {
                   rule->src_ports.push_back(r);
                   rule->src_ports_default = false;
                   DIA_("cfgapi_load_policy[#%d]: src_port object: %s",i,sport.c_str());
               } else {
                   DIA_("cfgapi_load_policy[#%d]: src_port object not found: %s",i,sport.c_str());
                   error = true;
               }
            }
            
            if(cur_object.lookupValue("dst",dst)) {
                CIDR* r = cfgapi_lookup_address(dst.c_str());
                if(r != nullptr) {
                    rule->dst.push_back(r);
                    rule->dst_default = false;
                    DIA_("cfgapi_load_policy[#%d]: dst address object: %s",i,dst.c_str());
                } else {
                    DIA_("cfgapi_load_policy[#%d]: dst address object not found: %s",i,dst.c_str());
                    error = true;
                }                
            }
            
            if(cur_object.lookupValue("dport",dport)) {
               range r = cfgapi_lookup_port(dport.c_str());
               if(r != NULLRANGE) {
                   rule->dst_ports.push_back(r);
                   rule->dst_ports_default = false;
                   DIA_("cfgapi_load_policy[#%d]: dst_port object: %s",i,dport.c_str());
               } else {
                   DIA_("cfgapi_load_policy[#%d]: dst_port object not found: %s",i,dport.c_str());
                   error = true;
               }
            }
            
            if(cur_object.lookupValue("action",action)) {
                int r_a = 1;
                if(action == "deny") {
                    DIA_("cfgapi_load_policy[#%d]: action: deny",i);
                    r_a = 0;
                } else if (action == "accept"){
                    DIA_("cfgapi_load_policy[#%d]: action: accept",i);
                    r_a = 1;
                } else {
                    DIA_("cfgapi_load_policy[#%d]: action: unknown action '%s'",i,action.c_str());
                    r_a  = 0;
                    error = true;
                }
                
                rule->action = r_a;
            } else {
                rule->action = 1;
            }

            if(cur_object.lookupValue("nat",nat)) {
                int nat_a = POLICY_NAT_NONE;
                
                if(nat == "none") {
                    DIA_("cfgapi_load_policy[#%d]: nat: none",i);
                    nat_a = POLICY_NAT_NONE;
                } else if (nat == "auto"){
                    DIA_("cfgapi_load_policy[#%d]: nat: auto",i);
                    nat_a = POLICY_NAT_AUTO;
                } else {
                    DIA_("cfgapi_load_policy[#%d]: nat: unknown nat method '%s'",i,nat.c_str());
                    nat_a  = POLICY_NAT_AUTO;
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
           
            name = cur_object.getName();
           
            DIA_("cfgapi_load_obj_profile_detect: processing '%s'",name.c_str());
            
            if( cur_object.lookupValue("mode",a->mode) ) {
                
                a->name = name;
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
            
            name = cur_object.getName();

            DEB_("cfgapi_load_obj_profile_content: processing '%s'",name.c_str());
            
            if( cur_object.lookupValue("write_payload",a->write_payload) ) {
                
                a->name = name;
                cfgapi_obj_profile_content[name] = a;
                
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
            
            name = cur_object.getName();

            DEB_("cfgapi_load_obj_profile_tls: processing '%s'",name.c_str());
            
            if( cur_object.lookupValue("inspect",a->inspect) ) {
                
                a->name = name;
                cur_object.lookupValue("allow_untrusted_issuers",a->allow_untrusted_issuers);
                cur_object.lookupValue("allow_invalid_certs",a->allow_invalid_certs);
                cur_object.lookupValue("allow_self_signed",a->allow_self_signed);
                cur_object.lookupValue("use_pfs",a->use_pfs);
                cur_object.lookupValue("ocsp_stapling",a->ocsp_stapling);
                cur_object.lookupValue("ocsp_stapling_mode",a->ocsp_stapling_mode);
                
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
            
            name = cur_object.getName();

            DEB_("cfgapi_load_obj_alg_dns_profile: processing '%s'",name.c_str());
            
            a->name = name;
            cur_object.lookupValue("match_request_id",a->match_request_id);
            cur_object.lookupValue("randomize_id",a->randomize_id);
            
            cfgapi_obj_profile_alg_dns[name] = a;
        }
    }
    
    return num;
}


int cfgapi_load_obj_profile_auth() {
    std::lock_guard<std::recursive_mutex> l(cfgapi_write_lock);
    
    int num = 0;
    
    INFS_("cfgapi_load_obj_profile_auth: start");
    
    INFS_("cfgapi_load_obj_profile_auth: portal settings");
    cfgapi.getRoot()["settings"]["auth_portal"].lookupValue("address",cfgapi_identity_portal_address);
    cfgapi.getRoot()["settings"]["auth_portal"].lookupValue("http_port",cfgapi_identity_portal_port_http);
    cfgapi.getRoot()["settings"]["auth_portal"].lookupValue("https_port",cfgapi_identity_portal_port_https);    
    
    INFS_("cfgapi_load_obj_profile_auth: profiles");
    if(cfgapi.getRoot().exists("auth_profiles")) {

        num = cfgapi.getRoot()["auth_profiles"].getLength();
        INF_("cfgapi_load_obj_profile_auth: found %d objects",num);
        
        Setting& curr_set = cfgapi.getRoot()["auth_profiles"];

        for( int i = 0; i < num; i++) {
            std::string name;
            ProfileAuth* a = new ProfileAuth;
            
            Setting& cur_object = curr_set[i];
            
            name = cur_object.getName();

            DEB_("cfgapi_load_obj_profile_auth: processing '%s'",name.c_str());
            
            a->name = name;
            cur_object.lookupValue("authenticate",a->authenticate);
            cur_object.lookupValue("resolve",a->resolve);
            
            cfgapi_obj_profile_auth[name] = a;
            
            DIA_("cfgapi_load_obj_profile_auth: '%s': ok",name.c_str());
        }
    }
    
    return num;
}




int cfgapi_cleanup_obj_address() {
    std::lock_guard<std::recursive_mutex> l(cfgapi_write_lock);
    
    int r = cfgapi_obj_address.size();
    
    for (std::map<std::string,CIDR*>::iterator i = cfgapi_obj_address.begin(); i != cfgapi_obj_address.end(); ++i)
    {
        std::pair<std::string,CIDR*> a = (*i);
        CIDR* c = a.second;
        if (c != nullptr) cidr_free(c);

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
        if (c != nullptr) delete c;
    }
    cfgapi_obj_profile_auth.clear();
    
    return r;
}


int cfgapi_obj_policy_apply(baseHostCX* originator, baseProxy* new_proxy) {
    std::lock_guard<std::recursive_mutex> l(cfgapi_write_lock);
    
    int policy_num = cfgapi_obj_policy_match(new_proxy);
    int verdict = cfgapi_obj_policy_action(policy_num);
    if(verdict == POLICY_ACTION_PASS) {
        bool cfg_wrt;
        
        ProfileContent* pc  = cfgapi_obj_policy_profile_content(policy_num);
        ProfileDetection* pd = cfgapi_obj_policy_profile_detection(policy_num);
        ProfileTls* pt = cfgapi_obj_policy_profile_tls(policy_num);
        ProfileAuth* pa = cfgapi_obj_policy_profile_auth(policy_num);
        ProfileAlgDns* p_alg_dns  = cfgapi_obj_policy_profile_alg_dns(policy_num);
        
        const char* pc_name = "none";
        const char* pc_global_no = "global_no";
        const char* pc_global_yes = "global_yes";
        const char* pc_global = pc_global_no;
        
        const char* pd_name = "none";
        const char* pt_name = "none";
        const char* pa_name = "none";
        
        //Algs will be list of single letter abreviations
        // DNS alg: D
        std::string algs_name = ""; 
        
        /* Processing content profile */
        
        MitmProxy* mitm_proxy = static_cast<MitmProxy*>(new_proxy); 
        
        AppHostCX* mitm_originator = static_cast<AppHostCX*>(originator);
        
        if(mitm_proxy != nullptr) {
            if(pc != nullptr) {
                DIA_("cfgapi_obj_policy_apply: policy content profile: write payload: %d", pc->write_payload);
                mitm_proxy->write_payload(pc->write_payload);
                pc_name = pc->name.c_str();
            }
            else if(cfgapi.getRoot()["settings"].lookupValue("default__payload",cfg_wrt)) {
                DIA_("cfgapi_obj_policy_apply: global content profile: %d", cfg_wrt);
                mitm_proxy->write_payload(cfg_wrt);
                if(cfg_wrt) {
                    pc_global = pc_global_yes;
                }
                
                pc_name = pc_global;
            }
            
            if(mitm_proxy->write_payload()) {
                mitm_proxy->tlog()->left_write("Connection start\n");
            }
        } else {
            WARS_("cfgapi_obj_policy_apply: cannot apply content profile: cast to MitmProxy failed.");
        }
        
        /* Processing detection profile */
        
        // we scan connection on client's side
        if(mitm_originator != nullptr) {
            mitm_originator->mode(AppHostCX::MODE_NONE);
            if(pd != nullptr)  {
                DIA_("cfgapi_obj_policy_apply: policy detection profile: mode: %d", pd->mode);
                mitm_originator->mode(pd->mode);
                pd_name = pd->name.c_str();
            }
        } else {
            WARS_("cfgapi_obj_policy_apply: cannot apply detection profile: cast to AppHostCX failed.");
        }

        
        /* Processing Tls profile */
        if(pt != nullptr) {
            bool tls_applied = false;
            
            // we should also apply tls profile to originating side! Verification is not in effect, but BYPASS is!
            cfgapi_obj_policy_apply_tls(pt,mitm_originator->com());
            
            for( cx_iterator i = mitm_proxy->rs().begin(); i != mitm_proxy->rs().end() ; ++i ) {
                baseHostCX* cx = (*i);
                baseCom* xcom = cx->com();
                
                if(cfgapi_obj_policy_apply_tls(pt,xcom) == true && tls_applied == false) {
                    tls_applied = true;
                }
            }
            
            if(tls_applied) {
                pt_name = pt->name.c_str();
            }
        } 
        
        /* Processing Auth profile */
        if(pa != nullptr) {
            // auth is applied on proxy
            mitm_proxy->opt_auth_authenticate = pa->authenticate;
            mitm_proxy->opt_auth_resolve = pa->resolve;
            
            pa_name = pa->name.c_str();
        } 
        
        // ALGS can operate only on MitmHostCX classes
        MitmHostCX* mh = dynamic_cast<MitmHostCX*>(mitm_originator);
        if(mh != nullptr) {
            
            // DNS ALG
            if(p_alg_dns != nullptr) {
                algs_name += "D";
                DNS_Inspector* n = new DNS_Inspector();
                if(n->l4_prefilter(mh)) {
                    n->opt_match_id = p_alg_dns->match_request_id;
                    n->opt_randomize_id = p_alg_dns->randomize_id;
                    mh->inspectors_.push_back(n);
                }
                else {
                    delete n;
                }
            }
        } else {
            NOT_("Connection %s cannot be inspected by ALGs",originator->full_name('L').c_str());
        }
        
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
            sslcom->opt_pfs = pt->use_pfs;
            sslcom->opt_ocsp_enabled = pt->ocsp_stapling;
            sslcom->opt_ocsp_mode = pt->ocsp_stapling_mode;
            
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
            WAR_("*** Socle library version %s is marked as development! ***",SOCLE_VERSION);
        }
#ifdef SOCLE_MEM_PROFILE
        WARS_("*** PERFORMANCE: Socle library has extra memory profiling enabled! ***");
#endif
        if(SMITH_DEVEL) {
            WAR_("*** Smithproxy version %s is marked as development! ***",SMITH_VERSION);
        }        
        WARS_("");
        
        if(warn_delay) {
            WARS_("  ... start will continue in 3 sec.");
            sleep(3);
        }
    }
}


