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

Config cfgapi;
std::map<std::string,CIDR*> cfgapi_obj_address;
std::map<std::string,range> cfgapi_obj_port;
std::map<std::string,int> cfgapi_obj_proto;
std::vector<PolicyRule*> cfg_obj_policy;

bool cfgapi_init(const char* fnm) {
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
    if(cfgapi_obj_address.find(name) != cfgapi_obj_address.end()) {
        return cfgapi_obj_address[name];
    }
    
    return nullptr;
}

range cfgapi_lookup_port(const char* name) {
    if(cfgapi_obj_port.find(name) != cfgapi_obj_port.end()) {
        return cfgapi_obj_port[name];
    }    
    
    return NULLRANGE;
}

int cfgapi_lookup_proto(const char* name) {
    if(cfgapi_obj_proto.find(name) != cfgapi_obj_proto.end()) {
        return cfgapi_obj_proto[name];
    }    
    
    return 0;
}

int cfgapi_load_obj_address() {
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
            
            if(!error){
                DIA_("cfgapi_load_policy[#%d]: ok",i);
                cfg_obj_policy.push_back(rule);
            } else {
                DIA_("cfgapi_load_policy[#%d]: not ok",i);
            }
        }
    }
    
    return num;
}

int cfgapi_obj_policy_match(baseProxy* proxy) {
    int x = 0;
    for( std::vector<PolicyRule*>::iterator i = cfg_obj_policy.begin(); i != cfg_obj_policy.end(); ++i) {
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

int cfgapi_obj_policy_action(int index) {
    if(index < 0) {
        return -1;
    }
    
    if(index < (signed int)cfg_obj_policy.size()) {
        return cfg_obj_policy.at(index)->action;
    } else {
        DIA_("cfg_obj_policy_action[#%d]: out of bounds, deny",index);
        return POLICY_ACTION_DENY;
    }
}

