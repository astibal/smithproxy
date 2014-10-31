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

Config cfgapi;
std::map<std::string,CIDR*> cfgapi_obj_address;
std::map<std::string,range> cfgapi_obj_port;
std::map<std::string,int> cfgapi_obj_proto;
std::vector<PolicyRule*> cfgapi_obj_policy;
std::map<std::string,ProfileDetection*> cfgapi_obj_profile_detection;
std::map<std::string,ProfileContent*> cfgapi_obj_profile_content;

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

ProfileContent* cfgapi_lookup_profile_content(const char* name) {
    if(cfgapi_obj_profile_content.find(name) != cfgapi_obj_profile_content.end()) {
        return cfgapi_obj_profile_content[name];
    }    
    
    return nullptr;
}

ProfileDetection* cfgapi_lookup_profile_detection(const char* name) {
    if(cfgapi_obj_profile_detection.find(name) != cfgapi_obj_profile_detection.end()) {
        return cfgapi_obj_profile_detection[name];
    }    
    
    return nullptr;
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
            
            
            /* try to load policy profiles */
            
            if(rule->action == 1) {
                // makes sense to load profiles only when action is accept! 
                std::string name_content;
                std::string name_detection;
                
                if(cur_object.lookupValue("detection_profile",name_detection)) {
                    ProfileDetection* prf  = cfgapi_lookup_profile_detection(name_detection.c_str());
                    if(prf != nullptr) {
                        DIA_("cfgapi_load_policy[#%d]: detect profile %s",i,name_detection.c_str());
                        rule->profile_detection = prf;
                    } else {
                        DIA_("cfgapi_load_policy[#%d]: detect profile %s cannot be loaded",i,name_detection.c_str());
                        error = true;
                    }
                }
                
                if(cur_object.lookupValue("content_profile",name_content)) {
                    ProfileContent* prf  = cfgapi_lookup_profile_content(name_content.c_str());
                    if(prf != nullptr) {
                        DIA_("cfgapi_load_policy[#%d]: content profile %s",i,name_content.c_str());
                        rule->profile_content = prf;
                    } else {
                        DIA_("cfgapi_load_policy[#%d]: content profile %s cannot be loaded",i,name_content.c_str());
                        error = true;
                    }
                }                
            }
            
            if(!error){
                DIA_("cfgapi_load_policy[#%d]: ok",i);
                cfgapi_obj_policy.push_back(rule);
            } else {
                DIA_("cfgapi_load_policy[#%d]: not ok (will not process traffic)",i);
            }
        }
    }
    
    return num;
}

int cfgapi_obj_policy_match(baseProxy* proxy) {
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

int cfgapi_obj_policy_action(int index) {
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


int cfgapi_load_obj_profile_detection() {
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

int cfgapi_cleanup_obj_address() {
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
    int r = cfgapi_obj_port.size();
    cfgapi_obj_port.clear();
    
    return r;
}

int cfgapi_cleanup_obj_proto() {
    int r = cfgapi_obj_proto.size();
    cfgapi_obj_proto.clear();
    
    return r;
}


int cfgapi_cleanup_obj_profile_content() {
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
    int r = cfgapi_obj_profile_detection.size();
    for(std::map<std::string, ProfileDetection*>::iterator i = cfgapi_obj_profile_detection.begin(); i != cfgapi_obj_profile_detection.end(); ++i) {
        std::pair<std::string,ProfileDetection*> t = (*i);
        ProfileDetection* c = t.second;
        if (c != nullptr) delete c;
    }
    cfgapi_obj_profile_detection.clear();
    
    return r;
}

baseProxy* cfgapi_obj_policy_apply(baseHostCX* originator, baseProxy* new_proxy) {
    
    int policy_num = cfgapi_obj_policy_match(new_proxy);
    int verdict = cfgapi_obj_policy_action(policy_num);
    if(verdict == POLICY_ACTION_PASS) {
        bool cfg_wrt;
        
        ProfileContent* pc  = cfgapi_obj_policy_profile_content(policy_num);
        ProfileDetection* pd = cfgapi_obj_policy_profile_detection(policy_num);
        const char* pc_name = "none";
        const char* pc_global_no = "global_no";
        const char* pc_global_yes = "global_yes";
        const char* pc_global = pc_global_no;
        
        const char* pd_name = "none";
        
        /* Processing content profile */
        
        MitmProxy* mitm_proxy = static_cast<MitmProxy*>(new_proxy);
        AppHostCX* mitm_originator = static_cast<AppHostCX*>(originator);
        
        if(mitm_proxy != nullptr) {
            if(pc != nullptr) {
                DIA_("MitmMasterProxy::on_left_new: policy content profile: write payload: %d", pc->write_payload);
                mitm_proxy->write_payload(pc->write_payload);
                pc_name = pc->name.c_str();
            }
            else if(cfgapi.getRoot()["settings"].lookupValue("default_write_payload",cfg_wrt)) {
                DIA_("MitmMasterProxy::on_left_new: global content profile: %d", cfg_wrt);
                mitm_proxy->write_payload(cfg_wrt);
                if(cfg_wrt) {
                    pc_global = pc_global_yes;
                }
                
                pc_name = pc_global;
            }
            
            if(mitm_proxy->write_payload()) {
                mitm_proxy->tlog().left_write("Connection start\n");
            }
        } else {
            WARS_("cfgapi_obj_policy_apply: cannot apply content profile: cast to MitmProxy failed.");
        }
        
        /* Processing detection profile */
        
        // we scan connection on client's side
        if(mitm_originator != nullptr) {
            mitm_originator->mode(AppHostCX::MODE_NONE);
            if(pd != nullptr)  {
                DIA_("MitmMasterProxy::on_left_new: policy detection profile: mode: %d", pd->mode);
                mitm_originator->mode(pd->mode);
                pd_name = pd->name.c_str();
            }
        } else {
            WARS_("cfgapi_obj_policy_apply: cannot apply detection profile: cast to AppHostCX failed.");
        }

        INF_("Connection %s accepted by policy #%d, prof_c=%s, prof_d=%s",originator->full_name('L').c_str(),policy_num,pc_name,pd_name);
        
    } else {
        INF_("Connection %s denied by policy #%d.",originator->full_name('L').c_str(),policy_num);
        delete new_proxy;
        
        return nullptr;
    }
    
    return new_proxy;
}




void cfgapi_cleanup()
{
  cfgapi_cleanup_obj_policy();
  cfgapi_cleanup_obj_address();
  cfgapi_cleanup_obj_port();
  cfgapi_cleanup_obj_proto();
  cfgapi_cleanup_obj_profile_content();
  cfgapi_cleanup_obj_profile_detection();
}
