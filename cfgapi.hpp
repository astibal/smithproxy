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
 
#include <libconfig.h++>
#include <cidr.hpp>
#include <ranges.hpp>
#include <policy.hpp>

#define PROTO_ICMP 1
#define PROTO_TCP  6
#define PROTO_UDP  17

using namespace libconfig;
extern Config cfgapi;
extern std::map<std::string,CIDR*> cfg_obj_address;
extern std::map<std::string,range> cfg_obj_port;
extern std::map<std::string,int> cfg_obj_proto;
extern std::vector<PolicyRule*> cfg_obj_policy;

bool  cfgapi_init(const char* fnm);

CIDR* cfgapi_lookup_address(const char* name);
range cfgapi_lookup_port(const char* name);
int   cfgapi_lookup_proto(const char* name);

int  cfgapi_load_obj_address();
int  cfgapi_load_obj_port();
int  cfgapi_load_obj_proto();
int  cfgapi_load_obj_policy();

int cfgapi_obj_policy_match(baseProxy*);
int cfgapi_obj_policy_action(int index);

#endif