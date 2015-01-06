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

#ifndef POLICY_HPP
 #define POLICY_HPP
 
 
#include <vector> 

#include <hostcx.hpp>
#include <baseproxy.hpp>
#include <cidr.hpp>
#include <ranges.hpp>

#define POLICY_ACTION_DENY  0
#define POLICY_ACTION_PASS  1

#define POLICY_NAT_NONE     0
#define POLICY_NAT_AUTO     1
#define POLICY_NAT_POOL     2

struct ProfileDetection;
struct ProfileContent;
struct ProfileTls;

class PolicyRule {

public:
       int proto = 6;
       bool proto_default = true;
    
       std::vector<CIDR*> src;
       bool src_default = true;
       std::vector<range> src_ports;
       bool src_ports_default = true;
       
       std::vector<CIDR*> dst;
       bool dst_default = true;
       std::vector<range> dst_ports;
       bool dst_ports_default = true;

       int action = POLICY_ACTION_PASS;
       int nat    = POLICY_NAT_NONE;
      
       bool match(baseProxy*);
       bool match(std::vector<baseHostCX*>& l, std::vector<baseHostCX*>& r);
       virtual ~PolicyRule();
       
       bool match_addrgrp_cx(std::vector<CIDR*>& cidrs,baseHostCX* cx);
       bool match_addrgrp_vecx(std::vector<CIDR*>& cidrs,std::vector<baseHostCX*>& vecx);
       bool match_rangegrp_cx(std::vector<range>& ranges,baseHostCX* cx);
       bool match_rangegrp_vecx(std::vector<range>& ranges,std::vector<baseHostCX*>& vecx);
       
       ProfileContent* profile_content = nullptr;
       ProfileDetection* profile_detection = nullptr;
       ProfileTls* profile_tls = nullptr;
};

struct ProfileDetection {
    /*
     *  0   MODE_NONE
     *  1   MODE_POST -- works in all scenarios, but sometimes we can read data, which should 
     *                   have been processed by upgraded com. Use MODE_PRE if possible.
     *  2   MODE_PRE  -- should be default, but not safe when cannot peek()
     */
    int mode = 0;
    std::string name;
};

struct ProfileContent {
    /*
     *  Quite obvious: if true, content of proxy transmission will be written to the 
     *                 mitm/ file.
     */
    bool write_payload = false;
    std::string name;
};

struct ProfileTls {
    bool inspect = false;
    bool allow_untrusted_issuers = false;
    bool allow_invalid_certs = false;
    bool allow_self_signed = false;
    std::string name;
};

#endif