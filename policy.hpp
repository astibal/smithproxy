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

      
       bool match(baseProxy*);
       virtual ~PolicyRule();
       
       bool match_addrgrp_cx(std::vector<CIDR*>& cidrs,baseHostCX* cx);
       bool match_addrgrp_vecx(std::vector<CIDR*>& cidrs,std::vector<baseHostCX*>& vecx);
       bool match_rangegrp_cx(std::vector<range>& ranges,baseHostCX* cx);
       bool match_rangegrp_vecx(std::vector<range>& ranges,std::vector<baseHostCX*>& vecx);
       
};
 
#endif