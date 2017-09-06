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
#include <addrobj.hpp>

#include <sobject.hpp>

#define POLICY_ACTION_DENY  0
#define POLICY_ACTION_PASS  1

#define POLICY_NAT_NONE     0
#define POLICY_NAT_AUTO     1
#define POLICY_NAT_POOL     2

struct ProfileDetection;
struct ProfileContent;
struct ProfileTls;
struct ProfileAuth;
struct ProfileAlgDns;


struct ProfileList {
       ProfileContent* profile_content = nullptr;
       ProfileDetection* profile_detection = nullptr;
       ProfileTls* profile_tls = nullptr;
       ProfileAuth* profile_auth = nullptr;
       ProfileAlgDns* profile_alg_dns = nullptr;
};

class PolicyRule : public ProfileList , public socle::sobject {

public:
       int proto = 6;
       bool proto_default = true;
    
       std::vector<AddressObject*> src;
       bool src_default = true;
       std::vector<range> src_ports;
       bool src_ports_default = true;
       
       std::vector<AddressObject*> dst;
       bool dst_default = true;
       std::vector<range> dst_ports;
       bool dst_ports_default = true;

       int action = POLICY_ACTION_PASS;
       int nat    = POLICY_NAT_NONE;
      
       PolicyRule() : ProfileList(), socle::sobject() {};
       virtual ~PolicyRule();
       
       bool match(baseProxy*);
       bool match(std::vector<baseHostCX*>& l, std::vector<baseHostCX*>& r);
       
       bool match_addrgrp_cx(std::vector<AddressObject*>& cidrs,baseHostCX* cx);
       bool match_addrgrp_vecx(std::vector<AddressObject*>& cidrs,std::vector<baseHostCX*>& vecx);
       bool match_rangegrp_cx(std::vector<range>& ranges,baseHostCX* cx);
       bool match_rangegrp_vecx(std::vector<range>& ranges,std::vector<baseHostCX*>& vecx);
       
       virtual bool ask_destroy() { return false; }
       virtual std::string to_string(int verbosity = 6);
       
       DECLARE_C_NAME("PolicyRule");
       DECLARE_LOGGING(to_string);       
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

struct ProfileContentRule {
    std::string match;
    std::string replace;
    bool fill_length = false;
    int replace_each_nth = 0;
    int replace_each_counter_ = 0;
};

struct ProfileContent {
    /*
     *  Quite obvious: if true, content of proxy transmission will be written to the 
     *                 mitm/ file.
     */
    bool write_payload = false;
    std::string name;
    
    std::vector<ProfileContentRule> content_rules;
};


struct ProfileTls {
    bool inspect = false;
    bool allow_untrusted_issuers = false;
    bool allow_invalid_certs = false;
    bool allow_self_signed = false;
    bool failed_certcheck_replacement = true; //instead of resetting connection, spoof and display human-readable explanation why connection failed
    bool failed_certcheck_override = false;   //failed ssl replacement will contain option to temporarily allow the connection for the source IP.
    int  failed_certcheck_override_timeout = 600; // if failed ssl override is active, this is the timeout.
    
    bool use_pfs = true;         // general switch, more conrete take precedence
    bool left_use_pfs = true;
    bool right_use_pfs = true;
    bool left_disable_reuse = false;
    bool right_disable_reuse = false;
    
    int ocsp_mode = 0;           //  0 = disable OCSP checks ; 1 = check only end certificate ; 2 = check all certificates
    bool ocsp_stapling = false;
    int  ocsp_stapling_mode = 0; // 0 = loose, 1 = strict, 2 = require
    std::string name;
    
    socle::spointer_vector_string sni_filter_bypass;
    socle::spointer_set_int redirect_warning_ports;
    
    bool sni_filter_use_dns_cache = true;       // if sni_filter_bypass is set, check during policy match if target IP isn't in DNS cache matching SNI filter entries.
                                                // For example: 
                                                // Connection to 1.1.1.1 policy check will look in all SNI filter entries ["abc.com","mybank.com"] and will try to find them in DNS cache. 
                                                // Sni filter entry mybank.com is found in DNS cache pointing to 1.1.1.1. Connection is bypassed.
                                                // Load increases with SNI filter length lineary, but DNS cache lookup is fast.
                                                // DNS cache has to be active this to be working.
    bool sni_filter_use_dns_domain_tree = true;
                                                // check IP address in full domain tree for each SNI filter entry.
                                                // if SNI filter entry can't be found in DNS cache, try to look in all DNS subdomains of SNI filter entries.
                                                // Example:
                                                // Consider SNI filter from previous example. You are now connecting to ip 2.2.2.2. 
                                                // Based on previous DNS traffic, there is subdomain cache for "mybank.com" filled with entries "www" and "ecom".
                                                // Both "www" and "ecom" are searched in DNS cache. www points to 1.1.1.1, but ecom points to 2.2.2.2. 
                                                // Connection is bypassed.
                                                // DNS cache has to active and sni_filter_use_dns_cache enabled before this feature can be activated.
                                                // Load increases with SNI filter size and subdomain cache, both lineary, so it's intensive feature.

};


struct ProfileSubAuth : public ProfileList {
    std::string name;
};

struct ProfileAuth {
    bool authenticate = false;
    bool resolve = false;  // resolve traffic by ip in auth table
    std::string name;
    std::vector<ProfileSubAuth*> sub_policies;
};

struct ProfileAlgDns {
    bool match_request_id = false;
    bool randomize_id = false;
    bool cached_responses = false;
    std::string name;
};

#endif