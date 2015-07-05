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

#ifndef MITMHOSTCX_HPP
 #define MITMHOSTCX_HPP

#include <sslmitmcom.hpp>
#include <apphostcx.hpp>
#include <dns.hpp>
#include <inspectors.hpp>

extern std::vector<duplexFlowMatch*> sigs_starttls;
extern std::vector<duplexFlowMatch*> sigs_detection;

class MyDuplexFlowMatch : public duplexFlowMatch {
    
public:    
    std::string sig_side;
    std::string category;
};


class MySSLMitmCom : public SSLMitmCom {
public:
    virtual ~MySSLMitmCom() {};

    virtual baseCom* replicate();
    virtual bool spoof_cert(X509* x, SpoofOptions& spo);
};


struct ApplicationData {
    virtual ~ApplicationData() {};
    bool is_ssl = false;
    
    virtual std::string hr() { return std::string(""); };
    virtual std::string original_request() { return request(); }; // parent request
    virtual std::string request() { return std::string(""); };
};
struct app_HttpRequest : public ApplicationData {
    virtual ~app_HttpRequest() {};
  
    std::string host;
    std::string uri;
    std::string params;
    std::string referer;
    std::string proto;
    
    
    // this function returns most usable link for visited site from the request.
    virtual std::string original_request() {
        if(referer.size() > 0) {
            INF_("std::string original_request: using referer: %s",referer.c_str());
            return referer;
        }
        
        INF_("std::string original_request: using request: %s",request().c_str());
        return request();
    }
    virtual std::string request() {
        
        if(uri == "/favicon.ico") {
            INFS_("std::string original_request: avoiding favicon.ico");
            return host;
        }
        return proto+host+uri+params;
    };
    virtual std::string hr() { std::string ret = proto+host+uri+params; if(referer.size()>0) { ret +=(" via "+referer); }; return ret; }
};

struct app_DNS : public ApplicationData {
    DNS_Request*  request = nullptr;
    DNS_Response* response = nullptr;
};

class MitmHostCX : public AppHostCX {
public:
    ApplicationData* application_data = nullptr;
    
    virtual ~MitmHostCX() { delete application_data; for(auto i: inspectors_) { delete i; } };
    
    MitmHostCX(baseCom* c, const char* h, const char* p );
    MitmHostCX( baseCom* c, int s );
    
    virtual int process();
    virtual void load_signatures();

    
    std::vector<Inspector*> inspectors_;
    virtual void inspect();
    virtual void on_detect(duplexFlowMatch* x_sig, flowMatchState& s, vector_range& r);    
    virtual void on_detect_www_get(duplexFlowMatch* x_sig, flowMatchState& s, vector_range& r);
    
    virtual void on_starttls();

    int matched_policy() { return matched_policy_; }
    void matched_policy(int p) { matched_policy_ = p; }

    typedef enum { REPLACETYPE_NONE=0, REPLACETYPE_HTTP=1} replacetype_flags;    
    replacetype_flags replace_type = REPLACETYPE_NONE; 

    typedef enum { REPLACE_NONE=0, REPLACE_REDIRECT=1, REPLACE_BLOCK=2 } replace_flags;    
    void replacement(replace_flags i) { replacement_ = i; }
    replace_flags replacement(void)   { return replacement_; }
protected:    
    int matched_policy_ = -1;
    
    replace_flags replacement_ = REPLACE_NONE;
    
public:
    bool is_ssl = false;
    bool is_ssl_port = false;
    
    bool is_http = false;
    bool is_http_port = false;

    bool is_dns = false;
    bool is_dns_port = false;
};

#endif