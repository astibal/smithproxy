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
    virtual std::string hr() = 0;
};
struct app_HttpRequest : public ApplicationData {
    virtual ~app_HttpRequest() {};
  
    std::string host;
    std::string uri;
    std::string params;
    virtual std::string hr() { return host+uri+params; }
};

class MitmHostCX : public AppHostCX {
public:
    ApplicationData* request = nullptr;
    
    virtual ~MitmHostCX() { delete request; };
    
    MitmHostCX(baseCom* c, const char* h, const char* p );
    MitmHostCX( baseCom* c, int s );
    
    virtual int process();
    virtual void load_signatures();

    virtual void on_detect(duplexFlowMatch* x_sig, flowMatchState& s, vector_range& r);    
    virtual void on_starttls();

    int matched_policy() { return matched_policy_; }
    void matched_policy(int p) { matched_policy_ = p; }

    typedef enum { REPLACE_NONE=0, REPLACE_REDIRECT=1, REPLACE_BLOCK=2 } replace_flags;    
    void replacement(replace_flags i) { replacement_ = i; }
    replace_flags replacement(void)   { return replacement_; }
protected:    
    int matched_policy_ = -1;
    
    replace_flags replacement_ = REPLACE_NONE;
};

#endif