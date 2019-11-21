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

#ifndef MITMHOSTCX_HPP
 #define MITMHOSTCX_HPP

#include <sslmitmcom.hpp>
#include <apphostcx.hpp>
#include <dns.hpp>
#include <inspectors.hpp>
#include <sxsignature.hpp>

extern std::vector<duplexFlowMatch*> sigs_starttls;
extern std::vector<duplexFlowMatch*> sigs_detection;



class MySSLMitmCom : public baseSSLMitmCom<SSLCom> {
public:
    ~MySSLMitmCom() override = default;

    baseCom* replicate() override;
    bool spoof_cert(X509* x, SpoofOptions& spo) override;
};

class MyDTLSMitmCom : public baseSSLMitmCom<DTLSCom> {
    ~MyDTLSMitmCom() override = default;
};


struct ApplicationData: public socle::sobject {
    ~ApplicationData() override = default;
    bool is_ssl = false;
    
    virtual std::string hr(int verbosity=iINF) const { return std::string(""); };
    virtual std::string original_request() { return request(); }; // parent request
    virtual std::string request() { return std::string(""); };
    
    bool ask_destroy() override { return false; };
    std::string to_string(int verbosity = iINF) const override { return name() + ": " + hr(verbosity); };
    
    DECLARE_C_NAME("ApplicationData");
};
struct app_HttpRequest : public ApplicationData {
    ~app_HttpRequest() override = default;
  
    std::string host;
    std::string uri;
    std::string params;
    std::string referer;
    std::string proto;
    
    
    // this function returns most usable link for visited site from the request.
    std::string original_request() override {
        if(referer.size() > 0) {
            DEB_("std::string original_request: using referer: %s",referer.c_str());
            return referer;
        }
        
        DEB_("std::string original_request: using request: %s",request().c_str());
        return request();
    }
    std::string request() override {
        
        if(uri == "/favicon.ico") {
            DEBS_("std::string original_request: avoiding favicon.ico");
            return host;
        }
        return proto+host+uri+params;
    };

    std::string hr(int verbosity=iINF) const override {
        std::stringstream ret;

        ret << proto << host << uri << params;

        if(verbosity> INF && referer.size()>0) {
            ret << " via " << referer;
        }

        return ret.str();
    }
    
    DECLARE_C_NAME("app_HttpRequest");
};

struct app_DNS : public ApplicationData{
    DNS_Request*  request = nullptr;
    DNS_Response* response = nullptr;
    
    DECLARE_C_NAME("app_DNS");
};

class MitmHostCX : public AppHostCX, public socle::sobject {
public:
    ApplicationData* application_data = nullptr;
    
    ~MitmHostCX() override { delete application_data; for(auto i: inspectors_) { delete i; } };
    
    MitmHostCX(baseCom* c, const char* h, const char* p );
    MitmHostCX( baseCom* c, int s );

    int process() override;
    virtual void load_signatures();

    
    std::vector<Inspector*> inspectors_;
    void inspect(char side) override;
    void on_detect(duplexFlowMatch* x_sig, flowMatchState& s, vector_range& r) override;
    virtual void on_detect_www_get(duplexFlowMatch* x_sig, flowMatchState& s, vector_range& r);
    
    void on_starttls() override;

    int matched_policy() { return matched_policy_; }
    void matched_policy(int p) { matched_policy_ = p; }

    typedef enum { REPLACETYPE_NONE=0, REPLACETYPE_HTTP=1 } replacetype_t;
    replacetype_t replacement_type() const { return replacement_type_; }
    void replacement_type(replacetype_t r) { replacement_type_ = r; }
    
    typedef enum { REPLACE_NONE=0, REPLACE_REDIRECT=1, REPLACE_BLOCK=2 } replaceflags_t;    
    void replacement_flag(replaceflags_t i) { replacement_flags_ = i; }
    replaceflags_t replacement_flag()   { return replacement_flags_; }
    
    typedef enum {} replacepurpose_t;
    
    int inspection_verdict() const { return inspect_verdict; };
protected:    
    int matched_policy_ = -1;
    
    replacetype_t replacement_type_ = REPLACETYPE_NONE; 
    replaceflags_t replacement_flags_ = REPLACE_NONE;

    logan_attached<MitmHostCX> log;
public:
    bool is_ssl = false;
    bool is_ssl_port = false;
    
    bool is_http = false;
    bool is_http_port = false;

    bool is_dns = false;
    bool is_dns_port = false;

    bool ask_destroy() override;
    std::string to_string(int verbosity = iINF) const override;
    
private:

    baseProxy* parent_proxy_ = nullptr;

    unsigned int inspect_cur_flow_size = 0;
    unsigned int inspect_flow_same_bytes = 0;
    int inspect_verdict = Inspector::OK;
    
    DECLARE_C_NAME("MitmHostCX");
    DECLARE_LOGGING(to_string);
};

#endif