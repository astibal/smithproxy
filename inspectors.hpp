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

//
/// \file  inspector.hpp
/// \brief Inspection modules called/updated usually MitmHostCX::inspect()
/// \sa MitmHostCX::inspect
//


#ifndef INSPECTORS_HPP_
#define INSPECTORS_HPP_

#include <basecom.hpp>
#include <tcpcom.hpp>
#include <dns.hpp>
#include <signature.hpp>
#include <apphostcx.hpp>
#include <regex>

#include <sobject.hpp>
#include <lockable.hpp>

//
/// \brief Abstract class intended to be parent for all inspector modules.
///        Serves as an interface.
///
//
class Inspector : public socle::sobject, public lockable {
public:
    virtual ~Inspector() {}
    //! called always when there are new data in the flow. \see class Flow.
    virtual void update(AppHostCX* cx) = 0;
    //! called before inserting to inspector list. 
    //! \return false if you don't want insert inspector to the list (and save some CPU cycles).
    virtual bool l4_prefilter(AppHostCX* cx) = 0;
    
    //! called before each update to indicate if update() should be called.
    virtual bool interested(AppHostCX*) = 0;
    
    //! indicate if inspection is complete. Completed inspectors are not updated.
    inline bool completed() const   { return completed_; }
    //! indicate if inspection started already.
    inline bool in_progress() const { return in_progress_; }
    //! indicate if inspector was able to parse and process the payload.
    inline bool result() const { return result_; }

    typedef enum { OK=0, BLOCK, CACHED } inspect_verdict;
    inspect_verdict verdict_ = OK;
    inspect_verdict verdict() const { return verdict_; };
    void verdict(inspect_verdict v) { verdict_ = v; }
    virtual void apply_verdict(AppHostCX* cx);
    
protected:
    bool completed_ = false;
    void completed(bool b) { completed_ = b; }
    bool in_progress_ = false;
    void in_progress(bool b) { in_progress_ = b; }
    bool result_ = false;
    void result(bool b) { result_ = b; }
    
    //! internal stage counter. It could be used 
    int stage = 0;
    
    
    virtual bool ask_destroy() { return false; };
    virtual std::string to_string(int verbosity=iINF) { return string_format("%s: in-progress: %d stage: %d completed: %d result: %d",
                                                c_name(),in_progress(), stage, completed(),result()); };
    
                                                
    static std::string remove_redundant_dots(std::string);
    static std::vector<std::string> split(std::string, unsigned char delimiter);
    static std::pair<std::string,std::string> split_fqdn_subdomain(std::string& fqdn);
                                                
    DECLARE_C_NAME("Inspector");
};


class DNS_Inspector : public Inspector {
public:
    virtual ~DNS_Inspector() {
        // clear local request cache
        for(auto x: requests_) { if(x.second) {delete x.second; } };
        if(cached_response != nullptr) delete cached_response;
    };  
    virtual void update(AppHostCX* cx);

    virtual bool l4_prefilter(AppHostCX* cx) { return interested(cx); };
    virtual bool interested(AppHostCX*cx);
    
    bool opt_match_id = false;
    bool opt_randomize_id = false;
    bool opt_cached_responses = false;
    
    DNS_Request* find_request(uint16_t r) { auto it = requests_.find(r); if(it == requests_.end()) { return nullptr; } else { return it->second; }  }
    bool validate_response(DNS_Response* ptr);
    bool store(DNS_Response* ptr);
    virtual void apply_verdict(AppHostCX* cx);
    
    virtual std::string to_string(int verbosity=iINF);

    static std::regex wildcard;
private:
    bool is_tcp = false;

    buffer* cached_response = nullptr;
    uint16_t cached_response_id = 0;
    std::vector<int> cached_response_ttl_idx;
    uint32_t cached_response_decrement = 0;

    std::unordered_map<uint16_t,DNS_Request*>  requests_;
    int responses_ = 0;
    bool stored_ = false;

    DECLARE_C_NAME("DNS_Inspector");
    DECLARE_LOGGING(name);
};


#endif //INSPECTORS_HPP_