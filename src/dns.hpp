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

#ifndef DNS_HPP
 #define DNS_HPP

#include <string>
#include <vector>
#include <mutex>
#include <unordered_map>
#include <ctime>

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <sobject.hpp>
#include <ptr_cache.hpp>
#include <buffer.hpp>
#include <display.hpp>
#include <log/logger.hpp>
#include <ext/libcidr/cidr.hpp>
#include <addrobj.hpp>

#include <dns.hpp>

#define DNS_HEADER_SZ 12


typedef enum DNS_Record_Type_ { 
    UNKNOWN=0,
    A=1,
    CNAME=5,
    SOA=6,
    TXT=16,
    AAAA=28,
    OPT=41
} DNS_Record_Type;


struct DNS_Response;

class DNSFactory {
    const char* _unknown = "unknown";
    const char* str_a = "A";
    const char* str_aaaa = "AAAA";
    const char* str_cname = "CNAME";
    const char* str_txt= "TXT";
    const char* str_opt = "OPT";
    const char* str_soa = "SOA";


    DNSFactory() : log(get_log()) {};

    logan_lite& log;
public:
    DNSFactory(DNSFactory const&) = delete;
    void operator=(DNSFactory const&) = delete;

    const char *dns_record_type_str(int a);
    int load_qname(unsigned char* ptr, unsigned int maxlen, std::string* str_storage);
    int generate_dns_request(unsigned short id, buffer& b, std::string const& hostname, DNS_Record_Type t);

    // send DNS request out to network. Return socket FD, or non-positive on error.
    // you want to call this for async request
    int send_dns_request (std::string const &hostname, DNS_Record_Type t, std::string const &nameserver);

    // @returns: response and return from receive - well. I don't like it this way either,
    // but we can't actually return nullptr, since it could be legit return value on non-blocking socket
    // you want to call this for async receive - ideally if socket is in readset.
    std::pair<DNS_Response*,int> recv_dns_response(int send_socket, unsigned int timeout_sec=2);


    // this is easiest way to resolve. Just do the thing, with blocking ... and waiting.
    DNS_Response* resolve_dns_s (std::string const& hostname, DNS_Record_Type t, std::string const& nameserver, unsigned int timeout_s=2);


    static DNSFactory& get() {
        static DNSFactory d;
        return d;
    };

    static logan_lite& get_log() {
        static logan_lite l("com.dns");
        return l;
    }
};

struct DNS_Question {
    std::string rec_str;
    uint16_t rec_type = 0;
    uint16_t rec_class = 0;
    size_t mem_size() const { return rec_str.size()+1 + 2*sizeof(uint16_t); };
    std::string hr() const { return string_format("type: %s class: %d record: %s", 
                                               DNSFactory::get().dns_record_type_str(rec_type),
                                               rec_class, rec_str.c_str()); }
};

struct DNS_Answer {
    uint16_t name_ = 0;
    uint16_t type_ = 0;
    uint16_t class_ = 0;
    uint32_t ttl_ = 0;
    uint16_t datalen_ = 0;
    buffer data_;
    
    std::string ip(bool nice=true) const { 
        std::string ret;
        if(type_ == A && data_.size() == 4) {
            uint32_t ip = data_.get_at<uint32_t>(0);

            in_addr a{0};
            a.s_addr = ip;
            
            if(nice) 
                ret = string_format("ip4: %s",inet_ntoa(a));
            else
                ret = string_format("%s",inet_ntoa(a));
        }
        else if(type_ == AAAA && data_.size() == 16) {
            char b[64];
            memset(b,0,64);
            
            inet_ntop(AF_INET6,data_.data(),b,64);
            
            if(nice)
                ret = string_format("ip6: %s",b);
            else
                ret = string_format("%s",b);
        }
        
        return ret;
    }
    
    CIDR* cidr() const {
        if(type_ == A && data_.size() == 4) {
            uint32_t ip = data_.get_at<uint32_t>(0);
            in_addr a{0};
            a.s_addr = ip;
            
            return cidr_from_inaddr(&a);
        } 
        else if (type_ == AAAA && data_.size() == 16) {
            in6_addr a{0};
            memcpy(&a.s6_addr,data_.data(),16);
            return cidr_from_in6addr(&a);
        }
        
        return nullptr;
    }
    
    std::string hr() const { 
        
        std::string ret = string_format("type: %s, class: %d, ttl: %d",
                                        DNSFactory::get().dns_record_type_str(type_),class_,ttl_);
        ret += ip();
        return ret;
    };
};


struct DNS_DnssecAdditionalInfo {
    uint8_t  name_ = 0; // 0 - ROOT
    uint16_t opt_ = 0;  // 0x29 - EDNS0
    uint16_t udp_size_ = 0;
    uint8_t  higher_bits_rcode_ = 0;
    uint8_t  edns0_version_ = 0;
    uint16_t z_ = 0;
    uint16_t datalen_ = 0;
    buffer   data_;
};

class DNS_Packet : public socle::sobject {
protected:
    uint16_t    id_ = 0;
    uint16_t    flags_ = 0;

    uint16_t    questions_ = 0;
    uint16_t    answers_ = 0;
    uint16_t    authorities_ = 0;
    uint16_t    additionals_ = 0;

    std::vector<DNS_Question> questions_list_;
    std::vector<DNS_Answer> answers_list_;
    std::vector<DNS_Answer> authorities_list_;
    //std::vector<DNS_AdditionalInfo> additionals_list;
    std::vector<DNS_Answer> additionals_list_;

private:
    logan_attached<DNS_Packet> log;

public:
    explicit DNS_Packet() {
        log = logan::attach<DNS_Packet>(this, "com.dns");
    };

    std::vector<int> answer_ttl_idx; // should be protected;
    time_t      loaded_at = 0;
    
    std::string to_string(int verbosity=iINF) const override;
    bool ask_destroy() override { return false; };

    ~DNS_Packet() override = default;

    int load(buffer* src); // initialize from memory. if non-zero is returned, there is yet another data and new DNS_packet should be read.

    inline uint16_t id() const { return id_; }
    inline uint16_t flags() const { return flags_; } // todo: split and inspect all bits of this field

    // helper inline functions to operate on most common content
    std::string question_str_0() const { 
        if(! questions_list_.empty()) {
            std::string ret;
            if(question_type_0() == A) ret = "A:";
            else if (question_type_0() == AAAA) ret = "AAAA:";
            ret += string_format("%s", questions_list_.at(0).rec_str.c_str());
            return ret;
        } 
        return std::string("? "); 
    };
    uint16_t question_type_0() const { if( ! questions_list_.empty() ) { return questions_list_.at(0).rec_type; } return 0; };
    uint16_t question_class_0() const { if( ! questions_list_.empty() ) { return questions_list_.at(0).rec_class; } return 0; };
    
    std::string answer_str() const;
    std::vector<CidrAddress*> get_a_anwsers() const;

    inline std::vector<DNS_Question>& questions() { return questions_list_; };
    inline std::vector<DNS_Answer>& answers() { return answers_list_; };
    inline std::vector<DNS_Answer>& authorities() { return authorities_list_; };
    inline std::vector<DNS_Answer>& additionals() { return additionals_list_; };
    

    DECLARE_C_NAME("DNS_Packet");
    DECLARE_LOGGING(to_string);
};

#define DNS_REQUEST_OVERHEAD 17

class DNS_Request : public DNS_Packet {
private:
    logan_attached<DNS_Request> log;

public:
    DNS_Request(): DNS_Packet() {
        log = logan::attach<DNS_Request>(this, "dns");
        _deb("DNS_Request::c-tor");
    };


    ~DNS_Request() override {
        _deb("DNS_Request::d-tor");
    };
    DECLARE_C_NAME("DNS_Request");
    DECLARE_LOGGING(to_string);
};


class DNS_Response : public DNS_Packet {
private:
    logan_attached<DNS_Response> log;

public:
    buffer* cached_packet = nullptr;
    unsigned int cached_id_idx = 0;
    
    DNS_Response(): DNS_Packet() {
        log = logan::attach<DNS_Response>(this,"dns");
        _deb("DNS_Response::c-tor");
    };
    ~DNS_Response() override {
        _deb("DNS_Request::d-tor");
        if(cached_packet != nullptr) {
            _deb("DNS_Request::d-tor deleting cached packet");
            delete cached_packet;
        }
    };
    
    DECLARE_C_NAME("DNS_Response");
    DECLARE_LOGGING(to_string);
};


class DNS {

public:
    static const unsigned int cache_size = 2000;
    static const unsigned int sub_ttl = 3600;
    static const unsigned int top_ttl = 28000;

private:
    typedef ptr_cache<std::string,DNS_Response> dns_cache_t;
    typedef ptr_cache<std::string,expiring_int> domain_cache_entry_t;
    typedef ptr_cache<std::string,domain_cache_entry_t> domain_cache_t;

    dns_cache_t dns_cache_;
    domain_cache_t domain_cache_;


    DNS() :
        dns_cache_("DNS cache - global", cache_size, true),
        domain_cache_("DNS 3l domain cache", cache_size, true)
    {}

public:

    inline dns_cache_t& dns_cache() { return dns_cache_; };
    inline domain_cache_t& domain_cache() { return domain_cache_; };

    inline std::recursive_mutex& dns_lock() { return dns_cache().getlock(); };
    inline std::recursive_mutex& domain_lock() { return domain_cache().getlock(); };


    static dns_cache_t& get_dns_cache() { return get().dns_cache(); };
    static domain_cache_t& get_domain_cache() { return get().domain_cache(); };

    static std::recursive_mutex& get_dns_lock() { return get().dns_lock(); };
    static std::recursive_mutex& get_domain_lock() { return get().domain_lock(); };

    static domain_cache_entry_t* make_domain_entry(std::string const& s) {
        return new domain_cache_entry_t(string_format("DNS cache for %s",s.c_str()).c_str(), DNS::sub_ttl, true);
    }

    static DNS& get() {
        static DNS st;
        return st;
    }
};

#endif