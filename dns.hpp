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
#include <logger.hpp>
#include <cidr.hpp>
#include <addrobj.hpp>

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

extern const char* _unknown;
extern const char* str_a;
extern const char* str_aaaa;
extern const char* str_cname;
extern const char* str_txt;
extern const char* str_opt;
extern const char* str_soa;

const char* dns_record_type_str(int a);

struct DNS_Question {
    std::string rec_str;
    uint16_t rec_type = 0;
    uint16_t rec_class = 0;
    size_t mem_size() const { return rec_str.size()+1 + 2*sizeof(uint16_t); };
    std::string hr() const { return string_format("type: %s class: %d record: %s", 
                                               dns_record_type_str(rec_type),
                                               rec_class, rec_str.c_str()); }
};

struct DNS_Answer {
    uint16_t name_ = 0;
    uint16_t type_ = 0;
    uint16_t class_ = 0;
    uint32_t ttl_ = 0;
    uint16_t datalen_ = 0;
    buffer data_;
    
    std::string ip() const { 
        std::string ret;
        if(type_ == A && data_.size() == 4) {
            uint32_t ip = data_.get_at<uint32_t>(0);
            in_addr a;
            a.s_addr = ip;
            std::string rr = string_format(" ip: %s",inet_ntoa(a));
            ret += rr;
        }
        else if(type_ == AAAA && data_.size() == 16) {
            char b[64];
            memset(b,0,64);
            
            inet_ntop(AF_INET6,data_.data(),b,64);
            ret += string_format(" ip6: %s",b);
        }
        
        return ret;
    }
    
    CIDR* cidr() const {
        if(type_ == A && data_.size() == 4) {
            uint32_t ip = data_.get_at<uint32_t>(0);
            in_addr a;
            a.s_addr = ip;
            
            return cidr_from_inaddr(&a);
        } 
        else if (type_ == AAAA && data_.size() == 16) {
            in6_addr a;
            memcpy(&a.s6_addr,data_.data(),16);
            return cidr_from_in6addr(&a);
        }
        
        return nullptr;
    }
    
    std::string hr() const { 
        
        std::string ret = string_format("type: %s, class: %d, ttl: %d",dns_record_type_str(type_),class_,ttl_);
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

    std::vector<DNS_Question> questions_list;
    std::vector<DNS_Answer> answers_list;
    std::vector<DNS_Answer> authorities_list;
    //std::vector<DNS_AdditionalInfo> additionals_list;
    std::vector<DNS_Answer> additionals_list;
    
public:    
    std::vector<int> answer_ttl_idx; // should be protected;
    time_t      loaded_at = 0;
    
    virtual std::string to_string(int verbosity=INF);
    virtual bool ask_destroy() { return false; };

    virtual ~DNS_Packet() {}
    int load(buffer* src); // initialize from memory. if non-zero is returned, there is yet another data and new DNS_packet should be read.

    inline uint16_t id() const { return id_; }
    inline uint16_t flags() const { return flags_; } // todo: split and inspect all bits of this field
    inline int questions() { return questions_list.size(); }
    inline int answers() { return questions_list.size(); }

    // helper inline functions to operate on most common content
    std::string question_str_0() const { 
        if(questions_list.size()) { 
            std::string ret;
            if(question_type_0() == A) ret = "A:";
            else if (question_type_0() == AAAA) ret = "AAAA:";
            return ret += string_format(questions_list.at(0).rec_str); 
        } 
        return std::string("? "); 
    };
    uint16_t question_type_0() const { if(questions_list.size()) { return questions_list.at(0).rec_type; } return 0; };
    uint16_t question_class_0() const { if(questions_list.size()) { return questions_list.at(0).rec_class; } return 0; };
    
    std::string answer_str() const;
    std::vector<CidrAddress*> get_a_anwsers();

    DECLARE_C_NAME("DNS_Packet");
    DECLARE_LOGGING(to_string);
};

class DNS_Request : public DNS_Packet {
public:
    DNS_Request(): DNS_Packet() {};        // we won't allow parsing in constructor
    virtual ~DNS_Request() {};
    DECLARE_C_NAME("DNS_Request");
    DECLARE_LOGGING(to_string);
};


class DNS_Response : public DNS_Packet {
public:
    buffer* cached_packet = nullptr;
    unsigned int cached_id_idx = 0;
    
    DNS_Response(): DNS_Packet() {};        // we won't allow parsing in constructor
    virtual ~DNS_Response() { if(cached_packet != nullptr) delete cached_packet; };
    
    DECLARE_C_NAME("DNS_Response");
    DECLARE_LOGGING(to_string);
};


typedef ptr_cache<std::string,DNS_Response> dns_cache;

extern dns_cache inspect_dns_cache;
extern std::unordered_map<std::string,ptr_cache<std::string,DNS_Response>*> inspect_per_ip_dns_cache;

typedef ptr_cache<std::string,expiring_int> domain_cache_entry_t;
typedef ptr_cache<std::string,domain_cache_entry_t> domain_cache_t;
extern domain_cache_t domain_cache;

#endif