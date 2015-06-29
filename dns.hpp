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

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <buffer.hpp>
#include <display.hpp>
#include <logger.hpp>

#define DNS_HEADER_SZ 12

typedef enum DNS_Record_Type_ { 
    UNKNOWN=0,
    A=1,
    CNAME=5,
    AAAA=28 
} DNS_Record_Type;

static const char* _unknown = "unknown";
static const char* str_a = "A";
static const char* str_aaaa = "AAAA";
static const char* str_cname = "CNAME";

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
            std::string rr = string_format("%s",inet_ntoa(a));
            ret += rr;
        }
        
        return ret;
    }
    std::string hr() const { 
        
        std::string ret = string_format("type: %s, class: %d, ttl: %d",dns_record_type_str(type_),class_,ttl_);
        ret += ip();
        return ret;
    };
};

class DNS_Packet {
protected:
    uint16_t    id_ = 0;
    uint16_t    flags_ = 0;

    uint16_t    questions_ = 0;
    uint16_t    answers_ = 0;
    uint16_t    authorities_ = 0;
    uint16_t    additionals_ = 0;

    std::vector<DNS_Question> questions_list;
    std::vector<DNS_Answer> answers_list;

public:    
    bool load(buffer* src); // initialize from memory
    virtual std::string hr() const;

    inline uint16_t id() const { return id_; }
    inline uint16_t flags() const { return flags_; } // todo: split and inspect all bits of this field
    inline int questions() { return questions_list.size(); }
    inline int answers() { return questions_list.size(); }

    // helper inline functions to operate on most common content
    std::string question_str_0() const { if(questions_list.size()) { return questions_list.at(0).rec_str; } return std::string(""); };
    uint16_t question_type_0() const { if(questions_list.size()) { return questions_list.at(0).rec_type; } return 0; };
    uint16_t question_class_0() const { if(questions_list.size()) { return questions_list.at(0).rec_class; } return 0; };
    
    std::string answer_str() const;
};

class DNS_Request : public DNS_Packet {
public:
    DNS_Request(): DNS_Packet() {};        // we won't allow parsing in constructor
};


class DNS_Response : public DNS_Packet {
public:
    DNS_Response(): DNS_Packet() {};        // we won't allow parsing in constructor
};


#endif