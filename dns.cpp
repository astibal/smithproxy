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

#include <arpa/inet.h>


#include <dns.hpp>
#include <logger.hpp>


const char* dns_record_type_str(int a) {
    switch(a) {
        case A: return str_a;
        case AAAA: return str_aaaa;
        case CNAME: return str_cname;
        
        default: return _unknown;
    }
}

bool DNS_Packet::load(buffer* src) {

    if(src->size() > DNS_HEADER_SZ) {
        id_ = ntohs(src->get_at<unsigned short>(0));
        flags_ = ntohs(src->get_at<unsigned short>(2));
        questions_ = ntohs(src->get_at<unsigned short>(4));
        answers_ = ntohs(src->get_at<unsigned short>(6));
        authorities_ = ntohs(src->get_at<unsigned short>(8));
        additionals_ = ntohs(src->get_at<unsigned short>(10));
        //std::string    rq((const char*)&src->data()[DNS_HEADER_SZ]);
        
        uint16_t questions_togo = questions_;
        uint16_t answers_togo = answers_;
        uint16_t authorities_togo = authorities_;
        uint16_t additionals_togo = additionals_;
        
        DIA_("DNS_Packet::load: Q: %d, A: %d, AU: %d, AD: %d  (packet length=%d)",questions_,answers_,authorities_,additionals_,src->size());
        
        unsigned int mem_counter = DNS_HEADER_SZ;
            
        /* QUESTION */
        if(questions_togo > 0) {
            for(; mem_counter < src->size() && questions_togo > 0 && questions_togo > 0;) {
                DNS_Question question_temp;
                int s = 0;
                
                for(unsigned int i = mem_counter; i < src->size() && questions_togo > 0;) {
                    s = src->get_at<uint8_t>(i);
                    if(s + i >= src->size()) break;
                    DEB_("DNS_Packet::load: question s=%d",s);
                    
                    // last part of the fqdn?
                    if(s == 0) {
                        question_temp.rec_type = ntohs(src->get_at<unsigned short>(i+1));
                        question_temp.rec_class =  ntohs(src->get_at<unsigned short>(i+1+2));
                        DEB_("type=%d,class=%d",question_temp.rec_type,question_temp.rec_class);
                        mem_counter += 1+(2*2);
                        DEB_("DNS_Packet::load: s==0, mem counter changed to: %d (0x%x)",mem_counter,mem_counter);
                        
                        if(questions_togo > 0) {
                            questions_list.push_back(question_temp);
                            questions_togo--;
                        }
                        // we don't currently process authorities and additional records
                        break;
                    } else {
                        if(question_temp.rec_str.size() != 0) question_temp.rec_str += ".";
                        
                        std::string t((const char*)&src->data()[i+1],s);
                        
                        i += (s + 1);
                        mem_counter += (s+1);
                        question_temp.rec_str += t;
                    }
                }
                DIA_("DNS_Packet::load: question[%d]: name: %s, type: %s, class: %d",questions_togo, question_temp.rec_str.c_str(),
                                    dns_record_type_str(question_temp.rec_type),question_temp.rec_class);
            }
        }
            
        /* ANSWER section */
        if(answers_togo > 0) {
            for(unsigned int i = mem_counter; i < src->size() && answers_togo > 0; ) {
                DNS_Answer answer_temp;
                answer_temp.name_ = ntohs(src->get_at<unsigned short>(i));
                answer_temp.type_ = ntohs(src->get_at<unsigned short>(i+2));
                answer_temp.class_ = ntohs(src->get_at<unsigned short>(i+4));
                answer_temp.ttl_ = ntohl(src->get_at<uint32_t>(i+6));
                answer_temp.datalen_ = ntohs(src->get_at<uint32_t>(i+10)); 
                answer_temp.data_.append(src->view(i+12,answer_temp.datalen_));
                int inc = 12 + answer_temp.datalen_;

                mem_counter += inc ;
                i += inc;
                
                DIA_("DNS_Packet::load: answer[%d]: name: %d, type: %d, class: %d, ttl: %d, len: %d, buflen: %d",answers_togo,
                                    answer_temp.name_,answer_temp.type_,answer_temp.class_,answer_temp.ttl_,answer_temp.datalen_,answer_temp.data_.size()  );
                answers_list.push_back(answer_temp);
                answers_togo--;
            }
        }
        
        if(questions_togo == 0 && answers_togo == 0 ) {
            
            return true;
        }
    }
    return false;
};


std::string DNS_Packet::hr() const {
    std::string r = string_format("id: %d, type 0x%x [ ",id_,flags_);
    for(auto x = questions_list.begin(); x != questions_list.end(); ++x) {
        r += x->hr();
        if(x+1 != questions_list.end()) {
            r += ",";
        }
    }
    r+=" ]";
    
    if(answers_list.size() > 0) {
        r += " -> [";
        for(auto x = answers_list.begin(); x != answers_list.end(); ++x) {
            r += x->hr();
            if(x+1 != answers_list.end()) {
                r += " | ";
            }
        }
        r+=" ]";
    }
    
    return r;

}


std::string DNS_Packet::answer_str() const {
    std::string ret = "";
    
    for(auto x = answers_list.begin(); x != answers_list.end(); ++x) {
        if(x->type_ == A) {
            ret += " " + x->ip();
        }
    }
    
    return ret;
}
