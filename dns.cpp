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

#include <arpa/inet.h>


#include <dns.hpp>
#include <logger.hpp>


DEFINE_LOGGING(DNS_Packet);
DEFINE_LOGGING(DNS_Request);
DEFINE_LOGGING(DNS_Response);

const char* _unknown = "unknown";
const char* str_a = "A";
const char* str_aaaa = "AAAA";
const char* str_cname = "CNAME";
const char* str_txt= "TXT";
const char* str_opt = "OPT";
const char* str_soa = "SOA";


//std::unordered_map<std::string, ptr_cache<std::string,DNS_Response>*> inspect_per_ip_dns_cache;

const char* dns_record_type_str(int a) {
    switch(a) {
        case A: return str_a;
        case AAAA: return str_aaaa;
        case CNAME: return str_cname;
        case TXT: return str_txt;
        case OPT: return str_opt;
        case SOA: return str_soa;
        
        default: return _unknown;
    }
}


int load_qname(unsigned char* ptr, unsigned int maxlen, std::string* str_storage=nullptr) {
    unsigned int xi = 0;

    DEB_("load_qname:\n%s",hex_dump(ptr,maxlen).c_str());
    
    
    if(ptr[xi] == 0) {
        xi++;
        DEBS_("zero label");
    } 
    else if(ptr[xi] < 0xC0) {
        std::string lab;
        for(; xi < maxlen; ++xi) {
            uint8_t c = ptr[xi];
            if (c == 0) break;
            lab += c;
        }
        ++xi;
        
        if(str_storage) str_storage->assign(lab);
        
        DEB_("plain label: %s",ESC(lab));
    } else {
        uint8_t label = ptr[++xi];
        DEB_("ref label: %d",label);
        ++xi;
    }
    
    return xi;
}

int generate_dns_request(unsigned short id, buffer& b, std::string const& h, DNS_Record_Type t) {
    
    std::string hostname = "." + h;
    //need to add dot at the beginning
    
    if(b.capacity() < (hostname.size()+DNS_REQUEST_OVERHEAD)) return -1;

    unsigned char* ptr = b.data();
    
    // transaction ID
    unsigned short* transaction_id = (unsigned short*)&ptr[0];
    *transaction_id = htons(id);
    
    //
    unsigned short* flags = (unsigned short*)&ptr[2];
    *flags = htons(0x0100);
    
    unsigned short* nquestions = (unsigned short*)&ptr[4];
    *nquestions = htons(1);
    
    unsigned short* nanswers = (unsigned short*)&ptr[6];
    *nanswers= 0;
    
    unsigned short* nauthorities = (unsigned short*)&ptr[8];
    *nauthorities = 0;
   
    unsigned short* nadditionals = (unsigned short*)&ptr[10];
    *nadditionals = 0;
    
    unsigned char* queries = &ptr[12];
    
    unsigned char* len_ptr = queries;
    unsigned int piece_sz = 0;
    
    for(unsigned int i = 0; i < hostname.size(); ++i) {
        char A = hostname[i];
        if(A == '.') {
            // write a len of previous piece
            *len_ptr = piece_sz;
            
            // mark this byte as lenght field and reset piece size
            len_ptr = &queries[i];
            piece_sz = 0;
        } else {
            
            //write character into target buffer
            queries[i] = A;
            piece_sz++;
        }
    }
    // set last piece size
    *len_ptr = piece_sz;
    
    unsigned char* trailer = &queries[hostname.size()];
    trailer[0] = 0x00;
    
    unsigned short* typ = (unsigned short*)&trailer[1];
    *typ = htons(t);
    
    unsigned short* clas = (unsigned short*)&trailer[3];
    *clas = htons(0x0001);


    b.size(hostname.size()+DNS_REQUEST_OVERHEAD);
    return b.size();
}


/*
 * returns 0 on OK, >0 if  there are still some bytes to read and -1 on error.
 */
int DNS_Packet::load(buffer* src) {

    loaded_at = ::time(nullptr);
    
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
        
        DIA___("DNS_Packet::load: processing [0x%x] Q: %d, A: %d, AU: %d, AD: %d  (buffer length=%d)",id_, questions_,answers_,authorities_,additionals_,src->size());
        DEB___("DNS Packet dump:\n%s",hex_dump(src->data(),src->size()).c_str());
        
        unsigned int mem_counter = DNS_HEADER_SZ;
            
        bool failure = false;
        
        /* QUESTION */
        if(!failure && questions_togo > 0) {
            DIA___("DNS Inspect: Questions: start (count %d)",questions_togo);            
            
            for(; mem_counter < src->size() && questions_togo > 0 && questions_togo > 0;) {
                DEB___("DNS_Packet::load: question loop start: current memory pos: %d",mem_counter);
                DNS_Question question_temp;
                unsigned int field_len = 0;
                
                for(unsigned int cur_mem = mem_counter; cur_mem < src->size() && questions_togo > 0;) {
                    
                    
                    buffer tmp_b = src->view(cur_mem,src->size()-cur_mem);
                    DUM__("current buffer: %s", hex_dump(tmp_b).c_str());
                    
                    // load next field length
                    field_len = src->get_at<uint8_t>(cur_mem);
                    
                    // 
                    if(cur_mem + field_len >= src->size()) {
                        DIA___("DNS_Packet::load: incomplete question data in the preamble, position %d, field_len %d out of buffer bounds %d",cur_mem, field_len, src->size());
                        failure = true;
                        break;
                    }
                    
                    DEB___("DNS_Packet::load: question field_len=%d i=%d buffer_size=%d",field_len,cur_mem,src->size());
                    
                    // last part of the fqdn?
                    if(field_len == 0) {
                        
                        if(cur_mem+5 > src->size()) {
                            DIA___("DNS_Packet::load: incomplete question data in the preamble, index+5 = %d is out of buffer bounds %d",cur_mem+5,src->size());
                            mem_counter = src->size();
                            failure = true;
                            break;
                        }
                        question_temp.rec_type = ntohs(src->get_at<unsigned short>(cur_mem+1));           DEB___("DNS_Packet::load: read 'type' at index %d", cur_mem+1);
                        question_temp.rec_class =  ntohs(src->get_at<unsigned short>(cur_mem+1+2));       DEB___("DNS_Packet::load: read 'class' at index %d", cur_mem+1+2);
                        DEB___("type=%d,class=%d",question_temp.rec_type,question_temp.rec_class);
                        mem_counter += (1 + (2*2));
                        DEB___("DNS_Packet::load: s==0, mem counter changed to: %d (0x%x)",mem_counter,mem_counter);
                        
                        if(questions_togo > 0) {
                            questions_list_.push_back(question_temp);
                            questions_togo--;
                        }
                        // we don't currently process authorities and additional records
                        break;
                    } else {
                        if(field_len > src->size()) {
                            DIA___("DNS_Packet::load: incomplete question data in the preamble, field_len %d is out of buffer bounds %d",field_len,src->size());
                            mem_counter = src->size();
                            failure = true;
                            break;
                        }
                        if(cur_mem+1 >= src->size()) {
                            DIA___("DNS_Packet::load: incomplete question data in the preamble, cur_mem+1 = %d is out of buffer bounds %d",cur_mem+1,src->size());
                            mem_counter = src->size();
                            failure = true;
                            break;
                            
                        }
                        
                        if( ! question_temp.rec_str.empty() ) question_temp.rec_str += ".";
                        
                        std::string t((const char*)&src->data()[cur_mem+1],field_len);
                        
                        cur_mem += (field_len + 1);
                        mem_counter += (field_len+1);
                        question_temp.rec_str += t;
                    }
                }
                
                if(!failure) {
                    DIA___("DNS_Packet::load: OK question[%d]: name: %s, type: %s, class: %d",questions_togo, question_temp.rec_str.c_str(),
                                        dns_record_type_str(question_temp.rec_type),question_temp.rec_class);
                } else {
                    DIA___("DNS_Packet::load: FAILED question[%d]",questions_togo);
                    break;
                }
            }
        }
            
        /* ANSWER section */
        if(!failure && answers_togo > 0) {
            DIA___("DNS Inspect: Answers: start (count %d)",answers_togo);
            
            for(unsigned int i = mem_counter; i < src->size() && answers_togo > 0; ) {
                DNS_Answer answer_temp;
                answer_temp.name_ = ntohs(src->get_at<unsigned short>(i));
                answer_temp.type_ = ntohs(src->get_at<unsigned short>(i+2));
                answer_temp.class_ = ntohs(src->get_at<unsigned short>(i+4));
                answer_ttl_idx.push_back(i+6);
                answer_temp.ttl_ = ntohl(src->get_at<uint32_t>(i+6));
                answer_temp.datalen_ = ntohs(src->get_at<uint32_t>(i+10)); 
                if(answer_temp.datalen_ > 0)
                    answer_temp.data_.append(src->view(i+12,answer_temp.datalen_));
                int inc = 12 + answer_temp.datalen_;

                mem_counter += inc ;
                i += inc;
                
                DIA___("DNS_Packet::load: answer[%d]: name: %d, type: %d, class: %d, ttl: %d, len: %d, buflen: %d",answers_togo,
                                    answer_temp.name_,answer_temp.type_,answer_temp.class_,answer_temp.ttl_,answer_temp.datalen_,answer_temp.data_.size()  );
                answers_list_.push_back(answer_temp);
                answers_togo--;
            }
        }
        
        /* AUTHORITIES sectin */
        if(!failure && authorities_togo > 0) {
            
            DIA___("DNS Inspect: Authorities: start (count %d)",authorities_togo);
            
            for(unsigned int i = mem_counter; i < src->size() && authorities_togo > 0; ) {
                DNS_Answer answer_temp;
                
                int xi = load_qname(src->data()+i,src->size()-i);
                
                //unsigned short pre_type = ntohs(src->get_at<unsigned short>(i+1));
                unsigned short pre_type = ntohs(src->get_at<unsigned short>(i+xi));                
                i += (xi + 2);
                
                DUM___("xi: %d, pre-type: %d",xi, pre_type);
                
                if(pre_type == SOA) {
                    //answer_temp.name_ = ntohs(src->get_at<unsigned short>(i));
                    answer_temp.type_ = pre_type;//ntohs(src->get_at<unsigned short>(i+1));
                    answer_temp.class_ = ntohs(src->get_at<unsigned short>(i));
                    answer_temp.ttl_ = ntohl(src->get_at<uint32_t>(i+2));
                    answer_temp.datalen_ = ntohs(src->get_at<uint16_t>(i+6)); 
                
                    
                    DUM___("DNS_Packet::load: authorities[%d]: name: %d, type: %d, class: %d, ttl: %d, len: %d",authorities_togo,
                                        answer_temp.name_,answer_temp.type_,answer_temp.class_,answer_temp.ttl_,answer_temp.datalen_);
                    
                    if(answer_temp.datalen_ > 0)
                        answer_temp.data_.append(src->view(i+8,answer_temp.datalen_));
                    int inc = 8 + answer_temp.datalen_;

                    mem_counter += inc ;
                    i += inc;
                    
                    DIA___("DNS_Packet::load: authorities[%d]: name: %d, type: %d, class: %d, ttl: %d, len: %d, buflen: %d",authorities_togo,
                                        answer_temp.name_,answer_temp.type_,answer_temp.class_,answer_temp.ttl_,answer_temp.datalen_,answer_temp.data_.size()  );
                    authorities_list_.push_back(answer_temp);
                    authorities_togo--;
                } 
                else {
                    mem_counter = src->size();
                    i = src->size();

                    failure = true;
                    break;
                }
            }
        }
        
        /* ADDITIONALS */
        if(!failure && additionals_togo > 0) {
            
            DIA___("DNS Inspect: Additionals: start (count %d)",additionals_togo);
            
            for(unsigned int i = mem_counter; i < src->size() && additionals_togo > 0; ) {
  
                
                int xi = load_qname(src->data()+i,src->size()-i);
                
                //unsigned short pre_type = ntohs(src->get_at<unsigned short>(i+1));
                unsigned short pre_type = ntohs(src->get_at<unsigned short>(i+xi));                
                i += (xi + 2);
                
               
                DIA___("DNS inspect: Additionals: packet pre_type = %s(%d)",dns_record_type_str(pre_type), pre_type);
                
                if(pre_type == OPT) {
                    //THIS IS DNSSEC ADDITIONALS - we need to handle it better, now remove                
                
                    DNS_DnssecAdditionalInfo answer_temp;
                    //answer_temp.name_ = src->get_at<uint8_t>(i);
                    answer_temp.opt_ = pre_type;
                    answer_temp.udp_size_ = ntohs(src->get_at<unsigned short>(i)); i+=2;
                    answer_temp.higher_bits_rcode_ = src->get_at<uint8_t>(i);      i+=1;
                    answer_temp.edns0_version_ = src->get_at<uint8_t>(i);          i+=1; 
                    answer_temp.z_ = ntohs(src->get_at<uint16_t>(i));              i+=2;
                    answer_temp.datalen_ = ntohs(src->get_at<uint16_t>(i));        i+=2;
                    
                    
                    if(i + answer_temp.datalen_ <= src->size()) {
                        
                        if(answer_temp.datalen_ > 0) {
                            answer_temp.data_.append(src->view(i,answer_temp.datalen_));
                            i += answer_temp.datalen_;
                        }

                        DIA___("DNS_Packet::load: additional DNSSEC info[%d]: name: %d, opt: %d, udp: %d, hb_rcode: %d, edns0: %d, z: %d, len %d, buflen: %d", additionals_togo,
                                            answer_temp.name_,answer_temp.opt_,answer_temp.udp_size_,answer_temp.higher_bits_rcode_,answer_temp.edns0_version_,answer_temp.z_,answer_temp.datalen_,answer_temp.data_.size()  );
                        
                        mem_counter = i;
                        
                        
                        additionals_togo--;
                    } else {
                        mem_counter = src->size();
                        i = src->size();
                    }
                }
                else if (pre_type == A || pre_type == AAAA || pre_type == TXT) {
                    DNS_Answer answer_temp;
                    //answer_temp.name_ = ntohs(src->get_at<unsigned short>(i));
                    
                    
                    
                    answer_temp.type_ = pre_type;
                    answer_temp.class_ = ntohs(src->get_at<unsigned short>(i));    i+=2;
                    answer_ttl_idx.push_back(i);
                    answer_temp.ttl_ = ntohl(src->get_at<uint32_t>(i));            i+=4;
                    answer_temp.datalen_ = ntohs(src->get_at<uint16_t>(i));        i+=2;

                    if(answer_temp.datalen_ > 0) {
                        answer_temp.data_.append(src->view(i,answer_temp.datalen_));
                        i += answer_temp.datalen_;
                    }

                    mem_counter = i;
                    
                    DEB___("mem_counter: %d, size %d",i, src->size());
                    
                    DIA___("DNS_Packet::load: additional answer[%d]: name: %d, type: %d, class: %d, ttl: %d, len: %d, buflen: %d",additionals_togo,
                                        answer_temp.name_,answer_temp.type_,answer_temp.class_,answer_temp.ttl_,answer_temp.datalen_,answer_temp.data_.size()  );
                    additionals_list_.push_back(answer_temp);
                    additionals_togo--;
                }
                else {
                    
                    WARS___("unsupported additional message, skipping the rest of message.");
                    
                    mem_counter = src->size();
                    i = mem_counter;
                    
                    failure = true;
                    break;
                }
            }
            
            //fix additionals number, for case we omitted some
            additionals_ = additionals_list_.size();
        }
        
        if(questions_togo == 0 && answers_togo == 0 && authorities_togo == 0 /*&& additionals_togo == 0*/) {
            DIA___("DNS_Packet::load: finished mem_counter=%d buffer_size=%d",mem_counter,src->size());
            if(mem_counter == src->size()) {
                return 0;
            }

            return mem_counter;
        }
    }
    return -1;
};


std::string DNS_Packet::to_string(int verbosity) {
    std::string r = string_format("%s: id: %d, type 0x%x [ ",c_name(),id_,flags_);
    for(auto x = questions_list_.begin(); x != questions_list_.end(); ++x) {
        r += x->hr();
        if(x+1 != questions_list_.end()) {
            r += ",";
        }
    }
    r+=" ]";
    
    if( ! answers_list_.empty() ) {
        r += " -> [";
        for(auto x = answers_list_.begin(); x != answers_list_.end(); ++x) {
            r += x->hr();
            if(x+1 != answers_list_.end()) {
                r += " | ";
            }
        }
        r+=" ]";
    }
    
    return r;

}


std::string DNS_Packet::answer_str() const {
    std::string ret;
    
    for(auto const& x: answers_list_) {
        if(x.type_ == A || x.type_ == AAAA) {
            ret += " " + x.ip();
        }
    }
    
    return ret;
}

std::vector< CidrAddress*> DNS_Packet::get_a_anwsers() {
    std::vector<CidrAddress*> ret;
    
    for(auto const& x: answers_list_) {
        if(x.type_ == A || x.type_ == AAAA) {
            ret.push_back(new CidrAddress(x.cidr()));
        }
    }
    
    return ret;
}

