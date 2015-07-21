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

#include <inspectors.hpp>


DEFINE_LOGGING(DNS_Inspector)

std::string Inspector::remove_redundant_dots(std::string orig) {
    std::string norm;  

    int dot_mark = 1;
    for(int i = 0; i < orig.size(); i++) {
        if(orig[i] == '.') {
            if(dot_mark > 0) continue;
            
            norm +=orig[i];
            dot_mark++;
        } else {
            dot_mark = 0;
            norm +=orig[i];
        }
    }
    if(dot_mark > 0) {
        norm = norm.substr(0,norm.size()-dot_mark);
    }
    
    return norm;
}

std::vector< std::string > Inspector::split(std::string str, unsigned char delimiter) {
    std::vector<std::string> ret;
    
    bool empty_back = true;
    for(unsigned int i = 0; i < str.size() ; i++) {
        if(i == 0)
            ret.push_back("");
            
        if(str[i] == delimiter) {
            
            if(ret.size() > 0)
                if(ret.back().size() == 0) ret.pop_back();

            ret.push_back("");
            empty_back = true;
        } else {
            ret.back()+= str[i];
            empty_back = false;
        }
    }
    
    if(empty_back) {
        ret.pop_back();
    }
    
    return ret;    
}



std::regex DNS_Inspector::wildcard = std::regex("[^.]+\.(.*)$");

bool DNS_Inspector::interested(AppHostCX* cx) {
    if(cx->com()->nonlocal_dst_port() == 53)
        return true;
    return false;
}

void DNS_Inspector::update(AppHostCX* cx) {
    
    duplexFlow& f = cx->flow();
    DIA___("DNS_Inspector::update[%s]: stage %d start (flow size %d, last flow entry data length %d)",cx->c_name(),stage, f.flow().size(),f.flow().back().second->size());
    
    /* INIT */
    
    if(!in_progress()) {
        baseCom* com = cx->com();
        TCPCom* tcp_com = dynamic_cast<TCPCom*>(com);
        if(tcp_com) 
            is_tcp = true;
        
        in_progress(true);
    }
    
    
    std::pair<char,buffer*> cur_pos = cx->flow().flow().back();
    
    DNS_Packet* ptr = nullptr;
    buffer *xbuf = cur_pos.second;
    buffer buf = xbuf->view(0,xbuf->size());

    int mem_pos = 0;
    int red = 0;
    
    if(is_tcp) {
        unsigned short data_size = ntohs(buf.get_at<unsigned short>(0));
        if(buf.size() < data_size) {
            DIA___("DNS_Inspector::update[%s]: not enough DNS data in TCP stream: expected %d, but having %d. Waiting to more.",cx->c_name(), data_size, buf.size());
            return;
        }
        red += 2;
    }
    
    int mem_len = buf.size();
    int max_it = 10; // "emergency" counter.
    switch(cur_pos.first)  {
        case 'r':
            stage = 0;
            for(int it = 0; red < buf.size() && it < 10; it++) {
                ptr = new DNS_Request();
                buffer cur_buf = buf.view(red,buf.size()-red);
                red = ptr->load(&cur_buf);
                
                // on success write to requests_
                if(red >= 0) {
                    DIA___("DNS_Inspector::update[%s]: adding key 0x%x red=%d, buffer_size=%d",cx->c_name(),ptr->id(),red,cur_buf.size());
                    if(requests_[ptr->id()] != nullptr) {
                        INF___("DNS_Inspector::update[%s]: detected re-sent request",cx->c_name());
                        delete requests_[ptr->id()];
                    }
                    requests_[ptr->id()] = (DNS_Request*)ptr;
                    cx->idle_delay(30);
                } else {
                    delete ptr;
                }
                
                // on failure or last data exit loop
                if(red <= 0) {
                    DIA___("DNS_Inspector::update[%s]: finishing reading from buffers: red=%d, buffer_size=%d",cx->c_name(),red,cur_buf.size());
                    break;
                }
            }
            break;
        case 'w':
            stage = 1;
            for(int it = 0; red < buf.size() && it < 10; it++) {
                ptr = new DNS_Response();
                buffer cur_buf = buf.view(red,buf.size()-red);
                red = ptr->load(&cur_buf);
                
                
                if(red >= 0) {
                    mem_pos += red;
                    DIA___("DNS_Inspector::update[%s]: loaded new response (at %d size %d out of %d)",cx->c_name(),red,mem_pos,mem_len);
                    if (!validate_response((DNS_Response*)ptr)) {
                        // invalid, delete

                        cx->writebuf()->clear();
                        cx->error(true);
                        WAR___("DNS inspection: cannot find corresponding DNS request id 0x%x: dropping connection.",ptr->id());
                        delete ptr;
                    }
                    else {
                        // DNS response is valid
                        responses_ ++;

                        DIA___("DNS_Inspector::update[%s]: valid response",cx->c_name());

                        if(store((DNS_Response*)ptr)) {
                            stored_ = true;
                            // DNS response is interesting (A record present) - we stored it , ptr is VALID
                            DIA___("DNS_Inspector::update[%s]: contains interesting info, stored",cx->c_name());
                            
                        } else {
                            delete ptr;
                            ptr = nullptr;
                            
                            DIA___("DNS_Inspector::update[%s]: no interesting info there, deleted",cx->c_name());
                        }
                        
                        if(is_tcp)
                            cx->idle_delay(30);
                        else
                            cx->idle_delay(1);  
                    }
                } else {
                    delete ptr;
                }
                
                // on failure or last data exit loop
                if(red <= 0) break;
            }
            break;
    }
    
    DIA___("DNS_Inspector::update[%s]: stage %d end (flow size %d)",cx->c_name(),stage, f.flow().size());
}




bool DNS_Inspector::store(DNS_Response* ptr) {
    bool is_a_record = true;

    std::string ip = ptr->answer_str().c_str();
    if(ip.size() > 0) {
        INF___("DNS inspection: %s is at%s",ptr->question_str_0().c_str(),ip.c_str()); //ip is already prepended with " "
    }
    else {
        DIA___("DNS inspection: non-A response for %s",ptr->question_str_0().c_str());
        is_a_record = false;
    }
    DIA___("DNS response: %s",ptr->to_string().c_str());


    if(is_a_record) {
        inspect_dns_cache.lock();
        inspect_dns_cache.set(ptr->question_str_0(),ptr);
        DIA___("DNS_Inspector::update: %s added to cache (%d elements of max %d)",ptr->question_str_0().c_str(),inspect_dns_cache.cache().size(), inspect_dns_cache.max_size());
        inspect_dns_cache.unlock();
    }    
    
    return is_a_record;
}

bool DNS_Inspector::validate_response(DNS_Response* ptr) {

    unsigned int id = ptr->id();
    DNS_Request* req = find_request(id);
    if(req) {
        DIA___("DNS_Inspector::validate_response: request 0x%x found",id);
        return true;
      
    } else {
        INF___("DNS_Inspector::validate_response: request 0x%x not found",id);
    }
    
    return false;
}

std::string DNS_Inspector::to_string(int verbosity) {
    std::string r = Inspector::to_string()+"\n  ";
    
    r += string_format("tcp: %d requests: %d valid responses: %d stored: %d",is_tcp,requests_.size(),responses_,stored_);
    
    return r;
}
