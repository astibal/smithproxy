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

bool DNS_Inspector::interested(AppHostCX* cx) {
    if(cx->com()->nonlocal_dst_port() == 53)
        return true;
    return false;
}

void DNS_Inspector::old_update(AppHostCX* cx) {

    duplexFlow& f = cx->flow();
    DEB_("DNS_Inspector::update: stage %d start (flow size %d)",stage, f.flow().size());
    
    /* INIT */
    
    if(!in_progress()) {
        baseCom* com = cx->com();
        TCPCom* tcp_com = dynamic_cast<TCPCom*>(com);
        if(tcp_com) 
            is_tcp = true;
    }
    
    
    DNS_Packet* ptr = nullptr;
    buffer * buf = nullptr;
    switch(stage) {
        case 0:
            ptr = dynamic_cast<DNS_Packet*>(&req_);
            buf = f.at('r',0);
            if(!buf) {
                DIA_("DNS_Inspector::update: not enough data at stage %d (flow size %d)",stage, f.flow().size());
                return;
            }
            if(!ptr) {
                DIA_("DNS_Inspector::update: stage %d (flow size %d), cannot convert to DNS_Packet",stage, f.flow().size());
                return;
            }
            break;
        case 1:
            ptr = dynamic_cast<DNS_Packet*>(&resp_);
            buf = f.at('w',0);
            if(!buf) {
                DIA_("DNS_Inspector::update: not enough data at stage %d (flow size %d)",stage, f.flow().size());
                return;
            }
            if(!ptr) {
                DIA_("DNS_Inspector::update: stage %d (flow size %d), cannot convert to DNS_Packet",stage, f.flow().size());
                return;
            }
            break;
    }
    
    bool rr = false;
    if(is_tcp) {
        
        // TODO: there could be MORE dns data, or less. This is too optimistic.
        if(buf->size() >= 2) {
            unsigned short bytes = ntohs(buf->get_at<unsigned short>(0));
            DIA_("%s: DNS over TCP (%d bytes, buffer size %d)",cx->hr().c_str(),bytes,buf->size());
            buffer x = buf->view(2,bytes);
            rr = (ptr->load(&x) == 0);
            
            //TODO: print at least warning message.
            if(bytes + sizeof(unsigned short) != buf->size()) {
                WAR_("%s: DNS inspection: processed %d, but len was %d",bytes,buf->size());
            }
        } else {
            return;
        }
    } else {
        DIA_("%s: DNS over UDP (buffer size %d)",cx->hr().c_str(),buf->size());
        rr = ( ptr->load(buf) == 0 );
    } 
    
    // on success, raise stage counter
    if(rr) {
        stage++;
        // consider stage 2 and more as succesfull inspection
        if(stage == 1) {
            cx->idle_delay(10); // request has been recognized as DNS, we expect reply will come very soon. 10 is very conservative.
        }
        else
        if(stage >= 2){
            completed(true);
            result(true);
            
            
            if(stage == 2) {
                bool is_a_record = true;
                std::string ip = resp_.answer_str().c_str();
                if(ip.size() > 0) {
                    INF_("DNS inspection: %s is at%s",resp_.question_str_0().c_str(),ip.c_str()); //ip is already prepended with " "
                }
                else {
                    INF_("DNS inspection: non-A response for %s",resp_.question_str_0().c_str());
                    is_a_record = false;
                }
                DIA_("DNS response: %s",resp_.hr().c_str());
                
                
                /* RULES */
                if(opt_match_id) {
                    DIAS_("DNS_Inspector::update: matching ID enabled");
                    if(req_.id() == resp_.id()) {
                        DIA_("DNS inspection: request and response ID 0x%x match.",req_.id());
                    } else {
                        cx->writebuf()->clear();
                        cx->error(true);
                        WAR_("DNS inspection: blind DNS reply attack: request ID 0x%x doesn't match response ID 0x%x.",req_.id(),resp_.id());
                    }
                }
                if(is_a_record) {
                    inspect_dns_cache.lock();
                    inspect_dns_cache.set(resp_.question_str_0(),new DNS_Response(resp_));
                    DIA_("DNS_Inspector::update: %s added to cache (%d elements of max %d)",resp_.question_str_0().c_str(),inspect_dns_cache.cache().size(), inspect_dns_cache.max_size());
                    inspect_dns_cache.unlock();
                }
                
                if(is_tcp)
                    cx->idle_delay(30);
                else
                    cx->idle_delay(1);
            } else {
                DIA_("DNS request: %s",req_.hr().c_str());
            }
        }            
        
    } else {
        NOT_("DNS inspection: failed parser at stage %d (flow size %d)",stage, f.flow().size());
        // on failure, set final false result
        completed(true);
        result(false);
    }
    
}

void DNS_Inspector::update(AppHostCX* cx) {
    
    duplexFlow& f = cx->flow();
    DIA_("DNS_Inspector::update[%s]: stage %d start (flow size %d, last flow entry data length %d)",cx->c_name(),stage, f.flow().size(),f.flow().back().second->size());
    
    /* INIT */
    
    if(!in_progress()) {
        baseCom* com = cx->com();
        TCPCom* tcp_com = dynamic_cast<TCPCom*>(com);
        if(tcp_com) 
            is_tcp = true;
    }
    
    
    std::pair<char,buffer*> cur_pos = cx->flow().flow().back();
    
    DNS_Packet* ptr = nullptr;
    buffer *xbuf = cur_pos.second;
    buffer buf = xbuf->view(0,xbuf->size());
    if(is_tcp) {
        unsigned short data_size = ntohs(buf.get_at<unsigned short>(0));
        buf = buf.view(2,xbuf->size());
        if(buf.size() < data_size) {
            DIA_("DNS_Inspector::update[%s]: not enough DNS data in TCP stream: expected %d, but having %d. Waiting to more.",cx->c_name(), data_size, buf.size());
            return;
        }
    }
    
    int red = 0;
    int mem_pos = 0;
    int mem_len = buf.size();
    int max_it = 10; // "emergency" counter.
    switch(cur_pos.first)  {
        case 'r':
            for(int it = 0; red < buf.size() && it < 10; it++) {
                ptr = new DNS_Request();
                buf = buf.view(red,buf.size()-red);
                red = ptr->load(&buf);
                
                // on success write to requests_
                if(red >= 0) {
                    DIA_("DNS_Inspector::update[%s]: adding key 0x%x red=%d, buffer_size=%d",cx->c_name(),ptr->id(),red,buf.size());
                    requests_[ptr->id()] = (DNS_Request*)ptr;
                }
                
                // on failure or last data exit loop
                if(red <= 0) {
                    DIA_("DNS_Inspector::update[%s]: finishing reading from buffers: red=%d, buffer_size=%d",cx->c_name(),red,buf.size());
                    break;
                }
            }
            break;
        case 'w':
            for(int it = 0; red < buf.size() && it < 10; it++) {
                ptr = new DNS_Response();
                buf = buf.view(red,buf.size()-red);
                red = ptr->load(&buf);
                
                // on success write to responses_
                if(red >= 0) {
                    mem_pos += red;
                    DIA_("DNS_Inspector::update[%s]: loaded new response (at %d size %d out of %d)",cx->c_name(),red,mem_pos,mem_len);
                    responses_[ptr->id()] = (DNS_Response*)ptr;
                    validate_response(ptr->id());
                }
                
                // on failure or last data exit loop
                if(red <= 0) break;
            }
            break;
    }
    
    DIA_("DNS_Inspector::update[%s]: stage %d end (flow size %d)",cx->c_name(),stage, f.flow().size());
}

bool DNS_Inspector::validate_response(short unsigned int id) {
    DNS_Request* req = find_request(id);
    if(req) {
        INF_("DNS_Inspector::validate_response: request 0x%x found",id);
    } else {
        INF_("DNS_Inspector::validate_response: request 0x%x not found",id);
    }
}
