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


void DNS_Inspector::update(AppHostCX* cx) {

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
            rr = ptr->load(&x);
            
            //TODO: print at least warning message.
            if(bytes + sizeof(unsigned short) != buf->size()) {
                WAR_("%s: DNS inspection: processed %d, but len was %d",bytes,buf->size());
            }
        } else {
            return;
        }
    } else {
        DIA_("%s: DNS over UDP (buffer size %d)",cx->hr().c_str(),buf->size());
        rr = ptr->load(buf);
    } 
    
    // on success, raise stage counter
    if(rr) {
        stage++;
        // consider stage 2 and more as succesfull inspection
        if(stage >= 2){
            completed(true);
            result(true);
            
            
            if(stage == 2) {
                std::string ip = resp_.answer_str().c_str();
                if(ip.size() > 0) {
                    INF_("DNS inspection: %s is at%s",resp_.question_str_0().c_str(),ip.c_str()); //ip is already prepended with " "
                }
                else {
                    INF_("DNS inspection: non-A response for %s",resp_.question_str_0().c_str());
                }
                DIA_("DNS response: %s",resp_.hr().c_str());
                
                
                /* RULES */
                if(req_.id() == resp_.id()) {
                    DIA_("DNS inspection: request and response ID 0x%x match.",req_.id());
                } else {
                    cx->writebuf()->clear();
                    cx->error(true);
                    WAR_("DNS inspection: blind DNS reply attack: request ID 0x%x doesn't match response ID 0x%x.",req_.id(),resp_.id());
                }
                
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
