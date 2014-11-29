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

#include <sockshostcx.hpp>
#include <logger.hpp>

socksServerCX::socksServerCX(baseCom* c, unsigned int s) : baseHostCX(c,s) {
    state_ = INIT;
}

int socksServerCX::process() {
    switch(state_) {
        case INIT:
            return process_socks_hello();
        case HELLO_SENT:
            return 0; // we sent response to client hello, don't process anything
        case WAIT_REQUEST:
            return process_socks_request();
        default:
            break;
    }
    
    return 0;
}

int socksServerCX::process_socks_hello() {
        
    buffer* b = readbuf();
    if(b->size() < 3) {
        // minimal size of "client hello" is 3 bytes
        return 0;
    }
    unsigned char version = b->get_at<unsigned char>(0);
    unsigned char nmethods = b->get_at<unsigned char>(1);
    
    if(b->size() < (unsigned int)(2 + nmethods)) {
        return 0;
    }
    
    // at this stage we have full client hello received
    if(version == 5) {
        // this is ok.
    } else {
        DIAS_("socksServerCX::process_socks_init: hello version mismatch");
        error(true);
    }
    
    DIAS_("socksServerCX::process_socks_init");
    
    unsigned char server_hello[2];
    server_hello[0] = 5; // version
    server_hello[1] = 0; // no authentication
    
    writebuf()->append(server_hello,2);
    state_ = HELLO_SENT;
    state_ = WAIT_REQUEST;
    
    // flush all data, assuming 
    return b->size();
}

int socksServerCX::process_socks_request() {

    socks5_request_error e = NONE;
    
    if(readbuf()->size() < 5) {
        return 0; // wait for more complete request
    }
    
    DIAS_("socksServerCX::process_socks_request");
    DEB_("Request dump:\n%s",hex_dump(readbuf()->data(),readbuf()->size()).c_str());
    
    unsigned char version = readbuf()->get_at<unsigned char>(0);
    unsigned char cmd     = readbuf()->get_at<unsigned char>(1);
    //@2 is reserved
    unsigned char atype   = readbuf()->get_at<unsigned char>(3);
    
    if(version != 5) {
        e = UNSUPPORTED_VERSION;
        goto error;
    }
    
    if(atype != IPV4) {
        e = UNSUPPORTED_ATYPE;
        goto error;
    }
    
    if(readbuf()->size() >= 10) {
        if(atype == IPV4) {
            req_atype = IPV4;
            state_ = REQ_RECEIVED;
            
            uint32_t dst = readbuf()->get_at<uint32_t>(4);
            req_port = ntohs(readbuf()->get_at<uint16_t>(8));

            
            req_addr.s_addr=dst;
            
            com()->nonlocal_dst_host() = string_format("%s",inet_ntoa(req_addr));
            com()->nonlocal_dst_port() = req_port;
            com()->nonlocal_dst_resolved(true);
            com()->nonlocal_src(true);
            DIA_("socksServerCX::process_socks_request: request for %s -> %s:%d",c_name(),com()->nonlocal_dst_host().c_str(),com()->nonlocal_dst_port());
            
            state_ = WAIT_POLICY;
            paused_read(true);
            // now 
            return readbuf()->size();
        }
    } else {
        return 0;
    }
    
    error:
        DIA_("socksServerCX::process_socks_request: error %d",e);
        error(true);
        return readbuf()->size();
}

bool socksServerCX::new_message() {
    if(state_ == WAIT_POLICY && verdict_ == PENDING) {
        return true;
    }
    if(state_ == HANDOFF) {
        return true;
    }
    
    return false;
}

void socksServerCX::verdict(socks5_policy p) {
    verdict_ = p;
    state_ = POLICY_RECEIVED;
    
    if(verdict_ == ACCEPT || verdict_ == REJECT) {
        process_socks_reply();
    }
}

int socksServerCX::process_socks_reply() {
    unsigned char b[128];
    
    b[0] = 5;
    b[1] = 2; // denied
    if(verdict_ == ACCEPT) b[1] = 0; //accept
    b[2] = 0;
    b[3] = req_atype;
    
    int cur = 4;
    
    if(req_atype == IPV4) {
        *((uint32_t*)&b[cur]) = req_addr.s_addr;
        cur += sizeof(uint32_t);
    }
    *((uint16_t*)&b[cur]) = htons(req_port);
    cur += sizeof(uint16_t);
    
    writebuf()->append(b,cur);
    state_ = REQRES_SENT;
    
    DEB_("Response dump:\n%s",hex_dump(b,cur).c_str());
    
    return cur;
}

void socksServerCX::pre_write() {
    DEB_("socksServerCX::pre_write[%s]: writebuf=%d, readbuf=%d",c_name(),writebuf()->size(),readbuf()->size());
    if(state_ == REQRES_SENT ) {
        if(writebuf()->size() == 0) {
            DIA_("socksServerCX::pre_write[%s]: all flushed, state change to HANDOFF writebuf=%d, readbuf=%d",c_name(),writebuf()->size(),readbuf()->size());
            paused(true);
            state(HANDOFF);
        }
    }
}
