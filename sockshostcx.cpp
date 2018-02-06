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

#include <sys/socket.h>

#include <cfgapi.hpp>
#include <sockshostcx.hpp>
#include <logger.hpp>
#include <dns.hpp>
#include <smithdnsupd.hpp>

std::string socksTCPCom::sockstcpcom_name_ = "sock5";
std::string socksSSLMitmCom::sockssslmitmcom_name_ = "s5+ssl+insp";

socksServerCX::socksServerCX(baseCom* c, unsigned int s) : baseHostCX(c,s) {
    state_ = INIT;
}

socksServerCX::~socksServerCX() {

    if(left)  { delete left; }
    if(right) { delete right; }
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
    
    if(atype != IPV4 && atype != FQDN) {
        e = UNSUPPORTED_ATYPE;
        goto error;
    }
    
    if(readbuf()->size() >= 10) {
        
        if(atype == FQDN) {
            req_atype = FQDN;
            state_ = REQ_RECEIVED;            
            
            unsigned char fqdn_sz = readbuf()->get_at<unsigned char>(4);
            if((unsigned int)fqdn_sz + 4 + 2 >= readbuf()->size()) {
                ERRS_("protocol error: request header out of boundary.");
                goto error;
            }
            
            DIA_("socks5 protocol: fqdn size: %d",fqdn_sz);
            std::string fqdn((const char*)&readbuf()->data()[5],fqdn_sz);
            DIA_("socks5 protocol: fqdn requested: %s",fqdn.c_str());
            req_str_addr = fqdn;
            
            req_port = ntohs(readbuf()->get_at<uint16_t>(5+fqdn_sz));
            DIA_("socks5 protocol: port requested: %d",req_port);
            
            std::vector<std::string> target_ips;
            
            // Some implementations use atype FQDN eventhough the target is already IP
            CIDR* adr_as_fqdn = cidr_from_str(fqdn.c_str());
            if(adr_as_fqdn != nullptr) {
                // hmm, it's an address
                cidr_free(adr_as_fqdn);
                
                target_ips.push_back(fqdn);
            } else {
                // really FQDN.
                
                inspect_dns_cache.lock();
                DNS_Response* dns_resp = inspect_dns_cache.get("A:"+fqdn);
                if(dns_resp) {
                    if (dns_resp->answers().size() > 0) {
                        int ttl = (dns_resp->loaded_at + dns_resp->answers().at(0).ttl_) - time(nullptr);                
                        if(ttl > 0) {
                            for( DNS_Answer& a: dns_resp->answers() ) {
                                std::string a_ip = a.ip(false);
                                if(a_ip.size()) {
                                    DIA_("cache candidate: %s",a_ip.c_str());
                                    target_ips.push_back(a_ip);
                                }
                            }
                        }
                    }
                }
                inspect_dns_cache.unlock();
            }
            
            if(target_ips.size() <= 0) {
                // no targets, send DNS query
                
                std::string nameserver = "8.8.8.8";
                if(cfgapi_obj_nameservers.size()) {
                    nameserver = cfgapi_obj_nameservers.at(0);
                }
                DNS_Response* resp = send_dns_request(fqdn,A,nameserver);
                bool del_resp = true;
                
                if(resp) {
                    for( DNS_Answer& a: resp->answers() ) {
                        std::string a_ip = a.ip(false);
                        if(a_ip.size()) {
                            DIA_("fresh candidate: %s",a_ip.c_str());
                            target_ips.push_back(a_ip);
                        }
                    }
                    
                    if(target_ips.size()) {
                        inspect_dns_cache.lock();
                        DNS_Inspector di;
                        del_resp = ! di.store(resp);
                        inspect_dns_cache.unlock();
                    }
                    
                    if(del_resp) {
                        delete resp;
                    }
                }
            }
            
            if(target_ips.size()) {
                // for now use just first one (cleaned up from empty ones)
                std::string t = target_ips.at(0);
                
                DIA_("chosen target: %s",t.c_str());
                com()->nonlocal_dst_host() = t;
                
            } else {
                goto error;
            }
        }
        else
        if(atype == IPV4) {
            req_atype = IPV4;
            state_ = REQ_RECEIVED;
            DIA_("socksServerCX::process_socks_request: request received, type %d", atype);
            
            uint32_t dst = readbuf()->get_at<uint32_t>(4);
            req_port = ntohs(readbuf()->get_at<uint16_t>(8));

            
            req_addr.s_addr=dst;
            
            com()->nonlocal_dst_host() = string_format("%s",inet_ntoa(req_addr));
        }
        
        
        com()->nonlocal_dst_port() = req_port;
        com()->nonlocal_dst_resolved(true);
        com()->nonlocal_src(true);
        DIA_("socksServerCX::process_socks_request: request for %s -> %s:%d",c_name(),com()->nonlocal_dst_host().c_str(),com()->nonlocal_dst_port());


        // prepare a new CX!
        
        
        // LEFT
        int s = socket();
        
        baseCom* new_com = nullptr;
        switch(com()->nonlocal_dst_port()) {
            case 443:
            case 465:
            case 636:
            case 993:
            case 995:
                new_com = new baseSSLMitmCom<SSLCom>();
                handoff_as_ssl = true;
                break;
            default:
                new_com = new TCPCom();
        }
        
        MitmHostCX* n_cx = new MitmHostCX(new_com, s);
        n_cx->paused(true);
        n_cx->com()->name();
        n_cx->name();
        n_cx->com()->nonlocal_dst(true);
        n_cx->com()->nonlocal_dst_host() = com()->nonlocal_dst_host();
        n_cx->com()->nonlocal_dst_port() = com()->nonlocal_dst_port();
        n_cx->com()->nonlocal_dst_resolved(true);
        
        
        // RIGHT


        MitmHostCX *target_cx = new MitmHostCX(n_cx->com()->slave(), n_cx->com()->nonlocal_dst_host().c_str(), 
                                            string_format("%d",n_cx->com()->nonlocal_dst_port()).c_str()
                                            );
        target_cx->paused(true);
        
        std::string h;
        std::string p;
        n_cx->name();
        n_cx->com()->resolve_socket_src(n_cx->socket(),&h,&p);
        
        
        target_cx->com()->nonlocal_src(false); //FIXME
        target_cx->com()->nonlocal_src_host() = h;
        target_cx->com()->nonlocal_src_port() = std::stoi(p); 
        
        
        
        left = n_cx;
        DIA_("socksServerCX::process_socks_request: prepared left: %s",left->c_name());
        right = target_cx;
        DIA_("socksServerCX::process_socks_request: prepared right: %s",right->c_name());
        
        // peers are now prepared for handover. Owning proxy will wipe this CX (it will be empty)
        // and if policy allows, left and right will be set (also in proxy owning this cx).
        
        state_ = WAIT_POLICY;
        paused_read(true);
        
        DIAS_("socksServerCX::process_socks_request: waiting for policy check");
        // now 
        return readbuf()->size();
        
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
    else if(req_atype == FQDN) {
        
        b[cur] = (unsigned char)req_str_addr.size();
        cur++;
        
        for (char c: req_str_addr) {
            b[cur] = c;
            cur++;
        }
    }
        
    *((uint16_t*)&b[cur]) = htons(req_port);
    cur += sizeof(uint16_t);
    
    writebuf()->append(b,cur);
    state_ = REQRES_SENT;
    
    DEB_("socksServerCX::process_socks_reply: response dump:\n%s",hex_dump(b,cur).c_str());
    
    return cur;
}

void socksServerCX::pre_write() {
    DEB_("socksServerCX::pre_write[%s]: writebuf=%d, readbuf=%d",c_name(),writebuf()->size(),readbuf()->size());
    if(state_ == REQRES_SENT ) {
        if(writebuf()->size() == 0) {
            DIA_("socksServerCX::pre_write[%s]: all flushed, state change to HANDOFF: writebuf=%d, readbuf=%d",c_name(),writebuf()->size(),readbuf()->size());
            paused(true);
            state(HANDOFF);
        }
    }
}
