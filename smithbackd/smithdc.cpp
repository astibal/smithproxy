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

/*
    This is standalone client utility for smithd backend server.
*/

#include <socle.hpp>
#include <baseproxy.hpp>
#include <uxcom.hpp>
#include <smithdcx.hpp>

class SmithClientCX : public SmithProtoCX {
public:
    SmithClientCX(baseCom* c, unsigned int s) : SmithProtoCX(c,s) {};
    SmithClientCX(baseCom* c, const char* h, const char* p) : SmithProtoCX(c,h,p) {};
    virtual ~SmithClientCX() {};
    

   
    virtual void process_package(LTVEntry* e) {
        DEB_("Package dump: \n%s",e->hr().c_str());
        
        LTVEntry* m = e->search({1,1});
        if (m) {
            INF_("URL category: %d",m->data_int())
        } else {
            INF_("Unknown response: \n%s",e->hr().c_str());
        }
        
        error(true);
    };
    
    LTVEntry* pkg_create_envelope(uint32_t req_id, int32_t req_t) {

        LTVEntry* packet = new LTVEntry();
        packet->container(100);
        
        LTVEntry* x = new LTVEntry();
        x->set_num(id_client::CL_VERSION,LTVEntry::num,0xF0);
        packet->add(x);
                
        x = new LTVEntry();
        x->set_num(id_client::CL_REQID,LTVEntry::num,req_id);
        packet->add(x);
        
        x = new LTVEntry();
        x->set_num(id_client::CL_REQTYPE,LTVEntry::num,req_t);
        packet->add(x);
        
        return packet;
    }
    
    LTVEntry* pkg_create_rateurl_request(uint32_t req_id, const char* URI) {
        LTVEntry* envelope = pkg_create_envelope(req_id,req_type::RQT_RATEURL);
        
        LTVEntry* inner = new LTVEntry();
        inner->container(CL_PAYLOAD);
        
        LTVEntry* x = new LTVEntry();
        x->set_str(RQT_RATEURL,LTVEntry::str,URI);
        inner->add(x);
        
        envelope->add(inner);
        
        return envelope;
    }
};

class SmithdProxy : public baseProxy {
public:
    SmithdProxy(baseCom* c) : baseProxy(c) {};
    virtual baseHostCX* new_cx(const char* h, const char* p) { return new SmithClientCX(com(),h,p); };
    virtual baseHostCX* new_cx(int s) { return new SmithClientCX(com(), s); };
    
    virtual void on_left_error(baseHostCX*) {  dead(true); };
    virtual void on_right_error(baseHostCX*) { dead(true); };
};

int main(int argc, char *argv[]) {
    
    get_logger()->dup2_cout(true);
    get_logger()->level(INF);
    
    SmithdProxy p = SmithdProxy(new UxCom());
    p.pollroot(true);
    
    SmithClientCX* cx = new SmithClientCX(p.com()->slave(),"/var/run/smithd.sock","");
    cx->connect(true);
    
    p.ladd(cx);
        
    LTVEntry* m = cx->pkg_create_rateurl_request(1,"www.smithproxy.org");
    
    
    m->pack();
    cx->send(m);
    
    p.run();
}