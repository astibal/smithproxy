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

#include <getopt.h>


#include <socle.hpp>
#include <baseproxy.hpp>
#include <uxcom.hpp>
#include <smithdcx.hpp>

static std::string cfg_ux_socket = "/var/run/smithd.sock";


class SmithClientCX : public SmithProtoCX {
public:
    SmithClientCX(baseCom* c, unsigned int s) : SmithProtoCX(c,s) {};
    SmithClientCX(baseCom* c, const char* h, const char* p) : SmithProtoCX(c,h,p) {};
    virtual ~SmithClientCX() {};
    

   
    virtual void process_package(LTVEntry* e) {
        
	DEB_("Package dump: \n%s",e->hr().c_str());
        
        LTVEntry* m = e->search({1,1});
        if (m) {
            DIA_("URL category: %d",m->data_int())
        } else {
            ERR_("Unknown response: \n%s",e->hr().c_str());
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




void test_url(const char* url = nullptr) {
    
    // Setup location of smithd socket 
    const char* u = cfg_ux_socket.c_str();
    if(url != nullptr) u = url;
  
    // Create basic proxy and associate com object (SmithdProxy is child of baseProxy)
    // Com object without master object set is automatically considered as master
    SmithdProxy p = SmithdProxy(new UxCom());
    // Basic proxy needs to know it will be running com's poll()
    p.pollroot(true);
   
    // Create client context (cx). Contexts could be attached to Proxy, typically 
    // to left or right. We will create CX with slave com and connect.
    SmithClientCX* cx = new SmithClientCX(p.com()->slave(),u,"");
    
    // since this is simple client, we will block. Normally it doesn't matter, run() would 
    // eventually take care of it
    cx->connect(true);
    
    // add cx to left side of proxy (there is no right side at all, we just need handle traffic
    // by proxy object.
    // You can think of proxy as of managing object, com as of set of methods handling socket IO,
    // and cx as one who understands what to do with bytes received and buffered for sending.
    p.ladd(cx);
   
    // create application payload
    LTVEntry* m = cx->pkg_create_rateurl_request(1,"www.smithproxy.org");
    // pack. Make buffer data from the object
    m->pack();
    
    // instruct cx to add data for sending
    cx->send(m);
    
    // manage and run all connections until it's stopped. We stop in the client code,
    // where we receive response and close cx. Which will also close the proxy, which in turn terminates
    // run method.
    p.run();  
}


int main(int argc, char *argv[]) {
    
    get_logger()->dup2_cout(true);
    get_logger()->level(INF);

    int loop_count = 100;
    
    // measure RTT for getting response
    struct timeb t_start, t_current;                           
    int t_diff;
    
    int t_min = 0;
    int t_max = 0;
    int t_sum = 0;
    int t_cnt = 0;
    
    
    for(int i = 0; i < loop_count; i++) {
    
      ftime(&t_start);                                            
      test_url();
      ftime(&t_current);
      
      t_diff = (int) (1000.0 * (t_current.time - t_start.time) + (t_current.millitm - t_start.millitm));
      t_cnt++;
      t_sum += t_diff;
      
      if(t_diff < t_min || t_min == 0) t_min = t_diff;
      if(t_diff > t_max || t_max == 0) t_max = t_diff;
      
      INF_(">> Server RTT: %dms  (avg=%.2fms min=%dms max=%dms)",t_diff,((float)t_sum)/t_cnt, t_min, t_max);
    }
}