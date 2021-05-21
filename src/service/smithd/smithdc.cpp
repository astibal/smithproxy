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

/*
    This is standalone client utility for smithd backend server.
*/

#include <functional>


#include <baseproxy.hpp>
#include <uxcom.hpp>
#include <service/smithd/smithdcx.hpp>

const std::string& cfg_ux_socket() {
    static std::string sock = "/var/run/smithd.default.sock";

    return sock;
}



class SmithClientCX : public SmithProtoCX, private LoganMate {
public:
    SmithClientCX(baseCom* c, int s) : SmithProtoCX(c, s) {};
    SmithClientCX(baseCom* c, const char* h, const char* p) : SmithProtoCX(c, h, p) {};
    ~SmithClientCX() override = default;

    logan_attached<SmithClientCX> log = logan_attached<SmithClientCX>(this, "com.smithd");
    friend class logan_attached<SmithClientCX>;

    std::string& class_name() const override {  static std::string s = "SmithServerCX"; return s; };
    std::string hr() const override { return class_name(); }

    //only used in test_url2
    std::function<void()> sig_on_package;
    std::function<void(SmithClientCX* cx, LTVEntry* pkg)> sig_package_detail;
    
   
    void process_package(LTVEntry* e) override {
        
	_deb("Package dump: \n%s",e->hr().c_str());
        
        LTVEntry* m = e->search({1,1});
        if (m) {
            _dia("URL category: %d",m->data_int());
        } else {
            _err("Unknown response: \n%s",e->hr().c_str());
        }
        
        //only used in test_url2
        std::invoke(sig_on_package);
        std::invoke(sig_package_detail, this, e);
        
        error(true);
    };
    
    static LTVEntry* pkg_create_envelope(uint32_t req_id, int32_t req_t) {

        auto* packet = new LTVEntry();
        packet->container(100);
        
        auto* x = new LTVEntry();
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
        
        auto* inner = new LTVEntry();
        inner->container(CL_PAYLOAD);
        
        auto* x = new LTVEntry();
        x->set_str(RQT_RATEURL,LTVEntry::str,URI);
        inner->add(x);
        
        envelope->add(inner);
        
        return envelope;
    }
};

class SmithdProxy : public baseProxy {
    public:
        explicit SmithdProxy(baseCom* c) : baseProxy(c) {};
        baseHostCX* new_cx(const char* h, const char* p) override { return new SmithClientCX(com()->slave(),h,p); };
        baseHostCX* new_cx(int s) override { return new SmithClientCX(com()->slave(), s); };
        
        void on_left_error(baseHostCX*) override { state().dead(true); };
        void on_right_error(baseHostCX*) override { state().dead(true); };
};

template <class COM, class CX, class PX>
class SimpleClient {
    public:
        SimpleClient<COM,CX,PX>() = default;
        SimpleClient<COM,CX,PX>(const char* h, const char* p):
            host_(h), port_(p) {
        
            px_ = std::make_unique<PX>(new COM());
            px_->pollroot(true);
        };

        inline std::unique_ptr<PX> const& px() { return px_; }
        inline CX* cx() {
            if(px() and not px()->ls().empty()) {
                return dynamic_cast<CX*>(px()->ls().at(0));
            }
            return nullptr;
        }

        virtual int connect() {
            px()->ladd(new CX(px_->com()->slave(), host_, port_));
            return cx()->connect();
        }
        virtual int run() { return px()->run(); }
    protected:
	    std::unique_ptr<PX> px_;
        const char* host_{};
        const char* port_{};
};


//only used in test_url2
class PackageHandler {
    public:
        logan_lite log = logan_lite("com.smithd");

        void on_package() const { _inf("MGR: package received (notify signal)"); };
        void on_package_detail(SmithClientCX* cx, LTVEntry* pkg) const {
            _inf("MGR: package received (detail signal)");
            _deb("cx %s: data: \n%s",cx->c_name(), pkg->hr().c_str());
        };
};

void test_url2(const char* url = nullptr) {
    // Setup location of smithd socket 
    const char* u = cfg_ux_socket().c_str();
    if(url != nullptr) u = url;

    SimpleClient<UxCom,SmithClientCX,SmithdProxy> client(u,"");


    client.connect();
    if(int sock = client.connect() > 0) {

        std::cout << "socket created: " << sock << std::endl;


        // signal management
        PackageHandler mgr;

        client.cx()->sig_on_package = [&mgr]() { mgr.on_package(); };
        client.cx()->sig_package_detail = [&mgr](SmithClientCX* cx, LTVEntry* pkg) { mgr.on_package_detail(cx, pkg); };


        // create application payload
        std::unique_ptr<LTVEntry> m(client.cx()->pkg_create_rateurl_request(1,"www.smithproxy.org"));

        // pack. Make buffer data from the object
        int sz = m->pack();
        std::cout << "prepared packet size: " << sz << "B" << std::endl;
        std::cout << string_format("%s\n", hex_dump(m->data(), m->buflen()).c_str());

        client.cx()->send(m.get());

        client.px()->com()->master()->poller.handler_db.clear();

        client.cx()->shutdown();
        client.px()->shutdown();
        std::cout << "sent" << std::endl;

        client.run();
    } else {
        std::cout << "cannot connect" << std::endl;
    }
}

[[maybe_unused]]
void test_url(const char* url = nullptr) {
    
    // Setup location of smithd socket 
    const char* u = cfg_ux_socket().c_str();
    if(url != nullptr) u = url;
  
    // Create basic proxy and associate com object (SmithdProxy is child of baseProxy)
    // Com object without master object set is automatically considered as master
    SmithdProxy p = SmithdProxy(new UxCom());
    // Basic proxy needs to know it will be running com's poll()
    p.pollroot(true);
   
    // Create client context (cx). Contexts could be attached to Proxy, typically 
    // to left or right. We will create CX with slave com and connect.
    auto* cx = new SmithClientCX(p.com()->slave(),u,"");
    
    // since this is simple client, we will block. Normally it doesn't matter, run() would 
    // eventually take care of it
    cx->connect();
    
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

    delete m; // coverity: 1407981

    // manage and run all connections until it's stopped. We stop in the client code,
    // where we receive response and close cx. Which will also close the proxy, which in turn terminates
    // run method.
    p.run();  
}


int main(int argc, char *argv[]) {

    logger().dup2_cout(true);
    logger().level(DEB);
    logan::get()["internal.ltv"]->level(iDEB);
    logan::get()["com.smithd"]->level(iDEB);



    int loop_count = 1;
    int t_diff;

    auto t_start = std::chrono::high_resolution_clock::now();

    //std::chrono::microseconds d = std::chrono::duration_cast<std::chrono::microseconds>(now - start_);

    int t_min = 0;
    int t_max = 0;
    int t_sum = 0;
    int t_cnt = 0;


    for (int i = 0; i < loop_count; i++) {

        t_start = std::chrono::high_resolution_clock::now();

        try {
            test_url2();
        } catch (socle::com_error const &e) {
            std::cerr << "com error: " << e.what();
            return 1;
        }


        auto t_current = std::chrono::high_resolution_clock::now();

        t_diff = std::chrono::duration_cast<std::chrono::microseconds>(t_current - t_start).count();
        t_cnt++;
        t_sum += t_diff;

        if (t_diff < t_min || t_min == 0) t_min = t_diff;
        if (t_diff > t_max || t_max == 0) t_max = t_diff;

        std::cout << string_format(">> Server RTT: %dus  (avg=%.2fus min=%dus max=%dus)\n", t_diff,
                                   ((double) t_sum) / t_cnt, t_min, t_max);
    }
}