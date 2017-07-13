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
        INF_("Package dump: \n",e->hr().c_str());
    };
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
    
    LTVEntry* m  = new LTVEntry();
    m->container(100);
    
    LTVEntry* e  = new LTVEntry();
    e->set_num(16,3,32); // value 32 seen while testing
    m->add(e);

    m->pack();
    
    cx->send(m);
    cx->close_after_write(true);
    
    p.run();
    sleep(5);
}