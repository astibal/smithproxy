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


#ifndef SMITHPROTOCX_HPP
#define SMITHPROTOCX_HPP

// this is the class mimicking Fortigate
#include <hostcx.hpp>
#include <basecom.hpp>
#include <ltventry.hpp>

#include <sigslot.h>

class SmithProtoCX : public baseHostCX {

public:
    SmithProtoCX(baseCom*c, unsigned int s);
    SmithProtoCX(baseCom*c, const char* h, const char* p);
    virtual ~SmithProtoCX();
        

    virtual int process();
    virtual void process_keepalive(LTVEntry*);
    virtual void process_package(LTVEntry*);
        
    virtual void on_timer();
    virtual int check_timeouts();
    
    virtual buffer to_read();
    virtual ssize_t finish();
    
    inline int unpack();
    int unpack(buffer*);
    
    inline std::vector<LTVEntry*>& packages() { return packages_; }
    void destroy();
    void destroy_packages();
    
    inline void send(LTVEntry* e) { buffer b(e->buffer(),e->buflen()); baseHostCX::send(b);  }
    
    inline unsigned int use_my_hb() { int r = hb_me; hb_me++; return r; }
    inline unsigned int my_hb() { return hb_me; }
    inline unsigned int use_peer_hb() { int r = hb_peer; hb_peer++; return r; }
    inline unsigned int peer_hb() { return hb_peer; }
    inline unsigned int peer_hb_counter() { return hb_peer_timeout_counter; }
    inline void         peer_hb_reset() { time(&hb_peer_received); hb_peer_timeout_counter = 0; } 
    
    const unsigned int id_keepalive = 1;
    
protected:
    std::vector<LTVEntry*> packages_;
    buffer to_read_buffer; 

    unsigned int hb_me = 0;
    time_t           hb_me_sent = 0;
    unsigned int hb_me_timeout = 10; 
    
    inline void reset_hb_me() { time(&hb_me_sent); }
    
    unsigned int hb_peer = 0;
    time_t           hb_peer_received = 0;
    unsigned int hb_peer_timeout = 10;
    unsigned int hb_peer_timeout_counter = 0;

protected:
    virtual void on_hb_timeout_me() { reset_hb_me(); };
    virtual void on_hb_timeout_peer() {};   
    
    LTVEntry* create_pkg_keepalive(int=0);
    LTVEntry* create_msg_keepalive(int=0);

};

#endif // SMITHPROTOCX_HPP
