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


#ifndef SMITHPROTOCX_HPP
#define SMITHPROTOCX_HPP

// this is the class mimicking Fortigate
#include <hostcx.hpp>
#include <basecom.hpp>
#include <ltventry.hpp>


class SmithProtoCX : public baseHostCX {

public:
    SmithProtoCX(baseCom*c, int s);
    SmithProtoCX(baseCom*c, const char* h, const char* p);
    ~SmithProtoCX() override;
        

    std::size_t process_in() override ;
    virtual void process_keepalive(LTVEntry*);
    virtual void process_package(LTVEntry*);
        
    void on_timer() override;
    virtual unsigned int check_timeouts();
    
    lockbuffer& to_read() override;
    std::size_t finish() override;

    inline unsigned int unpack();
    unsigned int unpack(buffer*);
    
    inline std::vector<LTVEntry*>& packages() { return packages_; }
    void destroy();
    void destroy_packages();
    
    inline void send(LTVEntry* e) { buffer b(e->buffer(),e->buflen()); baseHostCX::send(b);  }
    
    inline unsigned long use_my_hb() { unsigned long r = hb_me; hb_me++; return r; }
    inline unsigned long my_hb() { return hb_me; }
    inline unsigned long use_peer_hb() { unsigned long r = hb_peer; hb_peer++; return r; }
    inline unsigned long peer_hb() { return hb_peer; }
    inline int peer_hb_counter() { return hb_peer_timeout_counter; }
    inline void         peer_hb_reset() { time(&hb_peer_received); hb_peer_timeout_counter = 0; }
    
    const unsigned int id_keepalive = 1;

    enum id_client { CL_INIT=100, CL_VERSION=2, CL_REQID=3, CL_REQTYPE=127, CL_PAYLOAD=255 };
    enum req_type  { RQT_NONE=0, RQT_RATEURL=1 };
    
    enum rate_url { RATEURL_CAT=1 };
    
protected:
    std::vector<LTVEntry*> packages_;
    lockbuffer to_read_buffer;

    unsigned long hb_me = 0;
    time_t           hb_me_sent = 0;
    int hb_me_timeout = 10;
    
    inline void reset_hb_me() { time(&hb_me_sent); }
    
    unsigned long hb_peer = 0;
    time_t           hb_peer_received = 0;
    int  hb_peer_timeout = 10;
    int  hb_peer_timeout_counter = 0;

protected:
    virtual void on_hb_timeout_me() { reset_hb_me(); };
    virtual void on_hb_timeout_peer() {};   
    
    LTVEntry* create_pkg_keepalive(int=0);
    LTVEntry* create_msg_keepalive(int=0);

};

#endif // SMITHPROTOCX_HPP
