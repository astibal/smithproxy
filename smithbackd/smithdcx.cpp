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


#include <vector>

#include <smithdcx.hpp>
#include <hostcx.hpp>
#include <ltventry.hpp>
#include <logger.hpp>


SmithProtoCX::SmithProtoCX(baseCom*c, const char* h, const char* p): baseHostCX(c, h, p) {
    to_read_buffer = buffer(0);
    reset_hb_me();
    peer_hb_reset();
}
SmithProtoCX::SmithProtoCX(baseCom*c, unsigned int s): baseHostCX(c,s) {
    to_read_buffer = buffer(0);
    reset_hb_me();
    peer_hb_reset();
}
SmithProtoCX::~SmithProtoCX() {
    destroy();
}

void SmithProtoCX::destroy() {
    DEBS_("SmithProtoCX::destroy: ");
    destroy_packages();
}

void SmithProtoCX::destroy_packages() {

    DEB_("SmithProtoCX::destroy_packages[%s]: ",c_name());
    for (std::vector<LTVEntry*>::iterator i = packages().begin(); i != packages().end(); i++) {
        DEB_("SmithProtoCX::destroy_packages[%s]: deleting LTVEntry with id %d",c_name(),(*i)->id());
        delete (*i);
    };

    DEB_("SmithProtoCX::destroy_packages[%s]: clearing, size %d",c_name(),packages().size());
    packages().clear();
}



int SmithProtoCX::unpack() {
    return unpack(readbuf());
}


int SmithProtoCX::unpack(buffer* b) {

    DEB_("SmithProtoCX::unpack: buffer size %d",b->size());
    
    unsigned int r = 0;
    do {
        LTVEntry *l = new LTVEntry();
        l->owner(false);
        int c_r = l->unpack((uint8_t*)b->data()+r,b->size()-r);

        if (c_r <= 0) {
            delete l;
            break;
        }

        r += c_r;

        DUM_("SmithProtoCX::unpack[%s]: extracted message: ",c_name());
        DUMS_(l->hr());
        packages().push_back(l);
    }
    while (r <= b->size());

    return r;
}

int SmithProtoCX::process() {
        
    //retrieve packages from received buffer
    auto r = unpack();
    DEB_("SmithProtoCX::process[%s]: %d bytes unpacked",c_name(),r);

    for (std::vector<LTVEntry*>::iterator i = packages().begin(); i != packages().end(); i++) {

        auto id = (*i)->id();
        auto ty = (*i)->type();
        DEB_("SmithProtoCX::process[%s]: received message id=%d of type %d",c_name(),id,ty);

        if(id == id_keepalive) {
            process_keepalive(*i);
        } else {
            LTVEntry* k_a = (*i)->search({1});
            if(k_a) {
                DEB_("SmithProtoCX::process[%s]: non-keepalive msg contains sync data: %d (current %d)",c_name(), k_a->data_int(),hb_peer);
                DUMS_(k_a->hr());
                
                hb_peer = k_a->data_int();    
            }
            
            process_package(*i);
        }
    }

    return r;
}

void SmithProtoCX::on_timer() {
    
    baseHostCX::on_timer();
    check_timeouts();
}


ssize_t SmithProtoCX::finish() {

    DEB_("SmithProtoCX::finish[%s] packages=%d, to_read_buffer size=%d capacity=%d",c_name(), packages().size(), to_read_buffer.size(),to_read_buffer.capacity());

    destroy_packages();
    to_read_buffer.clear();

    return baseHostCX::finish();
}

buffer SmithProtoCX::to_read() {
    auto size = 0;
    for (std::vector<LTVEntry*>::iterator i = packages().begin(); i != packages().end(); i++) {
        size += (*i)->len();
    };


    to_read_buffer.clear();
    to_read_buffer.capacity(size);


    for (std::vector<LTVEntry*>::iterator i = packages().begin(); i != packages().end(); i++) {
        to_read_buffer.append((*i)->buffer(),(*i)->len());
    };

    return to_read_buffer.view();
}

int SmithProtoCX::check_timeouts() {

    if (!valid()) {
        DEB_("SmithProtoCX::check_timeouts[%s] -- socket not UP yet",c_name());
        return 0;
    }
    DEB_("SmithProtoCX::check_timeouts[%s]",c_name());

        
    int r = 0;
    
    time_t now;
    time(&now);
    
    if (now - hb_peer_received  > hb_peer_timeout + (hb_peer_timeout/10) ) {                
        DEB_("SmithProtoCX::check_timeouts[%s]: Peer not in time with heartbeat!",c_name());
        DIA_("SMITH peer %s heartbeat timeout",c_name());
        r |= 1;
        
        hb_peer_timeout_counter++;
        on_hb_timeout_peer();

    } else {
        if (opening()) {
            DEB_("SmithProtoCX::check_timeouts[%s]: peer is opening",c_name());
        } else {
            hb_peer_timeout_counter = 0;
            DEB_("SmithProtoCX::check_timeouts[%s]: peer is alive",c_name());
        }
    }

    
    if(now - hb_me_sent >  hb_me_timeout - (hb_me_timeout/10) ) {
        DEB_("SmithProtoCX::check_timeouts[%s]: we should send keepalive now",c_name());
        r |= 2;
        
        on_hb_timeout_me();
    }
    
    return r;
}


void SmithProtoCX::process_keepalive(LTVEntry* e) {

    LTVEntry* el = e->at(0);
    int k = el->data_int();
    
    hb_peer = k;
    time(&hb_peer_received);
    
    DEB_("SmithProtoCX::process_keepalive[%s]: heartbeat received: %d",c_name(),k);
}

void SmithProtoCX::process_package(LTVEntry* e) {
}


LTVEntry* SmithProtoCX::create_msg_keepalive(int n) {
    
    int nn = hb_me;
    if (n > 0) {
        nn = n;
    }
    
    LTVEntry* l = new LTVEntry();
    l->set_num(1,LTVEntry::num,nn);
    
    if (n == 0) {
        hb_me++;
    }
            
    return l;
}

LTVEntry* SmithProtoCX::create_pkg_keepalive(int n) {
    
    LTVEntry* l = new LTVEntry();
    l->container(id_keepalive);
    l->add(create_msg_keepalive(n));
    l->pack();
    
    return l;
}


