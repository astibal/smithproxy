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

#ifndef __SOCKSPROXY_HPP__
  #define __SOCKSPROXY_HPP__

#include <threadedacceptor.hpp>

#include <mitmproxy.hpp>
#include <sockshostcx.hpp>


class SocksProxy : public MitmProxy {
public:
    explicit SocksProxy(baseCom*);
    virtual ~SocksProxy();
    virtual void on_left_message(baseHostCX* cx);
    
    virtual void socks5_handoff(socksServerCX* cx);
    int policy_num = -1;
};


class MitmSocksProxy : public ThreadedAcceptorProxy<SocksProxy> {
public:
    
    MitmSocksProxy(baseCom* c, int worker_id) : ThreadedAcceptorProxy<SocksProxy>(c,worker_id) {};
    
    virtual baseHostCX* new_cx(int s);
    virtual void on_left_new(baseHostCX* just_accepted_cx);
};


#endif