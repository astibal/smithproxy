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

#ifndef _SOCKS5HOST_HPP_
  #define _SOCKS5HOST_HPP_

#include <threadedacceptor.hpp>
#include <mitmhost.hpp>
#include <mitmproxy.hpp>
#include <hostcx.hpp>
#include <tcpcom.hpp>
#include <sslmitmcom.hpp>

typedef enum socks5_state_ { INIT, HELLO_SENT, WAIT_REQUEST, REQ_RECEIVED, WAIT_POLICY, POLICY_RECEIVED, REQRES_SENT, HANDOFF , ZOMBIE } socks5_state;
typedef enum socks5_request_error_ { NONE=0, UNSUPPORTED_VERSION, UNSUPPORTED_ATYPE } socks5_request_error;
typedef enum socks5_atype_ { IPV4=1, FQDN=3, IPV6=4 } socks5_atype;
typedef enum socks5_policy_ { PENDING, ACCEPT, REJECT } socks5_policy;

typedef enum socks5_message_ { POLICY, UPGRADE } socks5_message;

class socksTCPCom: public TCPCom {
public:
    virtual const char* name() { return "s5+tcp"; };
    virtual baseCom* replicate() { return new socksTCPCom(); };
};

class socksSSLMitmCom: public MySSLMitmCom {
public:
    virtual const char* name() { return "s5+ssl+insp"; };
    virtual baseCom* replicate() { return new socksSSLMitmCom(); };
};

class socksServerCX : public baseHostCX {
public:
    socksServerCX(baseCom* c, unsigned int s);  


    virtual int process();
    virtual int process_socks_hello();
    virtual int process_socks_request();
    virtual int process_socks_reply();
    virtual void pre_write();
    
    virtual bool new_message();
    void verdict(socks5_policy);
    void state(socks5_state s) { state_ = s; };
    
    socks5_policy verdict_ = PENDING;
    socks5_state state_;
    
    //before handoff, prepare already new CX. 
    MitmHostCX* left = nullptr;
    MitmHostCX* right = nullptr;
    bool handoff_as_ssl = false;
    
private:
    socks5_atype req_atype;
    in_addr req_addr;
    unsigned short req_port;
};

#endif //_SOCKS5HOST_HPP_
 
