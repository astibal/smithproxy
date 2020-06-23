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

#ifndef _SOCKS5HOST_HPP_
  #define _SOCKS5HOST_HPP_

#include <threadedacceptor.hpp>
#include <proxy/mitmhost.hpp>
#include <proxy/mitmproxy.hpp>
#include <hostcx.hpp>
#include <tcpcom.hpp>
#include <sslmitmcom.hpp>
#include <async/asyncdns.hpp>

typedef enum class socks5_state_ { INIT=1, HELLO_SENT, WAIT_REQUEST, REQ_RECEIVED, WAIT_POLICY, POLICY_RECEIVED, REQRES_SENT, DNS_QUERY_SENT=15, DNS_RESP_RECV, HANDOFF=31 , ZOMBIE=255 } socks5_state;
typedef enum class socks5_request_error_ { NONE=0, UNSUPPORTED_VERSION, UNSUPPORTED_ATYPE } socks5_request_error;
typedef enum class socks5_atype_ { IPV4=1, FQDN=3, IPV6=4 } socks5_atype;
typedef enum class socks5_policy_ { PENDING, ACCEPT, REJECT } socks5_policy;

typedef enum socks5_message_ { POLICY, UPGRADE } socks5_message;





class socksTCPCom: public TCPCom {
public:
    static std::string sockstcpcom_name_;
    
    virtual std::string& name() { return sockstcpcom_name_; };
    virtual baseCom* replicate() { return new socksTCPCom(); };
};

class socksSSLMitmCom: public MySSLMitmCom {
public:
    static std::string sockssslmitmcom_name_;
    
    virtual std::string& name() { return sockssslmitmcom_name_; };
    virtual baseCom* replicate() { return new socksSSLMitmCom(); };
};

class socksServerCX : public baseHostCX, public epoll_handler {
public:
    socksServerCX(baseCom* c, unsigned int s);
    virtual ~socksServerCX();


    virtual int process();
    virtual int process_socks_hello();
    virtual int process_socks_request();
    virtual bool setup_target();
    virtual int process_socks_reply();
    virtual void pre_write();
    
    bool new_message() const override;
    void verdict(socks5_policy);
    void state(socks5_state s) { state_ = s; };
    
    socks5_policy verdict_ = socks5_policy::PENDING;
    socks5_state state_;
    
    //before handoff, prepare already new CX. 
    MitmHostCX* left = nullptr;
    MitmHostCX* right = nullptr;
    bool handoff_as_ssl = false;


    void handle_event (baseCom *com) override;
    void dns_response_callback(std::pair<DNS_Response *, int>&);

public:
    static bool global_async_dns;

private:
    unsigned char version;
    socks5_atype req_atype;
    in_addr req_addr;
    std::string req_str_addr;

    unsigned short req_port;
    bool process_dns_response(std::shared_ptr<DNS_Response> resp);

    bool choose_server_ip(std::vector<std::string>& target_ips);
    bool async_dns = true;
    //socket_state async_dns_socket;

    AsyncDnsQuery* async_dns_query = nullptr;

private:
    // implement advanced logging
    DECLARE_C_NAME("sockHostCX");
    DECLARE_LOGGING(c_name);

    logan_attached<socksServerCX> log;
};

#endif //_SOCKS5HOST_HPP_
 
