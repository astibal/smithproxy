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

#ifndef SOCKS5HOST_HPP
  #define SOCKS5HOST_HPP

#include <threadedacceptor.hpp>
#include <proxy/mitmcom.hpp>
#include <proxy/mitmhost.hpp>
#include <proxy/mitmproxy.hpp>
#include <hostcx.hpp>
#include <tcpcom.hpp>
#include <socketinfo.hpp>
#include <sslmitmcom.hpp>
#include <async/asyncdns.hpp>

#include <common/numops.hpp>

using socks5_state = enum class socks5_state_ { INIT=1u, HELLO_SENT, WAIT_REQUEST, REQ_RECEIVED, WAIT_POLICY, POLICY_RECEIVED, REQRES_SENT, DNS_QUERY_SENT, DNS_RESP_RECV, DNS_RESP_FAILED, HANDOFF , ZOMBIE };
using socks5_request_error = enum class socks5_request_error_ { NONE=0, UNSUPPORTED_VERSION, UNSUPPORTED_ATYPE, UNSUPPORTED_METHOD, MALFORMED_DATA, UNAUTHORIZED };

using socks5_cmd = enum socks5_cmd_ { CONNECT=1u, BIND=2u, UDP_ASSOCIATE=3u };
using socks5_atype = enum class socks5_atype_ { IPV4=1u, FQDN=3u, IPV6=4u };
using socks5_policy = enum class socks5_policy_ { PENDING, ACCEPT, REJECT };

using socks5_message = enum socks5_message_ { POLICY, UPGRADE };


class socksTCPCom: public TCPCom {
public:
    baseCom* replicate() override { return new socksTCPCom(); };

    TYPENAME_OVERRIDE("s5_tcp");
private:
    logan_lite log {"com.socks.tcp"};
};

class socksUDPCom: public UDPCom {
public:

    baseCom* replicate() override { return new socksUDPCom(); };

    TYPENAME_OVERRIDE("s5_udp");

private:
    logan_lite log {"com.socks.udp"};
};


class socksSSLMitmCom: public MySSLMitmCom {
public:
    baseCom* replicate() override { return new socksSSLMitmCom(); };

    TYPENAME_OVERRIDE("s5_tls");

private:
    logan_lite log {"com.socks.tls"};
};

class socksServerCX : public MitmHostCX, public epoll_handler {
public:
    socksServerCX(baseCom* c, unsigned int s);
    ~socksServerCX() override {

        if(udp_) {
            auto ass = UDP::db();

            auto lc_ = std::scoped_lock(UDP::lock);
            ass->clients.erase(udp_->my_assoc);
        }
    }

    bool is_ssl = false;
    bool tested_dns_a = false;
    bool tested_dns_aaaa  = false;
    static inline bool mixed_ip_versions = true; // allow cross-version connections
    static inline bool prefer_ipv6 = false;       // if set, try IPv6 DNS first (AAAA), then IPv4 (A)

    std::size_t process_in() override;
    virtual std::size_t process_socks_hello();
    virtual std::size_t process_socks_hello_tcp();
    virtual std::size_t process_socks_udp_request();

    struct UDP {
        struct associations {
            // this cannot be only port - must be also source IP
            std::map<std::string, socksServerCX*> clients;
        };

        std::string my_assoc;
        std::string my_allowed_target;

        bool make_authorized(std::string const& server, unsigned short port) {
            std::string const key = string_format("%s:%d", server.c_str(), port);
            if(my_allowed_target.empty()) {
                my_allowed_target = key;
                return true;
            }
            return key == my_allowed_target;
        }

        static std::shared_ptr<associations> db() {

            // double condition check to prevent locks
            if(not db_) {
                auto lc_ = std::scoped_lock(lock);
                if(not db_) {
                    db_ = std::make_shared<associations>();
                }
            }
            return db_;
        }

        static inline std::mutex lock;
    private:
        static inline std::shared_ptr<associations> db_;
    };

    std::unique_ptr<UDP> udp_;
    std::unique_ptr<UDP>& get_udp() noexcept { if(not udp_) udp_ = std::make_unique<UDP>(); return udp_; };



    virtual std::size_t process_socks_request();

    socks5_request_error handle4_connect();
    socks5_request_error socks5_parse_request();
    socks5_request_error handle5_connect();
    socks5_request_error handle5_connect_fqdn();

    virtual bool setup_target();
    virtual std::size_t process_socks_reply();
    virtual int process_socks_reply_v4();
    virtual std::size_t process_socks_reply_v5();


    void wait_policy() {
        // peers are now prepared for handover. Owning proxy will wipe this CX (it will be empty)
        // and if policy allows, left and right will be set (also in proxy owning this cx).

        state_ = socks5_state::WAIT_POLICY;
        read_waiting_for_peercom(true);
    }

    void pre_write() override;
    
    bool new_message() const override;
    void verdict(socks5_policy);
    void state(socks5_state s) { state_ = s; };

    socks5_request_error socks_error_ = socks5_request_error::NONE;
    socks5_policy verdict_ = socks5_policy::PENDING;
    socks5_state state_;
    
    //before handoff, prepare already new CX. 
    std::unique_ptr<MitmHostCX> left;
    std::unique_ptr<MitmHostCX> right;

    void handle_event (baseCom *com) override;

    void setup_dns_async(std::string const& fqdn, DNS_Record_Type type, const AddressInfo &nameserver);
    using dns_response_t = std::pair<std::shared_ptr<DNS_Response>, ssize_t>;
    void dns_response_callback(dns_response_t const& resp);

    static bool global_async_dns;

    uint8_t request_command() const noexcept { return req_cmd; }

    std::size_t process_socks_response();
    std::size_t process_out() override;

private:
    uint8_t version {0};
    uint8_t req_cmd {0};
    socks5_atype req_atype {0};
    AddressInfo req_addr {};
    std::string req_str_addr;

    unsigned short req_port {0};
    std::size_t req_hdr_size = 0L;

    bool process_dns_response(std::shared_ptr<DNS_Response> resp);

    bool choose_server_ip(std::vector<std::string>& target_ips);
    bool async_dns = true;

    std::unique_ptr<AsyncDnsQuery> async_dns_query;

    std::string to_string(int verbosity) const override { return MitmHostCX::to_string(verbosity); };

public:
    // implement advanced logging
    TYPENAME_OVERRIDE("sockHostCX")
    DECLARE_LOGGING(to_string)

private:
    logan_lite log {"com.socks.proxy"};

};


class socksMitmHostCX : public MitmHostCX {
public:
    ~socksMitmHostCX() override = default;
    using MitmHostCX::MitmHostCX;

    TYPENAME_OVERRIDE("socksMitmHostCX")
private:
    logan_lite log {"com.socks.proxy"};

};

#endif //SOCKS5HOST_HPP
 
