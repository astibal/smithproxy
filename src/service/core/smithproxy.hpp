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


#ifndef SMITHPROXY_SMITHPROXY_HPP
#define SMITHPROXY_SMITHPROXY_HPP

#include <proxy/mitmproxy.hpp>
#include <proxy/socks5/socksproxy.hpp>
#include <threadedacceptor.hpp>
#include <threadedreceiver.hpp>

#include <service/cfgapi/cfgapi.hpp>

#include <service/core/service.hpp>
#include <service/daemon.hpp>
#include <service/netservice.hpp>

#include <smithlog.hpp>
#include <service/dnsupd/smithdnsupd.hpp>

#include <atomic>

typedef ThreadedAcceptor<MitmMasterProxy> theAcceptor;
typedef ThreadedReceiver<MitmUdpProxy> theReceiver;
typedef ThreadedAcceptor<MitmSocksProxy> socksAcceptor;



class SmithProxy : public Service {

    SmithProxy() : Service() {};
    virtual ~SmithProxy ();

public:

    using vec_of_acceptors = std::vector<std::unique_ptr<theAcceptor>>;
    using vec_of_sock5tors = std::vector<std::unique_ptr<socksAcceptor>>;
    using vec_of_receivers = std::vector<std::unique_ptr<theReceiver>>;

    vec_of_acceptors plain_proxies;
    vec_of_acceptors ssl_proxies;
    vec_of_receivers udp_proxies;
    vec_of_receivers dtls_proxies;
    vec_of_sock5tors socks_proxies;

    vec_of_acceptors redir_plain_proxies;
    vec_of_acceptors redir_ssl_proxies;
    vec_of_receivers redir_udp_proxies;


    std::vector<std::shared_ptr<std::thread>> plain_threads;
    std::vector<std::shared_ptr<std::thread>> ssl_threads;
    std::vector<std::shared_ptr<std::thread>> udp_threads;
    std::vector<std::shared_ptr<std::thread>> dtls_threads;
    std::vector<std::shared_ptr<std::thread>> socks_threads;

    std::vector<std::shared_ptr<std::thread>> redir_plain_threads;
    std::vector<std::shared_ptr<std::thread>> redir_ssl_threads;
    std::vector<std::shared_ptr<std::thread>> redir_udp_threads;

    std::shared_ptr<std::thread> cli_thread;
    std::shared_ptr<std::thread> log_thread;
    std::shared_ptr<std::thread> dns_thread;
    std::shared_ptr<std::thread> id_thread;

    std::shared_ptr<std::thread> api_thread;

    SmithProxy (SmithProxy const&) = delete;
    SmithProxy& operator= (SmithProxy const& r) = delete;

    static SmithProxy& instance() {
        static SmithProxy sx;
        return sx;
    }

    static std::thread* create_identity_refresh_thread();

    void create_log_writer_thread();
    void create_dns_thread();
    void create_identity_thread();
    void create_api_thread();

    bool create_listeners();

    void run() override;
    void stop() override;
    void reload() override;

    void join_all();

    static bool init_syslog();
    bool load_config(std::string& config_f, bool reload = false);
};




#endif //SMITHPROXY_SMITHPROXY_HPP
