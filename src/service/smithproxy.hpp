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

#include <mitmproxy.hpp>
#include <socksproxy.hpp>
#include <threadedacceptor.hpp>
#include <threadedreceiver.hpp>

#include <cfgapi.hpp>
#include <service/daemon.hpp>
#include <service/srvutils.hpp>
#include <smithlog.hpp>
#include <smithdnsupd.hpp>

typedef ThreadedAcceptor<MitmMasterProxy,MitmProxy> theAcceptor;
typedef ThreadedReceiver<MitmUdpProxy,MitmProxy> theReceiver;
typedef ThreadedAcceptor<MitmSocksProxy,SocksProxy> socksAcceptor;


class MyPlainAcceptor : public theAcceptor {
};


class SmithProxy {

    explicit SmithProxy() : tenant_index_(0), tenant_name_("default") {
        log.level(WAR);
        reload_handler_ = my_usr1;
        terminate_handler_ = my_terminate;
    };
    virtual ~SmithProxy ();


    unsigned int tenant_index_;
    std::string  tenant_name_;

    void (*terminate_handler_)(int) = nullptr;
    void (*reload_handler_)(int) = nullptr;
public:
    bool cfg_daemonize = false;
    logan_lite log = logan_lite("service");

    theAcceptor* plain_proxy = nullptr;
    theAcceptor* ssl_proxy = nullptr;
    theReceiver* udp_proxy = nullptr;
    theReceiver* dtls_proxy = nullptr;
    socksAcceptor* socks_proxy = nullptr;


    std::thread* plain_thread = nullptr;
    std::thread* ssl_thread = nullptr;
    std::thread* dtls_thread = nullptr;
    std::thread* udp_thread = nullptr;
    std::thread* socks_thread = nullptr;
    std::thread* cli_thread = nullptr;
    std::thread* log_thread = nullptr;
    std::thread* dns_thread = nullptr;
    std::thread* id_thread = nullptr;

    SmithProxy (SmithProxy const&) = delete;
    SmithProxy& operator= (SmithProxy const& r) = delete;

    static SmithProxy& instance() {
        static SmithProxy sx;
        return sx;
    }

    unsigned int tenant_index () const { return tenant_index_; }
    void tenant_index (unsigned int tenantIndex) { tenant_index_ = tenantIndex;}

    const std::string& tenant_name () const { return tenant_name_;  }
    void tenant_name (const std::string &tenantName) { tenant_name_ = tenantName;  }

    void set_handler_term(void (*terminate_handler)(int)) { terminate_handler_ = terminate_handler;  }
    void set_handler_reload(void (*reload_handler)(int)) { reload_handler_ = reload_handler; }


    static std::thread* create_identity_refresh_thread();

    void create_log_writer_thread();
    void create_dns_thread();
    void create_identity_thread();
    void create_listeners();

    void run();
    void stop();

    static void my_terminate(int param);
    static void my_usr1 (int param);
    int load_signatures(libconfig::Config& cfg, const char* name, std::vector<duplexFlowMatch*>& target);
    bool init_syslog();
    bool load_config(std::string& config_f, bool reload = false);

    volatile static int cnt_terminate;
};




#endif //SMITHPROXY_SMITHPROXY_HPP
