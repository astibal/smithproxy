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

#include <memory>

#include <openssl/rand.h>

#include <staticcontent.hpp>

#include <policy/authfactory.hpp>
#include <inspect/sigfactory.hpp>

#include <service/core/smithproxy.hpp>
#include <service/cmd/cmdserver.hpp>
#include <service/httpd/httpd.hpp>
#include <service/cfgapi/cfgapi.hpp>
#include "service/http/webhooks.hpp"
#include "proxy/nbrhood.hpp"

#ifdef ASAN_LEAKS
extern "C" int __lsan_do_recoverable_leak_check();
#endif

SmithProxy::~SmithProxy () {

#ifndef MEMPOOL_DISABLE
    memPool::bailing = true;
#endif

}

void SmithProxy::reload() {
    _war("reloading configuration (excluding signatures)");
    SmithProxy::instance().load_config(CfgFactory::get()->config_file,true);
    _dia("USR1 signal handler finished");
}


std::thread* SmithProxy::create_identity_refresh_thread() {


    auto* id_thread = new std::thread([]() {
        auto const& log = instance().log;

        // give some time to init shm - don't run immediately
        // this is workaround for rare(?) race condition when shm is not
        // initialized yet.

        if (abort_sleep(20) ) {
            return;
        }

        for (unsigned i = 0; ; i++) {

            if(abort_sleep(20)) {
                _dia("id_thread: terminating");
                break;
            }

            _deb("id_thread: refreshing identities");

            AuthFactory::get().shm_ip4_table_refresh();
            AuthFactory::get().shm_ip6_table_refresh();
            AuthFactory::get().shm_token_table_refresh();
            AuthFactory::get().ip4_timeout_check();
            AuthFactory::get().ip6_timeout_check();

            _dum("id_thread: finished");


        }
    });

    return id_thread;
}



void SmithProxy::create_log_writer_thread() {
    // we have to create logger after daemonize is called
    log_thread  = std::shared_ptr<std::thread>(create_log_writer());

    if(log_thread) {
        pthread_setname_np( log_thread->native_handle(), string_format("sxy_lwr_%d", tenant_index()).c_str());
    }
}


void SmithProxy::create_dns_thread() {
    dns_thread = std::shared_ptr<std::thread>(create_dns_updater());
    if(dns_thread) {
        pthread_setname_np( dns_thread->native_handle(),
                            string_format("sxy_dns_%d",tenant_index()).c_str());
    }
}

void SmithProxy::create_identity_thread() {
    id_thread = std::shared_ptr<std::thread>(create_identity_refresh_thread());
    if(id_thread != nullptr) {
        pthread_setname_np(id_thread->native_handle(),string_format("sxy_idu_%d",
                                                                    CfgFactory::get()->tenant_index).c_str());
    }
}

void SmithProxy::create_api_thread() {
#ifdef USE_LMHPP

    api_thread = std::shared_ptr<std::thread>(sx::webserver::create_httpd_thread(sx::webserver::HttpSessions::api_port + tenant_index()));
    if(api_thread) {
        pthread_setname_np( api_thread->native_handle(),
                            string_format("sxy_api_%d",tenant_index()).c_str());
    }
#endif
}


bool SmithProxy::create_listeners() {

    bool success = false;

    try {

        std::string tcp_frm = "tcp";
        std::string tls_frm = "tls";
        std::string dtls_frm = "dtls";
        std::string udp_frm = "udp";

        std::string socks_frm = "socks-tcp";
        std::string socks_udp_frm = "socks-udp";

        std::string retcp_frm = "redir-tcp";
        std::string retls_frm = "redir-tls";
        std::string redns_frm = "redir-dns";


        auto log_listener = [&](auto& kind, auto& proxies) {
            if(! SmithProxy::instance().cfg_daemonize) {
                std::cout << string_format("%-5s", kind.c_str()) << ": " <<  proxies.size() << " listeners" << std::endl;
            }
        };

        if(CfgFactory::get()->accept_tproxy) {

            plain_proxies = NetworkServiceFactory::prepare_listener<theAcceptor, TCPCom>(
                    std::stoi(CfgFactory::get()->listen_tcp_port),
                    tcp_frm,
                    CfgFactory::get()->num_workers_tcp,
                    proxyType::transparent());

            log_listener(tcp_frm, plain_proxies);

            ssl_proxies = NetworkServiceFactory::prepare_listener<theAcceptor, MySSLMitmCom>(
                    std::stoi(CfgFactory::get()->listen_tls_port),
                    tls_frm,
                    CfgFactory::get()->num_workers_tls,
                    proxyType::transparent());

            log_listener(tls_frm, ssl_proxies);


            dtls_proxies = NetworkServiceFactory::prepare_listener<theReceiver, MyDTLSMitmCom>(
                    std::stoi(CfgFactory::get()->listen_dtls_port),
                    dtls_frm,
                    CfgFactory::get()->num_workers_dtls,
                    proxyType::transparent());

            log_listener(dtls_frm, dtls_proxies);


            udp_proxies = NetworkServiceFactory::prepare_listener<theReceiver, UDPCom>(
                    std::stoi(CfgFactory::get()->listen_udp_port),
                    udp_frm,
                    CfgFactory::get()->num_workers_udp,
                    proxyType::transparent());

            log_listener(udp_frm, udp_proxies);


            if ((plain_proxies.empty() && CfgFactory::get()->num_workers_tcp >= 0) ||
                (ssl_proxies.empty() && CfgFactory::get()->num_workers_tls >= 0) ||
                (dtls_proxies.empty() && CfgFactory::get()->num_workers_dtls >= 0) ||
                (udp_proxies.empty() && CfgFactory::get()->num_workers_udp >= 0)) {

                _fat("Failed to setup tproxy proxies. Bailing!");
                return false;
            }

        }

        if(CfgFactory::get()->accept_socks) {
            socks_proxies = NetworkServiceFactory::prepare_listener<socksAcceptor, socksTCPCom>(
                    std::stoi(CfgFactory::get()->listen_socks_port),
                    socks_frm,
                    CfgFactory::get()->num_workers_socks,
                    proxyType::proxy());

            log_listener(socks_frm, socks_proxies);


            socks_udp_proxies = NetworkServiceFactory::prepare_listener<socksReceiver , socksUDPCom>(
                    std::stoi(CfgFactory::get()->listen_socks_port),
                    socks_udp_frm,
                    CfgFactory::get()->num_workers_socks,
                    proxyType::proxy());

            log_listener(socks_udp_frm, socks_udp_proxies);



            if((socks_proxies.empty() && CfgFactory::get()->num_workers_socks >= 0) or
               (socks_udp_proxies.empty() && CfgFactory::get()->num_workers_socks >= 0)
            ) {
                _fat("Failed to setup socks proxies. Bailing!");
                return false;
            }
        }

        if(CfgFactory::get()->accept_redirect) {
            redir_plain_proxies = NetworkServiceFactory::prepare_listener<theAcceptor, TCPCom>(
                    std::stoi(CfgFactory::get()->listen_tcp_port) + 1000,
                    retcp_frm,
                    CfgFactory::get()->num_workers_tcp,
                    proxyType::redirect());

            log_listener(retcp_frm, redir_plain_proxies);

            redir_ssl_proxies = NetworkServiceFactory::prepare_listener<theAcceptor, MySSLMitmCom>(
                    std::stoi(CfgFactory::get()->listen_tls_port) + 1000,
                    "ssl-rdr",
                    CfgFactory::get()->num_workers_tls,
                    proxyType::redirect());

            log_listener(retls_frm, redir_ssl_proxies);

            redir_udp_proxies = NetworkServiceFactory::prepare_listener<theReceiver, UDPCom>(
                    std::stoi(CfgFactory::get()->listen_udp_port) +
                    973,  // 973 + default 50080 = 51053: should suggest DNS only
                    "udp-rdr",
                    CfgFactory::get()->num_workers_udp,
                    proxyType::redirect());

            log_listener(redns_frm, redir_udp_proxies);

            if((redir_plain_proxies.empty() && CfgFactory::get()->num_workers_tcp >= 0) ||
               (redir_ssl_proxies.empty() && CfgFactory::get()->num_workers_tls >= 0) ||
               (redir_udp_proxies.empty() && CfgFactory::get()->num_workers_udp >= 0)) {

                _fat("Failed to setup redirect proxies. Bailing!");
                return false;
            }
        }



        success = true;
    }
    catch (sx::netservice_cannot_bind const& e) {

        std::string msg = "Failed to create listeners (cannot bind): ";
        msg += e.what();

        _fat(msg.c_str());
        _cons(msg.c_str());
    }
    catch (std::logic_error const& e) {

        std::string msg = "Failed to create listeners (logic error): ";
        msg += e.what();

        _fat(msg.c_str());
        _cons(msg.c_str());
    }
    catch(socle::com_error const& e) {
        std::string msg = "Failed to create listeners (logic error): ";

        _fat(msg.c_str());
        _cons(msg.c_str());
    }

    return success;
}

void SmithProxy::run() {


    CRYPTO_set_mem_functions( mempool_alloc, mempool_realloc, mempool_free);

    std::string friendly_thread_name_tcp = string_format("sxy_tcp_%d",CfgFactory::get()->tenant_index);
    std::string friendly_thread_name_udp = string_format("sxy_udp_%d",CfgFactory::get()->tenant_index);
    std::string friendly_thread_name_tls = string_format("sxy_tls_%d",CfgFactory::get()->tenant_index);
    std::string friendly_thread_name_dls = string_format("sxy_dls_%d",CfgFactory::get()->tenant_index);
    std::string friendly_thread_name_skx = string_format("sxy_skx_%d",CfgFactory::get()->tenant_index);
    std::string friendly_thread_name_sku = string_format("sxy_sku_%d",CfgFactory::get()->tenant_index);
    std::string friendly_thread_name_cli = string_format("sxy_cli_%d",CfgFactory::get()->tenant_index);
    std::string friendly_thread_name_own = string_format("sxy_own_%d",CfgFactory::get()->tenant_index);

    std::string friendly_thread_name_redir_tcp = string_format("sxy_rdt_%d",CfgFactory::get()->tenant_index);
    std::string friendly_thread_name_redir_ssl = string_format("sxy_rds_%d",CfgFactory::get()->tenant_index);
    std::string friendly_thread_name_redir_udp = string_format("sxy_rdu_%d",CfgFactory::get()->tenant_index);


    if(not state_load()) {
        Log::get()->events().insert(ERR, "state was not fully loaded");
    }

    // cli_loop uses select :(
    cli_thread = std::make_shared<std::thread>([] () {
        CRYPTO_set_mem_functions( mempool_alloc, mempool_realloc, mempool_free);

        auto this_daemon = DaemonFactory::instance();
        auto const& log = this_daemon->get_log();

        _inf("Starting CLI");
        DaemonFactory::set_daemon_signals(SmithProxy::instance().terminate_handler_, SmithProxy::instance().reload_handler_);
        _dia("smithproxy_cli: max file descriptors: %d", this_daemon->get_limit_fd());

        cli_loop(CfgFactory::get()->cli_port + CfgFactory::get()->tenant_index);
        _dia("cli workers torn down.");
    } );
    pthread_setname_np(cli_thread->native_handle(),friendly_thread_name_cli.c_str());


    auto launch_proxy_threads = [&](auto &proxies, auto& thread_list, const char* log_friendly, const char* thread_friendly) {
        for(auto& proxy: proxies) {
            _inf("Starting: %s", log_friendly);

            // taking proxy as a value!
            auto a_thread = std::make_shared<std::thread>([&proxy]() {
                CRYPTO_set_mem_functions( mempool_alloc, mempool_realloc, mempool_free);

                auto this_daemon = DaemonFactory::instance();
                auto const& log = this_daemon->get_log();

                DaemonFactory::set_daemon_signals(SmithProxy::instance().terminate_handler_, SmithProxy::instance().reload_handler_);
                _dia("TCP listener: max file descriptors: %d", this_daemon->get_limit_fd());

                proxy->run();
                _dia("TCP listener: workers torn down.");
            } );
            pthread_setname_np(a_thread->native_handle(),thread_friendly);
            thread_list.push_back(a_thread);
        }
    };


    if(CfgFactory::get()->accept_tproxy) {
        launch_proxy_threads(plain_proxies, plain_threads, "TCP listener", friendly_thread_name_tcp.c_str());
        launch_proxy_threads(ssl_proxies, ssl_threads, "TLS listener", friendly_thread_name_tls.c_str());
        launch_proxy_threads(dtls_proxies, dtls_threads, "DTLS listener", friendly_thread_name_dls.c_str());
        launch_proxy_threads(udp_proxies, udp_threads, "UDP listener", friendly_thread_name_udp.c_str());
    }

    if(CfgFactory::get()->accept_socks) {
        launch_proxy_threads(socks_proxies, socks_threads, "SOCKS TCP listener", friendly_thread_name_skx.c_str());
        launch_proxy_threads(socks_udp_proxies, socks_udp_threads, "SOCKS UDP listener", friendly_thread_name_sku.c_str());
    }

    if(CfgFactory::get()->accept_redirect) {
        launch_proxy_threads(redir_plain_proxies, redir_plain_threads, "redirected TCP listener",
                             friendly_thread_name_redir_tcp.c_str());
        launch_proxy_threads(redir_ssl_proxies, redir_ssl_threads, "redirected TLS listener",
                             friendly_thread_name_redir_ssl.c_str());
        launch_proxy_threads(redir_udp_proxies, redir_udp_threads, "redirected UDP listener",
                             friendly_thread_name_redir_udp.c_str());
    }



    pthread_setname_np(pthread_self(),friendly_thread_name_own.c_str());

    // adapt daemon factory signal handlers for this thread, too
    DaemonFactory::set_daemon_signals(SmithProxy::instance().terminate_handler_, SmithProxy::instance().reload_handler_);

    //signal(SIGINT, [](int c) { SmithProxy::instance().terminate_flag = true; } );

    Log::get()->events().insert(INF, "... started");

    const unsigned int webhook_ping_interval = 120;
    unsigned int seconds = webhook_ping_interval - 10; // speed-up first ping

    instance().hostname = []() {
        std::array<char,64> h{0};
        gethostname(h.data(),63);
        return std::string(h.data());
    }();

    // initialize boot-time random
    auto* boot_random_ptr = &SmithProxy::boot_random;
    RAND_bytes(reinterpret_cast<unsigned char*>(boot_random_ptr), sizeof(uint32_t));
    // copy value also to static content, for parts where dependency on smithproxy instance is NOT desirable
    StaticContent::boot_random = SmithProxy::boot_random;

    while(true) {
        if(instance().terminate_flag) {
            if(!cfg_daemonize)
                std::cerr << "shutdown requested" << std::endl;
            break;
        }

        if(seconds >= webhook_ping_interval) {

            {
                // refresh enabled status
                auto lc_ = std::scoped_lock(CfgFactory::lock());
                auto const& fac = CfgFactory::get();
                sx::http::webhooks::set_enabled( fac->settings_webhook.enabled);
            }

            seconds = 0;
            sx::http::webhooks::ping();
            sx::webserver::HttpSessions::cleanup();

            state_save();
        }
        ++seconds;

        std::this_thread::sleep_for(std::chrono::seconds(1));

#ifdef ASAN_LEAKS
        // See: https://stackoverflow.com/questions/67705427/how-to-use-asan-on-a-long-time-running-server-program
        // More info in:
        //    https://github.com/llvm-mirror/compiler-rt/blob/master/include/sanitizer/lsan_interface.h
        // Interesting options:
        // ASAN_OPTIONS=halt_on_error=false:alloc_dealloc_mismatch=0:detect_leaks=1:verbose=1 LSAN_OPTIONS=report_objects=1

        if(time(nullptr) % 30 == 0) {
            if(__lsan_do_recoverable_leak_check() == 0) {
                std::cerr << "=== No leaks detected\n";
            }
        }
#endif
    }

    auto bail_it = [this]{
        kill_proxies();
        terminated = true;

        instance().join_all();
    };

    if(not cfg_daemonize) {
        auto counter = std::thread([] {
            timespec t{};
            t.tv_sec = 1;

            while (not SmithProxy::instance().terminated) {
                const unsigned long prsz = MitmProxy::current_sessions().load();
                std::cerr << "  -    proxies remaining: " << prsz << "\n";

                nanosleep(&t, nullptr);
                t.tv_sec = 3;
            }
        });

        bail_it();
        counter.join();

        if (!cfg_daemonize)
            std::cerr << "all master threads terminated" << std::endl;
    }
    else {
        bail_it();
    }
}

void SmithProxy::state_save() const {

    std::string state_dir;
    std::string tenant_name = "default";

    {
        auto fac = CfgFactory::get();
        auto lc_ = std::scoped_lock(fac->lock());
        state_dir = fac->capture_local.dir;
        tenant_name = fac->tenant_name;
    }

    auto nbr_file = string_format("%s/nbr-%s.json", state_dir.c_str(), tenant_name.c_str());

    state_save_neighbors(nbr_file);
}

void SmithProxy::state_save_neighbors(std::string const& fnm) const {
    auto js = NbrHood::instance().ser_json_out();
    auto of = std::ofstream(fnm, std::ios::out);
    if(of.is_open()) {
        of << js.dump(4);
        of.close();
    }
}


bool SmithProxy::state_load() {
    std::string state_dir;
    std::string tenant_name = "default";

    {
        auto fac = CfgFactory::get();
        auto lc_ = std::scoped_lock(fac->lock());
        state_dir = fac->capture_local.dir;
        tenant_name = fac->tenant_name;
    }

    auto nbr_file = string_format("%s/nbr-%s.json", state_dir.c_str(), tenant_name.c_str());
    bool nbr_loaded = state_load_neighbors(nbr_file);

    if(nbr_loaded) {
        return true;
    }

    return false;
}

bool SmithProxy::state_load_neighbors(std::string const& fnm) {

    auto ifs = std::ifstream(fnm);
    try {
        nlohmann::json js = nlohmann::json::parse(ifs);
        NbrHood::instance().ser_json_in(js);

        Log::get()->events().insert(INF, "neighbors file loaded successfully");
        return true;
    }
    catch(nlohmann::json::exception const& e) {
        _err("state_load_neighbors: error: %s", e.what());
        Log::get()->events().insert(ERR, "neighbors file not loaded");
    }
    return false;
}


void SmithProxy::join_all() {

    auto join_thread_list = [](auto thread_list) {
        for(auto const& t: thread_list) {
            if(t and t->joinable()) {
                t->join();
            }
        }
    };

    if(! plain_threads.empty()) {
        if(!cfg_daemonize)
            std::cerr << "terminating tcp thread\r\n" << std::endl;
        join_thread_list(plain_threads);
    }

    if(! ssl_threads.empty()) {
        if(!cfg_daemonize)
            std::cerr << "terminating tls thread" << std::endl;
        join_thread_list(ssl_threads);
    }

    if(! dtls_threads.empty()) {
        if(!cfg_daemonize)
            std::cerr << "terminating dtls thread" << std::endl;
        join_thread_list(dtls_threads);
    }

    if(! udp_threads.empty()) {
        if(!cfg_daemonize)
            std::cerr << "terminating udp thread" << std::endl;
        join_thread_list(udp_threads);
    }

    if(! socks_threads.empty()) {
        if(!cfg_daemonize)
            std::cerr << "terminating tcp socks thread" << std::endl;
        join_thread_list(socks_threads);
    }
    if(! socks_udp_threads.empty()) {
        if(!cfg_daemonize)
            std::cerr << "terminating udp socks thread" << std::endl;
        join_thread_list(socks_udp_threads);
    }


    if(! redir_plain_threads.empty()) {

        if(!cfg_daemonize)
            std::cerr << "terminating redir tcp thread" << std::endl;
        join_thread_list(redir_plain_threads);
    }
    if(! redir_ssl_threads.empty()) {
        if(!cfg_daemonize)
            std::cerr << "terminating redir tls thread" << std::endl;
        join_thread_list(redir_ssl_threads);
    }
    if(! redir_udp_threads.empty()) {
        if(!cfg_daemonize)
            std::cerr << "terminating redir dns thread" << std::endl;
        join_thread_list(redir_udp_threads);
    }
    if(cli_thread) {
        if(!cfg_daemonize)
            std::cerr << "terminating cli server thread" << std::endl;
        if(cli_thread->joinable())
            cli_thread->join();
    }
    if(dns_thread) {
        if(!cfg_daemonize)
            std::cerr << "terminating dns updater thread" << std::endl;

        if(dns_thread->joinable())
            dns_thread->join();
    }
    if(id_thread) {
        if(!cfg_daemonize)
            std::cerr << "terminating identity updater thread" << std::endl;
        if(id_thread->joinable())
            id_thread->join();
    }
    if(api_thread) {
        if(!cfg_daemonize)
            std::cerr << "terminating API updater thread" << std::endl;
        if(api_thread->joinable())
            api_thread->join();
    }

    auto ql = std::dynamic_pointer_cast<QueueLogger>(Log::get());
    if(ql) {
        if(!cfg_daemonize)
            std::cerr << "terminating logwriter thread" << std::endl;
        ql->sig_terminate = true;
        log_thread->join();
    }
    else if(log_thread) {
        if(!cfg_daemonize)
            std::cerr << "terminating logwriter thread (without the cast)" << std::endl;
        log_thread->join();
    }

}

void SmithProxy::kill_proxies() {

    baseCom::poll_msec = 50;
    baseCom::rescan_msec = 50;

    auto kill_proxies = [](auto& proxies) {
        for(auto& p: proxies) {
            if(p) {
                p->state().dead(true);
                p->join_workers();
            }
        }
    };

    kill_proxies(plain_proxies);
    kill_proxies(ssl_proxies);
    kill_proxies(dtls_proxies);
    kill_proxies(udp_proxies);

    kill_proxies(socks_proxies);
    kill_proxies(socks_udp_proxies);


    kill_proxies(redir_plain_proxies);
    kill_proxies(redir_ssl_proxies);
    kill_proxies(redir_udp_proxies);
}

void SmithProxy::stop() {

    terminate_flag = true;

#ifndef MEMPOOL_DISABLE
    memPool::bailing = true;
#endif

    kill_proxies();

    terminated = true;
}


bool SmithProxy::init_syslog() {

    // no server is set, this is not an error
    if(CfgFactory::get()->syslog_server.empty()) return true;

    auto const& log = instance().log;

    AddressInfo ai;
    ai.str_host = CfgFactory::get()->syslog_server;
    ai.port = htons(raw::down_cast_signed<unsigned short>(CfgFactory::get()->syslog_port).value_or(514));
    ai.family = CfgFactory::get()->syslog_family == 6 ? AF_INET6 : AF_INET;
    ai.pack();

    // create UDP socket
    int syslog_socket = socket(ai.family, SOCK_DGRAM, IPPROTO_UDP);

    if(0 != ::connect(syslog_socket,(sockaddr*) ai.as_ss(),sizeof(sockaddr_storage))) {
        _err("cannot connect syslog socket %d: %s", syslog_socket, string_error().c_str());
        ::close(syslog_socket);
    } else {

        Log::get()->remote_targets(string_format("syslog-udp%d-%d", CfgFactory::get()->syslog_family, syslog_socket),
                                   syslog_socket);

        auto lp = std::make_unique<logger_profile>();

        lp->logger_type = logger_profile::REMOTE_SYSLOG;
        lp->level_ = CfgFactory::get()->syslog_level;

        // raising internal logging level
        if (lp->level_ > Log::get()->level()) {
            _not("Internal logging raised from %d to %d due to syslog server loglevel.", Log::get()->level().level(),
                 lp->level_.level());
            Log::get()->level(lp->level_);
        }

        lp->syslog_settings.severity = static_cast<int>(lp->level_.level());
        lp->syslog_settings.facility = CfgFactory::get()->syslog_facility;

        Log::get()->target_profiles()[(uint64_t) syslog_socket] = std::move(lp);
    }

    return true;
}

bool SmithProxy::load_config(std::string& config_f, bool reload) {
    bool ret = true;
    auto this_daemon = DaemonFactory::instance();
    auto const& log = instance().log;

    using namespace libconfig;
    if(! CfgFactory::get()->cfgapi_init(config_f.c_str()) ) {
        _fat("Unable to load config.");
        ret = false;
    }

    CfgFactory::get()->config_file = config_f;

    // Add another level of lock. File is already loaded. We need to apply its content.
    // lock is needed here to not try to match against potentially empty/partial policy list
    std::lock_guard<std::recursive_mutex> l_(CfgFactory::lock());
    try {

        if(reload) {
            CfgFactory::get()->cleanup();
        }
        auto prev_LOAD_ERRORS = CfgFactory::LOAD_ERRORS.load();

        CfgFactory::LOAD_ERRORS = false;
        CfgFactory::get()->load_internal();

        CfgFactory::get()->load_db_address();
        CfgFactory::get()->load_db_port();
        CfgFactory::get()->load_db_proto();
        CfgFactory::get()->load_db_prof_detection();
        CfgFactory::get()->load_db_prof_content();
        CfgFactory::get()->load_db_prof_tls();
        CfgFactory::get()->load_db_prof_alg_dns();
        CfgFactory::get()->load_db_prof_auth();
        CfgFactory::get()->load_db_routing();

        CfgFactory::get()->load_db_features();

        // clean policy list: list behavior, elements are not overwritten, but added
        CfgFactory::get()->cleanup_db_policy();
        CfgFactory::get()->load_db_policy();


        SigFactory::get().signature_tree().reset();
        SigFactory::get().signature_tree().group_add(true);
        SigFactory::get().signature_tree().group_add(true);

        // load starttls signatures into 0 sensor (group)
        CfgFactory::get()->load_signatures(CfgFactory::cfg_obj(), "starttls_signatures", SigFactory::get().signature_tree(), 0);

        // load detection signatures into sensor (group) specified by signature. If none specified, it will be placed into 1 (base group)
        CfgFactory::get()->load_signatures(CfgFactory::cfg_obj(), "detection_signatures", SigFactory::get().signature_tree());

        CfgFactory::get()->load_settings();
        CfgFactory::get()->load_captures();
        CfgFactory::get()->load_debug();

        // don't mess with logging if just reloading
        if(! reload) {


            Log::get()->targets().clear();
            Log::get()->target_names().clear();

            //init crashlog file with dafe default
            this_daemon->set_crashlog("/tmp/smithproxy_crash.log");

            if(load_if_exists(CfgFactory::cfg_root()["settings"], "log_file",CfgFactory::get()->log_file_base)) {

                CfgFactory::get()->log_file = CfgFactory::get()->log_file_base;


                if(! CfgFactory::get()->log_file.empty()) {

                    CfgFactory::get()->log_file = string_format(CfgFactory::get()->log_file.c_str(), CfgFactory::get()->tenant_name.c_str());
                    // prepare custom crashlog file
                    std::string crlog = CfgFactory::get()->log_file + ".crashlog.log";
                    this_daemon->set_crashlog(crlog.c_str());

                    auto* o = new std::ofstream(CfgFactory::get()->log_file.c_str(),std::ios::app);
                    chmod(CfgFactory::get()->log_file.c_str(), 0600);

                    Log::get()->targets(CfgFactory::get()->log_file, o);
                    Log::get()->dup2_cout(false);
                    Log::get()->level(CfgFactory::get()->internal_init_level);

                    auto lp = std::make_unique<logger_profile>();
                    lp->print_srcline_ = Log::get()->print_srcline();
                    lp->print_srcline_always_ = Log::get()->print_srcline_always();
                    lp->level_ = CfgFactory::get()->internal_init_level;
                    Log::get()->target_profiles()[(uint64_t)o] = std::move(lp);

                }
            }
            //
            if(load_if_exists(CfgFactory::cfg_root()["settings"], "sslkeylog_file", CfgFactory::get()->sslkeylog_file_base)) {

                CfgFactory::get()->sslkeylog_file = CfgFactory::get()->sslkeylog_file_base;

                if(! CfgFactory::get()->sslkeylog_file.empty()) {

                    CfgFactory::get()->sslkeylog_file = string_format(CfgFactory::get()->sslkeylog_file.c_str(),
                                                                     CfgFactory::get()->tenant_name.c_str());

                    auto* o = new std::ofstream(CfgFactory::get()->sslkeylog_file.c_str(),std::ios::app);
                    chmod(CfgFactory::get()->sslkeylog_file.c_str(), 0600);

                    Log::get()->targets(CfgFactory::get()->sslkeylog_file, o);
                    Log::get()->dup2_cout(false);
                    Log::get()->level(CfgFactory::get()->internal_init_level);

                    auto lp = std::make_unique<logger_profile>();
                    lp->print_srcline_ = Log::get()->print_srcline();
                    lp->print_srcline_always_ = Log::get()->print_srcline_always();
                    lp->level_ = loglevel(iINF,flag_add(iNOT,CRT|KEYS));
                    Log::get()->target_profiles()[(uint64_t)o] = std::move(lp);

                }
            }


            if(not CfgFactory::get()->syslog_server.empty() ) {
                bool have_syslog = init_syslog();
                if(! have_syslog) {
                    _err("syslog logging not set.");
                }
            }

            if(load_if_exists(CfgFactory::cfg_root()["settings"],"log_console", CfgFactory::get()->log_console)) {
                Log::get()->dup2_cout(CfgFactory::get()->log_console);
            }
        }

        if(prev_LOAD_ERRORS and not CfgFactory::LOAD_ERRORS) {
            Log::get()->events().insert(NOT,"Configuration errors have been resolved.");
        }
    }
    catch(const SettingNotFoundException &nfex) {

        _fat("Setting not found: %s",nfex.getPath());
        ret = false;
    }

    return ret;
}


