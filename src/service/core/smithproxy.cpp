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
#include <service/core/smithproxy.hpp>
#include <cmd/cmdserver.hpp>
#include <cmd/clistate.hpp>
#include <policy/authfactory.hpp>
#include <inspect/sigfactory.hpp>
#include <cfgapi.hpp>

SmithProxy::~SmithProxy () {

    memPool::bailing = true;
}

void SmithProxy::reload() {
    _war("reloading configuration (excluding signatures)");
    SmithProxy::instance().load_config(CfgFactory::get().config_file,true);
    _dia("USR1 signal handler finished");
}


std::thread* SmithProxy::create_identity_refresh_thread() {


    auto* id_thread = new std::thread([]() {
        auto& log = instance().log;

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
                                                                    CfgFactory::get().tenant_index).c_str());
    }
}


bool SmithProxy::create_listeners() {

    bool success = false;

    try {

        if(CfgFactory::get().accept_tproxy) {
            plain_proxies = NetworkServiceFactory::prepare_listener<theAcceptor, TCPCom>(
                    std::stoi(CfgFactory::get().listen_tcp_port),
                    "plain-tcp",
                    CfgFactory::get().num_workers_tcp,
                    proxyType::transparent());

            ssl_proxies = NetworkServiceFactory::prepare_listener<theAcceptor, MySSLMitmCom>(
                    std::stoi(CfgFactory::get().listen_tls_port),
                    "tls",
                    CfgFactory::get().num_workers_tls,
                    proxyType::transparent());

            dtls_proxies = NetworkServiceFactory::prepare_listener<theReceiver, MyDTLSMitmCom>(
                    std::stoi(CfgFactory::get().listen_dtls_port),
                    "dtls",
                    CfgFactory::get().num_workers_dtls,
                    proxyType::transparent());

            udp_proxies = NetworkServiceFactory::prepare_listener<theReceiver, UDPCom>(
                    std::stoi(CfgFactory::get().listen_udp_port),
                    "udp",
                    CfgFactory::get().num_workers_udp,
                    proxyType::transparent());

            if ((plain_proxies.empty() && CfgFactory::get().num_workers_tcp >= 0) ||
                (ssl_proxies.empty() && CfgFactory::get().num_workers_tls >= 0) ||
                (dtls_proxies.empty() && CfgFactory::get().num_workers_dtls >= 0) ||
                (udp_proxies.empty() && CfgFactory::get().num_workers_udp >= 0)) {

                _fat("Failed to setup tproxy proxies. Bailing!");
                exit(-10);
            }

        }

        if(CfgFactory::get().accept_socks) {
            socks_proxies = NetworkServiceFactory::prepare_listener<socksAcceptor, socksTCPCom>(
                    std::stoi(CfgFactory::get().listen_socks_port),
                    "socks",
                    CfgFactory::get().num_workers_socks,
                    proxyType::proxy());

            if((socks_proxies.empty() && CfgFactory::get().num_workers_socks >= 0)) {
                _fat("Failed to setup socks proxies. Bailing!");
                exit(-11);
            }
        }

        if(CfgFactory::get().accept_redirect) {
            redir_plain_proxies = NetworkServiceFactory::prepare_listener<theAcceptor, TCPCom>(
                    std::stoi(CfgFactory::get().listen_tcp_port) + 1000,
                    "plain-rdr",
                    CfgFactory::get().num_workers_tcp,
                    proxyType::redirect());
            redir_ssl_proxies = NetworkServiceFactory::prepare_listener<theAcceptor, MySSLMitmCom>(
                    std::stoi(CfgFactory::get().listen_tls_port) + 1000,
                    "ssl-rdr",
                    CfgFactory::get().num_workers_tls,
                    proxyType::redirect());

            redir_udp_proxies = NetworkServiceFactory::prepare_listener<theReceiver, UDPCom>(
                    std::stoi(CfgFactory::get().listen_udp_port) +
                    973,  // 973 + default 50080 = 51053: should suggest DNS only
                    "udp-rdr",
                    CfgFactory::get().num_workers_udp,
                    proxyType::redirect());

            if((redir_plain_proxies.empty() && CfgFactory::get().num_workers_tcp >= 0) ||
               (redir_ssl_proxies.empty() && CfgFactory::get().num_workers_tls >= 0) ||
               (redir_udp_proxies.empty() && CfgFactory::get().num_workers_udp >= 0)) {

                if((socks_proxies.empty() && CfgFactory::get().num_workers_socks >= 0)) {
                    _fat("Failed to setup redirect proxies. Bailing!");
                    exit(-12);
                }
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

    std::string friendly_thread_name_tcp = string_format("sxy_tcp_%d",CfgFactory::get().tenant_index);
    std::string friendly_thread_name_udp = string_format("sxy_udp_%d",CfgFactory::get().tenant_index);
    std::string friendly_thread_name_tls = string_format("sxy_tls_%d",CfgFactory::get().tenant_index);
    std::string friendly_thread_name_dls = string_format("sxy_dls_%d",CfgFactory::get().tenant_index);
    std::string friendly_thread_name_skx = string_format("sxy_skx_%d",CfgFactory::get().tenant_index);
    std::string friendly_thread_name_cli = string_format("sxy_cli_%d",CfgFactory::get().tenant_index);
    std::string friendly_thread_name_own = string_format("sxy_own_%d",CfgFactory::get().tenant_index);

    std::string friendly_thread_name_redir_tcp = string_format("sxy_rdt_%d",CfgFactory::get().tenant_index);
    std::string friendly_thread_name_redir_ssl = string_format("sxy_rds_%d",CfgFactory::get().tenant_index);
    std::string friendly_thread_name_redir_udp = string_format("sxy_rdu_%d",CfgFactory::get().tenant_index);


    // cli_loop uses select :(
    cli_thread = std::make_shared<std::thread>([] () {
        CRYPTO_set_mem_functions( mempool_alloc, mempool_realloc, mempool_free);

        auto& this_daemon = DaemonFactory::instance();
        auto& log = this_daemon.log;

        _inf("Starting CLI");
        DaemonFactory::set_daemon_signals(SmithProxy::instance().terminate_handler_, SmithProxy::instance().reload_handler_);
        _dia("smithproxy_cli: max file descriptors: %d", this_daemon.get_limit_fd());

        cli_loop(CliState::get().cli_port);
        _dia("cli workers torn down.");
    } );
    pthread_setname_np(cli_thread->native_handle(),friendly_thread_name_cli.c_str());


    auto launch_proxy_threads = [&](auto &proxies, auto& thread_list, const char* log_friendly, const char* thread_friendly) {
        for(auto proxy: proxies) {
            _inf("Starting: %s", log_friendly);

            // taking proxy as a value!
            auto a_thread = std::make_shared<std::thread>([proxy]() {
                CRYPTO_set_mem_functions( mempool_alloc, mempool_realloc, mempool_free);

                auto& this_daemon = DaemonFactory::instance();
                auto& log = this_daemon.log;

                DaemonFactory::set_daemon_signals(SmithProxy::instance().terminate_handler_, SmithProxy::instance().reload_handler_);
                _dia("TCP listener: max file descriptors: %d", this_daemon.get_limit_fd());

                proxy->run();
                _dia("TCP listener: workers torn down.");
                proxy->shutdown();
            } );
            pthread_setname_np(a_thread->native_handle(),thread_friendly);
            thread_list.push_back(a_thread);
        }
    };


    if(CfgFactory::get().accept_tproxy) {
        launch_proxy_threads(plain_proxies, plain_threads, "TCP listener", friendly_thread_name_tcp.c_str());
        launch_proxy_threads(ssl_proxies, ssl_threads, "TLS listener", friendly_thread_name_tls.c_str());
        launch_proxy_threads(dtls_proxies, dtls_threads, "DTLS listener", friendly_thread_name_dls.c_str());
        launch_proxy_threads(udp_proxies, udp_threads, "UDP listener", friendly_thread_name_udp.c_str());
    }

    if(CfgFactory::get().accept_socks) {
        launch_proxy_threads(socks_proxies, socks_threads, "SOCKS listener", friendly_thread_name_skx.c_str());
    }

    if(CfgFactory::get().accept_redirect) {
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

    while(true) {
        if(instance().terminate_flag) {
            if(!cfg_daemonize)
                std::cerr << "shutdown requested" << std::endl;
            break;
        }

        std::this_thread::sleep_for(std::chrono::seconds(1));
    }

    instance().join_all();

    if(!cfg_daemonize)
        std::cerr << "all master threads terminated" << std::endl;
}

void SmithProxy::join_all() {

    auto join_thread_list = [](auto thread_list) {
        for(auto const& t: thread_list) {
            if(t) {
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
            std::cerr << "terminating socks thread" << std::endl;
        join_thread_list(socks_threads);
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
        cli_thread->join();
    }
    if(dns_thread) {
        if(!cfg_daemonize)
            std::cerr << "terminating dns updater thread" << std::endl;
        dns_thread->join();
    }
    if(id_thread) {
        if(!cfg_daemonize)
            std::cerr << "terminating identity updater thread" << std::endl;
        id_thread->join();
    }

    auto ql = std::dynamic_pointer_cast<QueueLogger>(LogOutput::get());
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

void SmithProxy::stop() {

    terminate_flag = true;
    memPool::pool().bailing = true;

    auto kill_proxies = [](auto proxies) {
        for(auto p: proxies) {
            p->state().dead(true);
        }
    };

    kill_proxies(plain_proxies);
    kill_proxies(ssl_proxies);
    kill_proxies(dtls_proxies);
    kill_proxies(udp_proxies);

    kill_proxies(socks_proxies);


    kill_proxies(redir_plain_proxies);
    kill_proxies(redir_ssl_proxies);
    kill_proxies(redir_udp_proxies);
}


int SmithProxy::load_signatures(libconfig::Config& cfg, const char* name, std::vector<std::shared_ptr<duplexFlowMatch>>& target) {

    auto& log = instance().log;

    using namespace libconfig;

    const Setting& root = cfg.getRoot();
    const Setting& cfg_signatures = root[name];
    int sigs_len = cfg_signatures.getLength();


    if(! target.empty()) {
        _dia("Clearing %s, size %d", name, target.size());
        target.clear();
    }

    _dia("Loading %s: %d", name, sigs_len);
    for ( int i = 0 ; i < sigs_len; i++) {
        auto newsig = std::make_shared<MyDuplexFlowMatch>(MyDuplexFlowMatch());


        const Setting& signature = cfg_signatures[i];
        load_if_exists(signature, "name", newsig->name());
        load_if_exists(signature, "side", newsig->sig_side);
        load_if_exists(signature, "cat", newsig->category);
        load_if_exists(signature, "severity", newsig->severity);

        const Setting& signature_flow = cfg_signatures[i]["flow"];
        int flow_count = signature_flow.getLength();

        _dia("Loading signature '%s' with %d flow matches",newsig->name().c_str(),flow_count);


        for ( int j = 0; j < flow_count; j++ ) {

            std::string side;
            std::string type;
            std::string sigtext;
            int bytes_start;
            int bytes_max;

            if(!( load_if_exists(signature_flow[j], "side", side)
                 && load_if_exists(signature_flow[j], "type", type)
                 && load_if_exists(signature_flow[j], "signature", sigtext)
                 && load_if_exists(signature_flow[j], "bytes_start", bytes_start)
                 && load_if_exists(signature_flow[j], "bytes_max", bytes_max))) {

                _war("Starttls signature %s properties failed to load: index %d",newsig->name().c_str(), i);
                continue;
            }

            if( type == "regex") {
                _deb(" [%d]: new regex flow match",j);
                try {
                    newsig->add(side[0], new regexMatch(sigtext, bytes_start, bytes_max));
                } catch(std::regex_error const& e) {

                    _err("Starttls signature %s regex failed to load: index %d, load aborted", newsig->name().c_str() , i);

                    newsig = nullptr;
                    break;
                }
            } else
            if ( type == "simple") {
                _deb(" [%d]: new simple flow match", j);
                newsig->add(side[0],new simpleMatch(sigtext,bytes_start,bytes_max));
            }
        }

        // load if not set to null due to loading error
        if(newsig)
            target.push_back(newsig);
    }

    return sigs_len;
}

bool SmithProxy::init_syslog() {

    auto& log = instance().log;

    // create UDP socket
    int syslog_socket = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);

    struct sockaddr_storage syslog_in {0};
    memset(&syslog_in, 0, sizeof(struct sockaddr_storage));

    if(CfgFactory::get().syslog_family != 6) {
        CfgFactory::get().syslog_family = 4;
        syslog_in.ss_family                = AF_INET;
        ((sockaddr_in*)&syslog_in)->sin_addr.s_addr = inet_addr(CfgFactory::get().syslog_server.c_str());
        if(((sockaddr_in*)&syslog_in)->sin_addr.s_addr == INADDR_NONE) {
            _err("Error initializing syslog server: %s", CfgFactory::get().syslog_server.c_str());
            ::close(syslog_socket); // coverity: 1407945
            return false;
        }

        ((sockaddr_in*)&syslog_in)->sin_port = htons(CfgFactory::get().syslog_port);
    } else {
        CfgFactory::get().syslog_family = 6;
        syslog_in.ss_family                = AF_INET6;
        int ret = inet_pton(AF_INET6, CfgFactory::get().syslog_server.c_str(),(unsigned char*)&((sockaddr_in6*)&syslog_in)->sin6_addr.s6_addr);
        if(ret <= 0) {
            _err("Error initializing syslog server: %s", CfgFactory::get().syslog_server.c_str());

            ::close(syslog_socket); // coverity: 1407945
            return false;
        }
        ((sockaddr_in6*)&syslog_in)->sin6_port = htons(CfgFactory::get().syslog_port);
    }


    if(0 != ::connect(syslog_socket,(sockaddr*)&syslog_in,sizeof(sockaddr_storage))) {
        _err("cannot connect syslog socket %d: %s", syslog_socket, string_error().c_str());
        ::close(syslog_socket);
    } else {

        LogOutput::get()->remote_targets(string_format("syslog-udp%d-%d", CfgFactory::get().syslog_family, syslog_socket),
                                         syslog_socket);

        auto *lp = new logger_profile();

        lp->logger_type = logger_profile::REMOTE_SYSLOG;
        lp->level_ = CfgFactory::get().syslog_level;

        // raising internal logging level
        if (lp->level_ > LogOutput::get()->level()) {
            _not("Internal logging raised from %d to %d due to syslog server loglevel.", LogOutput::get()->level().level(),
                 lp->level_.level());
            LogOutput::get()->level(lp->level_);
        }

        lp->syslog_settings.severity = static_cast<int>(lp->level_.level());
        lp->syslog_settings.facility = CfgFactory::get().syslog_facility;

        LogOutput::get()->target_profiles()[(uint64_t) syslog_socket] = lp;
    }

    return true;
}

bool SmithProxy::load_config(std::string& config_f, bool reload) {
    bool ret = true;
    auto& this_daemon = DaemonFactory::instance();
    auto& log = instance().log;

    using namespace libconfig;
    if(! CfgFactory::get().cfgapi_init(config_f.c_str()) ) {
        _fat("Unable to load config.");
        ret = false;
    }

    CfgFactory::get().config_file = config_f;

    // Add another level of lock. File is already loaded. We need to apply its content.
    // lock is needed here to not try to match against potentially empty/partial policy list
    std::lock_guard<std::recursive_mutex> l_(CfgFactory::lock());
    try {

        if(reload) {
            CfgFactory::get().cleanup();
        }

        CfgFactory::get().load_db_address();
        CfgFactory::get().load_db_port();
        CfgFactory::get().load_db_proto();
        CfgFactory::get().load_db_prof_detection();
        CfgFactory::get().load_db_prof_content();
        CfgFactory::get().load_db_prof_tls();
        CfgFactory::get().load_db_prof_alg_dns();
        CfgFactory::get().load_db_prof_auth();

        CfgFactory::get().load_db_policy();


        load_signatures(CfgFactory::cfg_obj(),"detection_signatures", SigFactory::get().detection());
        load_signatures(CfgFactory::cfg_obj(),"starttls_signatures", SigFactory::get().tls());

        CfgFactory::get().load_settings();
        CfgFactory::get().load_debug();

        // initialize stubborn logans :)
        auto _ = inet::Factory::log();


        // don't mess with logging if just reloading
        if(! reload) {


            //init crashlog file with dafe default
            this_daemon.set_crashlog("/tmp/smithproxy_crash.log");

            if(load_if_exists(CfgFactory::cfg_root()["settings"], "log_file",CfgFactory::get().log_file_base)) {

                CfgFactory::get().log_file = CfgFactory::get().log_file_base;


                if(! CfgFactory::get().log_file.empty()) {

                    CfgFactory::get().log_file = string_format(CfgFactory::get().log_file.c_str(), CfgFactory::get().tenant_name.c_str());
                    // prepare custom crashlog file
                    std::string crlog = CfgFactory::get().log_file + ".crashlog.log";
                    this_daemon.set_crashlog(crlog.c_str());

                    auto* o = new std::ofstream(CfgFactory::get().log_file.c_str(),std::ios::app);
                    LogOutput::get()->targets(CfgFactory::get().log_file, o);
                    LogOutput::get()->dup2_cout(false);
                    LogOutput::get()->level(CfgFactory::get().internal_init_level);

                    auto* lp = new logger_profile();
                    lp->print_srcline_ = LogOutput::get()->print_srcline();
                    lp->print_srcline_always_ = LogOutput::get()->print_srcline_always();
                    lp->level_ = CfgFactory::get().internal_init_level;
                    LogOutput::get()->target_profiles()[(uint64_t)o] = lp;

                }
            }
            //
            if(load_if_exists(CfgFactory::cfg_root()["settings"], "sslkeylog_file", CfgFactory::get().sslkeylog_file_base)) {

                CfgFactory::get().sslkeylog_file = CfgFactory::get().sslkeylog_file_base;

                if(! CfgFactory::get().sslkeylog_file.empty()) {

                    CfgFactory::get().sslkeylog_file = string_format(CfgFactory::get().sslkeylog_file.c_str(),
                                                                     CfgFactory::get().tenant_name.c_str());

                    auto* o = new std::ofstream(CfgFactory::get().sslkeylog_file.c_str(),std::ios::app);
                    LogOutput::get()->targets(CfgFactory::get().sslkeylog_file, o);
                    LogOutput::get()->dup2_cout(false);
                    LogOutput::get()->level(CfgFactory::get().internal_init_level);

                    auto* lp = new logger_profile();
                    lp->print_srcline_ = LogOutput::get()->print_srcline();
                    lp->print_srcline_always_ = LogOutput::get()->print_srcline_always();
                    lp->level_ = loglevel(iINF,flag_add(iNOT,CRT|KEYS));
                    LogOutput::get()->target_profiles()[(uint64_t)o] = lp;

                }
            }


            if( ! CfgFactory::get().syslog_server.empty() ) {
                bool have_syslog = init_syslog();
                if(! have_syslog) {
                    _err("syslog logging not set.");
                }
            }

            if(load_if_exists(CfgFactory::cfg_root()["settings"],"log_console", CfgFactory::get().log_console)) {
                LogOutput::get()->dup2_cout(CfgFactory::get().log_console);
            }
        }
    }
    catch(const SettingNotFoundException &nfex) {

        _fat("Setting not found: %s",nfex.getPath());
        ret = false;
    }

    return ret;
}


