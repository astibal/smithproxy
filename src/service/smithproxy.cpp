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

#include <service/smithproxy.hpp>
#include <cli/cmdserver.hpp>
#include <policy/authfactory.hpp>
#include <inspect/sigfactory.hpp>

volatile int SmithProxy::cnt_terminate = 0;



SmithProxy::~SmithProxy () {

    delete plain_thread;
    delete ssl_thread;
    delete dtls_thread;
    delete udp_thread;
    delete socks_thread;


    delete dns_thread;
    delete id_thread;

    delete log_thread;
}


std::thread* SmithProxy::create_identity_refresh_thread() {


     auto* id_thread = new std::thread([]() {
        unsigned int sleep_time = 1;
        auto& log = instance().log;

        // give some time to init shm - don't run immediately
        // this is workaround for rare(?) race condition when shm is not
        // initialized yet.

        ::sleep(20);

        for (unsigned i = 0; ; i++) {

            _deb("id_thread: refreshing identities");

            AuthFactory::get().shm_ip4_table_refresh();
            AuthFactory::get().shm_ip6_table_refresh();
            AuthFactory::get().shm_token_table_refresh();

            _dum("id_thread: finished");

            ::sleep(sleep_time);
        }
    });

    return id_thread;
};



void SmithProxy::create_log_writer_thread() {
    // we have to create logger after daemonize is called
    log_thread  = create_log_writer(get_logger());
    if(log_thread != nullptr) {
        pthread_setname_np( log_thread->native_handle(), string_format("sxy_lwr_%d", tenant_index()).c_str());
    }
}


void SmithProxy::create_dns_thread() {
    dns_thread = create_dns_updater();
    if(dns_thread != nullptr) {
        pthread_setname_np( dns_thread->native_handle(),
                            string_format("sxy_dns_%d",tenant_index()).c_str());
    }
}

void SmithProxy::create_identity_thread() {
    id_thread = create_identity_refresh_thread();
    if(id_thread != nullptr) {
        pthread_setname_np(id_thread->native_handle(),string_format("sxy_idu_%d",
                                                                    CfgFactory::get().tenant_index).c_str());
    }
}


void SmithProxy::create_listeners() {
    plain_proxy = ServiceFactory::prepare_listener<theAcceptor, TCPCom>(std::stoi(CfgFactory::get().listen_tcp_port),
                                                                        "plain-tcp",
                                                                        CfgFactory::get().num_workers_tcp,
                                                                        ServiceFactory::proxy_type::TRANSPARENT);

    ssl_proxy = ServiceFactory::prepare_listener<theAcceptor, MySSLMitmCom>(
            std::stoi(CfgFactory::get().listen_tls_port),
            "tls",
            CfgFactory::get().num_workers_tls,
            ServiceFactory::proxy_type::TRANSPARENT);

    dtls_proxy = ServiceFactory::prepare_listener<theReceiver, MyDTLSMitmCom>(
            std::stoi(CfgFactory::get().listen_dtls_port),
            "dtls",
            CfgFactory::get().num_workers_dtls,
            ServiceFactory::proxy_type::TRANSPARENT);

    udp_proxy = ServiceFactory::prepare_listener<theReceiver, UDPCom>(std::stoi(CfgFactory::get().listen_udp_port),
                                                                      "udp",
                                                                      CfgFactory::get().num_workers_udp,
                                                                      ServiceFactory::proxy_type::TRANSPARENT);

    socks_proxy = ServiceFactory::prepare_listener<socksAcceptor, socksTCPCom>(
            std::stoi(CfgFactory::get().listen_socks_port),
            "socks",
            CfgFactory::get().num_workers_socks,
            ServiceFactory::proxy_type::PROXY);

    redir_plain_proxy = ServiceFactory::prepare_listener<theAcceptor, TCPCom>(
            std::stoi(CfgFactory::get().listen_tcp_port) + 1000,
            "plain-rdr",
            CfgFactory::get().num_workers_tcp,
            ServiceFactory::proxy_type::REDIRECT);
    redir_ssl_proxy = ServiceFactory::prepare_listener<theAcceptor, MySSLMitmCom>(
            std::stoi(CfgFactory::get().listen_tls_port) + 1000,
            "ssl-rdr",
            CfgFactory::get().num_workers_tcp,
            ServiceFactory::proxy_type::REDIRECT);

    redir_udp_proxy = ServiceFactory::prepare_listener<theReceiver, UDPCom>(
            std::stoi(CfgFactory::get().listen_udp_port) + 973,  // 973 + default 50080 = 51053: should suggest DNS only
            "udp-rdr",
            CfgFactory::get().num_workers_udp,
            ServiceFactory::proxy_type::REDIRECT);


    if ((plain_proxy == nullptr && CfgFactory::get().num_workers_tcp >= 0) ||
        (ssl_proxy == nullptr && CfgFactory::get().num_workers_tls >= 0) ||
        (dtls_proxy == nullptr && CfgFactory::get().num_workers_dtls >= 0) ||
        (udp_proxy == nullptr && CfgFactory::get().num_workers_udp >= 0) ||
        (socks_proxy == nullptr && CfgFactory::get().num_workers_socks >= 0) ||
        (redir_plain_proxy == nullptr && CfgFactory::get().num_workers_tcp >= 0) ||
        (redir_ssl_proxy == nullptr && CfgFactory::get().num_workers_tls >= 0) ||
        (redir_udp_proxy == nullptr && CfgFactory::get().num_workers_udp >= 0)
       ) {

        _fat("Failed to setup proxies. Bailing!");
        exit(-1);
    }
}

void SmithProxy::run() {

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

    if(plain_proxy) {
        _inf("Starting TCP listener");
        plain_thread = new std::thread([]() {
            auto this_daemon = DaemonFactory::instance();
            auto& log = this_daemon.log;

            this_daemon.set_daemon_signals(SmithProxy::instance().terminate_handler_, SmithProxy::instance().reload_handler_);
            _dia("smithproxy_tcp: max file descriptors: %d", this_daemon.get_limit_fd());

            SmithProxy::instance().plain_proxy->run();
            _dia("plaintext workers torn down.");
            SmithProxy::instance().plain_proxy->shutdown();
        } );
        pthread_setname_np(plain_thread->native_handle(),friendly_thread_name_tcp.c_str());
    }

    if(ssl_proxy) {
        _inf("Starting TLS listener");
        ssl_thread = new std::thread([] () {
            auto this_daemon = DaemonFactory::instance();
            auto& log = this_daemon.log;

            this_daemon.set_daemon_signals(SmithProxy::instance().terminate_handler_, SmithProxy::instance().reload_handler_);
            this_daemon.set_limit_fd(0);
            _dia("smithproxy_tls: max file descriptors: %d", this_daemon.get_limit_fd());

            SmithProxy::instance().ssl_proxy->run();
            _dia("ssl workers torn down.");
            SmithProxy::instance().ssl_proxy->shutdown();
        } );
        pthread_setname_np(ssl_thread->native_handle(),friendly_thread_name_tls.c_str());
    }

    if(dtls_proxy) {
        _inf("Starting DTLS listener");
        dtls_thread = new std::thread([] () {
            auto this_daemon = DaemonFactory::instance();
            auto& log = this_daemon.log;

            this_daemon.set_daemon_signals(SmithProxy::instance().terminate_handler_, SmithProxy::instance().reload_handler_);
            this_daemon.set_limit_fd(0);
            _dia("smithproxy_tls: max file descriptors: %d", this_daemon.get_limit_fd());

            SmithProxy::instance().dtls_proxy->run();
            _dia("dtls workers torn down.");
            SmithProxy::instance().dtls_proxy->shutdown();
        } );
        pthread_setname_np(dtls_thread->native_handle(),friendly_thread_name_dls.c_str());
    }

    if(udp_proxy) {

        udp_proxy->set_quick_list(&CfgFactory::get().db_udp_quick_ports);

        _inf("Starting UDP listener");
        udp_thread = new std::thread([] () {
            auto this_daemon = DaemonFactory::instance();
            auto& log = this_daemon.log;

            this_daemon.set_daemon_signals(SmithProxy::instance().terminate_handler_, SmithProxy::instance().reload_handler_);
            this_daemon.set_limit_fd(0);
            _dia("smithproxy_udp: max file descriptors: %d", this_daemon.get_limit_fd());

            SmithProxy::instance().udp_proxy->run();
            _dia("udp workers torn down.");
            SmithProxy::instance().udp_proxy->shutdown();
        } );
        pthread_setname_np(udp_thread->native_handle(),friendly_thread_name_udp.c_str());
    }

    if(socks_proxy) {
        _inf("Starting SOCKS5 listener");
        socks_thread = new std::thread([] () {
            auto this_daemon = DaemonFactory::instance();
            auto& log = this_daemon.log;

            this_daemon.set_daemon_signals(SmithProxy::instance().terminate_handler_, SmithProxy::instance().reload_handler_);
            this_daemon.set_limit_fd(0);
            _dia("smithproxy_skx: max file descriptors: %d", this_daemon.get_limit_fd());

            SmithProxy::instance().socks_proxy->run();
            _dia("socks workers torn down.");
            SmithProxy::instance().socks_proxy->shutdown();
        } );
        pthread_setname_np(socks_thread->native_handle(),friendly_thread_name_skx.c_str());
    }

    if(redir_plain_proxy) {
        _inf("Starting REDIR-TCP listener");
        redir_plain_thread = new std::thread([] () {
            auto this_daemon = DaemonFactory::instance();
            auto& log = this_daemon.log;

            this_daemon.set_daemon_signals(SmithProxy::instance().terminate_handler_, SmithProxy::instance().reload_handler_);
            this_daemon.set_limit_fd(0);
            _dia("smithproxy_redir_plain: max file descriptors: %d", this_daemon.get_limit_fd());

            SmithProxy::instance().redir_plain_proxy->run();
            _dia("redir-plain workers torn down.");
            SmithProxy::instance().redir_plain_proxy->shutdown();
        } );
        pthread_setname_np(redir_plain_thread->native_handle(),friendly_thread_name_redir_tcp.c_str());
    }

    if(redir_ssl_proxy) {
        _inf("Starting REDIR-SSL listener");
        redir_ssl_thread = new std::thread([] () {
            auto this_daemon = DaemonFactory::instance();
            auto& log = this_daemon.log;

            this_daemon.set_daemon_signals(SmithProxy::instance().terminate_handler_, SmithProxy::instance().reload_handler_);
            this_daemon.set_limit_fd(0);
            _dia("smithproxy_redir_ssl: max file descriptors: %d", this_daemon.get_limit_fd());

            SmithProxy::instance().redir_ssl_proxy->run();
            _dia("redir-ssl workers torn down.");
            SmithProxy::instance().redir_ssl_proxy->shutdown();
        } );
        pthread_setname_np(redir_ssl_thread->native_handle(),friendly_thread_name_redir_ssl.c_str());
    }

    if(redir_udp_proxy) {
        _inf("Starting REDIR-UDP listener");
        redir_udp_thread = new std::thread([] () {
            auto this_daemon = DaemonFactory::instance();
            auto& log = this_daemon.log;

            this_daemon.set_daemon_signals(SmithProxy::instance().terminate_handler_, SmithProxy::instance().reload_handler_);
            this_daemon.set_limit_fd(0);
            _dia("smithproxy_redir_udp: max file descriptors: %d", this_daemon.get_limit_fd());

            SmithProxy::instance().redir_udp_proxy->run();
            _dia("redir-udp workers torn down.");
            SmithProxy::instance().redir_udp_proxy->shutdown();
        } );
        pthread_setname_np(redir_udp_thread->native_handle(),friendly_thread_name_redir_udp.c_str());
    }

    cli_thread = new std::thread([] () {
        auto this_daemon = DaemonFactory::instance();
        auto& log = this_daemon.log;

        _inf("Starting CLI");
        this_daemon.set_daemon_signals(SmithProxy::instance().terminate_handler_, SmithProxy::instance().reload_handler_);
        _dia("smithproxy_cli: max file descriptors: %d", this_daemon.get_limit_fd());

        cli_loop(CliState::get().cli_port);
        _dia("cli workers torn down.");
    } );
    pthread_setname_np(cli_thread->native_handle(),friendly_thread_name_cli.c_str());


    pthread_setname_np(pthread_self(),friendly_thread_name_own.c_str());

    if(plain_thread) {
        plain_thread->join();
    }
    if(ssl_thread) {
        ssl_thread->join();
    }
    if(dtls_thread) {
        dtls_thread->join();
    }
    if(udp_thread) {
        udp_thread->join();
    }
    if(socks_thread) {
        socks_thread->join();
    }
    auto* ql = dynamic_cast<QueueLogger*>(get_logger());
    if(ql) {
        ql->sig_terminate = true;
        log_thread->join();
    }
}

void SmithProxy::stop() {
    if (plain_proxy != nullptr) {
        plain_proxy->state().dead(true);
    }
    if(ssl_proxy != nullptr) {
        ssl_proxy->state().dead(true);

    }
    if(dtls_proxy != nullptr) {
        dtls_proxy->state().dead(true);
    }
    if(udp_proxy != nullptr) {
        udp_proxy->state().dead(true);

    }
    if(socks_proxy != nullptr) {
        socks_proxy->state().dead(true);
    }
}


void SmithProxy::my_terminate (int param) {

    auto& log = instance().log;

    if (! instance().cfg_daemonize )
        _err("Terminating ...\n");

    SmithProxy::instance().stop();

    cnt_terminate++;
    if(cnt_terminate == 3) {
        if (!instance().cfg_daemonize )
            _fat("Failed to terminate gracefully. Next attempt will be enforced.\n");
    }
    if(cnt_terminate > 3) {
        if (! instance().cfg_daemonize )
            _fat("Enforced exit.\n");
        abort();
    }
}


void SmithProxy::my_usr1 (int param) {
    auto& log = instance().log;

    _dia("USR1 signal handler started (param %d)", param);
    _war("reloading configuration (excluding signatures)");
    SmithProxy::instance().load_config(CfgFactory::get().config_file,true);
    _dia("USR1 signal handler finished");
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

    _dia("Loading %s: %d",name,sigs_len);
    for ( int i = 0 ; i < sigs_len; i++) {
        auto newsig = std::make_shared<MyDuplexFlowMatch>(MyDuplexFlowMatch());


        const Setting& signature = cfg_signatures[i];
        signature.lookupValue("name", newsig->name());
        signature.lookupValue("side", newsig->sig_side);
        signature.lookupValue("cat", newsig->category);
        signature.lookupValue("severity", newsig->severity);

        const Setting& signature_flow = cfg_signatures[i]["flow"];
        int flow_count = signature_flow.getLength();

        _dia("Loading signature '%s' with %d flow matches",newsig->name().c_str(),flow_count);


        for ( int j = 0; j < flow_count; j++ ) {

            std::string side;
            std::string type;
            std::string sigtext;
            int bytes_start;
            int bytes_max;

            if(!(signature_flow[j].lookupValue("side", side)
                 && signature_flow[j].lookupValue("type", type)
                 && signature_flow[j].lookupValue("signature", sigtext)
                 && signature_flow[j].lookupValue("bytes_start", bytes_start)
                 && signature_flow[j].lookupValue("bytes_max", bytes_max))) {

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
                _deb(" [%d]: new simple flow match",j);
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

        get_logger()->remote_targets(string_format("syslog-udp%d-%d", CfgFactory::get().syslog_family, syslog_socket),
                                     syslog_socket);

        auto *lp = new logger_profile();

        lp->logger_type = logger_profile::REMOTE_SYSLOG;
        lp->level_ = CfgFactory::get().syslog_level;

        // raising internal logging level
        if (lp->level_ > get_logger()->level()) {
            _not("Internal logging raised from %d to %d due to syslog server loglevel.", get_logger()->level(),
                 lp->level_);
            get_logger()->level(lp->level_);
        }

        lp->syslog_settings.severity = static_cast<int>(lp->level_.level());
        lp->syslog_settings.facility = CfgFactory::get().syslog_facility;

        get_logger()->target_profiles()[(uint64_t) syslog_socket] = lp;
    }

    return true;
}

bool SmithProxy::load_config(std::string& config_f, bool reload) {
    bool ret = true;
    auto this_daemon = DaemonFactory::instance();
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
            CfgFactory::get().cfgapi_cleanup();
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

            if(CfgFactory::cfg_root()["settings"].lookupValue("log_file",CfgFactory::get().log_file_base)) {

                CfgFactory::get().log_file = CfgFactory::get().log_file_base;


                if(! CfgFactory::get().log_file.empty()) {

                    CfgFactory::get().log_file = string_format(CfgFactory::get().log_file.c_str(), CfgFactory::get().tenant_name.c_str());
                    // prepare custom crashlog file
                    std::string crlog = CfgFactory::get().log_file + ".crashlog.log";
                    this_daemon.set_crashlog(crlog.c_str());

                    auto* o = new std::ofstream(CfgFactory::get().log_file.c_str(),std::ios::app);
                    get_logger()->targets(CfgFactory::get().log_file, o);
                    get_logger()->dup2_cout(false);
                    get_logger()->level(cfgapi_table.logging.level);

                    auto* lp = new logger_profile();
                    lp->print_srcline_ = get_logger()->print_srcline();
                    lp->print_srcline_always_ = get_logger()->print_srcline_always();
                    lp->level_ = cfgapi_table.logging.level;
                    get_logger()->target_profiles()[(uint64_t)o] = lp;

                }
            }
            //
            if(CfgFactory::cfg_root()["settings"].lookupValue("sslkeylog_file", CfgFactory::get().sslkeylog_file_base)) {

                CfgFactory::get().sslkeylog_file = CfgFactory::get().sslkeylog_file_base;

                if(! CfgFactory::get().sslkeylog_file.empty()) {

                    CfgFactory::get().sslkeylog_file = string_format(CfgFactory::get().sslkeylog_file.c_str(),
                                                                     CfgFactory::get().tenant_name.c_str());

                    auto* o = new std::ofstream(CfgFactory::get().sslkeylog_file.c_str(),std::ios::app);
                    get_logger()->targets(CfgFactory::get().sslkeylog_file,o);
                    get_logger()->dup2_cout(false);
                    get_logger()->level(cfgapi_table.logging.level);

                    auto* lp = new logger_profile();
                    lp->print_srcline_ = get_logger()->print_srcline();
                    lp->print_srcline_always_ = get_logger()->print_srcline_always();
                    lp->level_ = loglevel(iINF,flag_add(iNOT,CRT|KEYS));
                    get_logger()->target_profiles()[(uint64_t)o] = lp;

                }
            }


            if( ! CfgFactory::get().syslog_server.empty() ) {
                bool have_syslog = init_syslog();
                if(! have_syslog) {
                    _err("syslog logging not set.");
                }
            }

            if(load_if_exists(CfgFactory::cfg_root()["settings"],"log_console", CfgFactory::get().log_console)) {
                get_logger()->dup2_cout(CfgFactory::get().log_console);
            }
        }
    }
    catch(const SettingNotFoundException &nfex) {

        _fat("Setting not found: %s",nfex.getPath());
        ret = false;
    }

    return ret;
}


