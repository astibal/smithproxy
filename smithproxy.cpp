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

#include <smithproxy.hpp>
#include <cmdserver.hpp>

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


    std::thread * id_thread = new std::thread([]() {
        unsigned int sleep_time = 1;

        // give some time to init shm - don't run immediately
        // this is workaround for rare(?) race condition when shm is not
        // initialized yet.

        ::sleep(20);

        for (unsigned i = 0; ; i++) {

            DEBS_("id_thread: refreshing identities");

            cfgapi_auth_shm_ip_table_refresh();
            cfgapi_auth_shm_ip6_table_refresh();
            cfgapi_auth_shm_token_table_refresh();

            DUMS_("id_thread: finished");

            ::sleep(sleep_time);
        }
    });

    return id_thread;
};



void SmithProxy::create_logger() {
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
    plain_proxy = prepare_listener<theAcceptor, TCPCom>(std::stoi(CfgFactory::get().listen_tcp_port),
                                                        "plain-text",
                                                        50080,
                                                        CfgFactory::get().num_workers_tcp);

    ssl_proxy = prepare_listener<theAcceptor, MySSLMitmCom>(std::stoi(CfgFactory::get().listen_tls_port),
                                                            "SSL",
                                                            50443,
                                                            CfgFactory::get().num_workers_tls);

    dtls_proxy = prepare_listener<theReceiver, MyDTLSMitmCom>(std::stoi(CfgFactory::get().listen_dtls_port),
                                                              "DTLS",
                                                              50443,
                                                              CfgFactory::get().num_workers_dtls);

    udp_proxy = prepare_listener<theReceiver, UDPCom>(std::stoi(CfgFactory::get().listen_udp_port),
                                                      "plain-udp",
                                                      50080,
                                                      CfgFactory::get().num_workers_udp);

    socks_proxy = prepare_listener<socksAcceptor, socksTCPCom>(std::stoi(CfgFactory::get().listen_socks_port),
                                                               "socks",
                                                               1080,
                                                               CfgFactory::get().num_workers_socks);


    if ((plain_proxy == nullptr && CfgFactory::get().num_workers_tcp >= 0) ||
        (ssl_proxy == nullptr && CfgFactory::get().num_workers_tls >= 0) ||
        (dtls_proxy == nullptr && CfgFactory::get().num_workers_dtls >= 0) ||
        (udp_proxy == nullptr && CfgFactory::get().num_workers_udp >= 0) ||
        (socks_proxy == nullptr && CfgFactory::get().num_workers_socks >= 0)) {

        FATS_("Failed to setup proxies. Bailing!");
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


    if(plain_proxy) {
        INFS_("Starting TCP listener");
        plain_thread = new std::thread([]() {
            set_daemon_signals(SmithProxy::instance().terminate_handler_, SmithProxy::instance().reload_handler_);
            DIA_("smithproxy_tcp: max file descriptors: %d",daemon_get_limit_fd());

            SmithProxy::instance().plain_proxy->run();
            DIAS_("plaintext workers torn down.");
            SmithProxy::instance().plain_proxy->shutdown();
        } );
        pthread_setname_np(plain_thread->native_handle(),friendly_thread_name_tcp.c_str());
    }

    if(ssl_proxy) {
        INFS_("Starting TLS listener");
        ssl_thread = new std::thread([] () {
            set_daemon_signals(SmithProxy::instance().terminate_handler_, SmithProxy::instance().reload_handler_);
            daemon_set_limit_fd(0);
            DIA_("smithproxy_tls: max file descriptors: %d",daemon_get_limit_fd());

            SmithProxy::instance().ssl_proxy->run();
            DIAS_("ssl workers torn down.");
            SmithProxy::instance().ssl_proxy->shutdown();
        } );
        pthread_setname_np(ssl_thread->native_handle(),friendly_thread_name_tls.c_str());
    }

    if(dtls_proxy) {
        INFS_("Starting DTLS listener");
        dtls_thread = new std::thread([] () {
            set_daemon_signals(SmithProxy::instance().terminate_handler_, SmithProxy::instance().reload_handler_);
            daemon_set_limit_fd(0);
            DIA_("smithproxy_tls: max file descriptors: %d",daemon_get_limit_fd());

            SmithProxy::instance().dtls_proxy->run();
            DIAS_("dtls workers torn down.");
            SmithProxy::instance().dtls_proxy->shutdown();
        } );
        pthread_setname_np(dtls_thread->native_handle(),friendly_thread_name_dls.c_str());
    }

    if(udp_proxy) {

        udp_proxy->set_quick_list(&CfgFactory::get().db_udp_quick_ports);

        INFS_("Starting UDP listener");
        udp_thread = new std::thread([] () {
            set_daemon_signals(SmithProxy::instance().terminate_handler_, SmithProxy::instance().reload_handler_);
            daemon_set_limit_fd(0);
            DIA_("smithproxy_udp: max file descriptors: %d",daemon_get_limit_fd());

            SmithProxy::instance().udp_proxy->run();
            DIAS_("udp workers torn down.");
            SmithProxy::instance().udp_proxy->shutdown();
        } );
        pthread_setname_np(udp_thread->native_handle(),friendly_thread_name_udp.c_str());
    }

    if(socks_proxy) {
        INFS_("Starting SOCKS5 listener");
        socks_thread = new std::thread([] () {
            set_daemon_signals(SmithProxy::instance().terminate_handler_, SmithProxy::instance().reload_handler_);
            daemon_set_limit_fd(0);
            DIA_("smithproxy_skx: max file descriptors: %d",daemon_get_limit_fd());

            SmithProxy::instance().socks_proxy->run();
            DIAS_("socks workers torn down.");
            SmithProxy::instance().socks_proxy->shutdown();
        } );
        pthread_setname_np(socks_thread->native_handle(),friendly_thread_name_skx.c_str());
    }

    cli_thread = new std::thread([] () {
        INFS_("Starting CLI");
        set_daemon_signals(SmithProxy::instance().terminate_handler_, SmithProxy::instance().reload_handler_);
        DIA_("smithproxy_cli: max file descriptors: %d",daemon_get_limit_fd());

        cli_loop(cli_port);
        DIAS_("cli workers torn down.");
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
    QueueLogger* ql = dynamic_cast<QueueLogger*>(get_logger());
    if(ql) {
        ql->sig_terminate = true;
        log_thread->join();
    }
}

void SmithProxy::stop() {
    if (plain_proxy != nullptr) {
        plain_proxy->dead(true);
    }
    if(ssl_proxy != nullptr) {
        ssl_proxy->dead(true);

    }
    if(dtls_proxy != nullptr) {
        dtls_proxy->dead(true);
    }
    if(udp_proxy != nullptr) {
        udp_proxy->dead(true);

    }
    if(socks_proxy != nullptr) {
        socks_proxy->dead(true);
    }
}

