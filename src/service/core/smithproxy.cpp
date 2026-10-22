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
#include <algorithm>

#include <openssl/rand.h>

#include <staticcontent.hpp>
#include <privileged_socket.hpp>

#include <inspect/sigfactory.hpp>

#include <service/core/smithproxy.hpp>
#include <service/api/api_broker.hpp>
#include <service/cmd/cmdserver.hpp>
#include <service/cli/cli_broker.hpp>
#include <service/httpd/httpd.hpp>
#include <service/cfgapi/cfgapi.hpp>
#include "service/http/webhooks.hpp"
#include "proxy/nbrhood.hpp"
#include "proxy/multiflow/mfmitmproxy.hpp"
#include <inspect/dnsinspector.hpp>

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


void SmithProxy::create_log_writer_thread() {
    // we have to create logger after daemonize is called
    log_thread  = std::shared_ptr<std::thread>(create_log_writer());

    if(log_thread) {
        pthread_setname_np( log_thread->native_handle(), string_format("sxy_lwr_%d", tenant_index()).c_str());
    }
}


void SmithProxy::create_dns_thread() {
    DNS_Inspector::set_hostname_observer(
        [](std::string const& origin, std::vector<std::string> const& addresses,
           std::string const& hostname) {
            sx::http::webhooks::hostname_info(origin, addresses, hostname);
        });
    DNS_Inspector::set_dns_observer(
        [](DNS_Inspector::dns_observation const& observation) {
            sx::http::webhooks::send_sift_dns_observation(observation);
        });
    dns_thread = std::shared_ptr<std::thread>(create_dns_updater());
    if(dns_thread) {
        pthread_setname_np( dns_thread->native_handle(),
                            string_format("sxy_dns_%d",tenant_index()).c_str());
    }
}

void SmithProxy::create_api_thread() {
#ifdef USE_LMHPP
    const int listener = sx::comm::api::ingress_fd();
    if(listener < 0) {
        Log::get()->events().insert(CRI, "cannot obtain API communication listener: %s",
                                    string_error().c_str());
        terminate_flag = true;
        return;
    }
    api_thread = std::shared_ptr<std::thread>(sx::webserver::create_httpd_thread(
        sx::webserver::HttpSessions::api_port + tenant_index(), listener));
    if(api_thread) {
        pthread_setname_np( api_thread->native_handle(),
                            string_format("sxy_api_%d",tenant_index()).c_str());
    }
#endif
}

bool SmithProxy::create_tproxy_listeners() {
    plain_proxies = NetworkServiceFactory::prepare_listener<theAcceptor, TCPCom>(
        std::stoi(CfgFactory::get()->listen_tcp_port), "tcp",
        CfgFactory::get()->num_workers_tcp, proxyType::transparent());
    ssl_proxies = NetworkServiceFactory::prepare_listener<theAcceptor, MySSLMitmCom>(
        std::stoi(CfgFactory::get()->listen_tls_port), "tls",
        CfgFactory::get()->num_workers_tls, proxyType::transparent());
    udp_proxies = NetworkServiceFactory::prepare_listener<theReceiver, UDPCom>(
        std::stoi(CfgFactory::get()->listen_udp_port), "udp",
        CfgFactory::get()->num_workers_udp, proxyType::transparent());

    if (CfgFactory::get()->num_workers_quic >= 0) {
        if (!sx::quic::openssl_quic_available()) {
            _war("QUIC listener disabled: linked OpenSSL has no QUIC server support (OpenSSL 3.5+ required)");
        } else {
            auto certs_path = SSLFactory::factory().certs_path();
            if (!certs_path.empty() && certs_path.back() != '/') certs_path += '/';
            auto service = std::make_unique<sx::quic::listener_service>(
                static_cast<std::uint16_t>(std::stoi(CfgFactory::get()->listen_quic_port)),
                certs_path + SSLFactory::config_t::SR_CERTF,
                certs_path + SSLFactory::config_t::SR_KEYF,
                true, 443, true, sx::quic::lifecycle_options {}, sx::quic::resource_limits {},
                std::string {}, sx::multiflow::make_mitm_flow_proxy,
                CfgFactory::get()->capture_local.enabled || CfgFactory::get()->capture_remote.enabled);
            if (!service->prepare()) {
                _err("Failed to setup QUIC listener: %s", service->last_error().c_str());
                return false;
            }
            quic_services.emplace_back(std::move(service));
        }
    }

    return !((plain_proxies.empty() && CfgFactory::get()->num_workers_tcp >= 0) ||
             (ssl_proxies.empty() && CfgFactory::get()->num_workers_tls >= 0) ||
             (udp_proxies.empty() && CfgFactory::get()->num_workers_udp >= 0));
}

void SmithProxy::launch_tproxy_listeners() {
    auto launch = [](auto& proxies, auto& threads, const std::string& name) {
        for (auto& proxy : proxies) {
            auto* proxy_ptr = proxy.get();
            auto thread = std::make_shared<std::thread>([proxy_ptr]() {
                CRYPTO_set_mem_functions(mempool_alloc, mempool_realloc, mempool_free);
                DaemonFactory::set_daemon_signals(SmithProxy::instance().terminate_handler_,
                                                  SmithProxy::instance().reload_handler_);
                proxy_ptr->run();
            });
            pthread_setname_np(thread->native_handle(), name.c_str());
            threads.push_back(std::move(thread));
        }
    };
    const auto tenant = CfgFactory::get()->tenant_index;
    launch(plain_proxies, plain_threads, string_format("sxy_tcp_%d", tenant));
    launch(ssl_proxies, ssl_threads, string_format("sxy_tls_%d", tenant));
    launch(udp_proxies, udp_threads, string_format("sxy_udp_%d", tenant));
    for (auto& service : quic_services) {
        auto* service_ptr = service.get();
        auto thread = std::make_shared<std::thread>([service_ptr]() { service_ptr->run(); });
        pthread_setname_np(thread->native_handle(), string_format("sxy_quic_%d", tenant).c_str());
        quic_threads.push_back(std::move(thread));
    }
}

void SmithProxy::stop_tproxy_listeners() {
    for (auto& service : quic_services) if (service) service->drain();
    auto stop = [](auto& proxies) { for (auto& proxy : proxies) if (proxy) proxy->state().dead(true); };
    stop(plain_proxies);
    stop(ssl_proxies);
    stop(udp_proxies);
    stop(dtls_proxies);
    auto join = [](auto& threads) {
        for (auto& thread : threads) if (thread && thread->joinable()) thread->join();
        threads.clear();
    };
    join(plain_threads);
    join(ssl_threads);
    join(udp_threads);
    join(dtls_threads);
    join(quic_threads);
    for (auto& proxy : plain_proxies) if (proxy) proxy->drain_workers();
    for (auto& proxy : ssl_proxies) if (proxy) proxy->drain_workers();
    for (auto& proxy : udp_proxies) if (proxy) proxy->drain_workers();
    for (auto& proxy : dtls_proxies) if (proxy) proxy->drain_workers();
    plain_proxies.clear();
    ssl_proxies.clear();
    udp_proxies.clear();
    dtls_proxies.clear();
    quic_services.clear();
}

bool SmithProxy::create_socks_listeners() {
    socks_proxies = NetworkServiceFactory::prepare_listener<socksAcceptor, socksTCPCom>(
        std::stoi(CfgFactory::get()->listen_socks_port), "socks-tcp",
        CfgFactory::get()->num_workers_socks, proxyType::proxy());
    socks_udp_proxies = NetworkServiceFactory::prepare_listener<socksReceiver, socksUDPCom>(
        std::stoi(CfgFactory::get()->listen_socks_port), "socks-udp",
        CfgFactory::get()->num_workers_socks, proxyType::proxy());
    return !((socks_proxies.empty() || socks_udp_proxies.empty()) &&
             CfgFactory::get()->num_workers_socks >= 0);
}

bool SmithProxy::create_http_connect_listeners() {
    http_connect_proxies = NetworkServiceFactory::prepare_listener<httpConnectAcceptor, TCPCom>(
        std::stoi(CfgFactory::get()->listen_http_connect_port), "http-connect",
        CfgFactory::get()->num_workers_http_connect, proxyType::proxy());
    return !(http_connect_proxies.empty() && CfgFactory::get()->num_workers_http_connect >= 0);
}

bool SmithProxy::create_redirect_listeners() {
    redir_plain_proxies = NetworkServiceFactory::prepare_listener<theAcceptor, TCPCom>(
        std::stoi(CfgFactory::get()->listen_tcp_port) + 1000, "redirect-tcp",
        CfgFactory::get()->num_workers_tcp, proxyType::redirect());
    redir_ssl_proxies = NetworkServiceFactory::prepare_listener<theAcceptor, MySSLMitmCom>(
        std::stoi(CfgFactory::get()->listen_tls_port) + 1000, "redirect-tls",
        CfgFactory::get()->num_workers_tls, proxyType::redirect());
    redir_udp_proxies = NetworkServiceFactory::prepare_listener<theReceiver, UDPCom>(
        std::stoi(CfgFactory::get()->listen_udp_port) + 1000, "redirect-udp",
        CfgFactory::get()->num_workers_udp, proxyType::redirect());
    return !((redir_plain_proxies.empty() && CfgFactory::get()->num_workers_tcp >= 0) ||
             (redir_ssl_proxies.empty() && CfgFactory::get()->num_workers_tls >= 0) ||
             (redir_udp_proxies.empty() && CfgFactory::get()->num_workers_udp >= 0));
}

namespace {
template <class Proxies, class Threads>
void launch_live(Proxies& proxies, Threads& threads, const std::string& name) {
    for (auto& proxy : proxies) {
        auto* proxy_ptr = proxy.get();
        auto thread = std::make_shared<std::thread>([proxy_ptr]() { proxy_ptr->run(); });
        pthread_setname_np(thread->native_handle(), name.c_str());
        threads.push_back(std::move(thread));
    }
}

template <class Proxies, class Threads>
void drain_live(Proxies& proxies, Threads& threads) {
    // Stop accepting first. Workers observe the dead parent, reject new work and
    // leave only after their already-owned sessions have disappeared.
    for (auto& proxy : proxies) if (proxy) proxy->state().dead(true);
    for (auto& thread : threads) if (thread && thread->joinable()) thread->join();
    for (auto& proxy : proxies) if (proxy) proxy->drain_workers();
    threads.clear();
    proxies.clear();
}
}

void SmithProxy::launch_socks_listeners() {
    const auto tenant = CfgFactory::get()->tenant_index;
    launch_live(socks_proxies, socks_threads, string_format("sxy_skx_%d", tenant));
    launch_live(socks_udp_proxies, socks_udp_threads, string_format("sxy_sku_%d", tenant));
}

void SmithProxy::launch_http_connect_listeners() {
    launch_live(http_connect_proxies, http_connect_threads,
                string_format("sxy_hcx_%d", CfgFactory::get()->tenant_index));
}

void SmithProxy::launch_redirect_listeners() {
    const auto tenant = CfgFactory::get()->tenant_index;
    launch_live(redir_plain_proxies, redir_plain_threads, string_format("sxy_rtcp_%d", tenant));
    launch_live(redir_ssl_proxies, redir_ssl_threads, string_format("sxy_rtls_%d", tenant));
    launch_live(redir_udp_proxies, redir_udp_threads, string_format("sxy_rudp_%d", tenant));
}

void SmithProxy::stop_socks_listeners() {
    drain_live(socks_proxies, socks_threads);
    drain_live(socks_udp_proxies, socks_udp_threads);
}

void SmithProxy::stop_http_connect_listeners() {
    drain_live(http_connect_proxies, http_connect_threads);
}

void SmithProxy::stop_redirect_listeners() {
    drain_live(redir_plain_proxies, redir_plain_threads);
    drain_live(redir_ssl_proxies, redir_ssl_threads);
    drain_live(redir_udp_proxies, redir_udp_threads);
}

bool SmithProxy::listener_enabled(LiveListener listener) const {
    switch (listener) {
        case LiveListener::tproxy: return CfgFactory::get()->accept_tproxy;
        case LiveListener::redirect: return CfgFactory::get()->accept_redirect;
        case LiveListener::socks: return CfgFactory::get()->accept_socks;
        case LiveListener::http_connect: return CfgFactory::get()->accept_http_connect;
    }
    return false;
}

bool SmithProxy::create_listener_group(LiveListener listener) {
    switch (listener) {
        case LiveListener::tproxy: return create_tproxy_listeners();
        case LiveListener::redirect: return create_redirect_listeners();
        case LiveListener::socks: return create_socks_listeners();
        case LiveListener::http_connect: return create_http_connect_listeners();
    }
    return false;
}

void SmithProxy::launch_listener_group(LiveListener listener) {
    switch (listener) {
        case LiveListener::tproxy: launch_tproxy_listeners(); break;
        case LiveListener::redirect: launch_redirect_listeners(); break;
        case LiveListener::socks: launch_socks_listeners(); break;
        case LiveListener::http_connect: launch_http_connect_listeners(); break;
    }
}

void SmithProxy::stop_listener_group(LiveListener listener) {
    switch (listener) {
        case LiveListener::tproxy: stop_tproxy_listeners(); break;
        case LiveListener::redirect: stop_redirect_listeners(); break;
        case LiveListener::socks: stop_socks_listeners(); break;
        case LiveListener::http_connect: stop_http_connect_listeners(); break;
    }
}

bool SmithProxy::apply_listener_setting(LiveListener listener, bool previous_enabled) {
    std::lock_guard lock(listeners_mutex_);
    try {
        return smithproxy::live::apply_listener(
            previous_enabled,
            [this, listener] { return listener_enabled(listener); },
            [this, listener] { stop_listener_group(listener); },
            [this, listener] { return create_listener_group(listener); },
            [this, listener] { launch_listener_group(listener); });
    } catch (const std::exception& exception) {
        _err("Cannot apply listener setting live: %s", exception.what());
        stop_listener_group(listener);
        return false;
    }
}

bool SmithProxy::apply_worker_setting(LiveWorkers workers) {
    std::lock_guard lock(listeners_mutex_);
    try {
        // Worker counts are baked into a listener group. Rebuild only enabled
        // groups; stop_listener_group() performs the graceful drain first.
        const auto restart = [this](LiveListener listener) {
            if (!listener_enabled(listener)) return true;
            stop_listener_group(listener);
            if (!create_listener_group(listener)) return false;
            launch_listener_group(listener);
            return true;
        };

        return smithproxy::live::apply_workers(workers, restart);
    } catch (const std::exception& exception) {
        _err("Cannot apply worker setting live: %s", exception.what());
        return false;
    }
}

bool SmithProxy::create_listeners() {

    bool success = false;

    try {

        std::string tcp_frm = "tcp";
        std::string tls_frm = "tls";
        std::string udp_frm = "udp";
        std::string quic_frm = "quic";

        std::string socks_frm = "socks-tcp";
        std::string socks_udp_frm = "socks-udp";
        std::string http_connect_frm = "http-connect";

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


            udp_proxies = NetworkServiceFactory::prepare_listener<theReceiver, UDPCom>(
                    std::stoi(CfgFactory::get()->listen_udp_port),
                    udp_frm,
                    CfgFactory::get()->num_workers_udp,
                    proxyType::transparent());

            log_listener(udp_frm, udp_proxies);

            if (CfgFactory::get()->num_workers_quic >= 0) {
                if (!sx::quic::openssl_quic_available()) {
                    _war("QUIC listener disabled: linked OpenSSL has no QUIC server support "
                         "(OpenSSL 3.5+ required)");
                } else {
                    if (CfgFactory::get()->num_workers_quic > 1) {
                        _war("QUIC currently uses one event-loop thread; quic_workers=%d requested",
                             CfgFactory::get()->num_workers_quic);
                    }
                    auto certs_path = SSLFactory::factory().certs_path();
                    if (!certs_path.empty() && certs_path.back() != '/') certs_path += '/';
                    auto service = std::make_unique<sx::quic::listener_service>(
                        static_cast<std::uint16_t>(std::stoi(CfgFactory::get()->listen_quic_port)),
                        certs_path + SSLFactory::config_t::SR_CERTF,
                        certs_path + SSLFactory::config_t::SR_KEYF,
                        true, 443, true, sx::quic::lifecycle_options {},
                        sx::quic::resource_limits {}, std::string {},
                        sx::multiflow::make_mitm_flow_proxy,
                        CfgFactory::get()->capture_local.enabled
                            || CfgFactory::get()->capture_remote.enabled);
                    if (!service->prepare()) {
                        _fat("Failed to setup QUIC listener: %s", service->last_error().c_str());
                        return false;
                    }
                    quic_services.emplace_back(std::move(service));
                    log_listener(quic_frm, quic_services);
                }
            }


            if ((plain_proxies.empty() && CfgFactory::get()->num_workers_tcp >= 0) ||
                (ssl_proxies.empty() && CfgFactory::get()->num_workers_tls >= 0) ||
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

        if(CfgFactory::get()->accept_http_connect) {
            http_connect_proxies = NetworkServiceFactory::prepare_listener<httpConnectAcceptor, TCPCom>(
                    std::stoi(CfgFactory::get()->listen_http_connect_port),
                    http_connect_frm,
                    CfgFactory::get()->num_workers_http_connect,
                    proxyType::proxy());

            log_listener(http_connect_frm, http_connect_proxies);
            if(http_connect_proxies.empty()
               && CfgFactory::get()->num_workers_http_connect >= 0) {
                _fat("Failed to setup HTTP CONNECT proxies. Bailing!");
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
    std::string friendly_thread_name_quic = string_format("sxy_quic_%d",CfgFactory::get()->tenant_index);
    std::string friendly_thread_name_skx = string_format("sxy_skx_%d",CfgFactory::get()->tenant_index);
    std::string friendly_thread_name_sku = string_format("sxy_sku_%d",CfgFactory::get()->tenant_index);
    std::string friendly_thread_name_hcx = string_format("sxy_hcx_%d",CfgFactory::get()->tenant_index);
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

        cli_loop(sx::comm::cli::ingress_fd());
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
        launch_proxy_threads(udp_proxies, udp_threads, "UDP listener", friendly_thread_name_udp.c_str());
        for (auto& service : quic_services) {
            _inf("Starting: QUIC listener");
            auto* service_ptr = service.get();
            auto thread = std::make_shared<std::thread>([service_ptr]() { service_ptr->run(); });
            pthread_setname_np(thread->native_handle(), friendly_thread_name_quic.c_str());
            quic_threads.push_back(std::move(thread));
        }
    }

    if(CfgFactory::get()->accept_socks) {
        launch_proxy_threads(socks_proxies, socks_threads, "SOCKS TCP listener", friendly_thread_name_skx.c_str());
        launch_proxy_threads(socks_udp_proxies, socks_udp_threads, "SOCKS UDP listener", friendly_thread_name_sku.c_str());
    }

    if(CfgFactory::get()->accept_http_connect) {
        launch_proxy_threads(http_connect_proxies, http_connect_threads,
                             "HTTP CONNECT listener", friendly_thread_name_hcx.c_str());
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

    unsigned int webhook_ping_interval = 120;
    unsigned int webhook_nbr_interval = 120;
    int webhook_nbr_refresh_age = 300;


    auto update_intervals = [&]() {
        auto lc_ = std::scoped_lock(CfgFactory::lock());
        webhook_ping_interval = static_cast<unsigned int>(
            std::max(1, CfgFactory::get()->settings_webhook.ping_interval));
        webhook_nbr_interval = static_cast<unsigned int>(
            std::max(1, CfgFactory::get()->settings_webhook.nbr_update_interval));
        webhook_nbr_refresh_age = std::max(
            0, CfgFactory::get()->settings_webhook.nbr_tag_refresh_age);
    };
    update_intervals();

    unsigned int wh_ping_seconds = webhook_ping_interval > 10
                                   ? webhook_ping_interval - 10 : 0; // speed-up first ping
    unsigned int wh_nbr_seconds = 0;
    bool wh_hostname_snapshot_sent = false;



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

        if(sx::http::webhooks::is_enabled()) {

            update_intervals();
            if (wh_ping_seconds >= webhook_ping_interval) {

                {
                    // refresh enabled status
                    auto lc_ = std::scoped_lock(CfgFactory::lock());
                    auto const &fac = CfgFactory::get();
                    sx::http::webhooks::set_enabled(fac->settings_webhook.enabled);
                }

                wh_ping_seconds = 0;
                sx::http::webhooks::ping();
                if(not wh_hostname_snapshot_sent) {
                    sx::http::webhooks::hostname_info_dns_cache();
                    wh_hostname_snapshot_sent = true;
                }
                sx::webserver::HttpSessions::cleanup();

                state_save();
            }
            ++wh_ping_seconds;

            if (wh_nbr_seconds >= webhook_nbr_interval) {

                std::vector<std::string> hostnames;
                auto now = time(nullptr);

                {
                    auto &nbrs = NbrHood::instance();
                    nbrs.for_each([&hostnames, &now, &webhook_nbr_refresh_age](auto const &n) {
                        if (not n.hostname.empty()) {
                            if (now - n.tags_ts() > webhook_nbr_refresh_age)
                                hostnames.push_back(n.hostname);
                        }
                    });
                }

                if(not hostnames.empty()) {
                    sx::http::webhooks::neighbor_state(hostnames, "update");
                }
                wh_nbr_seconds = 0;
            }
            ++wh_nbr_seconds;
        }

        static unsigned int ct_warning_seconds = 5 * 60;
        if(ct_warning_seconds >= 5 * 60) {
            bool ct_unavailable = false;
            {
                const auto lock = std::scoped_lock(CfgFactory::lock());
                ct_unavailable = CfgFactory::get()->ct_requested() &&
                    !SSLFactory::factory().is_ct_available();
            }
            if(ct_unavailable) {
                _war("%s", CfgFactory::CT_UNAVAILABLE_WARNING.data());
                Log::get()->events().insert(
                    WAR, "%s", CfgFactory::CT_UNAVAILABLE_WARNING.data());
            }
            ct_warning_seconds = 0;
        }
        ++ct_warning_seconds;

        // Keep the housekeeping loop paced even when webhooks are disabled.
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
        // Webhook tasks can still be using configuration, logging and proxy
        // state. Stop and join them before those services are torn down.
        sx::tp::ThreadPool::instance::shutdown_if_created();
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

        state_save();
        std::cerr << "state saved." << std::endl;
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
    if (not ifs || ifs.peek() == std::ifstream::traits_type::eof()) {
        return false;
    }

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

    if(! quic_threads.empty()) {
        if(!cfg_daemonize)
            std::cerr << "terminating quic thread" << std::endl;
        join_thread_list(quic_threads);
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
    if(! http_connect_threads.empty()) {
        if(!cfg_daemonize)
            std::cerr << "terminating HTTP CONNECT thread" << std::endl;
        join_thread_list(http_connect_threads);
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

    for (auto& service : quic_services) {
        if (service) service->stop();
    }

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
    kill_proxies(http_connect_proxies);


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
    ai.port = raw::down_cast_signed<unsigned short>(CfgFactory::get()->syslog_port).value_or(514);
    ai.family = CfgFactory::get()->syslog_family == 6 ? AF_INET6 : AF_INET;
    if(!ai.pack()) {
        _err("cannot parse syslog server address '%s'", CfgFactory::get()->syslog_server.c_str());
        return false;
    }

    // create UDP socket
    int syslog_socket = socle::socket(ai.family,
                                      SOCK_DGRAM | SOCK_CLOEXEC, IPPROTO_UDP);
    if(syslog_socket < 0) {
        _err("cannot create syslog socket: %s", string_error().c_str());
        return false;
    }

    const socklen_t address_size = ai.family == AF_INET ? sizeof(sockaddr_in) : sizeof(sockaddr_in6);
    if(0 != ::connect(syslog_socket, reinterpret_cast<sockaddr*>(ai.as_ss()), address_size)) {
        _err("cannot connect syslog socket %d: %s", syslog_socket, string_error().c_str());
        ::close(syslog_socket);
        return false;
    } else {

        auto lp = std::make_shared<logger_profile>();

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

        const auto target_name = string_format("syslog-udp%d-%d", CfgFactory::get()->syslog_family,
                                               syslog_socket);
        if(!Log::get()->add_remote_target(target_name, syslog_socket, std::move(lp))) {
            _err("cannot duplicate syslog socket %d: %s", syslog_socket, string_error().c_str());
            ::close(syslog_socket);
            return false;
        }
        ::close(syslog_socket);
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
        CfgFactory::get()->load_db_prof_ssh();
        CfgFactory::get()->load_db_prof_alg_dns();
        CfgFactory::get()->load_db_prof_script();
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
        if(reload && !html()->load_files(CfgFactory::get()->dir_msg_templates)) {
            _err("Cannot reload messages from '%s'; keeping the previous complete template set",
                 CfgFactory::get()->dir_msg_templates.c_str());
        }
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
