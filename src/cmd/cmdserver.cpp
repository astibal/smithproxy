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

#include <string>
#include <thread>
#include <set>

#include <cstring>
#include <ctime>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>

#include <openssl/rand.h>
#include <log/logger.hpp>

#include <ext/libcli/libcli.h>
#include <cmd/cmdserver.hpp>
#include <cmd/cligen.hpp>
#include <cmd/diag/diag_cmds.hpp>

#include <cfgapi.hpp>
#include <timeops.hpp>

#include <socle.hpp>
#include <sslcom.hpp>
#include <sslcertstore.hpp>

#include <main.hpp>
#include <sobject.hpp>

#include <service/core/smithproxy.hpp>
#include <proxy/mitmproxy.hpp>
#include <proxy/socks5/socksproxy.hpp>
#include <policy/inspectors.hpp>
#include <policy/authfactory.hpp>

#include <inspect/sigfactory.hpp>
#include <inspect/dnsinspector.hpp>

#include <cmd/clihelp.hpp>
#include <cmd/clistate.hpp>

#include <utils/str.hpp>

#include "socle_version.h"
#include "smithproxy_version.h"


using namespace socle;


void apply_hostname(cli_def* cli) {
    char hostname[64]; memset(hostname,0,64);
    gethostname(hostname,63);

    cli_set_hostname(cli, string_format("smithproxy(%s)%s ", hostname, CliGlobalState::config_changed_flag ? "<*>" : "").c_str());
}

void debug_cli_params(struct cli_def *cli, const char *command, char *argv[], int argc) {

    _debug(cli, "Cli mode: %d", cli->mode);
    _debug(cli, "command: %s", command);
    for(int i = 0; i < argc; i++) {
        _debug(cli, "      arg[%d]: %s", i, argv[i]);
    }

}

void load_defaults() {
    CliState::get().orig_ssl_loglevel = SSLCom::log_level_ref();
    CliState::get().orig_sslmitm_loglevel = SSLMitmCom::log_level_ref();
    CliState::get().orig_sslca_loglevel = *SSLFactory::get_log().level();

    CliState::get().orig_dns_insp_loglevel = DNS_Inspector::log_level_ref();
    CliState::get().orig_dns_packet_loglevel = DNS_Packet::log_level_ref();

    CliState::get().orig_baseproxy_loglevel = baseProxy::log_level_ref();
    CliState::get().orig_epoll_loglevel = epoll::log_level;
    CliState::get().orig_mitmproxy_loglevel = MitmProxy::log_level_ref();
    CliState::get().orig_mitmmasterproxy_loglevel = MitmMasterProxy::log_level_ref();
}



void cmd_show_status(struct cli_def* cli) {
    
    //cli_print(cli,":connected using socket %d",fileno(cli->client));
  
    cli_print(cli,"Version: %s%s",SMITH_VERSION,SMITH_DEVEL ? " (dev)" : "");
    cli_print(cli,"Socle: %s%s",SOCLE_VERSION,SOCLE_DEVEL ? " (dev)" : "");
#if ( (SMITH_DEVEL > 0) || (SOCLE_DEVEL > 0))
    cli_print(cli, "Smithproxy source info: %s", SX_GIT_VERSION);
    cli_print(cli, "                branch: %s commit: %s", SX_GIT_BRANCH, SX_GIT_COMMIT_HASH);

    cli_print(cli, " Socle lib source info: %s", SOCLE_GIT_VERSION);
    cli_print(cli, "                branch: %s commit: %s", SOCLE_GIT_BRANCH, SOCLE_GIT_COMMIT_HASH);
    cli_print(cli, "Built: %s", __TIMESTAMP__);  // breaks reproducible builds
#endif

#ifndef BUILD_RELEASE
    cli_print(cli, "  + DEBUG BUILD");  // slower
#endif
#ifdef MEMPOOL_ALL
    cli_print(cli, "  + MEMPOOL_ALL");  // using everything from pool
#endif
#ifdef MEMPOOL_DEBUG
    cli_print(cli, "  + MEMPOOL_DEBUG");  // much slower
#endif

    auto get_proxy_type = [](auto& proxies) -> const char* {
        if(proxies.empty()) return "none";

        return proxies[0]->sq_type_str();
    };

    auto get_multiplier = [](auto& proxies) -> int {
        if(proxies.empty()) return -1;

        return proxies[0]->core_multiplier();
    };

    auto get_task_count = [](auto& proxies) -> int {
        if(proxies.empty()) return -1;

        return proxies[0]->task_count();
    };

    auto sq_plain = get_proxy_type(SmithProxy::instance().plain_proxies);
    auto sq_ssl = get_proxy_type(SmithProxy::instance().ssl_proxies);
    auto sq_udp = get_proxy_type(SmithProxy::instance().udp_proxies);
    auto sq_dtls = get_proxy_type(SmithProxy::instance().dtls_proxies);

    cli_print(cli," ");

    cli_print(cli, "CPU cores detected: %d, acc multi: %d recv multi: %d", std::thread::hardware_concurrency(),
              get_multiplier(SmithProxy::instance().plain_proxies),
              get_multiplier(SmithProxy::instance().udp_proxies));
    cli_print(cli, "Acceptor hinting: tcp:%s, tls:%s, udp:%s, dtls:%s", sq_plain, sq_ssl, sq_udp, sq_dtls);



    if(CfgFactory::get().accept_tproxy) {
        cli_print(cli," ");
        cli_print(cli, "Tproxy acceptors:");
        cli_print(cli, "  TCP: %2zu workers: %2zu",
                  SmithProxy::instance().plain_proxies.size(),
                  SmithProxy::instance().plain_proxies.size() * get_task_count(SmithProxy::instance().plain_proxies));

        cli_print(cli, "  UDP: %2zu workers: %2zu",
                  SmithProxy::instance().udp_proxies.size(),
                  SmithProxy::instance().udp_proxies.size() * get_task_count(SmithProxy::instance().udp_proxies));

        cli_print(cli, "  TLS: %2zu workers: %2zu",
                  SmithProxy::instance().ssl_proxies.size(),
                  SmithProxy::instance().ssl_proxies.size() * get_task_count(SmithProxy::instance().ssl_proxies));

        cli_print(cli, "  DTLS: %2zu workers: %2zu",
                  SmithProxy::instance().dtls_proxies.size(),
                  SmithProxy::instance().dtls_proxies.size() * get_task_count(SmithProxy::instance().dtls_proxies));
    }

    if(CfgFactory::get().accept_redirect) {
        cli_print(cli," ");
        cli_print(cli, "Redirect acceptors:");
        cli_print(cli, "  TCP: %2zu workers: %2zu",
                  SmithProxy::instance().redir_plain_proxies.size(),
                  SmithProxy::instance().redir_plain_proxies.size() * get_task_count(SmithProxy::instance().redir_plain_proxies));

        cli_print(cli, "  UDP: %2zu workers: %2zu",
                  SmithProxy::instance().redir_udp_proxies.size(),
                  SmithProxy::instance().redir_udp_proxies.size() * get_task_count(SmithProxy::instance().redir_udp_proxies));

        cli_print(cli, "  TLS: %2zu workers: %2zu",
                  SmithProxy::instance().redir_ssl_proxies.size(),
                  SmithProxy::instance().redir_ssl_proxies.size() * get_task_count(SmithProxy::instance().redir_ssl_proxies));

    }

    if(CfgFactory::get().accept_socks) {
        cli_print(cli," ");
        cli_print(cli, "Socks acceptors:");
        cli_print(cli, "  TCP: %2zu workers: %2zu",
                  SmithProxy::instance().socks_proxies.size(),
                  SmithProxy::instance().socks_proxies.size() * get_task_count(SmithProxy::instance().socks_proxies));
    }

    cli_print(cli," ");
    time_t uptime = time(nullptr) - SmithProxy::instance().ts_sys_started;
    cli_print(cli,"Uptime: %s",uptime_string(uptime).c_str());

    {
        std::scoped_lock<std::recursive_mutex> l_(sobjectDB::getlock());
        cli_print(cli, "Objects: %lu", static_cast<unsigned long>(socle::sobjectDB::db().size()));
    }
    unsigned long l = MitmProxy::total_mtr_up().get();
    unsigned long r = MitmProxy::total_mtr_down().get();
    cli_print(cli,"Performance: upload %sbps, download %sbps in last 60 seconds",number_suffixed(l*8).c_str(),number_suffixed(r*8).c_str());

    unsigned long t = MitmProxy::total_mtr_up().total() + MitmProxy::total_mtr_down().total();
    cli_print(cli,"Transferred: %s bytes", number_suffixed(t).c_str());
    cli_print(cli,"Total sessions: %lu", static_cast<unsigned long>(MitmProxy::total_sessions().load()));

    if(CliGlobalState::config_changed_flag) {
        cli_print(cli, "\n*** Configuration changes NOT saved ***");
    }

}

int cli_show_status(struct cli_def *cli, const char *command, char *argv[], int argc)
{
    debug_cli_params(cli, command, argv, argc);

    cmd_show_status(cli);
    return CLI_OK;
}


int cli_test_dns_genrequest(struct cli_def *cli, const char *command, char *argv[], int argc) {
    debug_cli_params(cli, command, argv, argc);

    buffer b(1024);

    if(argc > 0) {
        std::string argv0(argv[0]);
        if( argv0 == "?" || argv0 == "\t") {
            cli_print(cli,"specify hostname.");
            return CLI_OK;
        }

        unsigned char rand_pool[2];
#ifdef USE_OPENSSL11
        RAND_bytes(rand_pool,2);
#else
        RAND_pseudo_bytes(rand_pool,2);
#endif
        unsigned short id = *(unsigned short*)rand_pool;

        int s = DNSFactory::get().generate_dns_request(id,b,argv[0],A);
        cli_print(cli,"DNS generated request: \n%s, %dB",hex_dump(b).c_str(), s);
    } else {
        cli_print(cli,"you need to specify hostname");
    }

    return CLI_OK;
}


DNS_Response* send_dns_request(struct cli_def *cli, std::string const& hostname, DNS_Record_Type t, std::string const& nameserver) {

    buffer b(1024);
    int parsed = -1;
    DNS_Response* ret = nullptr;

    unsigned char rand_pool[2];
#ifdef USE_OPENSSL11
    RAND_bytes(rand_pool,2);
#else
    RAND_pseudo_bytes(rand_pool,2);
#endif
    unsigned short id = *(unsigned short*)rand_pool;

    int s = DNSFactory::get().generate_dns_request(id,b,hostname,t);
    cli_print(cli,"DNS generated request: \n%s, %dB",hex_dump(b).c_str(),s);

    // create UDP socket
    int send_socket = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    struct sockaddr_storage addr {0};
    memset(&addr, 0, sizeof(struct sockaddr_storage));
    addr.ss_family                = AF_INET;
    ((sockaddr_in*)&addr)->sin_addr.s_addr = inet_addr(nameserver.c_str());
    ((sockaddr_in*)&addr)->sin_port = htons(53);

    if(0 != ::connect(send_socket,(sockaddr*)&addr,sizeof(sockaddr_storage))) {
        cli_print(cli, "cannot connect socket");
        ::close(send_socket);
        return CLI_OK;
    }

    if(::send(send_socket,b.data(),b.size(),0) < 0) {
        std::string r = string_format("logger::write_log: cannot write remote socket: %d",send_socket);
        cli_print(cli,"%s",r.c_str());

        ::close(send_socket); // coverity: 1407944
        return CLI_OK;
    }

    int rv;
    fd_set confds;
    struct timeval tv {0};
    tv.tv_usec = 0;
    tv.tv_sec = 2;
    FD_ZERO(&confds);
    FD_SET(send_socket, &confds);
    rv = select(send_socket + 1, &confds, nullptr, nullptr, &tv);
    if(rv == 1) {
        buffer r(1500);
         int l = ::recv(send_socket,r.data(),r.capacity(),0);
        if(l > 0) {
            r.size(l);

            cli_print(cli, "received %d bytes",l);
            cli_print(cli, "\n%s\n",hex_dump(r).c_str());


            auto* resp = new DNS_Response();
            parsed = resp->load(&r);
            cli_print(cli, "parsed %d bytes (0 means all)",parsed);
            cli_print(cli, "DNS response: \n %s",resp->to_string().c_str());

            // save only fully parsed messages
            if(parsed == 0) {
                ret = resp;

            } else {
                delete resp;
            }

        } else {
            cli_print(cli, "recv() returned %d",l);
        }

    } else {
        cli_print(cli, "timeout, or an error occured.");
    }


    ::close(send_socket);

    return ret;
}

int cli_test_dns_sendrequest(struct cli_def *cli, const char *command, char *argv[], int argc) {

    debug_cli_params(cli, command, argv, argc);

    if(argc > 0) {

        std::string argv0(argv[0]);
        if( argv0 == "?" || argv0 == "\t") {
            cli_print(cli,"specify hostname.");
            return CLI_OK;
        }

        std::string nameserver = "8.8.8.8";
        if(! CfgFactory::get().db_nameservers.empty()) {
            nameserver = CfgFactory::get().db_nameservers.at(0);
        }

        auto resp = std::shared_ptr<DNS_Response>(send_dns_request(cli,argv0,A,nameserver));
        if(resp) {
            DNS_Inspector di;
            if(di.store(resp)) {
                cli_print(cli, "Entry successfully stored in cache.");
            }
        }

    } else {
        cli_print(cli,"you need to specify hostname");
    }

    return CLI_OK;
}


int cli_test_dns_refreshallfqdns(struct cli_def *cli, const char *command, char *argv[], int argc) {

    debug_cli_params(cli, command, argv, argc);

    if(argc > 0) {
        std::string argv0(argv[0]);
        if( argv0 == "?" || argv0 == "\t") {
            return CLI_OK;
        }
    }

    std::vector<std::string> fqdns;

    {
        std::lock_guard<std::recursive_mutex> l_(CfgFactory::lock());

        for (auto const& a: CfgFactory::get().db_address) {
            auto fa = std::dynamic_pointer_cast<FqdnAddress>(a.second);
            if (fa) {
                fqdns.push_back(fa->fqdn());
            }
        }
    }

    std::string nameserver = "8.8.8.8";
    if(! CfgFactory::get().db_nameservers.empty()) {
        nameserver = CfgFactory::get().db_nameservers.at(0);
    }

    DNS_Inspector di;
    for(auto const& a: fqdns) {

        {
            auto resp = std::shared_ptr<DNS_Response>(send_dns_request(cli, a, A, nameserver));
            if (resp) {
                if (di.store(resp)) {
                    cli_print(cli, "Entry successfully stored in cache.");
                }
            }
        }

        auto resp = std::shared_ptr<DNS_Response>(send_dns_request(cli, a, AAAA ,nameserver));
        if(resp) {
            if(di.store(resp)) {
                cli_print(cli, "Entry successfully stored in cache.");
            }
        }
    }

    return CLI_OK;
}



void cli_print_log_levels(struct cli_def *cli) {

    logger_profile* lp = LogOutput::get()->target_profiles()[(uint64_t)fileno(cli->client)];

    cli_print(cli,"THIS cli logging level set to: %d",lp->level_.level());
    cli_print(cli,"Internal logging level set to: %d", LogOutput::get()->level().level());
    cli_print(cli,"\n");
    for(auto [ target, mut ]: LogOutput::get()->remote_targets()) {
        cli_print(cli, "Logging level for remote: %s: %d",
                  LogOutput::get()->target_name((uint64_t)target),
                  LogOutput::get()->target_profiles()[(uint64_t)target]->level_.level());
    }
    for(auto [ o_ptr, mut]: LogOutput::get()->targets()) {
        cli_print(cli, "Logging level for target: %s: %d",
                  LogOutput::get()->target_name((uint64_t)(o_ptr)),
                  LogOutput::get()->target_profiles()[(uint64_t)(o_ptr)]->level_.level());
    }
}


int cli_debug_level(struct cli_def *cli, const char *command, char *argv[], int argc) {

    debug_cli_params(cli, command, argv, argc);

    logger_profile* lp = LogOutput::get()->target_profiles()[(uint64_t)fileno(cli->client)];
    if(argc > 0) {

        std::string a1 = argv[0];

        if(a1 == "?") {
            cli_print(cli,"valid parameters: %s", CliState::get().debug_levels);
        }
        else if(a1 == "reset") {
            lp->level_ = NON;

            LogOutput::get()->level(CfgFactory::get().internal_init_level);
            cli_print(cli, "internal logging level changed to %d", LogOutput::get()->level().level_ref());
        }
        else {
            //cli_print(cli, "called %s with %s, argc %d\r\n", __FUNCTION__, command, argc);
            int newlev = safe_val(argv[0]);
            if(newlev >= 0) {
                LogOutput::get()->level(loglevel(newlev, 0));
            } else {
                cli_print(cli,"Incorrect value for logging level: %d",newlev);
            }
        }
    } else {
        cli_print_log_levels(cli);
    }

    return CLI_OK;
}


int cli_debug_terminal(struct cli_def *cli, const char *command, char *argv[], int argc) {
    debug_cli_params(cli, command, argv, argc);

    logger_profile* lp = LogOutput::get()->target_profiles()[(uint64_t)fileno(cli->client)];
    if(argc > 0) {

        std::string a1 = argv[0];


        if(a1 == "?") {
            cli_print(cli,"valid parameters: %s", CliState::get().debug_levels);
        }
        else if(a1 == "reset") {
            lp->level_ = NON;
        }
        else {
            //cli_print(cli, "called %s with %s, argc %d\r\n", __FUNCTION__, command, argc);
            int newlev = safe_val(argv[0]);
            if(newlev >= 0) {
                lp->level_.level(newlev);
                cli_print(cli, "this terminal logging level changed to %d",lp->level_.level());

            } else {
                cli_print(cli,"Incorrect value for logging level: %d",newlev);
            }
        }

    } else {
        cli_print_log_levels(cli);
    }



    return CLI_OK;
}


int cli_debug_logfile(struct cli_def *cli, const char *command, char *argv[], int argc) {

    debug_cli_params(cli, command, argv, argc);

    if(argc > 0) {

        std::string a1 = argv[0];

        if(a1 == "?") {
            cli_print(cli,"valid parameters: %s", CliState::get().debug_levels);
        }
        else {

            int newlev = 0;
            if(a1 == "reset") {
                newlev = static_cast<int>(CfgFactory::get().internal_init_level.level());
            } else {
                newlev = safe_val(argv[0]);
            }

            if(newlev >= 0) {
                for(auto [ o_ptr, mut ]: LogOutput::get()->targets()) {

                    std::string fnm = LogOutput::get()->target_name((uint64_t)(o_ptr));

                    std::scoped_lock<std::recursive_mutex> l_(CfgFactory::lock());

                    if( fnm == CfgFactory::get().log_file ) {

                        cli_print(cli, "changing '%s' loglevel to %d", fnm.c_str(), newlev);
                        LogOutput::get()->target_profiles()[(uint64_t) (o_ptr)]->level_.level(newlev);
                    }
                }
            }
        }
    } else {
        cli_print_log_levels(cli);
    }

    return CLI_OK;
}

int cli_debug_ssl(struct cli_def *cli, const char *command, char *argv[], int argc) {
    debug_cli_params(cli, command, argv, argc);

    if(argc > 0) {
        std::string a1 = argv[0];

        int newlev = 0;
        if(a1 == "?") {
            cli_print(cli,"valid parameters: %s", CliState::get().debug_levels);
        }
        else if(a1 == "reset") {
            SSLCom::log_level_ref() = CliState::get().orig_ssl_loglevel;
            SSLMitmCom::log_level_ref() = CliState::get().orig_sslmitm_loglevel;
            SSLFactory::get_log().level(CliState::get().orig_sslca_loglevel);
        }
        else {
            newlev = safe_val(argv[0]);
            SSLCom::log_level_ref().level(newlev);
            SSLMitmCom::log_level_ref().level(newlev);
            SSLFactory::get_log().level(loglevel(newlev));

        }
    } else {
        unsigned int l = SSLCom::log_level_ref().level();
        cli_print(cli,"SSL debug level: %d",l);
        l = SSLMitmCom::log_level_ref().level();
        cli_print(cli,"SSL MitM debug level: %d",l);
        l = SSLFactory::get_log().level()->level();
        cli_print(cli,"SSL CA debug level: %d",l);
        cli_print(cli,"\n");
        cli_print(cli,"valid parameters: %s", CliState::get().debug_levels);
    }

    return CLI_OK;
}

int cli_debug_auth(struct cli_def *cli, const char *command, char *argv[], int argc) {
    debug_cli_params(cli, command, argv, argc);

    if(argc > 0) {
        std::string a1 = argv[0];

        int newlev = 0;
        if(a1 == "?") {
            cli_print(cli,"valid parameters: %s", CliState::get().debug_levels);
        }
        else if(a1 == "reset") {
            AuthFactory::log_level_ref() = CliState::get().orig_auth_loglevel;
        }
        else {
            newlev = safe_val(a1);
            AuthFactory::log_level_ref().level(newlev);

        }
    } else {
        unsigned int l = AuthFactory::log_level_ref().level();
        cli_print(cli,"Auth debug level: %d",l);
        cli_print(cli,"\n");
        cli_print(cli,"valid parameters: %s", CliState::get().debug_levels);
    }

    return CLI_OK;
}

int cli_debug_dns(struct cli_def *cli, const char *command, char *argv[], int argc) {
    debug_cli_params(cli, command, argv, argc);

    if(argc > 0) {
        std::string a1 = argv[0];
        if(a1 == "?") {
            cli_print(cli,"valid parameters: %s", CliState::get().debug_levels);
        }
        else if(a1 == "reset") {
            DNS_Inspector::log_level_ref() = CliState::get().orig_dns_insp_loglevel;
            DNS_Packet::log_level_ref() = CliState::get().orig_dns_packet_loglevel;
        }
        else {
            int lev = std::stoi(argv[0]);
            DNS_Inspector::log_level_ref().level(lev);
            DNS_Packet::log_level_ref().level(lev);

        }
    } else {
        unsigned int l = DNS_Inspector::log_level_ref().level();
        cli_print(cli,"DNS Inspector debug level: %d",l);
        l = DNS_Packet::log_level_ref().level();
        cli_print(cli,"DNS Packet debug level: %d",l);
        cli_print(cli,"\n");
        cli_print(cli,"valid parameters: %s", CliState::get().debug_levels);
    }

    return CLI_OK;
}

int cli_debug_sobject(struct cli_def *cli, const char *command, char *argv[], int argc) {
    debug_cli_params(cli, command, argv, argc);

    bool cur = socle::sobject_info::enable_bt_;

    if(argc != 0) {
        cli_print(cli, "Current sobject trace flag switched to: %d",cur);
        return CLI_OK;
    }


    cur = !cur;

    socle::sobject_info::enable_bt_ = cur;

    cli_print(cli, "Current sobject trace flag switched to: %d",cur);
    if(cur)
        cli_print(cli, "!!! backtrace logging may affect performance !!!");

    return CLI_OK;
}

int cli_debug_proxy(struct cli_def *cli, const char *command, char *argv[], int argc) {
    debug_cli_params(cli, command, argv, argc);

    if(argc > 0) {
        std::string a1 = argv[0];
        if(a1 == "?") {
            cli_print(cli,"valid parameters: %s", CliState::get().debug_levels);
        }
        else if(a1 == "reset") {
            baseProxy::log_level_ref() = CliState::get().orig_baseproxy_loglevel;
            epoll::log_level = CliState::get().orig_epoll_loglevel;

            MitmMasterProxy::log_level_ref() = CliState::get().orig_mitmproxy_loglevel;
            MitmHostCX::log_level_ref() = CliState::get().orig_mitmhostcx_loglevel;
            MitmProxy::log_level_ref() = CliState::get().orig_mitmproxy_loglevel;
            SocksProxy::log_level_ref() = CliState::get().orig_socksproxy_loglevel;
        }
        else {
            int lev = std::stoi(argv[0]);
            baseProxy::log_level_ref().level(lev);
            epoll::log_level.level(lev);

            MitmMasterProxy::log_level_ref().level(lev);
            MitmHostCX::log_level_ref().level(lev);
            MitmProxy::log_level_ref().level(lev);
            SocksProxy::log_level_ref().level(lev);

        }
    } else {
        unsigned int l = baseProxy::log_level_ref().level();
        cli_print(cli,"baseProxy debug level: %d",l);

        l = epoll::log_level.level();
        cli_print(cli,"epoll debug level: %d",l);

        l = MitmMasterProxy::log_level_ref().level();
        cli_print(cli,"MitmMasterProxy debug level: %d",l);

        l = MitmHostCX::log_level_ref().level();
        cli_print(cli,"MitmHostCX debug level: %d",l);

        l = MitmProxy::log_level_ref().level();
        cli_print(cli,"MitmProxy debug level: %d",l);

        l = SocksProxy::log_level_ref().level();
        cli_print(cli,"SocksProxy debug level: %d",l);


        cli_print(cli,"\n");
        cli_print(cli,"valid parameters: %s", CliState::get().debug_levels);
    }

    return CLI_OK;
}


int cli_debug_show(struct cli_def *cli, const char *command, char *argv[], int argc) {

    debug_cli_params(cli, command, argv, argc);

    unsigned int l = baseProxy::log_level_ref().level();
    cli_print(cli,"baseProxy debug level: %d",l);

    l = epoll::log_level.level();
    cli_print(cli,"epoll debug level: %d",l);

    l = MitmMasterProxy::log_level_ref().level();
    cli_print(cli,"MitmMasterProxy debug level: %d",l);

    l = MitmHostCX::log_level_ref().level();
    cli_print(cli,"MitmHostCX debug level: %d",l);

    l = MitmProxy::log_level_ref().level();
    cli_print(cli,"MitmProxy debug level: %d",l);

    l = SocksProxy::log_level_ref().level();
    cli_print(cli,"SocksProxy debug level: %d",l);


    cli_print(cli, "\n\nlogan light loggers");

    std::stringstream ss;
    for(auto const& i: logan::get().topic_db_) {
        std::string t = i.first;
        loglevel* lev = i.second;

        ss << "    [" << t << "] => level " << lev->level() << " flag: " << lev->topic() << "\n";
    }

    cli_print(cli, "%s", ss.str().c_str());

    return CLI_OK;
}



int cli_debug_set(struct cli_def *cli, const char *command, char *argv[], int argc) {

    debug_cli_params(cli, command, argv, argc);

    std::set<std::string> topics;
    std::stringstream topiclist;

    for(auto const& i: logan::get().topic_db_) {
        std::string t = i.first;
        // loglevel l = i.second;

        topics.insert(t);
        topiclist << t << "\n";
    }
    if(argc > 1) {
        auto var = std::string(argv[0]);
        int  newlev = safe_val(argv[1]);


        if(var == "all" || var == "*") {
            for(auto const& lv: logan::get().topic_db_) {

                auto orig_l = logan::get()[lv.first]->level();
                logan::get()[lv.first]->level(newlev);
                cli_print(cli, "debug level changed: %s: %d => %d", lv.first.c_str(), orig_l, newlev);
            }
        }
        else if(var == "cli") {
            CliState::get().cli_debug_flag = (newlev > 0);
        }
        else {
            if(logan::get().topic_db_.find(var) != logan::get().topic_db_.end()) {
                loglevel* l = logan::get()[var];

                unsigned int old_lev = l->level();
                logan::get()[var]->level(newlev);

                cli_print(cli, "debug level changed: %s: %d => %d", var.c_str(), old_lev, newlev);
            } else {
                cli_print(cli, "variable not recognized");
            }
        }
    }
    else {
        cli_print(cli, "Usage: \n"
                       "       debug set <string variable> <debug level value 0-10>");
        cli_print(cli, "         \n");
        cli_print(cli, "Variable list:\n");
        cli_print(cli, "%s", topiclist.str().c_str());

    }
    return CLI_OK;
}




int cli_save_config(struct cli_def *cli, const char *command, char *argv[], int argc) {
    debug_cli_params(cli, command, argv, argc);

    int n = CfgFactory::get().save_config();
    if(n < 0) {
        cli_print(cli, "error writing config file!");
    }
    else {
        cli_print(cli, "config saved successfully.");
        CliGlobalState::config_changed_flag = false;

        apply_hostname(cli);
    }
    return CLI_OK;
}


int cli_exec_reload(struct cli_def *cli, const char *command, char *argv[], int argc) {
    debug_cli_params(cli, command, argv, argc);

    CliGlobalState::config_changed_flag = false;
    bool CONFIG_LOADED = SmithProxy::instance().load_config(CfgFactory::get().config_file, true);

    if(CONFIG_LOADED) {
        cli_print(cli, "Configuration file reloaded successfully");
        CliGlobalState::config_changed_flag = false;
        apply_hostname(cli);

    } else {
        cli_print(cli, "Configuration file reload FAILED");
    }

    return CLI_OK;
}


int cli_exec_shutdown(struct cli_def *cli, const char *command, char *argv[], int argc) {
    debug_cli_params(cli, command, argv, argc);

    cli_print(cli, " ");
    cli_print(cli, " !!!   terminating smithproxy   !!!");
    cli_print(cli, " ");

    SmithProxy::instance().stop();

    return CLI_OK;
}



int cli_show_config_full (struct cli_def *cli, const char *command, char **argv, int argc) {
    debug_cli_params(cli, command, argv, argc);

    std::scoped_lock<std::recursive_mutex> l_(CfgFactory::lock());

    if(CfgFactory::cfg_write(CfgFactory::cfg_obj(), cli->client) != 0) {
        cli_print(cli, "error: config print failed");
    }

    return CLI_OK;
}



std::optional<int> make_int(std::string const& v)  {
    if(v.empty())
        return 0;

    return std::stoi(v);
};

std::optional<long long int> make_lli(std::string const& v) {

    if(v.empty())
        return 0L;

    return std::stoll(v);
};


std::optional<bool> make_bool(std::string const& v) {

    if(v.empty())
        return true;

    auto uv = string_tolower(v);
    if (uv == "true" or uv == "1" or uv == "yes" or uv == "y" or uv == "t") {
            return true;
    } else if (uv == "false" or uv == "0" or uv == "no" or uv == "n" or uv == "f") {
            return false;
    } else {
        return std::nullopt;
    }
}

std::optional<float> make_float(std::string const& v) {

    if(v.empty())
        return 0.0f;

    return std::stof(v);
}

bool write_value(Setting& setting, std::optional<std::string> string_value, cli_def* cli, Setting::Type add_as_type = Setting::TypeNone) {

    bool ret_verdict = false;
    std::string original_value;

    if(string_value.has_value()) {
        original_value = string_value.value();
    }

    auto value_check_verdict = CliHelp::get().value_check(setting.getPath(), original_value, cli);
    if(value_check_verdict.has_value()) {
        original_value = value_check_verdict.value();
    } else {
        _debug(cli, "filter rejected the value");
        return false;
    }


    auto setting_type = setting.getType();
    if(add_as_type != Setting::TypeNone)
        setting_type = add_as_type;

    std::any converted_value;
    switch(setting_type) {
        case Setting::TypeInt: {
            auto a = make_int(original_value);
            if (a.has_value()) converted_value = a.value();
        }
        break;

        case Setting::TypeInt64: {
            auto a = make_lli(original_value);
            if(a.has_value()) converted_value = a.value();
        }
        break;

        case Setting::TypeBoolean: {
            auto a = make_bool(original_value);
            if (a.has_value()) converted_value = a.value();
        }
        break;

        case Setting::TypeFloat: {
            auto a = make_float(original_value);
            if(a.has_value()) converted_value = a.value();
        }
        break;
        case Setting::TypeString:
            converted_value = original_value;
            break;

        case Setting::TypeNone:
            throw std::logic_error("write value cannot be used for TypeNone");
            break;
        case Setting::TypeGroup:
            throw std::logic_error("write value cannot be used for TypeGroup");
            break;
        case Setting::TypeArray:
            throw std::logic_error("write value cannot be used for TypeArray");
            break;
        case Setting::TypeList:
            throw std::logic_error("write value cannot be used for TypeList");
            break;
    }

    if (converted_value.has_value()) {
        //_debug(cli, "DEBUG: attempting to write %s: (TypeInt)%d ", varname.c_str(), i.value());

        _debug(cli, "filter ok");

        switch(setting_type) {
            case Setting::TypeInt: {
                auto value = std::any_cast<int>(converted_value);
                if(add_as_type != Setting::TypeNone) {
                    setting.add(Setting::TypeInt) = value;
                } else {
                    setting = value;
                }

                ret_verdict = true;
            }
            break;

            case Setting::TypeInt64: {
                auto value = std::any_cast<long long int>(converted_value);
                if(add_as_type != Setting::TypeNone) {
                    setting.add(Setting::TypeInt64) = value;
                } else {
                    setting = value;
                }

                ret_verdict = true;
            }
            break;

            case Setting::TypeBoolean: {
                auto value = std::any_cast<bool>(converted_value);
                if(add_as_type != Setting::TypeNone) {
                    setting.add(Setting::TypeBoolean) = value;
                } else {
                    setting = value;
                }

                ret_verdict = true;
            }
            break;

            case Setting::TypeFloat: {
                auto value = std::any_cast<float>(converted_value);
                if(add_as_type != Setting::TypeNone) {
                    setting.add(Setting::TypeFloat) = value;
                } else {
                    setting = value;
                }

                ret_verdict = true;
            }
            break;

            case Setting::TypeString: {
                auto value = std::any_cast<std::string>(converted_value);
                if(add_as_type != Setting::TypeNone) {
                    setting.add(Setting::TypeString) = value;
                } else {
                    setting = value;
                }

                ret_verdict = true;
            }
            break;

            case Setting::TypeNone:
                throw std::logic_error("write value cannot be used for TypeNone");
                break;
            case Setting::TypeGroup:
                throw std::logic_error("write value cannot be used for TypeGroup");
                break;
            case Setting::TypeArray:
                throw std::logic_error("write value cannot be used for TypeArray");
                break;
            case Setting::TypeList:
                throw std::logic_error("write value cannot be used for TypeList");
                break;
        }

    } else {
        _debug(cli, "unexpected value");
    }

    return ret_verdict;
}


bool cfg_write_value(Setting& parent, bool create, std::string& varname, const std::vector<std::string> &values, cli_def* cli) {

    auto log = logan::create("config");

    bool ret_verdict = true;
    bool no_args_erases_array = true;




    if( parent.exists(varname.c_str()) ) {

        _not("config item exists %s", varname.c_str());

        Setting& setting = parent[varname.c_str()];
        auto setting_type = setting.getType();

        std::string lvalue;

        _debug(cli, "DEBUG: attempting to write %s", varname.c_str());

        try {
            switch (setting_type) {
            case Setting::TypeInt:
            case Setting::TypeInt64:
            case Setting::TypeBoolean:
            case Setting::TypeFloat:
            case Setting::TypeString:

                if(not values.empty()) {

                    // write only first value into scalar
                    ret_verdict = write_value(setting, values[0], cli);
                }
                else {
                    ret_verdict = write_value(setting, std::nullopt, cli);
                }
                break;


            case Setting::TypeArray:
                {
                    auto first_elem_type = Setting::TypeString;
                    if ( setting.getLength() > 0 ) {
                        first_elem_type = setting[0].getType();
                    }

                    std::vector<std::string> consolidated_values;
                    for(auto const &v: values) {
                        auto arg_values = string_split(v, ',');

                        for (auto const &av: arg_values)
                            consolidated_values.push_back(av);
                    }

                    for(auto const& i: consolidated_values) {
                        _debug(cli, "%s values: %s", setting.getPath().c_str(), i.c_str());
                    }


                    // check values
                    for(auto const& i: consolidated_values) {

                        auto verdict = CliHelp::get().value_check(setting.getPath(), i, cli);

                        if(verdict) {
                            _debug(cli, "checking value OK: %s => %s", i.c_str(), i.c_str());
                        }
                        else {
                            _debug(cli, "checking value failed: %s => %s", i.c_str(), i.c_str());

                            ret_verdict = false;
                            break;
                        }
                    }

                    if(ret_verdict) {
                        if (not consolidated_values.empty() or no_args_erases_array) {

                            // ugly (but only) way to remove
                            for (int x = setting.getLength() - 1; x >= 0; x--) {
                                _debug(cli, "removing index %d", x);
                                setting.remove(x);
                            }

                            for(auto const& cons_val: consolidated_values) {
                                ret_verdict = write_value(setting, cons_val, cli, first_elem_type);
                            }

                        } else {
                            throw (std::invalid_argument("no valid arguments"));
                        }
                    }
                }

                break;

            default:
                    ;
            }
        }
        catch(std::bad_any_cast const& e) {
            cli_print(cli, "invalid value conversion!");
            ret_verdict = false;
        }
        catch(std::invalid_argument const& e) {
            cli_print(cli, "invalid argument!");
            ret_verdict = false;
        }
        catch(std::exception const& e) {
            cli_print(cli , "error writing config variable: %s", e.what());
            _err("error writing config variable: %s", e.what());
            ret_verdict = false;
        }
    }
    else if(create) {
        _err("nyi: error writing creating a new config variable: %s", varname.c_str());
        ret_verdict = false;
    } else {
        _err("cli error: no such attribute name: %s", varname.c_str());

        _debug(cli, "error: no such attribute name: %s", varname.c_str());
        ret_verdict = false;
    }

    return ret_verdict;
}

bool apply_setting(std::string const& section, std::string const& varname, struct cli_def *cli) {

    _debug(cli, "apply_setting: %s", section.c_str());

    bool ret = false;

    if( 0 == section.find("settings") ) {
        ret = CfgFactory::get().load_settings();
    } else
    if( 0 == section.find("debug") ) {
        ret = CfgFactory::get().load_debug();
    } else
    if( 0 == section.find("policy") ) {

        CfgFactory::get().cleanup_db_policy();
        ret = CfgFactory::get().load_db_policy();
    } else
    if( 0 == section.find("port_objects") ) {

        CfgFactory::get().cleanup_db_port();
        ret = CfgFactory::get().load_db_port();

        if(ret) {
            CfgFactory::get().cleanup_db_policy();
            ret = CfgFactory::get().load_db_policy();
        }
    } else
    if( 0 == section.find("proto_objects") ) {

        CfgFactory::get().cleanup_db_proto();
        ret = CfgFactory::get().load_db_proto();

        if(ret) {
            CfgFactory::get().cleanup_db_policy();
            ret = CfgFactory::get().load_db_policy();
        }
    } else
    if( 0 == section.find("address_objects") ) {

        CfgFactory::get().cleanup_db_address();
        ret = CfgFactory::get().load_db_address();

        if(ret) {
            CfgFactory::get().cleanup_db_policy();
            ret = CfgFactory::get().load_db_policy();
        }
    } else
    if( 0 == section.find("detection_profiles") ) {

        CfgFactory::get().cleanup_db_prof_detection();
        ret = CfgFactory::get().load_db_prof_detection();

        if(ret) {
            CfgFactory::get().cleanup_db_policy();
            ret = CfgFactory::get().load_db_policy();
        }
    } else
    if( 0 == section.find("content_profiles") ) {

        CfgFactory::get().cleanup_db_prof_content();
        ret = CfgFactory::get().load_db_prof_content();

        if(ret) {
            CfgFactory::get().cleanup_db_policy();
            ret = CfgFactory::get().load_db_policy();
        }
    } else
    if( 0 == section.find("tls_profiles") ) {

        CfgFactory::get().cleanup_db_prof_tls();
        ret = CfgFactory::get().load_db_prof_tls();

        if(ret) {
            CfgFactory::get().cleanup_db_policy();
            ret = CfgFactory::get().load_db_policy();
        }
    } else
    if( 0 == section.find("alg_dns_profiles") ) {

        CfgFactory::get().cleanup_db_prof_alg_dns();
        ret = CfgFactory::get().load_db_prof_alg_dns();

        if(ret) {
            CfgFactory::get().cleanup_db_policy();
            ret = CfgFactory::get().load_db_policy();
        }
    } else
    if( 0 == section.find("auth_profiles") ) {

        CfgFactory::get().cleanup_db_prof_auth();
        ret = CfgFactory::get().load_db_prof_auth();

        if(ret) {
            CfgFactory::get().cleanup_db_policy();
            ret = CfgFactory::get().load_db_policy();
        }
    } else
    if( 0 == section.find("starttls_signatures") ) {
        SmithProxy::load_signatures(CfgFactory::cfg_obj(),"starttls_signatures", SigFactory::get().tls());

        CfgFactory::get().cleanup_db_policy();
        ret = CfgFactory::get().load_db_policy();
    } else
    if( 0 == section.find("detection_signatures") ) {
        SmithProxy::load_signatures(CfgFactory::cfg_obj(),"detection_signatures", SigFactory::get().detection());

        CfgFactory::get().cleanup_db_policy();
        ret = CfgFactory::get().load_db_policy();
    } else {
        cli_print(cli, "config apply - unknown config section!");
    }


    if(! ret) {
        cli_print(cli, "!!! Config was not applied");
        cli_print(cli, " -  saving and reload is necessary to apply your settings.");
    } else {

        bool status_change = not CliGlobalState::config_changed_flag;

        CliGlobalState::config_changed_flag = true;

        if(status_change) {
            apply_hostname(cli);
            cli_print(cli, " ");
            cli_print(cli, "Running config applied (not saved to file).");
        }
    }

    return ret;
}

int cli_uni_set_cb(std::string const& confpath, struct cli_def *cli, const char *command, char *argv[], int argc) {
    debug_cli_params(cli, command, argv, argc);

    std::scoped_lock<std::recursive_mutex> l_(CfgFactory::lock());

    if (CfgFactory::cfg_obj().exists(confpath)) {

        Setting& conf = CfgFactory::cfg_obj().lookup(confpath);

        auto cmd = string_split(command, ' ');
        std::string varname;

        if(argc > 0) {
            varname = cmd[cmd.size() - 1];
        } else {
            if(cmd.size() >= 2) {
                varname = cmd[1];
            }
        }

        _debug(cli, "var: %s", varname.c_str());


        std::vector<std::string> args;

        // counting from 1, since 0 is varname

        bool args_qmark = false;
        if (argc > 0) {
            for (int i = 0; i < argc; i++) {
                auto escaped = std::string(argv[i]);
                for(auto sub_escaped: string_split(escaped, ',')) {

                    sx::str::string_cfg_escape(sub_escaped);
                    args.emplace_back(sub_escaped);
                }
            }
            args_qmark = (args[0] == "?");

        } else {
            if(cmd.size() > 2) {
                for (unsigned int i = 2; i < cmd.size(); i++) {

                    auto escaped = std::string(cmd[i]);
                    for(auto sub_escaped: string_split(escaped, ',')) {

                        sx::str::string_cfg_escape(sub_escaped);
                        args.emplace_back(sub_escaped);
                    }
                }

                args_qmark = (args[0] == "?");
            }
        }

        if (! args_qmark) {

            // special treatment for "name" varname, which is always a string with spaces allowed
            if(varname == "name") {
                std::stringstream  ss_name;
                for(auto it = args.begin(); it != args.end(); ++it) {
                    ss_name << *it;
                    if( it + 1 != args.end()) {
                        ss_name << " ";
                    }
                }
                args.clear();

                auto name_str = ss_name.str();
                sx::str::string_cfg_escape(name_str);
                args.emplace_back(name_str);
            }

            decltype(args) consolidated_args;
            for(auto const& a: args) {
                if (std::find(consolidated_args.begin(), consolidated_args.end(), a) == consolidated_args.end()) {
                    consolidated_args.emplace_back(a);
                }
            }


            std::scoped_lock<std::recursive_mutex> ll_(CfgFactory::lock());

            if (cfg_write_value(conf, false, varname, consolidated_args, cli)) {
                // cli_print(cli, "change written to current config");

                if ( apply_setting( conf.getPath(), varname , cli )) {
                    cli_print(cli, " ");
                    // cli_print(cli, "Value changed");
                } else {
                    // FIXME
                    cli_print(cli, " ");
                    cli_print(cli, " ");
                    cli_print(cli, "  Something didn't go well: running config NOT changed !!!");
                    cli_print(cli, "    Change will be visible in show config, but not written to mapped variables");
                    cli_print(cli, "    therefore 'save config' won't write them to file.");
                    cli_print(cli, "    ");
                    cli_print(cli, "    Consider running 'execute reload'  ... sorry for inconvenience.");
                }
            } else {

                //  display error only if arguments were present
                if(not args.empty()) {
                    cli_print(cli, " ");
                    cli_print(cli, "Error setting value");
                } else {
                    cli_print(cli, " ");
                    cli_print(cli, "Error setting empty value");
                }
            }

        } else {
            if (!conf.isRoot() && conf.getName()) {

                auto h = CliHelp::get().help(CliHelp::help_type_t::HELP_QMARK, conf.getPath(), varname);

                cli_print(cli, "hint:  %s (%s)", h.c_str(), conf.getPath().c_str());
            }
        }
    }

    return CLI_OK;
}


#define CLI_PRINT_ARGS( cli, command , argv, argc ) \
    cli_print(cli, "called: '%s' with '%s' args: %d", __FUNCTION__, command, argc); \
    for(int i = 0 ; i < argc ; i++) {       \
        cli_print(cli, "arg[%d] = '%s'", i, argv[i]);   \
    }


int cli_generic_set_cb(struct cli_def *cli, const char *command, char *argv[], int argc) {
    debug_cli_params(cli, command, argv, argc);
    return cli_uni_set_cb(CliState::get().sections(cli->mode), cli, command, argv, argc);
}

int cli_generic_remove_cb(struct cli_def *cli, const char *command, char *argv[], int argc) {
    debug_cli_params(cli, command, argv, argc);

    std::vector<std::string> args;
    bool args_qmark = false;
    if (argc > 0) {
        for (int i = 0; i < argc; i++) {
            args.emplace_back(std::string(argv[i]));
        }
        args_qmark = (args[0] == "?");

    }

    if(args_qmark) {
        cli_print(cli, " ... hint: remove <object_name>");
        return CLI_OK;
    }

    auto section = CliState::get().sections(cli->mode);
    auto vec_full_args = string_split(command, ' ');

    // concat with additional args
    vec_full_args.insert(vec_full_args.end(), args.begin(), args.end());

    // erase "remove" from the list
    vec_full_args.erase(vec_full_args.begin());

    bool templated = false;

    if(section.find(".[x]") != std::string::npos) {
        sx::str::string_replace_all(section, ".[x]", "");
        templated = true;
    }

    std::scoped_lock<std::recursive_mutex> l_(CfgFactory::lock());
    if(CfgFactory::cfg_root().exists(section.c_str())) {

        auto reconstruct_cli = [&]() {
            if(templated) {

                if(CliState::get().has_callback(section + "." + vec_full_args[0])) {
                    auto &callback_entry = CliState::get().callbacks(section + "." + vec_full_args[0]);
                    // remove edit hooks and re-register for new list

                    // unregister "edit <this>"
                    auto cli_edit = std::get<1>(callback_entry).cli_edit();
                    if(cli_edit)
                        cli_unregister_single(cli, cli_edit);



                    // unregister "remove <this>"
                    auto cli_remove = std::get<1>(callback_entry).cli_remove();
                    if(cli_remove)
                        cli_unregister_single(cli, cli_remove);


                    CliState::get().erase_callback(section + "." + vec_full_args[0]);
                }
                else {
                    cli_print(cli, "templated, but no callbacks for: %s", section.c_str());
                }

            } else {
                if(CliState::get().has_callback(section)) {
                   // auto &callback_entry = CliState::get().callbacks(section);
//
//                // remove edit hooks and re-register for new list
//                cli_unregister_all(cli, std::get<1>(callback_entry).cli_edit());
//
//                // generate new CLI sub-tree
//                cli_generate_commands(cli, section, nullptr);
                }
                else {
                    cli_print(cli, "no callbacks for: %s", section.c_str());
                }
                cli_print(cli, "cannot remove: %s - only templated entries can be removed", section.c_str());
            }

            bool status_change = not CliGlobalState::config_changed_flag;
            CliGlobalState::config_changed_flag = true;

            if(status_change) {
                apply_hostname(cli);
                cli_print(cli, " ");
                cli_print(cli, "Running config applied (not saved to file).");
            }

        };


        // remove unconditionally @what element entries in the config @section
        //      @what is 'auto' to detect type, we can have name via string, or index via unsigned int
        auto remove = [&cli] (std::string const& section, auto const& what ) -> int {

            int removed = 0;

            for(auto const& arg: what) {

                try {
                    CfgFactory::cfg_root().lookup(section).remove(arg);
                    removed++;
                }
                catch(std::exception const& e) {
                    cli_print(cli, " ");
                    cli_print(cli, "Error removing: %s", e.what());
                }


            }

            // return number of removed elements
            return removed;
        };


        // check if any @what element entries from @section has some dependencies
        auto check_deps = [&cli](std::string const& section, std::vector<std::string> const& what) -> bool {
            bool ok_to_remove = true;

            for(auto const& arg: what) {

                // attempt to get and cast section element to CfgElement shared pointer
                auto elem = CfgFactory::get().section_element<CfgElement>(section, arg);
                if(elem and elem->has_usage()) {

                    auto brk = false;
                    for(auto const& dep: elem->usage_strvec()) {
                        cli_print(cli, "Cannot delete - used by: %s", dep.c_str());

                        brk = true;
                    }

                    if(brk) {
                        ok_to_remove = false;
                        break;
                    }
                }
            }

            return ok_to_remove;
        };

        if(! check_deps(section, vec_full_args)) {
            cli_print(cli, "Removal aborted.");
            return CLI_OK;
        }

        bool removed_internal = false;

        if(section == "proto_objects") {

            removed_internal = ( remove(section, vec_full_args) > 0 );
            if(removed_internal) {
                CfgFactory::get().cleanup_db_proto();
                CfgFactory::get().load_db_proto();
            }
        }
        else if(section == "port_objects") {

            removed_internal = ( remove(section, vec_full_args) > 0 );
            if(removed_internal) {
                CfgFactory::get().cleanup_db_port();
                CfgFactory::get().load_db_port();
            }

        }
        else if(section == "address_objects") {

            removed_internal = ( remove(section, vec_full_args) > 0 );
            if(removed_internal) {
                CfgFactory::get().cleanup_db_address();
                CfgFactory::get().load_db_address();
            }
        }
        else if(section == "detection_profiles") {

            removed_internal = ( remove(section, vec_full_args) > 0 );
            if(removed_internal) {
                CfgFactory::get().cleanup_db_prof_detection();
                CfgFactory::get().load_db_prof_detection();
            }
        }
        else if(section == "content_profiles") {

            removed_internal = ( remove(section, vec_full_args) > 0 );
            if(removed_internal) {
                CfgFactory::get().cleanup_db_prof_content();
                CfgFactory::get().load_db_prof_content();
            }
        }
        else if(section == "tls_ca") {

            removed_internal = ( remove(section, vec_full_args) > 0 );
            if(removed_internal) {
                CfgFactory::get().cleanup_db_tls_ca();
                CfgFactory::get().load_db_tls_ca();
            }
        }
        else if(section == "tls_profiles") {

            removed_internal = ( remove(section, vec_full_args) > 0 );
            if(removed_internal) {
                CfgFactory::get().cleanup_db_prof_tls();
                CfgFactory::get().load_db_prof_tls();
            }
        }
        else if(section == "alg_dns_profiles") {

            removed_internal = ( remove(section, vec_full_args) > 0 );
            if(removed_internal) {
                CfgFactory::get().cleanup_db_prof_alg_dns();
                CfgFactory::get().load_db_prof_alg_dns();
            }
        }
        else if(section == "auth_profiles") {

            removed_internal = ( remove(section, vec_full_args) > 0 );
            if(removed_internal) {
                CfgFactory::get().cleanup_db_prof_auth();
                CfgFactory::get().load_db_prof_auth();
            }
        }
        else if(section == "policy") {

            std::string unmask = section;
            sx::str::string_replace_all(unmask, ".[x]", "");

            std::vector<unsigned int> vec_full_args_int;
            std::for_each(vec_full_args.begin(), vec_full_args.end(), [&vec_full_args_int](auto const& arg) {

                auto xarg = arg;
                sx::str::string_replace_all(xarg, "[", "");
                sx::str::string_replace_all(xarg, "]", "");
                sx::str::string_replace_all(xarg, " ", "");

                auto v = safe_val(xarg);
                if( v >= 0)
                    vec_full_args_int.push_back(v);
            });

            removed_internal = ( remove(unmask, vec_full_args_int) > 0 );
            if(removed_internal) {

                section = unmask;

                CfgFactory::get().cleanup_db_policy();
                CfgFactory::get().load_db_policy();
            }
        }


        if(removed_internal) {
            reconstruct_cli();

            CfgFactory::get().cleanup_db_policy();
            CfgFactory::get().load_db_policy();

            cli_print(cli, " ");
            cli_print(cli, "%s element has been removed.", section.c_str());
        }
    }
    else {
        cli_print(cli, "unknown section %s", section.c_str());
    }

    return CLI_OK;
}


int cli_policy_move_cb(struct cli_def *cli, const char *command, char *argv[], int argc) {
    debug_cli_params(cli, command, argv, argc);

    std::vector<std::string> args;
    bool args_qmark = false;
    auto section = CliState::get().sections(cli->mode);

    if (argc > 0) {
        for (int i = 0; i < argc; i++) {
            args.emplace_back(std::string(argv[i]));
        }
        args_qmark = (args[0] == "?");

    }

    if (args_qmark) {
        cli_print(cli, " ... hint: move <policy_id> [before|after] <policy_id>");
        return CLI_OK;
    }

    if (section.find(".[x]") != std::string::npos) {
        sx::str::string_replace_all(section, ".[x]", "");
    }

    auto cmd_split = string_split(command, ' ');


    int index_1 = -1;
    int index_2 = -1;

    if(cmd_split.size() == 4) {

        auto x1 = cmd_split[1];
        auto x2 = cmd_split[3];
        sx::str::string_replace_all(x1, "[", "");
        sx::str::string_replace_all(x2, "[", "");
        sx::str::string_replace_all(x1, "]", "");
        sx::str::string_replace_all(x2, "]", "");
        sx::str::string_replace_all(x1, " ", "");
        sx::str::string_replace_all(x2, " ", "");

        index_1 = safe_val(x1);
        index_2 = safe_val(x2);

    } else if(cmd_split.size() == 3) {

        auto x1 = cmd_split[1];
        sx::str::string_replace_all(x1, "[", "");
        sx::str::string_replace_all(x1, "]", "");
        sx::str::string_replace_all(x1, " ", "");
        index_1 = safe_val(x1);

        if (index_1 >= 0) {
            bool unknown_command = false;
            // process only ok-parsed items

            if (cmd_split[2] == "up") {
                index_2 = index_1 - 1;
            } else if (cmd_split[2] == "top") {
                index_2 = 0;
            } else if (cmd_split[2] == "down") {
                auto elem = CfgFactory::get().db_policy_list.size();
                if (index_1 + 1 < static_cast<int>(elem))
                    index_2 = index_1 + 1;
            } else if (cmd_split[2] == "bottom") {

                auto elem = CfgFactory::get().db_policy_list.size();
                if (elem > 0)
                    index_2 = static_cast<int>(elem - 1);
            } else {
                unknown_command = true;
            }

            if (unknown_command) {
                cli_print(cli, "cannot move policy: '%s' to specified direction", command);
                return CLI_OK;
            }
        }
    }
    else {
        cli_print(cli, "cannot parse request: '%s'", command);
        return CLI_OK;
    }


    if(index_1 < 0 or index_2 < 0) {
        cli_print(cli, "invalid arguments in request: '%s'", command);
        return CLI_OK;
    }
    _debug(cli, "moving %d %s %d", index_1, cmd_split[2].c_str(), index_2);

    if(cmd_split[2] == "after" or cmd_split[2] == "down" or cmd_split[2] == "bottom") {
        if(CfgFactory::get().move_policy(index_1, index_2, CfgFactory::op_move::OP_MOVE_AFTER)) {
            CfgFactory::get().cleanup_db_policy();
            CfgFactory::get().load_db_policy();

            cli_print(cli, " ");
            // cli_print(cli, "Policy moved.");

        } else {
            cli_print(cli, " ");
            cli_print(cli, "Error moving policies");
        }
    }
    else if(cmd_split[2] == "before" or cmd_split[2] == "up" or cmd_split[2] == "top") {
        if(CfgFactory::get().move_policy(index_1, index_2, CfgFactory::op_move::OP_MOVE_BEFORE)) {
            CfgFactory::get().cleanup_db_policy();
            CfgFactory::get().load_db_policy();

            cli_print(cli, " ");
            // cli_print(cli, "Policy moved.");
        } else {
            cli_print(cli, " ");
            cli_print(cli, "Error moving policies");
        }
    }
    else {
        cli_print(cli, "invalid command in request: '%s'", command);
        return CLI_OK;
    }

    return CLI_OK;
}


int cli_generic_add_cb(struct cli_def *cli, const char *command, char *argv[], int argc) {
    debug_cli_params(cli, command, argv, argc);

    std::vector<std::string> args;
    bool args_qmark = false;
    auto section = CliState::get().sections(cli->mode);

    if (argc > 0) {
        for (int i = 0; i < argc; i++) {
            args.emplace_back(std::string(argv[i]));
        }
        args_qmark = (args[0] == "?");

    }

    if(args_qmark) {
        cli_print(cli, " ... hint: add <object_name> (name must not start with reserved __)");
        return CLI_OK;
    }

    // remove template suffix
    bool templated = false;
    if(section.find(".[x]") != std::string::npos) {
        templated = true;
        sx::str::string_replace_all(section, ".[x]", "");
    }

    if(section == "policy") {
        args.clear();
        args.push_back(string_format("[%d]", CfgFactory::get().db_policy_list.size()));
    }

    // if nothing to add, print out something smart and exit
    if(args.empty())  {
        cli_print(cli, " ");
        cli_print(cli, "New entry in this section must have an unique name.");
        return CLI_OK;
    }


    if(args[0].find("__") == 0) {

        cli_print(cli, " ");
        cli_print(cli, "Error: name must not start with reserved \'__\'");
        return CLI_OK;
    }


    std::scoped_lock<std::recursive_mutex> l_(CfgFactory::lock());
    if(CfgFactory::cfg_root().exists(section.c_str())) {

        auto register_cli = [&]() {

            // load callbacks, must prefer templated
            auto& callback_entry = templated ? CliState::get().callbacks(section + ".[x]") : CliState::get().callbacks(section);

            if(std::get<1>(callback_entry).cap_edit()) {

                auto cli_edit_x = cli_register_command(cli, std::get<1>(callback_entry).cli_edit(), args[0].c_str(),
                                     std::get<1>(callback_entry).cmd_edit(), PRIVILEGE_PRIVILEGED, cli->mode,
                                     " edit new entry");

                // set also leaf node
                std::get<1>(CliState::get().callbacks(section + "." + args[0])).cli_edit(cli_edit_x);
            }

            if(std::get<1>(callback_entry).cap_move()) {
                auto cli_move = std::get<1>(callback_entry).cli_move();
                if(cli_move) {

                    // 'add' has empty args when adding to an array, so let's be a bit nasty here
                    if(section == "policy")
                        cli_generate_move_commands(cli, cli->mode, cli_move, std::get<1>(callback_entry).cmd_move(),
                                                   static_cast<int>(CfgFactory::get().db_policy_list.size()-1),
                                                   CfgFactory::get().db_policy_list.size());
                }
            }

            if(std::get<1>(callback_entry).cap_remove()) {
                auto cli_remove = std::get<1>(callback_entry).cli_remove();

                if(cli_remove) {
                    auto cli_remove_x = cli_register_command(cli, std::get<1>(callback_entry).cli_remove(), args[0].c_str(),
                                         std::get<1>(callback_entry).cmd_remove(), PRIVILEGE_PRIVILEGED, cli->mode,
                                         " delete this entry");

                    // set also leaf node
                    std::get<1>(CliState::get().callbacks(section + "." + args[0])).cli_remove(cli_remove_x);
                }
            }

            if(section == "policy") {
                // 'add' has empty args when adding to an array, so let's be a bit nasty here
                cli_generate_set_commands(cli, section + ".[" + string_format("%d]", static_cast<int>(CfgFactory::get().db_policy_list.size()-1)));
            }
            else {
                cli_generate_set_commands(cli, section + "." + args[0]);
            }
        };

        bool created_internal = false;

        Setting &s = CfgFactory::cfg_root().lookup(section.c_str());
        if(section == "proto_objects") {
            if (CfgFactory::get().new_proto_object(s, args[0])) {
                CfgFactory::get().load_db_proto();
                register_cli();
                created_internal = true;
            }
        }
        else if(section == "port_objects") {
            if (CfgFactory::get().new_port_object(s, args[0])) {
                CfgFactory::get().load_db_port();
                register_cli();
                created_internal = true;
            }
        }
        else if(section == "address_objects") {
            if (CfgFactory::get().new_address_object(s, args[0])) {
                CfgFactory::get().load_db_address();
                register_cli();
                created_internal = true;
            }
        }
        else if(section == "detection_profiles") {
            if (CfgFactory::get().new_detection_profile(s, args[0])) {
                CfgFactory::get().load_db_prof_detection();
                register_cli();
                created_internal = true;
            }
        }
        else if(section == "content_profiles") {
            if (CfgFactory::get().new_content_profile(s, args[0])) {
                CfgFactory::get().load_db_prof_content();
                register_cli();
                created_internal = true;
            }
        }
        else if(section == "tls_ca") {
            if (CfgFactory::get().new_tls_ca(s, args[0])) {
                // missing load_db_tls_ca
                register_cli();
                created_internal = true;
            }
        }
        else if(section == "tls_profiles") {
            if (CfgFactory::get().new_tls_profile(s, args[0])) {
                CfgFactory::get().load_db_prof_tls();
                register_cli();
                created_internal = true;
            }
        }
        else if(section == "alg_dns_profiles") {
            if (CfgFactory::get().new_alg_dns_profile(s, args[0])) {
                CfgFactory::get().load_db_prof_alg_dns();
                register_cli();
                created_internal = true;
            }
        }
        else if(section == "auth_profiles") {
            if (CfgFactory::get().new_auth_profile(s, args[0])) {
                CfgFactory::get().load_db_prof_auth();
                register_cli();
                created_internal = true;
            }
        }
        else if(section == "policy") {
            if (CfgFactory::get().new_policy(s, args[0])) {

                // policy is a list - it must be cleared before loaded again
                CfgFactory::get().cleanup_db_policy();
                CfgFactory::get().load_db_policy();
                register_cli();
                created_internal = true;
            }
        }

        if(created_internal) {
            cli_print(cli, " ");
            cli_print(cli, "New %s '%s' has been created.", section.c_str(), args[0].c_str());

            bool status_change = not CliGlobalState::config_changed_flag;

            CliGlobalState::config_changed_flag = true;

            if(status_change) {
                apply_hostname(cli);
                cli_print(cli, " ");
                cli_print(cli, "Running config applied (not saved to file).");
            }
        }
    }
    return CLI_OK;
}


// index < 0 means all
void cli_print_section(cli_def* cli, const std::string& xname, int index , unsigned long pipe_sz ) {

    std::string name = xname;
    sx::str::string_replace_all(name, ".[x]", "");

    std::scoped_lock<std::recursive_mutex> l_(CfgFactory::lock());

    if(CfgFactory::cfg_root().exists(name.c_str())) {
        Setting &s = CfgFactory::cfg_root().lookup(name.c_str());

        Config nc;

        auto section_nodes = string_split(name, '.');


        #if ( LIBCONFIGXX_VER_MAJOR >= 1 && LIBCONFIGXX_VER_MINOR < 7 )

        nc.setOptions(Setting::OptionOpenBraceOnSeparateLine);

        #else

        nc.setOptions(Config::OptionOpenBraceOnSeparateLine);

        #endif

        Setting* target = &nc.getRoot();
        target = &target->add(s.getName(), s.getType());

        CfgFactory::cfg_clone_setting( *target, s , index /*, cli */ );
        CfgFactory::cfg_write(nc, cli->client, pipe_sz);

    } else {
        cli_print(cli, "'%s' config section doesn't exist", name.c_str());
    }
}

int cli_show_config_setting(struct cli_def *cli, const char *command, char *argv[], int argc) {
    debug_cli_params(cli, command, argv, argc);

    cli_print_section(cli, "settings", -1, 200 * 1024);
    return CLI_OK;
}

int cli_show_config_policy(struct cli_def *cli, const char *command, char *argv[], int argc) {
    debug_cli_params(cli, command, argv, argc);

    int index = -1;
    if(argc > 0) {
        index = std::stoi(argv[0]);
    }
    cli_print_section(cli, "policy", index, 10 * 1024 * 1024);
    return CLI_OK;
}

int cli_show_config_objects(struct cli_def *cli, const char *command, char *argv[], int argc) {
    debug_cli_params(cli, command, argv, argc);

    cli_print_section(cli, "proto_objects", -1,  1 * 1024 * 1024);
    cli_print_section(cli, "port_objects", -1, 1 * 1024 * 1024);
    cli_print_section(cli, "address_objects", -1,  1 * 1024 * 1024);
    return CLI_OK;
}

int cli_show_config_proto_objects(struct cli_def *cli, const char *command, char *argv[], int argc) {
    debug_cli_params(cli, command, argv, argc);

    cli_print_section(cli, "proto_objects", -1, 1 * 1024 * 1024);
    return CLI_OK;
}

int cli_show_config_port_objects(struct cli_def *cli, const char *command, char *argv[], int argc) {
    debug_cli_params(cli, command, argv, argc);

    cli_print_section(cli, "port_objects", -1, 1 * 1024 * 1024);
    return CLI_OK;
}

int cli_show_config_address_objects(struct cli_def *cli, const char *command, char *argv[], int argc) {
    debug_cli_params(cli, command, argv, argc);

    cli_print_section(cli, "address_objects", -1, 1 * 1024 * 1024);
    return CLI_OK;
}

int cli_show_config_detection(struct cli_def *cli, const char *command, char *argv[], int argc) {
    debug_cli_params(cli, command, argv, argc);

    cli_print_section(cli, "detection_profiles", -1, 1 * 1024 * 1024);
    return CLI_OK;
}


int cli_show_config_content(struct cli_def *cli, const char *command, char *argv[], int argc) {
    debug_cli_params(cli, command, argv, argc);

    cli_print_section(cli, "content_profiles", -1, 1 * 1024 * 1024);
    return CLI_OK;
}


int cli_show_config_tls_ca(struct cli_def *cli, const char *command, char *argv[], int argc) {
    debug_cli_params(cli, command, argv, argc);

    cli_print_section(cli, "tls_ca", -1, 1 * 1024 * 1024);
    return CLI_OK;
}


int cli_show_config_tls_profiles(struct cli_def *cli, const char *command, char *argv[], int argc) {
    debug_cli_params(cli, command, argv, argc);

    cli_print_section(cli, "tls_profiles", -1, 1 * 1024 * 1024);
    return CLI_OK;
}

int cli_show_config_alg_dns(struct cli_def *cli, const char *command, char *argv[], int argc) {
    debug_cli_params(cli, command, argv, argc);

    cli_print_section(cli, "alg_dns_profiles", -1, 1 * 1024 * 1024);
    return CLI_OK;
}

int cli_show_config_auth_profiles(struct cli_def *cli, const char *command, char *argv[], int argc) {
    debug_cli_params(cli, command, argv, argc);

    cli_print_section(cli, "auth_profiles", -1,  1 * 1024 * 1024);
    return CLI_OK;
}

int cli_show_config_starttls_sig(struct cli_def *cli, const char *command, char *argv[], int argc) {
    debug_cli_params(cli, command, argv, argc);

    cli_print_section(cli, "starttls_signatures", -1, 1 * 1024 * 1024);
    return CLI_OK;
}

int cli_show_config_detection_sig(struct cli_def *cli, const char *command, char *argv[], int argc) {
    debug_cli_params(cli, command, argv, argc);

    cli_print_section(cli, "detection_signatures", -1, 1 * 1024 * 1024);
    return CLI_OK;
}

void cli_register_static(struct cli_def* cli) {

    auto save  = cli_register_command(cli, nullptr, "save", nullptr, PRIVILEGE_PRIVILEGED, MODE_ANY, "save configs");
            cli_register_command(cli, save, "config", cli_save_config, PRIVILEGE_PRIVILEGED, MODE_ANY, "save config file");

    auto exec = cli_register_command(cli, nullptr, "execute", nullptr, PRIVILEGE_PRIVILEGED, MODE_ANY, "execute various tasks");
            [[maybe_unused]] auto exec_reload = cli_register_command(cli, exec, "reload", cli_exec_reload, PRIVILEGE_PRIVILEGED, MODE_ANY, "reload config file");
            [[maybe_unused]] auto exec_shutdown = cli_register_command(cli, exec, "shutdown", cli_exec_shutdown, PRIVILEGE_PRIVILEGED, MODE_ANY, "terminate this smithproxy process");

    auto show  = cli_register_command(cli, nullptr, "show", cli_show, PRIVILEGE_UNPRIVILEGED, MODE_ANY, "show basic information");
            cli_register_command(cli, show, "status", cli_show_status, PRIVILEGE_UNPRIVILEGED, MODE_EXEC, "show smithproxy status");
            auto show_config = cli_register_command(cli, show, "config", nullptr, PRIVILEGE_UNPRIVILEGED, MODE_ANY, "show smithproxy configuration related commands");
                    cli_register_command(cli, show_config, "full", cli_show_config_full, PRIVILEGE_UNPRIVILEGED, MODE_ANY, "show smithproxy full configuration");

                    cli_register_command(cli, show_config, "settings", cli_show_config_setting, PRIVILEGE_UNPRIVILEGED, MODE_ANY, "show smithproxy config section: settings");
                    cli_register_command(cli, show_config, "policy", cli_show_config_policy, PRIVILEGE_UNPRIVILEGED, MODE_ANY, "show smithproxy config section: policy");
                    cli_register_command(cli, show_config, "objects", cli_show_config_objects, PRIVILEGE_UNPRIVILEGED, MODE_ANY, "show smithproxy config section: all objects");
                    cli_register_command(cli, show_config, "proto_objects", cli_show_config_proto_objects, PRIVILEGE_UNPRIVILEGED, MODE_ANY, "show smithproxy config section: proto_objects");
                    cli_register_command(cli, show_config, "port_objects", cli_show_config_port_objects, PRIVILEGE_UNPRIVILEGED, MODE_ANY, "show smithproxy config section: port_objects");
                    cli_register_command(cli, show_config, "address_objects", cli_show_config_address_objects, PRIVILEGE_UNPRIVILEGED, MODE_ANY, "show smithproxy config section: address_objects");
                    cli_register_command(cli, show_config, "detection_profiles", cli_show_config_detection, PRIVILEGE_UNPRIVILEGED, MODE_ANY, "show smithproxy config section: detection_profiles");
                    cli_register_command(cli, show_config, "content_profiles", cli_show_config_content, PRIVILEGE_UNPRIVILEGED, MODE_ANY, "show smithproxy config section: content_profiles");
                    cli_register_command(cli, show_config, "tls_ca", cli_show_config_tls_ca, PRIVILEGE_UNPRIVILEGED, MODE_ANY, "show smithproxy config section: tls_ca profiles");
                    cli_register_command(cli, show_config, "tls_profiles", cli_show_config_tls_profiles, PRIVILEGE_UNPRIVILEGED, MODE_ANY, "show smithproxy config section: tls_profiles");
                    cli_register_command(cli, show_config, "alg_dns_profiles", cli_show_config_alg_dns, PRIVILEGE_UNPRIVILEGED, MODE_ANY, "show smithproxy config section: alg_dns_profiles");
                    cli_register_command(cli, show_config, "auth_profiles", cli_show_config_auth_profiles, PRIVILEGE_UNPRIVILEGED, MODE_ANY, "show smithproxy config section: auth_profiles");

                    cli_register_command(cli, show_config, "starttls_signatures", cli_show_config_starttls_sig, PRIVILEGE_UNPRIVILEGED, MODE_ANY, "show smithproxy config section: starttls_signatures");
                    cli_register_command(cli, show_config, "detection_signatures", cli_show_config_detection_sig, PRIVILEGE_UNPRIVILEGED, MODE_ANY, "show smithproxy config section: detection_signatures");

    auto test  = cli_register_command(cli, nullptr, "test", nullptr, PRIVILEGE_UNPRIVILEGED, MODE_EXEC, "various testing commands");
            auto test_dns = cli_register_command(cli, test, "dns", nullptr, PRIVILEGE_UNPRIVILEGED, MODE_EXEC, "dns related testing commands");
                    cli_register_command(cli, test_dns, "genrequest", cli_test_dns_genrequest, PRIVILEGE_UNPRIVILEGED, MODE_EXEC, "generate dns request");
                    cli_register_command(cli, test_dns, "sendrequest", cli_test_dns_sendrequest, PRIVILEGE_UNPRIVILEGED, MODE_EXEC, "generate and send dns request to configured nameserver");
                cli_register_command(cli, test_dns, "refreshallfqdns", cli_test_dns_refreshallfqdns, PRIVILEGE_UNPRIVILEGED, MODE_EXEC, "refresh all configured FQDN address objects against configured nameserver");

    auto diag  = cli_register_command(cli, nullptr, "diag", nullptr, PRIVILEGE_UNPRIVILEGED, MODE_EXEC, "diagnose commands helping to troubleshoot");
            register_diags(cli, diag);

    auto debuk = cli_register_command(cli, nullptr, "debug", nullptr, PRIVILEGE_PRIVILEGED, MODE_EXEC, "diagnostic commands");
    cli_register_command(cli, debuk, "term", cli_debug_terminal, PRIVILEGE_PRIVILEGED, MODE_EXEC, "set level of logging to this terminal");
    cli_register_command(cli, debuk, "file", cli_debug_logfile, PRIVILEGE_PRIVILEGED, MODE_EXEC, "set level of logging to standard log file");
    cli_register_command(cli, debuk, "level", cli_debug_level, PRIVILEGE_PRIVILEGED, MODE_EXEC, "set general logging level");
    cli_register_command(cli, debuk, "ssl", cli_debug_ssl, PRIVILEGE_PRIVILEGED, MODE_EXEC, "set ssl file logging level");
    cli_register_command(cli, debuk, "dns", cli_debug_dns, PRIVILEGE_PRIVILEGED, MODE_EXEC, "set dns file logging level");
    cli_register_command(cli, debuk, "proxy", cli_debug_proxy, PRIVILEGE_PRIVILEGED, MODE_EXEC, "set proxy file logging level");
    cli_register_command(cli, debuk, "auth", cli_debug_auth, PRIVILEGE_PRIVILEGED, MODE_EXEC, "set authentication file logging level");
    cli_register_command(cli, debuk, "sobject", cli_debug_sobject, PRIVILEGE_PRIVILEGED, MODE_EXEC, "toggle on/off sobject creation tracing (affect performance)");
    cli_register_command(cli, debuk, "show", cli_debug_show, PRIVILEGE_PRIVILEGED, MODE_EXEC, "show all possible debugs and their settings");
    cli_register_command(cli, debuk, "set", cli_debug_set, PRIVILEGE_PRIVILEGED, MODE_EXEC, "change light logan loglevels");
}


void client_thread(int client_socket) {

    auto log = logan::create("service");

    struct cli_def *cli = cli_init();

    // Set the hostname (shown in the the prompt)
    apply_hostname(cli);

    // Set the greeting
    cli_set_banner(cli, "--==[ Smithproxy command line utility ]==--");

    cli_allow_enable(cli, CliState::get().cli_enable_password.c_str());

    cli_register_static(cli);

    cli_regular(cli, [](cli_def* c) -> int { if(SmithProxy::instance().terminate_flag) return CLI_ERROR; return CLI_OK; } );
    cli_regular_interval(cli, 1);


    // generate dynamically content of config
//    .cmd_set(cli_generic_set_cb)
//            .cmd_config(edit_cb);



    auto register_callback = [](std::string const& section, int mode) -> CliCallbacks& {
        CliState::get().callbacks(
                section,
                CliState::callback_entry(mode, CliCallbacks(section)));

        return std::get<1>(CliState::get().callbacks(section));

    };

    register_callback("settings",MODE_EDIT_SETTINGS)
                .cmd_set(cli_generic_set_cb)
                .cmd_edit(cli_conf_edit_settings);

    register_callback( "settings.auth_portal",MODE_EDIT_SETTINGS_AUTH)
                .cmd_set(cli_generic_set_cb)
                .cmd_edit(cli_conf_edit_settings_auth)
                .cap_edit(true);

    register_callback(
            "settings.nameservers",MODE_EDIT_SETTINGS + 1);

    register_callback(
            "settings.socks", MODE_EDIT_SETTINGS_SOCKS)
                .cmd_set(cli_generic_set_cb)
                .cmd_edit(cli_conf_edit_settings_socks)
                .cap_edit(true);

    register_callback("settings.cli", MODE_EDIT_SETTINGS_CLI)
                .cmd_set(cli_generic_set_cb)
                .cmd_edit(cli_conf_edit_settings_cli)
                .cap_edit(true);

    register_callback("debug", MODE_EDIT_DEBUG)
            .cmd_set(cli_generic_set_cb)
            .cmd_edit(cli_conf_edit_debug)
            .cap_edit(true);

    register_callback("debug.log", MODE_EDIT_DEBUG_LOG)
            .cmd_set(cli_generic_set_cb)
            .cmd_edit(cli_conf_edit_debug_log)
            .cap_edit(true);


    register_callback( "proto_objects", MODE_EDIT_PROTO_OBJECTS)
                .cap_edit(true).cmd_edit(cli_conf_edit_proto_objects);

    register_callback( "proto_objects.[x]", MODE_EDIT_PROTO_OBJECTS)
            .cmd_set(cli_generic_set_cb)
            .cap_edit(true).cmd_edit(cli_conf_edit_proto_objects)
            .cap_add(true).cmd_add(cli_generic_add_cb)
            .cap_remove(true).cmd_remove(cli_generic_remove_cb);


    register_callback("address_objects", MODE_EDIT_ADDRESS_OBJECTS)
            .cap_edit(true).cmd_edit(cli_conf_edit_address_objects);

    register_callback("address_objects.[x]", MODE_EDIT_ADDRESS_OBJECTS)
            .cmd_set(cli_generic_set_cb)
            .cap_edit(true).cmd_edit(cli_conf_edit_address_objects)
            .cap_add(true).cmd_add(cli_generic_add_cb)
            .cap_remove(true).cmd_remove(cli_generic_remove_cb);


    register_callback("port_objects", MODE_EDIT_PORT_OBJECTS)
            .cap_edit(true).cmd_edit(cli_conf_edit_port_objects);

    register_callback("port_objects.[x]", MODE_EDIT_PORT_OBJECTS)
            .cmd_set(cli_generic_set_cb)
            .cap_edit(true)
            .cmd_edit(cli_conf_edit_port_objects)
            .cap_add(true)
            .cmd_add(cli_generic_add_cb)
            .cap_remove(true)
            .cmd_remove(cli_generic_remove_cb);


    register_callback("policy", MODE_EDIT_POLICY)
                .cmd_edit(cli_conf_edit_policy);

    // template for policy list entries
    register_callback( "policy.[x]", MODE_EDIT_POLICY)
            .cmd_set(cli_generic_set_cb)
            .cap_add(true).cmd_add(cli_generic_add_cb)
            .cap_remove(true).cmd_remove(cli_generic_remove_cb)
            .cap_edit(true).cmd_edit(cli_conf_edit_policy)
            .cap_move(true).cmd_move(cli_policy_move_cb);

    register_callback("detection_profiles", MODE_EDIT_DETECTION_PROFILES)
                    .cmd_edit(cli_conf_edit_detection_profiles);

    register_callback("detection_profiles.[x]", MODE_EDIT_DETECTION_PROFILES)
            .cmd_set(cli_generic_set_cb)
            .cap_edit(true).cmd_edit(cli_conf_edit_detection_profiles)
            .cap_add(true).cmd_add(cli_generic_add_cb)
            .cap_remove(true).cmd_remove(cli_generic_remove_cb);


    register_callback("content_profiles", MODE_EDIT_CONTENT_PROFILES)
            .cmd_edit(cli_conf_edit_content_profiles);

    register_callback("content_profiles.[x]", MODE_EDIT_CONTENT_PROFILES)
            .cmd_set(cli_generic_set_cb)
            .cap_edit(true).cmd_edit(cli_conf_edit_content_profiles)
            .cap_add(true).cmd_add(cli_generic_add_cb)
            .cap_remove(true).cmd_remove(cli_generic_remove_cb);


    register_callback("tls_profiles", MODE_EDIT_TLS_PROFILES)
            .cmd_edit(cli_conf_edit_tls_profiles);

    register_callback("tls_profiles.[x]", MODE_EDIT_TLS_PROFILES)
            .cmd_set(cli_generic_set_cb)
            .cap_edit(true).cmd_edit(cli_conf_edit_tls_profiles)
            .cap_add(true).cmd_add(cli_generic_add_cb)
            .cap_remove(true).cmd_remove(cli_generic_remove_cb);


    register_callback("auth_profiles", MODE_EDIT_AUTH_PROFILES)
            .cmd_edit(cli_conf_edit_auth_profiles);

    register_callback("auth_profiles.[x]", MODE_EDIT_AUTH_PROFILES)
            .cmd_set(cli_generic_set_cb)
            .cap_edit(true).cmd_edit(cli_conf_edit_auth_profiles)
            .cap_add(true).cmd_add(cli_generic_add_cb)
            .cap_remove(true).cmd_remove(cli_generic_remove_cb);

    register_callback("alg_dns_profiles", MODE_EDIT_ALG_DNS_PROFILES)
                    .cmd_edit(cli_conf_edit_alg_dns_profiles);

    register_callback("alg_dns_profiles.[x]", MODE_EDIT_ALG_DNS_PROFILES)
            .cmd_set(cli_generic_set_cb)
            .cap_edit(true).cmd_edit(cli_conf_edit_alg_dns_profiles)
            .cap_add(true).cmd_add(cli_generic_add_cb)
            .cap_remove(true).cmd_remove(cli_generic_remove_cb);




    register_callback("starttls_signatures", MODE_EDIT_STARTTLS_SIGNATURES)
    .cmd_edit(cli_conf_edit_starttls_signatures);

    register_callback("starttls_signatures.[x]", MODE_EDIT_STARTTLS_SIGNATURES)
                    .cmd_set(cli_generic_set_cb)
                    // .cap_add(true).cmd_add(cli_generic_add_cb)
                    // .cap_remove(true).cmd_remove(cli_generic_remove_cb)
                    .cap_edit(true).cmd_edit(cli_conf_edit_starttls_signatures);

    register_callback("detection_signatures", MODE_EDIT_DETECTION_SIGNATURES)
        .cmd_edit(cli_conf_edit_detection_signatures);


    register_callback("detection_signatures.[x]", MODE_EDIT_DETECTION_SIGNATURES)
                    .cmd_set(cli_generic_set_cb)
                    // .cap_add(true).cmd_add(cli_generic_add_cb)
                    // .cap_remove(true).cmd_remove(cli_generic_remove_cb)
                    .cap_edit(true).cmd_edit(cli_conf_edit_detection_signatures);



    auto conft_edit = cli_register_command(cli, nullptr, "edit", nullptr, PRIVILEGE_PRIVILEGED, MODE_CONFIG, "configure smithproxy settings");


    std::vector<std::string> edit_sections = {"settings", "debug",
                                              "proto_objects", "address_objects", "port_objects" ,
                                              "detection_profiles", "content_profiles", "tls_profiles", "auth_profiles",
                                              "alg_dns_profiles",
                                              "policy",
                                              "starttls_signatures",
                                              "detection_signatures" };

    auto gen_edit_sections = [&]() {
        for (auto const &section : edit_sections) {

            if (CfgFactory::cfg_root().exists(section.c_str())) {

                std::string edit_help = string_format(" \t - edit %s", section.c_str());
                auto const &callback_entry = CliState::get().callbacks(section);

                cli_register_command(cli, conft_edit, section.c_str(), std::get<1>(callback_entry).cmd_edit(),
                                     PRIVILEGE_PRIVILEGED, MODE_CONFIG, edit_help.c_str());

                std::scoped_lock<std::recursive_mutex> l_(CfgFactory::lock());
                cli_generate_commands(cli, section, nullptr);
            }
        }
    };

    gen_edit_sections();

    // Pass the connection off to libcli
    LogOutput::get()->remote_targets(string_format("cli-%d", client_socket), client_socket);

    logger_profile lp;
    lp.level_ = CfgFactory::get().cli_init_level;
    LogOutput::get()->target_profiles()[(uint64_t)client_socket] = &lp;


    load_defaults();
    cli_loop(cli, client_socket);


    LogOutput::get()->remote_targets().remove_if([client_socket](auto e) { return e.first == client_socket; });
    LogOutput::get()->target_profiles().erase(client_socket);
    close(client_socket);

    // Free data structures
    cli_done(cli);
}

void cli_loop(short unsigned int port) {

    auto log = logan::create("service");
    sockaddr_in servaddr{0};
    int on = 1;

    // Create a socket
    int s = socket(AF_INET, SOCK_STREAM, 0);
    setsockopt(s, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on));

    memset(&servaddr, 0, sizeof(servaddr));
    servaddr.sin_family = AF_INET;
    servaddr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    servaddr.sin_port = htons(port);

    while(0 != bind(s, (struct sockaddr *)&servaddr, sizeof(servaddr))) {
        _err("cli main thread - cannot bind %d port: %s", port, string_error().c_str());
        ::sleep(1);
        _err("...retrying");
    }

    // Wait for a connection
    listen(s, 50);

    int client_socket = 0;


    epoll epoller;
    if ( epoller.init() <= 0) {
        _err("cli main thread: Can't initialize epoll");
        return;
    }

    epoller.add(s, EPOLLIN);


    while(true) {
        int nfds = epoller.wait(1*1000);

        if(nfds > 0) {
            sockaddr_storage addr {0};
            socklen_t addr_len {0};

            client_socket = accept(s, (struct sockaddr*)&addr, &addr_len);
            new std::thread(client_thread, client_socket);
        }

        if(SmithProxy::instance().terminate_flag) {
            break;
        }
    }

}


int cli_show(struct cli_def *cli, const char *command, char **argv, int argc) {

    debug_cli_params(cli, command, argv, argc);

    cli_print_section(cli, CliState::get().sections(cli->mode), -1, 200 * 1024);

    return CLI_OK;
}
