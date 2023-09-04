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

#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>

#include <openssl/rand.h>
#include <log/logger.hpp>

#include <ext/libcli/libcli.h>

#include <service/cmd/cmdserver.hpp>
#include <service/cmd/cligen.hpp>
#include <service/cmd/diag/diag_cmds.hpp>
#include <service/cfgapi/cfgvalue.hpp>
#include <service/cmd/clistate.hpp>
#include <service/core/authpam.hpp>

#include <service/cfgapi/cfgapi.hpp>

#include <service/tpool.hpp>
#include <service/http/request.hpp>
#include <service/http/async_request.hpp>

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
#include <traflog/pcaplog.hpp>

#include <inspect/sigfactory.hpp>
#include <inspect/dnsinspector.hpp>
#include <inspect/kb/kb.hpp>

#include <utils/str.hpp>
#include <display.hpp>

#include "socle_version.h"
#include "smithproxy_version.h"


using namespace socle;
using namespace libconfig;

struct CliGlobals {
    static std::string create_hostname() {
        char hostname[64]; memset(hostname,0,64);
        gethostname(hostname,63);
        auto tenant = "." + CfgFactory::get()->tenant_name;

        std::string hostname_full = hostname + (tenant == ".default" ? "" : tenant );
        return hostname_full;
    }
    static std::string const& hostname() {
        static const std::string h = create_hostname();
        return h;
    };

    static thread_local inline bool ct_warning_flag = false;

};

auto cli_id() {
    std::stringstream ss;
    ss << "cli-" << std::this_thread::get_id();

    return ss.str();
}

void apply_hostname(cli_def* cli) {

    auto board = CfgFactory::board();

    board->ack_current(cli_id());

    board->ack_saved(cli_id());

    const bool cfg_change_unsaved = (board->at(cli_id()).seen_current != board->at(cli_id()).seen_saved);


    cli_set_hostname(cli, string_format("smithproxy(%s)%s", CliGlobals::hostname().c_str(), cfg_change_unsaved ? "<*>" : "").c_str());

}

void debug_cli_params(struct cli_def *cli, const char *command, char *argv[], int argc) {

    _debug(cli, "Cli mode: %d", cli->mode);
    _debug(cli, "command: %s", command);
    for(int i = 0; i < argc; i++) {
        _debug(cli, "      arg[%d]: %s", i, argv[i]);
    }

}

void debug_cli_params(struct cli_def *cli, const char *command, std::vector<std::string> const& args) {

    _debug(cli, "Cli mode: %d", cli->mode);
    _debug(cli, "command: %s", command);
    for(auto const& arg: args) {
        _debug(cli, "      arg: %s", arg.c_str());
    }

}


void load_defaults() {
    CliState::get().orig_ssl_loglevel = SSLCom::log_level();
    CliState::get().orig_sslmitm_loglevel = SSLMitmCom::log_level();
    CliState::get().orig_sslca_loglevel = *SSLFactory::get_log().level();

    CliState::get().orig_dns_insp_loglevel = DNS_Inspector::log_level();
    CliState::get().orig_dns_packet_loglevel = DNS_Packet::log_level();

    CliState::get().orig_baseproxy_loglevel = baseProxy::log_level();
    CliState::get().orig_epoll_loglevel = epoll::log_level;
    CliState::get().orig_mitmproxy_loglevel = MitmProxy::log_level();
    CliState::get().orig_mitmmasterproxy_loglevel = MitmMasterProxy::log_level();
}



void cmd_show_status(struct cli_def* cli) {

    cli_print(cli,"Version: %s%s",SMITH_VERSION,SMITH_DEVEL ? " (dev)" : "");
    cli_print(cli,"Socle: %s%s",SOCLE_VERSION,SOCLE_DEVEL ? " (dev)" : "");
#if ( (SMITH_DEVEL > 0) || (SOCLE_DEVEL > 0))
    cli_print(cli, "Smithproxy source info: %s", SX_GIT_VERSION);
    cli_print(cli, "                branch: %s commit: %s", SX_GIT_BRANCH, SX_GIT_COMMIT_HASH);

    cli_print(cli, " Socle lib source info: %s", SOCLE_GIT_VERSION);
    cli_print(cli, "                branch: %s commit: %s", SOCLE_GIT_BRANCH, SOCLE_GIT_COMMIT_HASH);

#endif

std::stringstream features;
#ifndef BUILD_RELEASE
    features << "DEBUG ";  // slower
#endif
#ifdef USE_UNWIND
    features << "UNWIND ";
#endif
#ifdef MEMPOOL_ALL
    features << "MEMPOOL_ALL ";  // using everything from pool
#endif
#ifdef MEMPOOL_DEBUG
    features << "MEMPOOL_DEBUG ";  // much slower
#endif
#ifdef USE_PYTHON
    features << "PYTHON ";
#endif
#ifdef USE_LMHPP
    features << "LMHPP ";
#endif

#ifdef USE_EXPERIMENT
    features << "EXPERIMENTAL ";
#endif
    cli_print(cli, "Built with: %s", features.str().c_str());


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



    if(CfgFactory::get()->accept_tproxy) {
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

    if(CfgFactory::get()->accept_redirect) {
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

    } else {
        cli_print(cli," ");
        cli_print(cli, "Redirect acceptors: disabled");
    }

    if(CfgFactory::get()->accept_socks) {
        cli_print(cli," ");
        cli_print(cli, "Socks acceptors:");
        cli_print(cli, "  TCP: %2zu workers: %2zu",
                  SmithProxy::instance().socks_proxies.size(),
                  SmithProxy::instance().socks_proxies.size() * get_task_count(SmithProxy::instance().socks_proxies));
    } else {
        cli_print(cli," ");
        cli_print(cli, "SOCKS acceptors: disabled");
    }

    cli_print(cli," ");
    const time_t uptime = time(nullptr) - SmithProxy::instance().ts_sys_started;
    cli_print(cli,"Uptime: %s",uptime_string(uptime).c_str());

    {
        auto lc_ = std::scoped_lock(sobjectDB::getlock());
        cli_print(cli, "Objects: %lu", static_cast<unsigned long>(socle::sobjectDB::db().size()));
    }
    const unsigned long l = MitmProxy::total_mtr_up().get();
    const unsigned long r = MitmProxy::total_mtr_down().get();
    cli_print(cli,"Performance: upload %sbps, download %sbps in last 60 seconds",number_suffixed(l*8).c_str(),number_suffixed(r*8).c_str());

    const unsigned long t = MitmProxy::total_mtr_up().total() + MitmProxy::total_mtr_down().total();
    cli_print(cli,"Transferred: %s bytes", number_suffixed(t).c_str());
    cli_print(cli,"Total sessions: %lu", static_cast<unsigned long>(MitmProxy::total_sessions().load()));

    if(CfgFactory::board()->version_saved() < CfgFactory::board()->version_current()) {
        cli_print(cli, "\n*** Configuration changes NOT saved ***");
    }

}

void cmd_show_events_list(struct cli_def* cli) {

    std::stringstream  ss;

    auto& events = Log::get()->events();
    {
        auto lc_ = std::scoped_lock(events.events_lock());
        for (auto const& [ id, ev ]: events.entries()) {
            auto found = ( events.event_details().find(id) != events.event_details().end() );
            ss << (found ? "* " : "  ") << id << ": " << ev << "\r\n";
        }
    }
    cli_print(cli, ss.str().c_str());
}

void cmd_show_events_detail(struct cli_def* cli, std::vector<std::string> const& args) {

    if(args.empty()) {
        cli_print(cli, "enter event ID please");
        return;
    }
    auto val = safe_ull_value(args[0]).value_or(0);
    if(val <= 0) {
        cli_print(cli, "enter valid event ID please");
        return;
    }

    std::stringstream  ss;


    auto& events = Log::get()->events();
    {
        auto lc_ = std::scoped_lock(events.events_lock());
        auto it = events.event_details().find(val);
        if(it != events.event_details().end()) {
            cli_print(cli, "%s", it->second.c_str());
        } else {
            cli_print(cli, "no details for this event id %lld", val);
        }
    }
    cli_print(cli, ss.str().c_str());
}

void cmd_exec_events_clear(struct cli_def* cli) {

    Log::get()->events().clear();
    Log::get()->events().insert(CRI, "events cleared by admin");
    cli_print(cli, "Events cleared");
}

int cli_show_status(struct cli_def *cli, const char *command, char *argv[], int argc)
{
    debug_cli_params(cli, command, argv, argc);

    cmd_show_status(cli);
    return CLI_OK;
}


int cli_show_events_list(struct cli_def *cli, const char *command, char *argv[], int argc)
{
    debug_cli_params(cli, command, argv, argc);

    cmd_show_events_list(cli);
    return CLI_OK;
}

int cli_show_events_detail(struct cli_def *cli, const char *command, char *argv[], int argc)
{
    debug_cli_params(cli, command, argv, argc);

    cmd_show_events_detail(cli, args_to_vec(argv, argc));
    return CLI_OK;
}


int cli_exec_kb_print(struct cli_def *cli, const char *command, char *argv[], int argc)
{
    debug_cli_params(cli, command, argv, argc);

    std::string dump;
    {
        auto kb = sx::KB::get();
        auto lc_ = std::scoped_lock(sx::KB::lock());
        dump = kb->to_json().dump(4);
    }

    cli_print(cli, "Knowledgebase dump:");
    cli_print(cli, "%s", dump.c_str());

    return CLI_OK;
}


int cli_exec_kb_clear(struct cli_def *cli, const char *command, char *argv[], int argc)
{
    debug_cli_params(cli, command, argv, argc);

    std::size_t sz = 0;

    {
        auto kb = sx::KB::get();
        auto lc_ = std::scoped_lock(sx::KB::lock());

        sz = kb->elements.size();
        kb->elements.clear();
    }

    cli_print(cli, "Knowledgebase cleared %zu entries", sz);

    return CLI_OK;
}



int cli_exec_events_clear(struct cli_def *cli, const char *command, char *argv[], int argc)
{
    debug_cli_params(cli, command, argv, argc);

    cmd_exec_events_clear(cli);
    return CLI_OK;
}

int cli_test_dns_genrequest(struct cli_def *cli, const char *command, char *argv[], int argc) {
    debug_cli_params(cli, command, argv, argc);

    buffer b(1024);

    if(argc > 0) {
        const std::string argv0(argv[0]);
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
        const auto id = *(unsigned short*)rand_pool;

        int s = DNSFactory::get().generate_dns_request(id,b,argv[0],A);
        cli_print(cli,"DNS generated request: \n%s, %dB",hex_dump(b).c_str(), s);
    } else {
        cli_print(cli,"you need to specify hostname");
    }

    return CLI_OK;
}

int cli_test_webhook(struct cli_def *cli, const char *command, char *argv[], int argc) {

    auto fd = fileno(cli->client);

    auto args = args_to_vec(argv, argc);
    if(args.size() != 1) {
        cli_print(cli, "missing URL argument (for simple POST json message)");
        return CLI_OK;
    }
    auto const& url = args[0];
    sx::http::AsyncRequest::emit(url, R"({"key": "value"})", [fd](auto reply) {

        // this is potentially dangerous: cli may not exist, because it's hook called after operation finished

        const long code = reply.has_value() ? reply->first : -1;
        const std::string msg = reply.has_value() ? reply->second : "request failed";

        // check at least if client socket is still mapped to targets, so cli is valid
        if (Log::get()->target_profiles().find((uint64_t) fd) != Log::get()->target_profiles().end()) {
            auto log = string_format("Response: %ld:%s\r\n", code, msg.c_str());
            [[maybe_unused]] auto wr_ret = ::write(fd, log.c_str(), log.size());
        }
    });

    return CLI_OK;
}


DNS_Response* send_dns_request(struct cli_def *cli, std::string const& hostname, DNS_Record_Type t, const AddressInfo &nameserver) {

    buffer b(1024);
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
    int send_socket = socket(nameserver.family, SOCK_DGRAM, IPPROTO_UDP);

    if(0 != ::connect(send_socket,(sockaddr const*) nameserver.as_ss(), sizeof(sockaddr_storage))) {
        cli_print(cli, "cannot connect socket");
        ::close(send_socket);
        return CLI_OK;
    }

    if(::send(send_socket, b.data(), b.size(), 0) < 0) {
        const std::string r = string_format("logger::write_log: cannot write remote socket: %d",send_socket);
        cli_print(cli,"%s",r.c_str());

        ::close(send_socket); // coverity: 1407944
        return CLI_OK;
    }

    epoll e;
    e.init();
    e.add(send_socket, EPOLLIN);

    int rv = e.wait(4000);
    if(rv >= 1) {
        buffer recv_buf(1500);
        auto l = ::recv(send_socket, recv_buf.data(), recv_buf.capacity(), 0);

        if(l > 0) {
            recv_buf.size(l);

            cli_print(cli, "received %zd bytes", l);
            cli_print(cli, "\n%s\n", hex_dump(recv_buf).c_str());


            auto* resp = new DNS_Response();
            auto parsed = resp->load(&recv_buf);
            cli_print(cli, "parsed %zd bytes (0 means all)", parsed.value_or(-1));
            cli_print(cli, "DNS response: \n %s", resp->str().c_str());

            // save only fully parsed messages
            if(parsed == 0) {
                ret = resp;

            } else {
                delete resp;
            }

        } else {
            cli_print(cli, "recv() returned %zd", l);
        }

    } else {
        cli_print(cli, "timeout, or an error occurred.");
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

        auto const& nameserver = DNS_Setup::choose_dns_server(0);

        auto resp = std::shared_ptr<DNS_Response>(send_dns_request(cli,argv0,A, nameserver));
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
        auto lc_ = std::scoped_lock(CfgFactory::lock());

        for (auto const& a: CfgFactory::get()->db_address) {
            auto fa = std::dynamic_pointer_cast<FqdnAddress>(a.second);
            if (fa) {
                fqdns.push_back(fa->fqdn());
            }
        }
    }

    auto const& nameserver = DNS_Setup::choose_dns_server(0);

    for(auto const& a: fqdns) {

        {
            auto resp = std::shared_ptr<DNS_Response>(send_dns_request(cli, a, A, nameserver));
            if (resp) {
                if (DNS_Inspector::store(resp)) {
                    cli_print(cli, "Entry successfully stored in cache.");
                }
            }
        }

        auto resp = std::shared_ptr<DNS_Response>(send_dns_request(cli, a, AAAA ,nameserver));
        if(resp) {
            if(DNS_Inspector::store(resp)) {
                cli_print(cli, "Entry successfully stored in cache.");
            }
        }
    }

    return CLI_OK;
}



void cli_print_log_levels(struct cli_def *cli) {

    auto const& lp = Log::get()->target_profiles()[(uint64_t)fileno(cli->client)];

    cli_print(cli,"THIS cli logging level set to: %d",lp->level_.level());
    cli_print(cli, "Internal logging level set to: %d", Log::get()->level().level());
    cli_print(cli,"\n");
    for(auto const& [ target, mut ]: Log::get()->remote_targets()) {
        cli_print(cli, "Logging level for remote: %s: %d",
                  Log::get()->target_name((uint64_t)target),
                  Log::get()->target_profiles()[(uint64_t)target]->level_.level());
    }
    for(auto const& [ o_ptr, mut]: Log::get()->targets()) {
        cli_print(cli, "Logging level for target: %s: %d",
                  Log::get()->target_name((uint64_t)(o_ptr.get())),
                  Log::get()->target_profiles()[(uint64_t)(o_ptr.get())]->level_.level());
    }
}


int cli_debug_level(struct cli_def *cli, const char *command, char *argv[], int argc) {

    debug_cli_params(cli, command, argv, argc);

    auto const& lp = Log::get()->target_profiles()[(uint64_t)fileno(cli->client)];
    if(argc > 0) {

        std::string a1 = argv[0];

        if(a1 == "?") {
            cli_print(cli,"valid parameters: %s", CliState::get().debug_levels);
        }
        else if(a1 == "reset") {
            lp->level_ = NON;

            Log::get()->level(CfgFactory::get()->internal_init_level);
            cli_print(cli, "internal logging level changed to %d", Log::get()->level().level());
        }
        else {
            //cli_print(cli, "called %s with %s, argc %d\r\n", __FUNCTION__, command, argc);
            int newlev = safe_val(argv[0]);
            if(newlev >= 0) {
                Log::get()->level(loglevel(newlev, 0));
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

    auto const& lp = Log::get()->target_profiles()[(uint64_t)fileno(cli->client)];
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
                newlev = static_cast<int>(CfgFactory::get()->internal_init_level.level());
            } else {
                newlev = safe_val(argv[0]);
            }

            if(newlev >= 0) {
                for(auto const& [ o_ptr, mut ]: Log::get()->targets()) {

                    std::string fnm = Log::get()->target_name((uint64_t)(o_ptr.get()));

                    std::scoped_lock<std::recursive_mutex> l_(CfgFactory::lock());

                    if( fnm == CfgFactory::get()->log_file ) {

                        cli_print(cli, "changing '%s' loglevel to %d", fnm.c_str(), newlev);
                        Log::get()->target_profiles()[(uint64_t) (o_ptr.get())]->level_.level(newlev);
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
            SSLCom::log_level() = CliState::get().orig_ssl_loglevel;
            SSLMitmCom::log_level() = CliState::get().orig_sslmitm_loglevel;
            SSLFactory::get_log().level(CliState::get().orig_sslca_loglevel);
        }
        else {
            newlev = safe_val(argv[0]);
            SSLCom::log_level().level(newlev);
            SSLMitmCom::log_level().level(newlev);
            SSLFactory::get_log().level(loglevel(newlev));

        }
    } else {
        unsigned int l = SSLCom::log_level().level();
        cli_print(cli,"SSL debug level: %d",l);
        l = SSLMitmCom::log_level().level();
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
            AuthFactory::log_level() = CliState::get().orig_auth_loglevel;
        }
        else {
            newlev = safe_val(a1);
            AuthFactory::log_level().level(newlev);

        }
    } else {
        unsigned int l = AuthFactory::log_level().level();
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
            DNS_Inspector::log_level() = CliState::get().orig_dns_insp_loglevel;
            DNS_Packet::log_level() = CliState::get().orig_dns_packet_loglevel;
        }
        else {
            int lev = std::stoi(argv[0]);
            DNS_Inspector::log_level().level(lev);
            DNS_Packet::log_level().level(lev);

        }
    } else {
        unsigned int l = DNS_Inspector::log_level().level();
        cli_print(cli,"DNS Inspector debug level: %d",l);
        l = DNS_Packet::log_level().level();
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
            baseProxy::log_level() = CliState::get().orig_baseproxy_loglevel;
            epoll::log_level = CliState::get().orig_epoll_loglevel;

            MitmMasterProxy::log_level() = CliState::get().orig_mitmproxy_loglevel;
            MitmHostCX::log_level() = CliState::get().orig_mitmhostcx_loglevel;
            MitmProxy::log_level() = CliState::get().orig_mitmproxy_loglevel;
            SocksProxy::log_level() = CliState::get().orig_socksproxy_loglevel;
        }
        else {
            int lev = std::stoi(argv[0]);
            baseProxy::log_level().level(lev);
            epoll::log_level.level(lev);

            MitmMasterProxy::log_level().level(lev);
            MitmHostCX::log_level().level(lev);
            MitmProxy::log_level().level(lev);
            SocksProxy::log_level().level(lev);

        }
    } else {
        unsigned int l = baseProxy::log_level().level();
        cli_print(cli,"baseProxy debug level: %d",l);

        l = epoll::log_level.level();
        cli_print(cli,"epoll debug level: %d",l);

        l = MitmMasterProxy::log_level().level();
        cli_print(cli,"MitmMasterProxy debug level: %d",l);

        l = MitmHostCX::log_level().level();
        cli_print(cli,"MitmHostCX debug level: %d",l);

        l = MitmProxy::log_level().level();
        cli_print(cli,"MitmProxy debug level: %d",l);

        l = SocksProxy::log_level().level();
        cli_print(cli,"SocksProxy debug level: %d",l);


        cli_print(cli,"\n");
        cli_print(cli,"valid parameters: %s", CliState::get().debug_levels);
    }

    return CLI_OK;
}


int cli_debug_show(struct cli_def *cli, const char *command, char *argv[], int argc) {

    debug_cli_params(cli, command, argv, argc);

    unsigned int l = baseProxy::log_level().level();
    cli_print(cli,"baseProxy debug level: %d",l);

    l = epoll::log_level.level();
    cli_print(cli,"epoll debug level: %d",l);

    l = MitmMasterProxy::log_level().level();
    cli_print(cli,"MitmMasterProxy debug level: %d",l);

    l = MitmHostCX::log_level().level();
    cli_print(cli,"MitmHostCX debug level: %d",l);

    l = MitmProxy::log_level().level();
    cli_print(cli,"MitmProxy debug level: %d",l);

    l = SocksProxy::log_level().level();
    cli_print(cli,"SocksProxy debug level: %d",l);


    cli_print(cli, "\n\nlogan light loggers");

    std::stringstream ss;

    auto log = logan::get();

    for(auto const& i: log->topic_db_) {
        std::string t = i.first;
        auto lev = i.second;

        ss << "    [" << t << "] => level " << lev->level() << " flag: " << lev->topic() << "\n";
    }

    cli_print(cli, "%s", ss.str().c_str());

    return CLI_OK;
}



int cli_debug_set(struct cli_def *cli, const char *command, char *argv[], int argc) {

    debug_cli_params(cli, command, argv, argc);

    std::set<std::string> topics;
    std::stringstream topiclist;

    auto log = logan::get();

    auto args = args_to_vec(argv, argc);

    for(auto const& i: log->topic_db_) {
        std::string t = i.first;
        // loglevel l = i.second;

        topics.insert(t);
        topiclist << t << "\n";
    }
    if(not args.empty()) {

        auto var = args[0];

        if(var == "all" || var == "*") {

            int newlev = -1;
            if(args.size() > 1) {
                newlev = safe_val(args[1]);
            }

            for(auto const& lv: log->topic_db_) {

                auto orig_l = log->level(lv.first);
                if(newlev >= 0) {
                    log->entry(lv.first)->level(newlev);
                    cli_print(cli, "debug level changed: %s: %d => %d", lv.first.c_str(), orig_l, newlev);
                } else {
                    cli_print(cli, "debug level: %s: %d", lv.first.c_str(), orig_l);
                }
            }
        }
        else if(var == "cli") {
            int  newlev = -1;
            if(args.size() > 1) {
                newlev = safe_val(args[1]);
                CliState::get().cli_debug_flag = (newlev > 0);
            }
            cli_print(cli, "cli debug now %s", CliState::get().cli_debug_flag ? "ON" : "OFF");
        }
        else if(var == "filter") {
            std::string filter_val;
            if(args.size() > 1) filter_val = args[1];

            if(not filter_val.empty()) {
                logan_lite::context_filter.active(false);
                logan_lite::context_filter.set(filter_val);
                logan_lite::context_filter.active(true);

                cli_print(cli, "\nLogging context filter set to: '%s'", filter_val.c_str());
            } else {
                logan_lite::context_filter.active(false);
                logan_lite::context_filter.set("");

                cli_print(cli, "\nLogging context filter '%s' deactivated", logan_lite::context_filter.value().c_str());
            }
        }
        else {
            int  newlev = -1;
            if(args.size() > 1)
                newlev = safe_val(args[1]);

            if(log->topic_db_.find(var) != log->topic_db_.end()) {

                unsigned int old_lev = log->entry(var)->level();

                if(newlev >= 0) {
                    log->entry(var)->level(newlev);

                    cli_print(cli, "debug level changed: %s: %d => %d", var.c_str(), old_lev, newlev);
                } else {
                    cli_print(cli, "debug level: %s: %d", var.c_str(), old_lev);
                }

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
        cli_print(cli, "         \n");

        if(not logan_lite::context_filter.active()) {
            cli_print(cli, "Context filter inactive\n");
        } else {
            cli_print(cli, "Context filter ON:\n");
            cli_print(cli, "   '%s'\n", logan_lite::context_filter.value().c_str());
        }

    }
    return CLI_OK;
}




int cli_save_config(struct cli_def *cli, const char *command, char *argv[], int argc) {
    debug_cli_params(cli, command, argv, argc);

    int n = CfgFactory::get()->save_config();
    if(n < 0) {
        cli_print(cli, "error writing config file!");
    }
    else {
        cli_print(cli, "config saved successfully.");

        CfgFactory::board()->save(cli_id());
        CfgFactory::board()->ack_saved(cli_id());

        apply_hostname(cli);
    }
    return CLI_OK;
}


int cli_exec_reload(struct cli_def *cli, const char *command, char *argv[], int argc) {
    debug_cli_params(cli, command, argv, argc);

    bool CONFIG_LOADED = SmithProxy::instance().load_config(CfgFactory::get()->config_file, true);
    CfgFactory::board()->rollback(cli_id());

    if(CONFIG_LOADED) {
        cli_print(cli, "Configuration file reloaded successfully");

        CfgFactory::board()->ack_current(cli_id());
        apply_hostname(cli);

    } else {
        cli_print(cli, "Configuration file reload FAILED");
    }

    return CLI_OK;
}

int cli_exec_pcap_rollover(struct cli_def *cli, const char *command, char *argv[], int argc) {
    debug_cli_params(cli, command, argv, argc);

    auto& single = socle::traflog::PcapLog::single_instance();
    single.rotate_now = true;

    return CLI_OK;
}



int cli_exec_shutdown(struct cli_def *cli, const char *command, char *argv[], int argc) {
    debug_cli_params(cli, command, argv, argc);

    cli_print(cli, " ");
    cli_print(cli, " !!!   terminating smithproxy   !!!");
    cli_print(cli, " ");

    auto counter = std::thread([&cli]{
        timespec t {};
        t.tv_sec = 1;

        while(not SmithProxy::instance().terminated) {
            const unsigned long prsz = MitmProxy::current_sessions().load();
            cli_print(cli, "  -    proxies remaining: %lu", prsz);

            nanosleep(&t, nullptr);
            t.tv_sec = 3;
        }
    });

    SmithProxy::instance().terminate_flag = true;
    counter.join();

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

bool apply_setting(std::string const& section, std::string const& varname, struct cli_def *cli) {

    _debug(cli, "apply_setting: %s", section.c_str());

    auto ret = CfgFactory::get()->apply_config_change(section);

    if(not ret) {
        cli_print(cli, "config apply - unknown config section!");
    }


    if(! ret) {
        cli_print(cli, "!!! Config was not applied");
        cli_print(cli, " -  saving and reload is necessary to apply your settings.");
    } else {


        CfgFactory::board()->upgrade(cli_id());

        apply_hostname(cli);
        cli_print(cli, " ");
        cli_print(cli, "Running config applied (not saved to file).");
    }

    return ret;
}

int cli_uni_set_cb(std::string const& confpath, struct cli_def *cli, const char *command, char *argv[], int argc) {
    debug_cli_params(cli, command, argv, argc);

    if (CfgFactory::cfg_obj().exists(confpath)) {

        auto normalized = CfgValueCleaner::normalize(command, argv, argc);

        _debug(cli, "var: %s", normalized.varname.c_str());

        auto lc_ = std::scoped_lock(CfgFactory::lock());
        Setting& conf = CfgFactory::cfg_obj().lookup(confpath);

        if(! conf.exists(normalized.varname)) {
            cli_print(cli, "set: cannot find varname %s", normalized.varname.c_str() );
            return CLI_OK;
        }

        if (! normalized.is_question) {


            auto [ write_status, write_msg ] = CfgFactory::get()->cfg_write_value(conf, false, normalized.varname, normalized.args);
            if (write_status) {
                _debug(cli, "change written to current config");
                cli_print(cli, " ");

                if (not apply_setting( conf.getPath(), normalized.varname , cli )) {
                    CliStrings::cli_print(cli, CliStrings::config_not_applied());
                }

                // write on board there is a new configuration
                CfgFactory::board()->upgrade(cli_id());
            } else {

                //  display error only if arguments were present
                if(not normalized.args.empty()) {
                    cli_print(cli, " ");
                    cli_print(cli, "Error setting value");
                } else {
                    cli_print(cli, " ");
                    cli_print(cli, "Error setting empty value");
                }
            }

        } else {
            if (!conf.isRoot() && conf.getName()) {

                auto h = CfgValueHelp::get().help(CfgValueHelp::help_type_t::HELP_QMARK, conf.getPath(), normalized.varname);

                cli_print(cli, "hint:  %s (%s)", h.c_str(), conf.getPath().c_str());
            }
        }
    }

    return CLI_OK;
}


int cli_uni_toggle_cb(std::string const& confpath, struct cli_def *cli, const char *command, char *argv[], int argc) {
    debug_cli_params(cli, command, argv, argc);

    std::scoped_lock<std::recursive_mutex> l_(CfgFactory::lock());

    if (CfgFactory::cfg_obj().exists(confpath)) {

        auto normalized = CfgValueCleaner::normalize(command, argv, argc);

        _debug(cli, "var: %s", normalized.varname.c_str());

        std::scoped_lock<std::recursive_mutex> ll_(CfgFactory::lock());
        Setting& conf = CfgFactory::cfg_obj().lookup(confpath);

        if(! conf.exists(normalized.varname)) {
            cli_print(cli, "toggle: cannot find varname %s", normalized.varname.c_str() );
            return CLI_OK;
        }

        if (! normalized.is_question) {

            auto& this_conf = conf[normalized.varname.c_str()];

            if(this_conf.isArray() or this_conf.isList()) {
                std::vector<std::string> cfg_values;

                for(int i = 0; i < this_conf.getLength(); i++) {
                    std::string sub = this_conf[i];
                    cfg_values.emplace_back(sub);
                }
                normalized.args = CfgValueCleaner::toggle(cfg_values, normalized.args);
            }

            auto [ write_status, write_msg ] = CfgFactory::get()->cfg_write_value(conf, false, normalized.varname, normalized.args);
            if (write_status) {
                _debug(cli, "change written to current config");
                cli_print(cli, " ");

                if (not apply_setting( conf.getPath(), normalized.varname , cli )) {
                    CliStrings::cli_print(cli, CliStrings::config_not_applied());
                }
            } else {

                //  display error only if arguments were present
                if(not normalized.args.empty()) {
                    cli_print(cli, " ");
                    cli_print(cli, "Error setting value: %s", write_msg.c_str());
                } else {
                    cli_print(cli, " ");
                    cli_print(cli, "Error setting empty value: %s", write_msg.c_str());
                }
            }

        } else {
            if (!conf.isRoot() && conf.getName()) {

                auto h = CfgValueHelp::get().help(CfgValueHelp::help_type_t::HELP_QMARK, conf.getPath(), normalized.varname);

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

int cli_generic_toggle_cb(struct cli_def *cli, const char *command, char *argv[], int argc) {
    debug_cli_params(cli, command, argv, argc);
    return cli_uni_toggle_cb(CliState::get().sections(cli->mode), cli, command, argv, argc);
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
                    auto cli_edit = std::get<1>(callback_entry).cli("edit");
                    if(cli_edit)
                        cli_unregister_single(cli, cli_edit);



                    // unregister "remove <this>"
                    auto cli_remove = std::get<1>(callback_entry).cli("remove");
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
//                cli_unregister_all(cli, std::get<1>(callback_entry).cli("edit"));
//
//                // generate new CLI sub-tree
//                cli_generate_commands(cli, section, nullptr);
                }
                else {
                    cli_print(cli, "no callbacks for: %s", section.c_str());
                }
                cli_print(cli, "cannot remove: %s - only templated entries can be removed", section.c_str());
            }

            if(CfgFactory::board()->differs_current(cli_id())) {
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
                auto elem = CfgFactory::get()->section_element<CfgElement>(section, arg);
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
                CfgFactory::get()->cleanup_db_proto();
                CfgFactory::get()->load_db_proto();
            }
        }
        else if(section == "port_objects") {

            removed_internal = ( remove(section, vec_full_args) > 0 );
            if(removed_internal) {
                CfgFactory::get()->cleanup_db_port();
                CfgFactory::get()->load_db_port();
            }

        }
        else if(section == "address_objects") {

            removed_internal = ( remove(section, vec_full_args) > 0 );
            if(removed_internal) {
                CfgFactory::get()->cleanup_db_address();
                CfgFactory::get()->load_db_address();
            }
        }
        else if(section == "detection_profiles") {

            removed_internal = ( remove(section, vec_full_args) > 0 );
            if(removed_internal) {
                CfgFactory::get()->cleanup_db_prof_detection();
                CfgFactory::get()->load_db_prof_detection();
            }
        }
        else if(section == "content_profiles") {

            removed_internal = ( remove(section, vec_full_args) > 0 );
            if(removed_internal) {
                CfgFactory::get()->cleanup_db_prof_content();
                CfgFactory::get()->load_db_prof_content();
            }
        }
        else if(section == "tls_ca") {

            removed_internal = ( remove(section, vec_full_args) > 0 );
            if(removed_internal) {
                CfgFactory::get()->cleanup_db_tls_ca();
                CfgFactory::get()->load_db_tls_ca();
            }
        }
        else if(section == "tls_profiles") {

            removed_internal = ( remove(section, vec_full_args) > 0 );
            if(removed_internal) {
                CfgFactory::get()->cleanup_db_prof_tls();
                CfgFactory::get()->load_db_prof_tls();
            }
        }
        else if(section == "alg_dns_profiles") {

            removed_internal = ( remove(section, vec_full_args) > 0 );
            if(removed_internal) {
                CfgFactory::get()->cleanup_db_prof_alg_dns();
                CfgFactory::get()->load_db_prof_alg_dns();
            }
        }
        else if(section == "auth_profiles") {

            removed_internal = ( remove(section, vec_full_args) > 0 );
            if(removed_internal) {
                CfgFactory::get()->cleanup_db_prof_auth();
                CfgFactory::get()->load_db_prof_auth();
            }
        }
        else if(section == "routing") {

            removed_internal = ( remove(section, vec_full_args) > 0 );
            if(removed_internal) {
                CfgFactory::get()->cleanup_db_routing();
                CfgFactory::get()->load_db_routing();
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

                CfgFactory::get()->cleanup_db_policy();
                CfgFactory::get()->load_db_policy();
            }
        }


        if(removed_internal) {

            CfgFactory::board()->upgrade(cli_id());

            reconstruct_cli();

            CfgFactory::get()->cleanup_db_policy();
            CfgFactory::get()->load_db_policy();

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
                auto elem = CfgFactory::get()->db_policy_list.size();
                if (index_1 + 1 < static_cast<int>(elem))
                    index_2 = index_1 + 1;
            } else if (cmd_split[2] == "bottom") {

                auto elem = CfgFactory::get()->db_policy_list.size();
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
        if(CfgFactory::get()->move_policy(index_1, index_2, CfgFactory::op_move::OP_MOVE_AFTER)) {
            CfgFactory::get()->cleanup_db_policy();
            CfgFactory::get()->load_db_policy();

            cli_print(cli, " ");
            // cli_print(cli, "Policy moved.");

        } else {
            cli_print(cli, " ");
            cli_print(cli, "Error moving policies");
        }
    }
    else if(cmd_split[2] == "before" or cmd_split[2] == "up" or cmd_split[2] == "top") {
        if(CfgFactory::get()->move_policy(index_1, index_2, CfgFactory::op_move::OP_MOVE_BEFORE)) {
            CfgFactory::get()->cleanup_db_policy();
            CfgFactory::get()->load_db_policy();

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



auto register_cli_entry(struct cli_def *cli, std::string const& entry) {

    auto section = CliState::get().sections(cli->mode);

    // remove template suffix
    bool templated = false;
    if(section.find(".[x]") != std::string::npos) {
        templated = true;
        sx::str::string_replace_all(section, ".[x]", "");
    }

    // load callbacks, must prefer templated
    auto& callback_entry = templated ? CliState::get().callbacks(section + ".[x]") : CliState::get().callbacks(section);

    if(std::get<1>(callback_entry).cap("edit")) {

        auto cb_edit = std::get<1>(callback_entry).cli("edit");
        if(cb_edit) {
            auto cli_edit_x = cli_register_command(cli, cb_edit, entry.c_str(),
                                                   std::get<1>(callback_entry).cmd("edit"), PRIVILEGE_PRIVILEGED, cli->mode,
                                                   " edit new entry");

            // set also leaf node
            std::get<1>(CliState::get().callbacks(section + "." + entry)).cli("edit", cli_edit_x);
        }
    }

    if(std::get<1>(callback_entry).cap("move")) {
        auto cli_move = std::get<1>(callback_entry).cli("move");
        if(cli_move) {

            // 'add' has empty args when adding to an array, so let's be a bit nasty here
            if(section == "policy")
                cli_generate_move_commands(cli, cli->mode, cli_move, std::get<1>(callback_entry).cmd("move"),
                                           static_cast<int>(CfgFactory::get()->db_policy_list.size()-1),
                                           CfgFactory::get()->db_policy_list.size());
        }
    }

    if(std::get<1>(callback_entry).cap("remove")) {
        auto cli_remove = std::get<1>(callback_entry).cli("remove");

        if(cli_remove) {
            auto cli_remove_x = cli_register_command(cli, std::get<1>(callback_entry).cli("remove"), entry.c_str(),
                                                     std::get<1>(callback_entry).cmd("remove"), PRIVILEGE_PRIVILEGED, cli->mode,
                                                     " delete this entry");

            // set also leaf node
            std::get<1>(CliState::get().callbacks(section + "." + entry)).cli("remove", cli_remove_x);
        }
    }

    if(section == "policy") {
        // 'add' has empty args when adding to an array, so let's be a bit nasty here
        cli_generate_set_commands(cli, section + ".[" + string_format("%d]", static_cast<int>(CfgFactory::get()->db_policy_list.size()-1)));
    }
    else {
        cli_generate_set_commands(cli, section + "." + entry);
    }
};

int cli_generic_add_cb(struct cli_def *cli, const char *command, char *argv[], int argc) {
    debug_cli_params(cli, command, argv, argc);

    std::vector<std::string> args = args_to_vec(argv, argc);
    auto section = CliState::get().sections(cli->mode);

    // remove dynamic suffix
    if(section.find(".[x]") != std::string::npos) {
        sx::str::string_replace_all(section, ".[x]", "");
    }

    // returns true if ok to proceed


    if(auto const& [status, msg] = CfgFactory::cfg_add_prepare_params(section, args);  not status) {
        cli_print(cli, " %s", msg.c_str());
        return CLI_OK;
    } else if( not msg.empty()){
        cli_print(cli, " %s", msg.c_str());
    }

    auto [ status, msg ]  = CfgFactory::get()->cfg_add_entry(section, args[0]);
    if(status) {
        CfgFactory::board()->upgrade(cli_id());
    }

    cli_print(cli, "  ");
    cli_print(cli, " %s", msg.c_str());

    if (CfgFactory::board()->differs_current(cli_id())) {

        register_cli_entry(cli, args[0]);

        apply_hostname(cli);
        cli_print(cli, " ");
        cli_print(cli, "Running config applied (not saved to file).");
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
        index = safe_val(argv[0]);
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

int cli_show_config_routing(struct cli_def *cli, const char *command, char *argv[], int argc) {
    debug_cli_params(cli, command, argv, argc);

    cli_print_section(cli, "routing", -1, 1 * 1024 * 1024);
    return CLI_OK;
}

int cli_show_config_captures(struct cli_def *cli, const char *command, char *argv[], int argc) {
    debug_cli_params(cli, command, argv, argc);

    cli_print_section(cli, "captures", -1, 1 * 1024 * 1024);
    return CLI_OK;
}

#ifdef USE_EXPERIMENT
int cli_show_config_experiment(struct cli_def *cli, const char *command, char *argv[], int argc) {
    debug_cli_params(cli, command, argv, argc);

    cli_print_section(cli, "experiment", -1, 1 * 1024 * 1024);
    return CLI_OK;
}
#endif

void cli_register_static(struct cli_def* cli) {

    auto save  = cli_register_command(cli, nullptr, "save", nullptr, PRIVILEGE_PRIVILEGED, MODE_ANY, "save configs");
            cli_register_command(cli, save, "config", cli_save_config, PRIVILEGE_PRIVILEGED, MODE_ANY, "save config file");

    auto exec = cli_register_command(cli, nullptr, "execute", nullptr, PRIVILEGE_PRIVILEGED, MODE_ANY, "execute various tasks");
            [[maybe_unused]] auto exec_reload = cli_register_command(cli, exec, "reload", cli_exec_reload, PRIVILEGE_PRIVILEGED, MODE_ANY, "reload config file");
            [[maybe_unused]] auto exec_shutdown = cli_register_command(cli, exec, "shutdown", cli_exec_shutdown, PRIVILEGE_PRIVILEGED, MODE_ANY, "terminate this smithproxy process");
                             auto exec_pcap = cli_register_command(cli, exec, "pcap", nullptr, PRIVILEGE_UNPRIVILEGED, MODE_ANY, "manage PCAP writer");
                            [[maybe_unused]] auto exec_pcap_rollover = cli_register_command(cli, exec_pcap, "rollover", cli_exec_pcap_rollover, PRIVILEGE_PRIVILEGED, MODE_ANY, "rollover pcap file now");
                             auto exec_events = cli_register_command(cli, exec, "events", nullptr, PRIVILEGE_UNPRIVILEGED, MODE_ANY, "mange event messages");
                            [[maybe_unused]] auto exec_events_clear = cli_register_command(cli, exec_events, "clear", cli_exec_events_clear, PRIVILEGE_PRIVILEGED, MODE_ANY, "clear event ring buffer");
                             auto exec_kb = cli_register_command(cli, exec, "kb", nullptr, PRIVILEGE_UNPRIVILEGED, MODE_ANY, "mange KB");
                            [[maybe_unused]] auto exec_kb_print = cli_register_command(cli, exec_kb, "print", cli_exec_kb_print, PRIVILEGE_PRIVILEGED, MODE_ANY, "print all KB entries");
                            [[maybe_unused]] auto exec_kb_clear = cli_register_command(cli, exec_kb, "clear", cli_exec_kb_clear, PRIVILEGE_PRIVILEGED, MODE_ANY, "clear all KB entries");

    auto show  = cli_register_command(cli, nullptr, "show", cli_show, PRIVILEGE_UNPRIVILEGED, MODE_ANY, "show basic information");
            cli_register_command(cli, show, "status", cli_show_status, PRIVILEGE_UNPRIVILEGED, MODE_EXEC, "show smithproxy status");
            auto show_events = cli_register_command(cli, show, "event", nullptr, PRIVILEGE_UNPRIVILEGED, MODE_EXEC, "show event commands");
                            cli_register_command(cli, show_events, "list", cli_show_events_list, PRIVILEGE_UNPRIVILEGED, MODE_EXEC, "show event list");
                            cli_register_command(cli, show_events, "detail", cli_show_events_detail, PRIVILEGE_PRIVILEGED, MODE_EXEC, "show event detail");

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
                    cli_register_command(cli, show_config, "routing", cli_show_config_routing, PRIVILEGE_UNPRIVILEGED, MODE_ANY, "show smithproxy config section: routing");
                    cli_register_command(cli, show_config, "captures", cli_show_config_captures, PRIVILEGE_UNPRIVILEGED, MODE_ANY, "show smithproxy config section: captures");
                    #ifdef USE_EXPERIMENT
                    cli_register_command(cli, show_config, "experiment", cli_show_config_experiment, PRIVILEGE_UNPRIVILEGED, MODE_ANY, "show smithproxy config section: experiment");
                    #endif

    auto test  = cli_register_command(cli, nullptr, "test", nullptr, PRIVILEGE_UNPRIVILEGED, MODE_EXEC, "various testing commands");
            auto test_dns = cli_register_command(cli, test, "dns", nullptr, PRIVILEGE_UNPRIVILEGED, MODE_EXEC, "dns related testing commands");
                    cli_register_command(cli, test_dns, "genrequest", cli_test_dns_genrequest, PRIVILEGE_UNPRIVILEGED, MODE_EXEC, "generate dns request");
                    cli_register_command(cli, test_dns, "sendrequest", cli_test_dns_sendrequest, PRIVILEGE_UNPRIVILEGED, MODE_EXEC, "generate and send dns request to configured nameserver");
                cli_register_command(cli, test_dns, "refreshallfqdns", cli_test_dns_refreshallfqdns, PRIVILEGE_UNPRIVILEGED, MODE_EXEC, "refresh all configured FQDN address objects against configured nameserver");

            auto test_webhook = cli_register_command(cli, test, "webhook", cli_test_webhook, PRIVILEGE_UNPRIVILEGED, MODE_EXEC, "test webhook");


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

void generate_callbacks() {

    CliState::get().clear_all();

    register_callback("settings",MODE_EDIT_SETTINGS)
            .cap("set", true)
            .cmd("set", cli_generic_set_cb)
            .cap("edit", true)
            .cmd("edit", cli_conf_edit_settings)
            .cap("toggle", true)
            .cmd("toggle", cli_generic_toggle_cb);


    register_callback( "settings.auth_portal",MODE_EDIT_SETTINGS_AUTH)
            .cap("set", true)
            .cmd("set", cli_generic_set_cb)
            .cap("edit", true)
            .cmd("edit", cli_conf_edit_settings_auth);

    register_callback( "settings.tuning",MODE_EDIT_SETTINGS_TUNING)
            .cap("set", true)
            .cmd("set", cli_generic_set_cb)
            .cap("edit", true)
            .cmd("edit", cli_conf_edit_settings_tuning);

    register_callback( "settings.http_api",MODE_EDIT_SETTINGS_HTTP_API)
            .cap("set", true)
            .cmd("set", cli_generic_set_cb)
            .cap("edit", true)
            .cmd("edit", cli_conf_edit_settings_http_api)
            .cap("toggle", true)
            .cmd("toggle", cli_generic_toggle_cb);

    register_callback( "settings.webhook",MODE_EDIT_SETTINGS_WEBHOOK)
            .cap("set", true)
            .cmd("set", cli_generic_set_cb)
            .cap("edit", true)
            .cmd("edit", cli_conf_edit_settings_webhook);


    register_callback( "settings.admin",MODE_EDIT_SETTINGS_ADMIN)
            .cap("set", true)
            .cmd("set", cli_generic_set_cb)
            .cap("edit", true)
            .cmd("edit", cli_conf_edit_settings_admin)
            .cap("toggle", true)
            .cmd("toggle", cli_generic_toggle_cb);

    register_callback(
            "settings.nameservers",MODE_EDIT_SETTINGS + 1)
            .cap("set", true)
            .cmd("set", cli_generic_set_cb);

    register_callback(
            "settings.socks", MODE_EDIT_SETTINGS_SOCKS)
            .cap("set", true)
            .cmd("set", cli_generic_set_cb)
            .cap("edit", true)
            .cmd("edit", cli_conf_edit_settings_socks);


    register_callback("settings.cli", MODE_EDIT_SETTINGS_CLI)
            .cap("set", true)
            .cmd("set", cli_generic_set_cb)
            .cap("edit", true)
            .cmd("edit", cli_conf_edit_settings_cli);

    register_callback("debug", MODE_EDIT_DEBUG)
            .cap("set", true)
            .cmd("set", cli_generic_set_cb)
            .cap("edit", true)
            .cmd("edit", cli_conf_edit_debug);

    register_callback("debug.log", MODE_EDIT_DEBUG_LOG)
            .cap("set", true)
            .cmd("set", cli_generic_set_cb)
            .cap("edit", true)
            .cmd("edit", cli_conf_edit_debug_log);


    register_callback( "proto_objects", MODE_EDIT_PROTO_OBJECTS)
            .cap("edit", true)
            .cmd("edit", cli_conf_edit_proto_objects);

    register_callback( "proto_objects.[x]", MODE_EDIT_PROTO_OBJECTS)
            .cap("set", true)
            .cmd("set", cli_generic_set_cb)
            .cap("edit", true)
            .cmd("edit", cli_conf_edit_proto_objects)
            .cap("add", true)
            .cmd("add", cli_generic_add_cb)
            .cap("remove", true)
            .cmd("remove", cli_generic_remove_cb);


    register_callback("address_objects", MODE_EDIT_ADDRESS_OBJECTS)
            .cap("edit", true)
            .cmd("edit", cli_conf_edit_address_objects);

    register_callback("address_objects.[x]", MODE_EDIT_ADDRESS_OBJECTS)
            .cap("set", true)
            .cmd("set", cli_generic_set_cb)
            .cap("edit", true)
            .cmd("edit", cli_conf_edit_address_objects)
            .cap("add", true)
            .cmd("add", cli_generic_add_cb)
            .cap("remove", true)
            .cmd("remove", cli_generic_remove_cb);


    register_callback("port_objects", MODE_EDIT_PORT_OBJECTS)
            .cap("edit", true)
            .cmd("edit", cli_conf_edit_port_objects);

    register_callback("port_objects.[x]", MODE_EDIT_PORT_OBJECTS)
            .cap("set", true)
            .cmd("set", cli_generic_set_cb)
            .cap("edit", true)
            .cmd("edit", cli_conf_edit_port_objects)
            .cap("add", true)
            .cmd("add", cli_generic_add_cb)
            .cap("remove", true)
            .cmd("remove", cli_generic_remove_cb);


    register_callback("policy", MODE_EDIT_POLICY)
            .cap("edit", true)
            .cmd("edit", cli_conf_edit_policy);

    // template for policy list entries
    register_callback( "policy.[x]", MODE_EDIT_POLICY)
            .cap("set", true)
            .cmd("set", cli_generic_set_cb)
            .cap("add", true)
            .cmd("add", cli_generic_add_cb)
            .cap("remove", true)
            .cmd("remove", cli_generic_remove_cb)
            .cap("edit", true)
            .cmd("edit", cli_conf_edit_policy)
            .cap("move", true)
            .cmd("move", cli_policy_move_cb)
            .cap("toggle", true)
            .cmd("toggle", cli_generic_toggle_cb);

    register_callback("detection_profiles", MODE_EDIT_DETECTION_PROFILES)
            .cap("edit", true)
            .cmd("edit", cli_conf_edit_detection_profiles);

    register_callback("detection_profiles.[x]", MODE_EDIT_DETECTION_PROFILES)
            .cap("set", true)
            .cmd("set", cli_generic_set_cb)
            .cap("edit", true)
            .cmd("edit", cli_conf_edit_detection_profiles)
            .cap("add", true)
            .cmd("add", cli_generic_add_cb)
            .cap("remove", true)
            .cmd("remove", cli_generic_remove_cb);


    register_callback("content_profiles", MODE_EDIT_CONTENT_PROFILES)
            .cap("edit", true)
            .cmd("edit", cli_conf_edit_content_profiles);

    register_callback("content_profiles.[x]", MODE_EDIT_CONTENT_PROFILES)
            .cap("set", true)
            .cmd("set", cli_generic_set_cb)
            .cap("edit", true)
            .cmd("edit", cli_conf_edit_content_profiles)
            .cap("add", true)
            .cmd("add", cli_generic_add_cb)
            .cap("remove", true)
            .cmd("remove", cli_generic_remove_cb);


    register_callback("tls_profiles", MODE_EDIT_TLS_PROFILES)
            .cap("edit", true)
            .cmd("edit", cli_conf_edit_tls_profiles);

    register_callback("tls_profiles.[x]", MODE_EDIT_TLS_PROFILES)
            .cap("set", true)
            .cmd("set", cli_generic_set_cb)
            .cap("edit", true)
            .cmd("edit", cli_conf_edit_tls_profiles)
            .cap("add", true)
            .cmd("add", cli_generic_add_cb)
            .cap("remove", true)
            .cmd("remove", cli_generic_remove_cb)
            .cap("toggle", true)
            .cmd("toggle", cli_generic_toggle_cb);


    register_callback("auth_profiles", MODE_EDIT_AUTH_PROFILES)
            .cap("edit", true)
            .cmd("edit", cli_conf_edit_auth_profiles);

    register_callback("auth_profiles.[x]", MODE_EDIT_AUTH_PROFILES)
            .cap("set", true)
            .cmd("set", cli_generic_set_cb)
            .cap("edit", true)
            .cmd("edit", cli_conf_edit_auth_profiles)
            .cap("add", true)
            .cmd("add", cli_generic_add_cb)
            .cap("remove", true)
            .cmd("remove", cli_generic_remove_cb);

    register_callback("alg_dns_profiles", MODE_EDIT_ALG_DNS_PROFILES)
            .cap("edit", true)
            .cmd("edit", cli_conf_edit_alg_dns_profiles);

    register_callback("alg_dns_profiles.[x]", MODE_EDIT_ALG_DNS_PROFILES)
            .cap("set", true)
            .cmd("set", cli_generic_set_cb)
            .cap("edit", true)
            .cmd("edit", cli_conf_edit_alg_dns_profiles)
            .cap("add", true)
            .cmd("add", cli_generic_add_cb)
            .cap("remove", true)
            .cmd("remove", cli_generic_remove_cb);




    register_callback("starttls_signatures", MODE_EDIT_STARTTLS_SIGNATURES)
            .cap("edit", true)
            .cmd("edit", cli_conf_edit_starttls_signatures);

    register_callback("starttls_signatures.[x]", MODE_EDIT_STARTTLS_SIGNATURES)
            .cap("set", true)
            .cmd("set", cli_generic_set_cb)
                    // .cap("add", true).cmd("add", cli_generic_add_cb)
                    // .cap("remove", true).cmd("remove", cli_generic_remove_cb)
            .cap("edit", true)
            .cmd("edit", cli_conf_edit_starttls_signatures);

    register_callback("detection_signatures", MODE_EDIT_DETECTION_SIGNATURES)
            .cap("edit", true)
            .cmd("edit", cli_conf_edit_detection_signatures);


    register_callback("detection_signatures.[x]", MODE_EDIT_DETECTION_SIGNATURES)
            .cap("set", true)
            .cmd("set", cli_generic_set_cb)
                    // .cap("add", true).cmd("add", cli_generic_add_cb)
                    // .cap("remove", true).cmd("remove", cli_generic_remove_cb)
            .cap("edit", true)
            .cmd("edit", cli_conf_edit_detection_signatures);


    register_callback("routing", MODE_EDIT_ROUTING)
            .cap("edit", true)
            .cmd("edit", cli_conf_edit_routing);

    register_callback("routing.[x]", MODE_EDIT_ROUTING)
            .cap("set", true)
            .cmd("set", cli_generic_set_cb)
            .cap("edit", true)
            .cmd("edit", cli_conf_edit_routing)
            .cap("add", true)
            .cmd("add", cli_generic_add_cb)
            .cap("remove", true)
            .cmd("remove", cli_generic_remove_cb)
            .cap("toggle", true)
            .cmd("toggle", cli_generic_toggle_cb);

    register_callback("captures", MODE_EDIT_CAPTURES)
            .cap("edit", true)
            .cmd("edit", cli_conf_edit_captures);
    register_callback( "captures.local",MODE_EDIT_CAPTURES_LOCAL)
            .cap("set", true)
            .cmd("set", cli_generic_set_cb)
            .cap("edit", true)
            .cmd("edit", cli_conf_edit_captures_local);
    register_callback( "captures.remote",MODE_EDIT_CAPTURES_REMOTE)
            .cap("set", true)
            .cmd("set", cli_generic_set_cb)
            .cap("edit", true)
            .cmd("edit", cli_conf_edit_captures_remote);

#ifdef USE_EXPERIMENT
    register_callback("experiment", MODE_EDIT_EXPERIMENT)
            .cap("set", true)
            .cmd("set", cli_generic_set_cb)
            .cap("edit", true)
            .cmd("edit", cli_conf_edit_experiment);
#endif

}


void register_regular_callback(cli_def* cli) {

    auto regular_callback = [](cli_def* cli) {

        if(CfgFactory::board()->differs(cli_id())) {
            apply_hostname(cli);

            // exit only if config was updated by different update subscriber
            if(CfgFactory::board()->updater() != cli_id()) {
                generate_callbacks();
                register_edit_command(cli);

                cli_set_configmode(cli, MODE_EXEC, nullptr);
                cli_reprompt(cli);
            }
        }

        if(SmithProxy::instance().terminate_flag) {

            cli_print(cli, "\n\n !!!   Shutdown   !!!\n");
            return CLI_QUIT;
        }

        if(not SSLFactory::factory().is_ct_available() and not CliGlobals::ct_warning_flag) {
            cli_print(cli, "\r\n Warning: Certificate Transparency checks not available");
            cli_print(cli, "          - download it using `sx_download_ctlog` tool and restart service");

            CliGlobals::ct_warning_flag = true;
        }

        return CLI_OK;
    };
    cli_regular(cli, regular_callback);
}

void register_edit_command(cli_def* cli) {

    if(CliState::get().cmd_edit_root) {
        cli_unregister_all(cli, CliState::get().cmd_edit_root);
    }
    CliState::get().cmd_edit_root = cli_register_command(cli, nullptr, "edit", nullptr, PRIVILEGE_PRIVILEGED, MODE_CONFIG, "configure smithproxy settings");


    std::vector<std::string> edit_sections = {"settings", "debug",
                                              "proto_objects", "address_objects", "port_objects" ,
                                              "detection_profiles", "content_profiles", "tls_profiles", "auth_profiles",
                                              "alg_dns_profiles",
                                              "routing",
#ifdef USE_EXPERIMENT
            "experiment",
#endif
                                              "captures",
                                              "policy",
                                              "starttls_signatures",
                                              "detection_signatures" };

    auto gen_edit_sections = [&]() {
        for (auto const &section : edit_sections) {

            if (CfgFactory::cfg_root().exists(section.c_str())) {

                std::string edit_help = string_format(" \t - edit %s", section.c_str());
                auto &callback_entry = CliState::get().callbacks(section);

                cli_register_command(cli, CliState::get().cmd_edit_root, section.c_str(), std::get<1>(callback_entry).cmd("edit"),
                                     PRIVILEGE_PRIVILEGED, MODE_CONFIG, edit_help.c_str());

                std::scoped_lock<std::recursive_mutex> l_(CfgFactory::lock());
                cli_generate_commands(cli, section, nullptr);
            }
        }
    };

    gen_edit_sections();

}

#ifdef USE_PAM
int cli_auth_cb(cli_def* cli, const char* username, const char* password) {
    if(sx::auth::pam_auth_user_pass(username, password)) {
        if(sx::auth::unix_is_group_member(username, CfgFactory::get()->admin_group.c_str())) {

            if(CfgFactory::get()->cli_enable_password.empty()) {

                cli_set_privilege(cli, PRIVILEGE_PRIVILEGED);
                cli_set_configmode(cli, MODE_EXEC, nullptr);
            }

            return 0;
        }
        return -1;
    }
    return -2;
}
#endif


using fn_auth_cb = int(*)(cli_def*, const char*,const char*);
fn_auth_cb get_auth_callback() {
#ifdef USE_PAM
    return &cli_auth_cb;
#else
    return nullptr;
#endif
}

void client_thread(int client_socket) {

    static auto log = logan::create("service");

    struct cli_def *cli = cli_init();


    std::string admin_group;
    std::string enable_pwd;

    {
        // load stuff from cfgfactory
        auto lc_ = std::scoped_lock(CfgFactory::get()->lock());

        // RAII subscriber removing us from board after exit
        UpdateBoardSubscriber ubs(cli_id(), CfgFactory::board());
        admin_group = CfgFactory::get()->admin_group;
        enable_pwd = CfgFactory::get()->cli_enable_password;
    }
    // Set the hostname (shown in the prompt)
    apply_hostname(cli);

    Log::get()->events().insert(NOT, "admin CLI access");

    // Set the greeting
    cli_set_banner(cli, "--==[ Smithproxy command line utility ]==--");

    if (get_auth_callback() and not admin_group.empty()) {
        cli_set_auth_callback(cli, get_auth_callback());
    }

    if (not enable_pwd.empty()) {
        cli_allow_enable(cli, enable_pwd.c_str());
    }

    cli_register_static(cli);
    cli_regular_interval(cli, 1);

    generate_callbacks();
    register_edit_command(cli);

    // Pass the connection off to libcli
    Log::get()->remote_targets(string_format("cli-%d", client_socket), client_socket);

    auto lp = std::make_unique<logger_profile>();
    lp->level_ = CfgFactory::get()->cli_init_level;
    Log::get()->target_profiles()[(uint64_t)client_socket] = std::move(lp);


    load_defaults();

    register_regular_callback(cli);

    cli_loop(cli, client_socket);


    Log::get()->remote_targets().remove_if([client_socket](auto const& e) { return e.first == client_socket; });
    Log::get()->target_profiles().erase(client_socket);
    close(client_socket);

    // Free data structures
    cli_done(cli);
}

void cli_loop(short unsigned int port) {

    static auto log = logan::create("service");
    sockaddr_in servaddr{};
    int on = 1;

    // Create a socket
    int s = socket(AF_INET, SOCK_STREAM, 0);
    setsockopt(s, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on));

    memset(&servaddr, 0, sizeof(servaddr));
    servaddr.sin_family = AF_INET;
    servaddr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    servaddr.sin_port = htons(port);

    while(0 != bind(s, (struct sockaddr *)&servaddr, sizeof(servaddr))) {

        if(SmithProxy::instance().terminate_flag) return;

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


    std::vector<std::thread> cli_threads;

    while(true) {
        int nfds = epoller.wait(1000);

        if(nfds > 0) {
            sockaddr_storage addr {};
            socklen_t addr_len {0};

            client_socket = accept(s, (struct sockaddr*)&addr, &addr_len);

            auto cli_thr = std::thread(client_thread, client_socket);
            cli_threads.emplace_back(std::move(cli_thr));
        }

        if(SmithProxy::instance().terminate_flag) {
            break;
        }
    }

    std::for_each(cli_threads.begin(), cli_threads.end(), [](auto& x){
        if(x.joinable()) {
            x.join();
        }
    });

}


int cli_show(struct cli_def *cli, const char *command, char **argv, int argc) {

    debug_cli_params(cli, command, argv, argc);

    cli_print_section(cli, CliState::get().sections(cli->mode), -1, 200 * 1024);

    return CLI_OK;
}
