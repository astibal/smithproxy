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
#include <cstdlib>
#include <ctime>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <linux/sockios.h>
#include <arpa/inet.h>
#include <unistd.h>

#include <openssl/rand.h>
#include <biostring.hpp>

#include <log/logger.hpp>

#include <cli/cmdserver.hpp>
#include <cli/cligen.hpp>

#include <cfgapi.hpp>
#include <timeops.hpp>

#include <socle.hpp>
#include <sslcom.hpp>
#include <sslcertstore.hpp>

#include <main.hpp>
#include <sobject.hpp>

#include <service/smithproxy.hpp>
#include <proxy/mitmproxy.hpp>
#include <proxy/socks5/socksproxy.hpp>
#include <policy/inspectors.hpp>
#include <policy/authfactory.hpp>

#include <inspect/sigfactory.hpp>
#include <inspect/dnsinspector.hpp>





extern bool cfg_openssl_mem_dbg;

#include "socle_version.h"
#include "smithproxy_version.h"


using namespace socle;


void apply_hostname(cli_def* cli) {
    char hostname[64]; memset(hostname,0,64);
    gethostname(hostname,63);

    cli_set_hostname(cli, string_format("smithproxy(%s)%s ", hostname, CliState::get().config_changed_flag ? "<*>" : "").c_str());
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
    cli_print(cli,"Built: %s", __TIMESTAMP__);
#endif

    int sq_plain = SmithProxy::instance().plain_proxy->sq_type();
    int sq_ssl = SmithProxy::instance().ssl_proxy->sq_type();
    int sq_udp = SmithProxy::instance().udp_proxy->sq_type();
    int sq_dtls = SmithProxy::instance().dtls_proxy->sq_type();

    cli_print(cli," ");

    cli_print(cli, "cores detected: %d, acc multi: %d recv multi: %d", std::thread::hardware_concurrency(),
              SmithProxy::instance().plain_proxy->core_multiplier(),
              SmithProxy::instance().udp_proxy->core_multiplier());

    cli_print(cli," ");

    cli_print(cli, "TCP   threads: %d", SmithProxy::instance().plain_proxy->task_count());
    cli_print(cli, "Socks threads: %d", SmithProxy::instance().socks_proxy->task_count());
    cli_print(cli, "UDP   threads: %d", SmithProxy::instance().udp_proxy->task_count());
    cli_print(cli, "TLS   threads: %d", SmithProxy::instance().ssl_proxy->task_count());
    cli_print(cli, "DTLS  threads: %d", SmithProxy::instance().dtls_proxy->task_count());
    cli_print(cli, "Acceptor hint: tcp:%d, tls:%d, udp:%d, dtls:%d", sq_plain, sq_ssl, sq_udp, sq_dtls);


    cli_print(cli," ");
    time_t uptime = time(nullptr) - SmithProxy::instance().ts_sys_started;
    cli_print(cli,"Uptime: %s",uptime_string(uptime).c_str());
    cli_print(cli,"Objects: %ld",socle::sobjectDB::db().cache().size());
    unsigned long l = MitmProxy::total_mtr_up().get();
    unsigned long r = MitmProxy::total_mtr_down().get();
    cli_print(cli,"Performance: upload %sbps, download %sbps in last second",number_suffixed(l*8).c_str(),number_suffixed(r*8).c_str());

    unsigned long t = MitmProxy::total_mtr_up().total() + MitmProxy::total_mtr_down().total();
    cli_print(cli,"Transferred: %s bytes", number_suffixed(t).c_str());
    cli_print(cli,"Total sessions: %lu", MitmProxy::total_sessions().load());

    if(CliState::get().config_changed_flag) {
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

        DNS_Response* resp = send_dns_request(cli,argv0,A,nameserver);
        if(resp) {
            DNS_Inspector di;
            if(di.store(resp)) {
                cli_print(cli, "Entry successfully stored in cache.");
            } else {
                delete resp;
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

        for (auto a: CfgFactory::get().db_address) {
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
        DNS_Response* resp =  send_dns_request(cli,a,A,nameserver);
        if(resp) {
            if(di.store(resp)) {
                cli_print(cli, "Entry successfully stored in cache.");
            } else {
                delete resp;
            }
        }

        resp = send_dns_request(cli,a,AAAA,nameserver);
        if(resp) {
            if(di.store(resp)) {
                cli_print(cli, "Entry successfully stored in cache.");
            } else {
                delete resp;
            }
        }
    }

    return CLI_OK;
}


int cli_diag_ssl_cache_stats(struct cli_def *cli, const char *command, char *argv[], int argc) {

    debug_cli_params(cli, command, argv, argc);

    SSLFactory* store = SSLCom::certstore();


    int n_cache = 0;
    {
        std::lock_guard<std::recursive_mutex> l(store->lock());
        n_cache = store->cache().size();
    };


    cli_print(cli,"certificate store stats: ");
    cli_print(cli,"    CN cert cache size: %d ",n_cache);

    return CLI_OK;
}


int cli_diag_ssl_cache_list(struct cli_def *cli, const char *command, char *argv[], int argc) {

    debug_cli_params(cli, command, argv, argc);

    SSLFactory* store = SSLCom::certstore();
    bool print_refs = false;

    if(argc > 0) {
        int lev = safe_val(argv[0]);
        if(lev >= 7) {
            print_refs = true;
        }
    }

    std::stringstream ss;

    cli_print(cli,"certificate store entries: ");

    {
        std::lock_guard<std::recursive_mutex> l_(store->lock());

        for (auto const& x: store->cache()) {
            std::string fqdn = x.first;
            SSLFactory::X509_PAIR* ptr = x.second;

            ss << string_format("    %s\n", fqdn.c_str());

            if(print_refs) {
                ss << string_format("        : keyptr=0x%x certptr=0x%x\n", ptr->first, ptr->second);
            }

            #ifndef USE_OPENSSL11
            if(print_refs)
               ss << string_format("            refcounts: key=%d cert=%d\n",ptr->first->references, ptr->second->references);
            #endif
        }
    }


    cli_print(cli, "%s", ss.str().c_str());

    return CLI_OK;
}

int cli_diag_ssl_cache_print(struct cli_def *cli, const char *command, char *argv[], int argc) {

    debug_cli_params(cli, command, argv, argc);

    SSLFactory *store = SSLCom::certstore();
    bool print_refs = false;

    if (argc > 0) {
        int lev = safe_val(argv[0]);
        if (lev >= 7) {
            print_refs = true;
        }
    }

    std::stringstream ss;

    cli_print(cli, "certificate store entries: \n");

    {
        std::lock_guard<std::recursive_mutex> l_(store->lock());

        for (auto x: store->cache()) {
            std::string fqdn = x.first;
            SSLFactory::X509_PAIR *ptr = x.second;

            std::regex r("\\+san:");
            std::string nice_fqdn = std::regex_replace(fqdn, r, "\n    san: ");

            ss << "--------: " << nice_fqdn << "\n-------- ";

            if(print_refs) {
                ss << string_format("--------: keyptr=0x%x certptr=0x%x\n", ptr->first, ptr->second);
            }

            ss << SSLFactory::print_cert(ptr->second);

            ss << "\n\n";
        }
    }

    cli_print(cli, "%s", ss.str().c_str());

    return CLI_OK;
}


int cli_diag_ssl_cache_clear(struct cli_def *cli, const char *command, char *argv[], int argc) {

    debug_cli_params(cli, command, argv, argc);

    SSLFactory* store = SSLCom::certstore();
    std::stringstream ss;


    {
        std::lock_guard<std::recursive_mutex> l_(store->lock());

        for (auto x: store->cache()) {
            std::string fqdn = x.first;
            ss << string_format("removing    %s\n",fqdn.c_str());
            SSLFactory::X509_PAIR* ptr = x.second;

            if(argc > 0) {
                std::string a1 = argv[0];
                if(a1 == "7") {
                    #ifndef USE_OPENSSL11
                    ss << string_format("            refcounts: key=%d cert=%d\n",
                              ptr->first->references,
                              ptr->second->references);
                    #endif
                }
            }

            EVP_PKEY_free(ptr->first);
            X509_free(ptr->second);
        }
        store->cache().clear();
    }

    cli_print(cli, "%s", ss.str().c_str());

    return CLI_OK;
}

int cli_diag_ssl_wl_list(struct cli_def *cli, const char *command, char *argv[], int argc) {

    debug_cli_params(cli, command, argv, argc);

    cli_print(cli,"\nSSL whitelist:");
    std::string out;

    std::lock_guard<std::recursive_mutex> l_(MitmProxy::whitelist_verify().getlock());
    for(auto we: MitmProxy::whitelist_verify().cache()) {
        out += "\n\t" + we.first;

        int ttl = we.second->expired_at() - ::time(nullptr);

        out += string_format(" ttl: %d", ttl);
        if(ttl <= 0) {
            out += " *expired*";
        }
    }

    cli_print(cli,"%s",out.c_str());
    return CLI_OK;
}

int cli_diag_ssl_wl_clear(struct cli_def *cli, const char *command, char *argv[], int argc) {

    debug_cli_params(cli, command, argv, argc);

    std::lock_guard<std::recursive_mutex> l_(MitmProxy::whitelist_verify().getlock());

    MitmProxy::whitelist_verify().clear();

    return CLI_OK;
}


int cli_diag_ssl_wl_stats(struct cli_def *cli, const char *command, char *argv[], int argc) {

    debug_cli_params(cli, command, argv, argc);

    std::stringstream ss;

    std::lock_guard<std::recursive_mutex> l_(MitmProxy::whitelist_verify().getlock());
    {
        int n_sz_cache = MitmProxy::whitelist_verify().cache().size();
        int n_max_cache = MitmProxy::whitelist_verify().max_size();
        bool n_autorem = MitmProxy::whitelist_verify().auto_delete();
        std::string n_name = MitmProxy::whitelist_verify().name();

        ss << string_format("'%s' cache stats: \n",n_name.c_str());
        ss << string_format("    current size: %d\n",n_sz_cache);
        ss << string_format("    maximum size: %d\n",n_max_cache);
        ss << string_format("      autodelete: %d\n ",n_autorem);
    }


    cli_print(cli, "%s", ss.str().c_str());

    return CLI_OK;
}

int cli_diag_ssl_crl_list(struct cli_def *cli, const char *command, char *argv[], int argc) {

    debug_cli_params(cli, command, argv, argc);

    std::stringstream out;

    out << "Downloaded CRLs:\n\n";

    {
        std::lock_guard<std::recursive_mutex> l_(SSLFactory::crl_cache.getlock());
        for (auto const& x: SSLFactory::crl_cache.cache()) {
            std::string uri = x.first;
            auto cached_result = x.second;

            out << "    " + uri;
            if (cached_result) {
                long ttl = cached_result->expired_at() - ::time(nullptr);
                out << string_format(", ttl=%d", ttl);

                if (ttl <= 0) {
                    out << "  *expired*";
                }
            } else {
                out << ", ttl=?";
            }

            out << "\n";
        }
    }

    cli_print(cli,"\n%s",out.str().c_str());

    return CLI_OK;
}

int cli_diag_ssl_crl_stats(struct cli_def *cli, const char *command, char *argv[], int argc) {

    debug_cli_params(cli, command, argv, argc);

    std::stringstream ss;

    {
        std::lock_guard<std::recursive_mutex> l_(SSLFactory::crl_cache.getlock());

        int n_sz_cache = SSLFactory::crl_cache.cache().size();
        int n_max_cache = SSLFactory::crl_cache.max_size();
        bool n_autorem = SSLFactory::crl_cache.auto_delete();
        std::string n_name = SSLFactory::crl_cache.name();


        ss << string_format("'%s' cache stats: ", n_name.c_str());
        ss << string_format("    current size: %d \n", n_sz_cache);
        ss << string_format("    maximum size: %d \n", n_max_cache);
        ss << string_format("      autodelete: %d \n", n_autorem);
    }

    cli_print(cli,"\n%s",ss.str().c_str());

    return CLI_OK;
}
int cli_diag_ssl_verify_clear(struct cli_def *cli, const char *command, char *argv[], int argc) {

    debug_cli_params(cli, command, argv, argc);

    mp::vector<std::string> to_delete;
    mp::stringstream what;

    for(int i = 0 ; i < argc ; i++) {
        to_delete.push_back(std::string(argv[i]));
        what << std::string(argv[i]);
    }

    if(to_delete.empty()) {
        what << "*";
    }

    cli_print(cli, "request to clear ocsp cache from: %s", what.str().c_str());
    std::stringstream out;

    std::lock_guard<std::recursive_mutex> l_(SSLFactory::factory().verify_cache.getlock());
    if(to_delete.empty()) {
        SSLFactory::factory().verify_cache.clear();
    }
    else {

        mp::vector<std::string> to_delete_keys;

        for(auto& i: SSLFactory::factory().verify_cache.cache()) {
            for(auto const& k: to_delete)
            if(i.first.find(k,0) == 0) {
                to_delete_keys.push_back(i.first);
            }
        }

        for(auto const& k: to_delete_keys) {
            out << "erasing key: " << k << "\n";
            SSLFactory::factory().verify_cache.erase(k);
        }
    }

    cli_print(cli, "%s", out.str().c_str());

    return CLI_OK;
}


int cli_diag_ssl_verify_list(struct cli_def *cli, const char *command, char *argv[], int argc) {

    debug_cli_params(cli, command, argv, argc);

    std::stringstream out;

    out << "Verify status list:\n\n";

    {
        std::lock_guard<std::recursive_mutex> l_(SSLFactory::factory().verify_cache.getlock());
        for (auto const& x: SSLFactory::factory().verify_cache.cache()) {
            std::string cn = x.first;
            SSLFactory::expiring_verify_result *cached_result = x.second;
            long ttl = 0;
            if (cached_result) {
                ttl = cached_result->expired_at() - ::time(nullptr);
                out << string_format("    %s, ttl=%d, status=%d", cn.c_str(), ttl, cached_result->value());

                if (ttl <= 0) {
                    out << "  *expired*";
                }
                out << "\n";
            } else {
                out << string_format("    %s, ttl=?\n", cn.c_str());
            }

        }
    }

    cli_print(cli,"\n%s",out.str().c_str());

    return CLI_OK;
}

int cli_diag_ssl_verify_stats(struct cli_def *cli, const char *command, char *argv[], int argc) {

    debug_cli_params(cli, command, argv, argc);

    std::stringstream ss;
    {
        auto& verify_cache = SSLFactory::factory().verify_cache;
        std::lock_guard<std::recursive_mutex> l_(verify_cache.getlock());

        int n_sz_cache  = verify_cache.cache().size();
        int n_max_cache = verify_cache.max_size();
        bool n_autorem  = verify_cache.auto_delete();
        std::string n_name = verify_cache.name();


        ss << string_format("'%s' cache stats: \n", n_name.c_str());
        ss << string_format("    current size: %d \n", n_sz_cache);
        ss << string_format("    maximum size: %d \n", n_max_cache);
        ss << string_format("      autodelete: %d \n", n_autorem);
    }

    cli_print(cli,"\n%s",ss.str().c_str());

    return CLI_OK;
}


int cli_diag_ssl_ticket_list(struct cli_def *cli, const char *command, char *argv[], int argc) {

    debug_cli_params(cli, command, argv, argc);

    std::stringstream out;

    {
        std::lock_guard<std::recursive_mutex> l_(SSLFactory::session_cache.getlock());

        out << "SSL ticket/sessionid list:\n\n";

        for (auto const& x: SSLFactory::session_cache.cache()) {
            std::string key = x.first;
            session_holder *session_keys = x.second;

            bool showall = false;

            if (argc > 0) {
                int lev = safe_val(argv[0]);
                if (lev >= 7) {
                    showall = true;
                }
            }
            bool ticket = false;

#ifdef USE_OPENSSL11

            if (session_keys->ptr) {

                if (SSL_SESSION_has_ticket(session_keys->ptr)) {
                    size_t ticket_len = 0;
                    const unsigned char *ticket_ptr = nullptr;

                    SSL_SESSION_get0_ticket(session_keys->ptr, &ticket_ptr, &ticket_len);
                    if (ticket_ptr && ticket_len) {
                        ticket = true;
                        std::string tick = hex_print((unsigned char *) ticket_ptr, ticket_len);
                        out << string_format("    %s,    ticket: %s\n", key.c_str(), tick.c_str());

                    }
                }

                unsigned int session_id_len = 0;
                const unsigned char *session_id = SSL_SESSION_get_id(session_keys->ptr, &session_id_len);
                if (!ticket || showall) {
                    if (session_id_len > 0) {
                        std::string sessionid = hex_print((unsigned char *) session_id, session_id_len);
                        out << string_format("    %s, sessionid: %s\n", key.c_str(), sessionid.c_str());
                    }
                    out << string_format("    usage cnt: %d\n", session_keys->cnt_loaded);
                }
            }

#else
            if (session_keys->ptr->tlsext_ticklen > 0) {
                ticket = true;
                std::string tick = hex_print(session_keys->ptr->tlsext_tick, session_keys->ptr->tlsext_ticklen);
                out += string_format("    %s,    ticket: %s\n",key.c_str(),tick.c_str());
            }

            if(! ticket || showall) {
                if(session_keys->ptr->session_id_length > 0) {
                    std::string sessionid = hex_print(session_keys->ptr->session_id, session_keys->ptr->session_id_length);
                    out += string_format("    %s, sessionid: %s\n",key.c_str(),sessionid.c_str());
                }
                out += string_format("    usage cnt: %d\n",session_keys->cnt_loaded);
            }
#endif

        }
    }

    cli_print(cli,"\n%s",out.str().c_str());

    return CLI_OK;
}

int cli_diag_ssl_ticket_stats(struct cli_def *cli, const char *command, char *argv[], int argc) {

    debug_cli_params(cli, command, argv, argc);

    std::stringstream out;

    {
        std::lock_guard<std::recursive_mutex> l_(SSLFactory::session_cache.getlock());

        int n_sz_cache = SSLFactory::session_cache.cache().size();
        int n_max_cache = SSLFactory::session_cache.max_size();
        bool n_autorem = SSLFactory::session_cache.auto_delete();
        std::string n_name = SSLFactory::session_cache.name();

        out << string_format("'%s' cache stats: \n", n_name.c_str());
        out << string_format("    current size: %d \n", n_sz_cache);
        out << string_format("    maximum size: %d \n", n_max_cache);
        out << string_format("      autodelete: %d \n", n_autorem);
    }

    cli_print(cli, "%s", out.str().c_str());
    return CLI_OK;
}

int cli_diag_ssl_ticket_size(struct cli_def *cli, const char *command, char *argv[], int argc) {

    debug_cli_params(cli, command, argv, argc);

    std::stringstream out;

    {
        std::scoped_lock<std::recursive_mutex> l_(SSLFactory::session_cache.getlock());

        int n_sz_cache = SSLFactory::session_cache.cache().size();
        int n_max_cache = SSLFactory::session_cache.max_size();
        bool n_autorem = SSLFactory::session_cache.auto_delete();
        std::string n_name = SSLFactory::session_cache.name();

        out << string_format("'%s' cache stats: ", n_name.c_str());
        out << string_format("    current size: %d ", n_sz_cache);
        out << string_format("    maximum size: %d ", n_max_cache);
        out << string_format("      autodelete: %d ", n_autorem);
    }

    cli_print(cli, "%s", out.str().c_str());

    return CLI_OK;
}


#ifndef USE_OPENSSL11
int cli_diag_ssl_memcheck_list(struct cli_def *cli, const char *command, char *argv[], int argc) {

    std::string out;
    BIO* b_out = BIO_new_string(&out);

    CRYPTO_mem_leaks(b_out);
    cli_print(cli,"OpenSSL memory leaks:\n%s",out.c_str());
    BIO_free(b_out);

    return CLI_OK;
}


int cli_diag_ssl_memcheck_enable(struct cli_def *cli, const char *command, char *argv[], int argc) {

    CRYPTO_mem_ctrl(CRYPTO_MEM_CHECK_ENABLE);

    return CLI_OK;
}

int cli_diag_ssl_memcheck_disable(struct cli_def *cli, const char *command, char *argv[], int argc) {

    CRYPTO_mem_ctrl(CRYPTO_MEM_CHECK_DISABLE);

    return CLI_OK;
}
#endif

int cli_diag_ssl_ca_reload(struct cli_def *cli, const char *command, char *argv[], int argc) {

    debug_cli_params(cli, command, argv, argc);

    cli_print(cli,"Not yet implemented");

    return CLI_OK;
}


int cli_diag_dns_cache_list(struct cli_def *cli, const char *command, char *argv[], int argc) {

    debug_cli_params(cli, command, argv, argc);

    std::stringstream out;
    {
        std::scoped_lock<std::recursive_mutex> l_(DNS::get_dns_lock());


        out << "\nDNS cache populated from traffic: \n";

        for (auto const& it: DNS::get_dns_cache().cache()) {
            std::string s = it.first;
            DNS_Response *r = it.second;

            if (r != nullptr && r->answers().size() > 0) {
                long ttl = (r->loaded_at + r->answers().at(0).ttl_) - time(nullptr);
                out << string_format("    %s  -> [ttl:%d]%s\n", s.c_str(), ttl, r->answer_str().c_str());
            }
        }
    }

    cli_print(cli, "%s", out.str().c_str());

    return CLI_OK;
}

int cli_diag_dns_cache_stats(struct cli_def *cli, const char *command, char *argv[], int argc) {

    debug_cli_params(cli, command, argv, argc);

    std::stringstream out;
    {
        std::scoped_lock<std::recursive_mutex> l_(DNS::get_dns_lock());

        out << "\nDNS cache statistics: \n";
        int cache_size = DNS::get_dns_cache().cache().size();
        int max_size = DNS::get_dns_cache().max_size();
        bool del = DNS::get_dns_cache().auto_delete();


        out << string_format("  Current size: %5d\n", cache_size);
        out << string_format("  Maximum size: %5d\n", max_size);
        out << string_format("\n    Autodelete: %5d\n", del);
    }

    cli_print(cli, "%s", out.str().c_str());
    return CLI_OK;
}

int cli_diag_dns_cache_clear(struct cli_def *cli, const char *command, char *argv[], int argc) {

    debug_cli_params(cli, command, argv, argc);

    {
        std::scoped_lock<std::recursive_mutex> l_(DNS::get_dns_lock());
        DNS::get_dns_cache().clear();
    }

    cli_print(cli,"\nDNS cache cleared.");

    return CLI_OK;
}

int cli_diag_dns_domain_cache_list(struct cli_def *cli, const char *command, char *argv[], int argc) {

    debug_cli_params(cli, command, argv, argc);

    cli_print(cli, "\n Domain cache list:");
    std::stringstream out;

    {
        std::scoped_lock<std::recursive_mutex> l_(DNS::get_domain_lock());

        for (auto const& sub_domain_cache: DNS::get_domain_cache().cache()) {

            std::string domain = sub_domain_cache.first;
            std::string str;

            for (auto sub_e: sub_domain_cache.second->cache()) {
                str += " " + sub_e.first;
            }
            out << string_format("\n\t%s: \t%s", domain.c_str(), str.c_str());

        }
    }

    cli_print(cli,"%s",out.str().c_str());

    return CLI_OK;
}

int cli_diag_dns_domain_cache_clear(struct cli_def *cli, const char *command, char *argv[], int argc) {
    debug_cli_params(cli, command, argv, argc);

    cli_print(cli, "\n Clearing domain cache:");

    {
        std::scoped_lock<std::recursive_mutex> l_(DNS::get_domain_lock());
        DNS::get_domain_cache().clear();
    }

    cli_print(cli," done.");

    return CLI_OK;
}



int cli_diag_identity_ip_list(struct cli_def *cli, const char *command, char *argv[], int argc) {
    debug_cli_params(cli, command, argv, argc);

    cli_print(cli, "\nIPv4 identities:");
    std::stringstream ss4;

    {
        std::scoped_lock<std::recursive_mutex> l_(AuthFactory::get_ip4_lock());
        for (auto ip: AuthFactory::get_ip4_map()) {

            IdentityInfo &id = ip.second;

            ss4 << "\n";
            ss4 << "    ipv4: " << ip.first << ", user: " << id.username << ", groups: " << id.groups << ", rx/tx: ";
            ss4 <<   number_suffixed(id.tx_bytes) << "/" << number_suffixed(id.rx_bytes);

            ss4 << "\n          uptime: " << std::to_string(id.uptime()) << ", idle: " << std::to_string(id.i_time());
            ss4 << "\n          status: " << std::to_string(!id.i_timeout()) << ", last policy: ";
            ss4 <<   std::to_string(id.last_seen_policy);
            ss4 << "\n";
        }

    }
    cli_print(cli, "%s", ss4.str().c_str());


    cli_print(cli, "\nIPv6 identities:");
    std::stringstream ss6;
    {
        std::scoped_lock<std::recursive_mutex> l_(AuthFactory::get_ip6_lock());
        for (auto ip: AuthFactory::get_ip6_map()) {

            IdentityInfo6 &id = ip.second;

            ss6 << "\n";
            ss6 << "    ipv6: " << ip.first << ", user: " << id.username << ", groups: " << id.groups << ", rx/tx: ";
            ss6 <<   number_suffixed(id.tx_bytes) << "/" << number_suffixed(id.rx_bytes);
            ss6 << "\n          uptime: " << std::to_string(id.uptime()) << ", idle: " << std::to_string(id.i_time());
            ss6 << "\n          status: " << std::to_string(!id.i_timeout()) << ", last policy: ";
            ss6 <<   std::to_string(id.last_seen_policy);
            ss6 << "\n";

        }
    }
    cli_print(cli, "%s", ss6.str().c_str());

    return CLI_OK;
}

int cli_diag_identity_ip_clear(struct cli_def *cli, const char *command, char *argv[], int argc) {
    debug_cli_params(cli, command, argv, argc);

    cli_print(cli, "\nClearing all identities:");
    std::string out;

    {
        std::scoped_lock<std::recursive_mutex> l_(AuthFactory::get_ip4_lock());
        AuthFactory::get_ip4_map().clear();
        AuthFactory::get().shm_ip4_map.acquire();
        AuthFactory::get().shm_ip4_map.map_entries().clear();
        AuthFactory::get().shm_ip4_map.entries().clear();
        AuthFactory::get().shm_ip4_map.save(true);


        AuthFactory::get().shm_ip4_map.seen_version(0);
        AuthFactory::get().shm_ip4_map.release();
    }

    {
        std::scoped_lock<std::recursive_mutex> l_(AuthFactory::get_ip6_lock());
        AuthFactory::get_ip6_map().clear();
        AuthFactory::get().shm_ip6_map.acquire();
        AuthFactory::get().shm_ip6_map.map_entries().clear();
        AuthFactory::get().shm_ip6_map.entries().clear();
        AuthFactory::get().shm_ip6_map.save(true);


        AuthFactory::get().shm_ip6_map.seen_version(0);
        AuthFactory::get().shm_ip6_map.release();
    }

    return CLI_OK;
}

int cli_diag_writer_stats(struct cli_def *cli, const char *command, char *argv[], int argc) {
    debug_cli_params(cli, command, argv, argc);

    auto wr = threadedPoolFileWriter::instance();

    std::stringstream ss;

    {
        std::scoped_lock<std::mutex> l_(wr->queue_lock());

        ss << "Not started files: " << wr->task_files().size() << "\n";
        ss << "Queue being processed:\n";

        for (auto const& elem: wr->queue()) {
            auto const& k = elem.first;
            auto const& q = elem.second;

            ss << "    '" << k << "' : " << q.size() << " chunks\n";
        }
    };
    {
        std::scoped_lock<std::recursive_mutex> l_(wr->ofstream_lock());

        ss << "Recent (opened files):\n";
        for (auto const& elem: wr->ofstream_cache().cache()) {
            ss << "    " << elem.first << "\n";
        }
    }

    cli_print(cli, "%s", ss.str().c_str());

    return CLI_OK;
}

void cli_print_log_levels(struct cli_def *cli) {

    logger_profile* lp = get_logger()->target_profiles()[(uint64_t)fileno(cli->client)];

    cli_print(cli,"THIS cli logging level set to: %d",lp->level_.level());
    cli_print(cli,"Internal logging level set to: %d",get_logger()->level().level());
    cli_print(cli,"\n");
    for(int const& target: get_logger()->remote_targets()) {
        cli_print(cli, "Logging level for remote: %s: %d",
                get_logger()->target_name((uint64_t)target),
                get_logger()->target_profiles()[(uint64_t)target]->level_.level());
    }
    for(auto const* o_ptr: get_logger()->targets()) {
        cli_print(cli, "Logging level for target: %s: %d",
                get_logger()->target_name((uint64_t)(o_ptr)),
                get_logger()->target_profiles()[(uint64_t)(o_ptr)]->level_.level());
    }
}


int cli_debug_level(struct cli_def *cli, const char *command, char *argv[], int argc) {

    debug_cli_params(cli, command, argv, argc);

    logger_profile* lp = get_logger()->target_profiles()[(uint64_t)fileno(cli->client)];
    if(argc > 0) {

        std::string a1 = argv[0];

        if(a1 == "?") {
            cli_print(cli,"valid parameters: %s", CliState::get().debug_levels);
        }
        else if(a1 == "reset") {
            lp->level_ = NON;

            get_logger()->level(cfgapi_table.logging.level);
            cli_print(cli, "internal logging level changed to %d",get_logger()->level().level_ref());
        }
        else {
            //cli_print(cli, "called %s with %s, argc %d\r\n", __FUNCTION__, command, argc);
            int newlev = safe_val(argv[0]);
            if(newlev >= 0) {
                get_logger()->level(loglevel(newlev,0));
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

    logger_profile* lp = get_logger()->target_profiles()[(uint64_t)fileno(cli->client)];
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
                newlev = cfgapi_table.logging.level.level();
            } else {
                newlev = safe_val(argv[0]);
            }

            if(newlev >= 0) {
                for(auto const* o_ptr: get_logger()->targets()) {

                    std::string fnm = get_logger()->target_name((uint64_t)(o_ptr));

                    std::scoped_lock<std::recursive_mutex> l_(CfgFactory::lock());

                    if( fnm == CfgFactory::get().log_file ) {

                        cli_print(cli, "changing '%s' loglevel to %d", fnm.c_str(), newlev);
                        get_logger()->target_profiles()[(uint64_t) (o_ptr)]->level_.level(newlev);
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

    for(auto i: logan::get().topic_db_) {
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


int cli_diag_mem_buffers_stats(struct cli_def *cli, const char *command, char *argv[], int argc) {
    debug_cli_params(cli, command, argv, argc);

    cli_print(cli,"Memory buffers stats: ");
    cli_print(cli,"memory alloc   bytes: %lld",buffer::alloc_bytes);
    cli_print(cli,"memory free    bytes: %lld",buffer::free_bytes);
    cli_print(cli,"memory current bytes: %lld",buffer::alloc_bytes-buffer::free_bytes);
    cli_print(cli,"\nmemory alloc   counter: %lld",buffer::alloc_count);
    cli_print(cli,"memory free    counter: %lld",buffer::free_count);
    cli_print(cli,"memory current counter: %lld",buffer::alloc_count-buffer::free_count);


    if (buffer::use_pool) {

        {
            std::scoped_lock<std::mutex> g(memPool::pool().lock);

            cli_print(cli, "\nMemory pool API stats:");
            cli_print(cli, "acquires: %lld/%lldB", memPool::pool().stat_acq, memPool::pool().stat_acq_size);
            cli_print(cli, "releases: %lld/%lldB", memPool::pool().stat_ret, memPool::pool().stat_ret_size);

            cli_print(cli, "\nNon-API allocations:");
            cli_print(cli, "mp_allocs: %lld", stat_mempool_alloc);
            cli_print(cli, "mp_reallocs: %lld", stat_mempool_realloc);
            cli_print(cli, "mp_frees: %lld", stat_mempool_free);
            cli_print(cli, "mp_realloc cache miss: %lld", stat_mempool_realloc_miss);
            cli_print(cli, "mp_realloc fitting returns: %lld", stat_mempool_realloc_fitting);
            cli_print(cli, "mp_free cache miss: %lld", stat_mempool_free_miss);
        }
        size_t mp_size = 0L;
        {
            std::scoped_lock<std::mutex> l(mpdata::lock());
            mp_size = mpdata::map().size();
        }
        cli_print(cli, "mp ptr cache size: %ld", mp_size);

        cli_print(cli," ");
        cli_print(cli, "API allocations above limits:");
        {
            std::scoped_lock<std::mutex> g(memPool::pool().lock);
            cli_print(cli, "allocations: %lld/%lldB", memPool::pool().stat_alloc, memPool::pool().stat_alloc_size);
            cli_print(cli, "   releases: %lld/%lldB", memPool::pool().stat_out_free,
                      memPool::pool().stat_out_free_size);

            cli_print(cli, "\nPool capacities (available/limits):");
            cli_print(cli, " 32B pool size: %lu/%lu", memPool::pool().mem_32_av(), memPool::pool().mem_32_sz());
            cli_print(cli, " 64B pool size: %lu/%lu", memPool::pool().mem_64_av(), memPool::pool().mem_64_sz());
            cli_print(cli, "128B pool size: %lu/%lu", memPool::pool().mem_128_av(), memPool::pool().mem_128_sz());
            cli_print(cli, "256B pool size: %lu/%lu", memPool::pool().mem_256_av(), memPool::pool().mem_256_sz());
            cli_print(cli, " 1kB pool size: %lu/%lu", memPool::pool().mem_1k_av(), memPool::pool().mem_1k_sz());
            cli_print(cli, " 5kB pool size: %lu/%lu", memPool::pool().mem_5k_av(), memPool::pool().mem_5k_sz());
            cli_print(cli, "10kB pool size: %lu/%lu", memPool::pool().mem_10k_av(), memPool::pool().mem_10k_sz());
            cli_print(cli, "20kB pool size: %lu/%lu", memPool::pool().mem_20k_av(), memPool::pool().mem_20k_sz());
            cli_print(cli, " big pool size: %lu", memPool::pool().mem_big_av());

            // (10 for 32 byte pool, and 3 for 64, 128 and 256 pool)
            unsigned long long total_pools = (10 + 3) * memPool::pool().mem_256_sz() + memPool::pool().mem_1k_sz() +
                                             memPool::pool().mem_5k_sz() + memPool::pool().mem_10k_sz() +
                                             memPool::pool().mem_20k_sz();
            cli_print(cli,"   total pools: %lld", total_pools);
        }



    }

#ifdef SOCLE_MEM_PROFILE
    if(argc > 0) {

        std::string arg1(argv[0]);
        if(arg1 == "?") {
            cli_print(cli,"buffers        print all still allocated buffers' traces");
            cli_print(cli,"buffers_all    print all buffers' traces, including properly freed");
            cli_print(cli,"clear          remove all buffer tracking entries");
            return CLI_OK;
        }

        bool b = false;
        bool ba = false;
        bool clr = false;

        if(arg1 == "buffers") { b = true; }
        if(arg1 == "buffers_all") { b = true; ba = true; }
        if(arg1 == "clear") { clr = true; }

        if(b) {
            cli_print(cli,"\nExtra memory traces: ");
            buffer::alloc_map_lock();
            for( auto it = buffer::alloc_map.begin(); it != buffer::alloc_map.end(); ++it) {
                std::string bt = it->first;
                int& counter = it->second;

                if(counter > 0 || ba) {
                    cli_print(cli,"\nActive trace: %d references %s",counter,bt.c_str());
                }
            }
            buffer::alloc_map_unlock();
        }
        else if (clr) {
            buffer::alloc_bytes = 0;
            buffer::free_bytes = 0;
            buffer::alloc_count = 0;
            buffer::free_count = 0;
            cli_print(cli,"buffer usage counters reset.");

            int n = buffer::alloc_map.size();
            buffer::counter_clear_bt();
            cli_print(cli,"%d entries from buffer tracker database deleted.",n);
        }
    }

    buffer::alloc_map_unlock();
#endif
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
        CliState::get().config_changed_flag = false;

        apply_hostname(cli);
    }
    return CLI_OK;
}


int cli_exec_reload(struct cli_def *cli, const char *command, char *argv[], int argc) {
    debug_cli_params(cli, command, argv, argc);

    CliState::get().config_changed_flag = false;
    bool CONFIG_LOADED = SmithProxy::instance().load_config(CfgFactory::get().config_file, true);

    if(CONFIG_LOADED) {
        cli_print(cli, "Configuration file reloaded successfully");
        CliState::get().config_changed_flag = false;
        apply_hostname(cli);

    } else {
        cli_print(cli, "Configuration file reload FAILED");
    }

    return CLI_OK;
}


int cfg_write(Config& cfg, FILE* where, unsigned long iobufsz = 0) {

    int fds[2];
    int fret = pipe(fds);
    if(0 != fret) {
        return -1;
    }

    FILE* fw = fdopen(fds[1], "w");
    FILE* fr = fdopen(fds[0], "r");


    // set pipe buffer size to 10MB - we need to fit whole config into it.
    unsigned long nbytes = 10*1024*1024;
    if(iobufsz > 0) {
        nbytes = iobufsz;
    }

    ioctl(fds[0], FIONREAD, &nbytes);
    ioctl(fds[1], FIONREAD, &nbytes);

    cfg.write(fw);
    fclose(fw);


    int c = EOF;
    do {
        c = fgetc(fr);
        //cli_print(cli, ">>> 0x%x", c);

        switch(c) {
            case EOF:
                break;

            case '\n':
                fputc('\r', where);
                // omit break - so we write also '\n'

            default:
                fputc(c, where);
        }

    } while(c != EOF);


    fclose(fr);

    return 0;
}

int cli_show_config_full (struct cli_def *cli, const char *command, char **argv, int argc) {
    debug_cli_params(cli, command, argv, argc);

    std::scoped_lock<std::recursive_mutex> l_(CfgFactory::lock());

    if(cfg_write(CfgFactory::cfg_obj(), cli->client) != 0) {
        cli_print(cli, "error: config print failed");
    }

    return CLI_OK;
}

// libconfig API is lacking cloning facility despite it's really trivial to implement:

void cfg_clone_setting(Setting& dst, Setting& orig, int index/*, struct cli_def *debug_cli*/ ) {


    std::string orig_name;
    if(orig.getName()) {
        orig_name = orig.getName();
    }

    //cli_print(debug_cli, "clone start: name: %s, len: %d", orig_name.c_str(), orig.getLength());

    for (unsigned int i = 0; i < (unsigned int) orig.getLength(); i++) {

        if( index >= 0 && index != (int)i) {
            continue;
        }

        Setting &cur_object = orig[(int)i];


        Setting::Type type = cur_object.getType();
        //cli_print(debug_cli, "clone      : type: %d", type);

        std::string name;
        if(cur_object.getName()) {
            name = cur_object.getName();
            //cli_print(debug_cli, "clone      : type: %d, name: %s", type, name.c_str());
        }


        Setting& new_setting =  name.empty() ? dst.add(type) : dst.add(name.c_str(), type);

        if(cur_object.isScalar()) {
            switch(type) {
                case Setting::TypeInt:
                    new_setting = (int)cur_object;
                    break;

                case Setting::TypeInt64:
                    new_setting = (long long int)cur_object;

                    break;

                case Setting::TypeString:
                    new_setting = (const char*)cur_object;
                    break;

                case Setting::TypeFloat:
                    new_setting = (float)cur_object;
                    break;

                case Setting::TypeBoolean:
                    new_setting = (bool)cur_object;
                    break;

                default:
                    // well, that sucks. Unknown type and no way to convert or report
                    break;
            }
        }
        else {

            //cli_print(debug_cli, "clone      : --- entering non-scalar");

            // index is always here -1, we don't filter sub-items
            cfg_clone_setting(new_setting, cur_object, -1 /*, debug_cli */ );
        }
    }
}



bool cfg_write_value(Setting& parent, bool create, std::string& varname, const std::vector<std::string> &values, cli_def* cli) {

    auto log = logan::create("service");

    bool verdict = true;

    if( parent.exists(varname.c_str()) ) {

        _not("config item exists %s", varname.c_str());

        Setting& s = parent[varname.c_str()];
        auto t = s.getType();

        std::string lvalue;

        try {
            switch (t) {
                case Setting::TypeInt:
                {
                    int i = std::stoi(values[0]);
                    _debug(cli, "DEBUG: attempting to write %s: (TypeInt)%d ", varname.c_str(), i);

                    verdict = CliHelp::instance().value_check(s.getPath(), i, cli);
                    if(verdict)
                        s = i;
                }
                    break;

                case Setting::TypeInt64:
                {
                    long long int lli = std::stoll(values[0]);
                    _debug(cli, "DEBUG: attempting to write %s: (TypeInt64)%lld ", varname.c_str(), lli);

                    verdict = CliHelp::instance().value_check(s.getPath(), lli, cli);
                    if(verdict)
                        s = lli;
                }
                    break;

                case Setting::TypeBoolean:

                    lvalue = string_tolower(values[0]);
                    _debug(cli, "DEBUG: attempting to write %s: (TypeBool)%s ", varname.c_str(), lvalue.c_str());

                    if( lvalue == "true" || lvalue == "1" ) {

                        verdict = CliHelp::instance().value_check(s.getPath(), true, cli);
                        if(verdict)
                            s = true;
                    }
                    else if ( lvalue == "false" || lvalue == "0" ) {
                        verdict = CliHelp::instance().value_check(s.getPath(), false, cli);
                        if(verdict)
                            s = false;
                    }

                    break;

                case Setting::TypeFloat:
                {
                    float f = std::stof(values[0]);
                    _debug(cli, "DEBUG: attempting to write %s: (TypeFloat)%f ", varname.c_str(), f);

                    verdict = CliHelp::instance().value_check(s.getPath(), f, cli);
                    if(verdict)
                        s = f;
                }
                    break;

                case Setting::TypeString:
                    _debug(cli, "DEBUG: attempting to write %s: (TypeString)%s ", varname.c_str(), values[0].c_str());

                    verdict = CliHelp::instance().value_check(s.getPath(), values[0], cli);
                    if(verdict)
                        s = values[0];

                    break;


                case Setting::TypeArray:
                    {
                        auto first_elem_type = Setting::TypeString;
                        if ( s.getLength() > 0 ) {
                            first_elem_type = s[0].getType();
                        }

                        std::vector<std::string> consolidated_values;
                        for(auto const &v: values) {
                            auto arg_values = string_split(v, ',');

                            for (auto const &av: arg_values)
                                consolidated_values.push_back(av);
                        }

                        for(auto const& i: consolidated_values) {
                            _debug(cli, "%s values: %s", s.getPath().c_str(), i.c_str());
                        }


                        // check values
                        for(auto const& i: consolidated_values) {

                            if(first_elem_type == Setting::TypeString) {
                                verdict = CliHelp::instance().value_check(s.getPath(), i, cli);
                                _debug(cli, "checking string value: %s => %d", i.c_str(), verdict);

                            }
                            else if(first_elem_type == Setting::TypeInt) {
                                verdict = CliHelp::instance().value_check(s.getPath(), std::stoi(i), cli);
                                _debug(cli, "checking int value: %s => %d", i.c_str(), verdict);

                            }
                            else if(first_elem_type == Setting::TypeFloat) {
                                verdict = CliHelp::instance().value_check(s.getPath(), std::stof(i), cli);
                                _debug(cli, "checking float value: %s => %d", i.c_str(), verdict);
                            }
                            else {
                                throw(std::invalid_argument("unknown array type"));
                            }

                            if(! verdict)
                                break;
                        }

                        if(verdict) {
                            if (!consolidated_values.empty()) {

                                // ugly (but only) way to remove
                                for (int x = s.getLength() - 1; x >= 0; x--) {
                                    _debug(cli, "removing index %d", x);
                                    s.remove(x);
                                }

                                for (auto const &i: consolidated_values) {

                                    if (first_elem_type == Setting::TypeString) {
                                        _debug(cli, "adding string value: %s", i.c_str());
                                        s.add(Setting::TypeString) = i.c_str();
                                    } else if (first_elem_type == Setting::TypeInt) {
                                        _debug(cli, "adding int value: %s", i.c_str());
                                        s.add(Setting::TypeInt) = std::stoi(i);
                                    } else if (first_elem_type == Setting::TypeFloat) {
                                        _debug(cli, "adding float value: %s", i.c_str());
                                        s.add(Setting::TypeFloat) = std::stof(i);
                                    } else {
                                        throw (std::invalid_argument("unknown array type"));
                                    }
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
        catch(std::invalid_argument const& e) {
            cli_print(cli, "invalid argument!");
            verdict = false;

        }
        catch(std::exception const& e) {
            cli_print(cli , "error writing config variable: %s", e.what());
            _err("error writing config variable: %s", e.what());
            verdict = false;
        }
    }
    else if(create) {
        _err("nyi: error writing creating a new config variable: %s", varname.c_str());
        verdict = false;
    }

    return verdict;
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
        SmithProxy::instance().load_signatures(CfgFactory::cfg_obj(),"starttls_signatures", SigFactory::get().tls());

        CfgFactory::get().cleanup_db_policy();
        ret = CfgFactory::get().load_db_policy();
    } else
    if( 0 == section.find("detection_signatures") ) {
        SmithProxy::instance().load_signatures(CfgFactory::cfg_obj(),"detection_signatures", SigFactory::get().detection());

        CfgFactory::get().cleanup_db_policy();
        ret = CfgFactory::get().load_db_policy();
    }

    else {
        cli_print(cli, "config apply - unknown config section!");
    }


    if(! ret) {
        cli_print(cli, "!!! Config was not applied");
        cli_print(cli, " -  saving and reload is necessary to apply your settings.");
    } else {
        CliState::get().config_changed_flag = true;
        apply_hostname(cli);
        cli_print(cli, "running config applied (not saved to file).");
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
            if(cmd.size() > 2) {
                varname = cmd[1];
            }
        }

        _debug(cli, "var: %s", varname.c_str());


        std::vector<std::string> args;

        // counting from 1, since 0 is varname

        bool args_qmark = false;
        if (argc > 0) {
            for (int i = 0; i < argc; i++) {
                args.emplace_back(std::string(argv[i]));
            }
            args_qmark = (args[0] == "?");

        } else {
            if(cmd.size() > 2) {
                for (unsigned int i = 2; i < cmd.size(); i++) {
                    args.emplace_back(std::string(cmd[i]));
                }

                args_qmark = (args[0] == "?");
            }
        }

        if (! args_qmark) {

            std::scoped_lock<std::recursive_mutex> ll_(CfgFactory::lock());

            if (cfg_write_value(conf, false, varname, args, cli)) {
                // cli_print(cli, "change written to current config");

                if ( apply_setting( conf.getPath(), varname , cli )) {
                    cli_print(cli, "change applied to current config");
                } else {
                    // FIXME
                    cli_print(cli, "change NOT applied to current config - reverting NYI, sorry");
                    cli_print(cli, "change will be visible in show config, but not written to mapped variables");
                    cli_print(cli, "therefore 'save config' won't write them to file.");
                }
            } else {
                cli_print(cli, "error setting value");
            }

        } else {
            if (!conf.isRoot() && conf.getName()) {

                auto h = CliHelp::instance().help(CliHelp::help_type_t::HELP_QMARK, conf.getPath(), varname);

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

// index < 0 means all
void cli_print_section(cli_def* cli, const std::string& name, int index , unsigned long pipe_sz ) {

    std::scoped_lock<std::recursive_mutex> l_(CfgFactory::lock());

    if(CfgFactory::cfg_root().exists(name.c_str())) {
        Setting &s = CfgFactory::cfg_root().lookup(name.c_str());

        Config nc;

        auto section_nodes = string_split(name, '.');

        nc.setOptions(Setting::OptionOpenBraceOnSeparateLine);

        Setting* target = &nc.getRoot();
        target = &target->add(s.getName(), s.getType());

        cfg_clone_setting( *target, s , index /*, cli */ );

        cfg_write(nc, cli->client, pipe_sz);

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

int cli_show_config_debug(struct cli_def *cli, const char *command, char *argv[], int argc) {
    debug_cli_params(cli, command, argv, argc);

    cli_print_section(cli, "debug", -1, 1 * 1024 * 1024);
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



int cli_diag_mem_objects_stats(struct cli_def *cli, const char *command, char *argv[], int argc) {

    debug_cli_params(cli, command, argv, argc);

    cli_print(cli,"Statistics:\n");
    cli_print(cli,"%s", sobjectDB::str_stats(nullptr).c_str());
    return CLI_OK;

}

int cli_diag_mem_trace_mark (struct cli_def *cli, const char *command, char **argv, int argc) {

    debug_cli_params(cli, command, argv, argc);

#ifdef MEMPOOL_DEBUG

    std::scoped_lock<std::mutex> l(mempool_ptr_map_lock);

    for ( auto it = mempool_ptr_map.begin() ; it != mempool_ptr_map.end() ; ++it) {
        it->second.mark = 1;
    }


#else

    cli_print(cli, "memory tracing not enabled.");
#endif

    return CLI_OK;
}



int cli_diag_mem_trace_list (struct cli_def *cli, const char *command, char **argv, int argc) {

    debug_cli_params(cli, command, argv, argc);

#ifdef MEMPOOL_DEBUG
    int n = 100;
    uint32_t filter = 0;

    try {
        if (argc > 0) {
            n = std::stoi(std::string(argv[0]));
        }

    } catch (const std::exception& e) {
        cli_print(cli, "invalid argument: %s", argv[0]);
        return CLI_OK;
    }


    if(mem_chunk::trace_enabled)
    {
        std::unordered_map<std::string, long long int> occ;
        {
            std::scoped_lock<std::mutex> l(mempool_ptr_map_lock);

            for (auto mem: mempool_ptr_map) {
                auto mch = mem.second;
                if ( (!mch.in_pool) && mch.mark == filter) {
                    std::string k;

                    //k = mch.str_trace();
                    k.resize((size_t)(sizeof(void*))*mch.trace_size);
                    ::memcpy((void*)k.data(), mch.trace, (size_t)(sizeof(void*))*mch.trace_size);


                    auto i = occ.find(k);
                    if (i != occ.end()) {

                        occ[k]++;
                    } else {
                        occ[k] = 1;
                    }
                }
            }

            cli_print(cli, "Allocation traces: processed %ld used mempool entries", mempool_ptr_map.size());
        }
        cli_print(cli, "Allocation traces: parsed %ld unique entries.", occ.size());

        std::map<long long int, std::string> ordered;
        for(auto i: occ) {
            ordered[i.second] = i.first;
        }

        cli_print(cli, "\nAllocation traces (top-%d):", n);

        auto i = ordered.rbegin();
        while(i != ordered.rend() && n > 0) {
            mem_chunk_t m;

            memcpy(&m.trace, i->second.data(), i->second.size());
            m.trace_size = (int) i->second.size()/sizeof(void*);

            cli_print(cli, "\nNumber of traces: %lld\n%s", i->first, m.str_trace().c_str());
            ++i;
            --n;
        }
    };


#else
    cli_print(cli, "memory tracing not enabled.");

#endif
    return CLI_OK;
}



int cli_diag_mem_objects_list(struct cli_def *cli, const char *command, char *argv[], int argc) {

    debug_cli_params(cli, command, argv, argc);

    std::string object_filter;
    int verbosity = iINF;

    if(argc > 0) {
        std::string a1 = argv[0];
        if(a1 == "?") {
            cli_print(cli,"valid parameters:");
            cli_print(cli,"         <empty> - all entries will be printed out");
            cli_print(cli,"         0x prefixed string - only object with matching Id will be printed out");
            cli_print(cli,"         any other string   - only objects with class matching this string will be printed out");

            return CLI_OK;
        } else {
            // a1 is param for the lookup
            if("*" == a1 || "ALL" == a1) {
                object_filter = "";
            } else {
                object_filter = a1;
            }
        }

        if(argc > 1) {
            std::string a2 = argv[1];
            verbosity = safe_val(a2,iINF);
        }
    }


    std::string r = sobjectDB::str_list((object_filter.empty()) ? nullptr : object_filter.c_str(), nullptr, verbosity);
                r += "\n" + sobjectDB::str_stats((object_filter.empty()) ? nullptr : object_filter.c_str());


    cli_print(cli,"Smithproxy objects (filter: %s):\n%s\nFinished.",(object_filter.empty()) ? "ALL" : object_filter.c_str() ,r.c_str());
    return CLI_OK;
}


int cli_diag_mem_objects_search(struct cli_def *cli, const char *command, char *argv[], int argc) {

    debug_cli_params(cli, command, argv, argc);

    std::string object_filter;
    int verbosity = iINF;

    if(argc > 0) {
        std::string a1 = argv[0];
        if(a1 == "?") {
            cli_print(cli,"valid parameters:");
            cli_print(cli,"         <empty>     - all entries will be printed out");
            cli_print(cli,"         any string  - objects with descriptions containing this string will be printed out");

            return CLI_OK;
        } else {
            // a1 is param for the lookup
            if("*" == a1 || "ALL" == a1) {
                object_filter = "";
            } else {
                object_filter = a1;
            }
        }

        if(argc > 1) {
            std::string a2 = argv[1];
            verbosity = safe_val(a2,iINF);
        }
    }


    std::string r = sobjectDB::str_list(nullptr,nullptr,verbosity,object_filter.c_str());

    cli_print(cli,"Smithproxy objects (filter: %s):\n%s\nFinished.",(object_filter.empty()) ? "ALL" : object_filter.c_str() ,r.c_str());
    return CLI_OK;
}



int cli_diag_mem_objects_clear(struct cli_def *cli, const char *command, char *argv[], int argc) {

    debug_cli_params(cli, command, argv, argc);

    std::string address;

    if(argc > 0) {
        std::string a1 = argv[0];
        if(a1 == "?") {
            cli_print(cli,"valid parameters:");
            cli_print(cli,"         <object id>");

            return CLI_OK;
        } else {
            // a1 is param for the lookup
            address = a1.c_str();

            uint64_t key = strtol(address.c_str(),nullptr,16);
            cli_print(cli,"Trying to clear 0x%lux",key);


            int ret = -1;
            {
                std::scoped_lock<std::recursive_mutex> l_(sobjectDB::db().getlock());
                ret = sobjectDB::ask_destroy((void *) key);
            }

            switch(ret) {
                case 1:
                    cli_print(cli,"object agrees to terminate.");
                    break;
                case 0:
                    cli_print(cli,"object doesn't agree to terminate, or doesn't support it.");
                    break;
                case -1:
                    cli_print(cli, "object not found.");
                    break;
                default:
                    cli_print(cli, "unknown result.");
                    break;
            }
        }
    }

    return CLI_OK;
}



int cli_diag_proxy_session_list(struct cli_def *cli, const char *command, char *argv[], int argc) {

    debug_cli_params(cli, command, argv, argc);

    return cli_diag_proxy_session_list_extra(cli, command, argv, argc, SL_NONE);
}

int cli_diag_proxy_session_io_list(struct cli_def *cli, const char *command, char *argv[], int argc) {

    debug_cli_params(cli, command, argv, argc);

    int f = 0;
    flag_set<int>(&f, SL_IO_OSBUF_NZ);
    flag_set<int>(&f, SL_IO_EMPTY);

    return cli_diag_proxy_session_list_extra(cli, command, argv, argc, f);
}


int cli_diag_proxy_session_list_extra(struct cli_def *cli, const char *command, char *argv[], int argc, int sl_flags) {

    debug_cli_params(cli, command, argv, argc);

    std::string a1,a2;
    int verbosity = iINF;
    if(argc > 0) {
        a1 = argv[0];
        verbosity = safe_val(a1,iINF);
    }
    if(argc > 1) a2 = argv[1];

    std::stringstream ss;

    time_t  curtime = time(nullptr);


    {
        std::scoped_lock<std::recursive_mutex> l_(sobjectDB::db().getlock());

        for (auto it: sobjectDB::db().cache()) {

            socle::sobject *ptr = it.first;
            std::string prefix;


            if (!ptr) continue;

            if (ptr->class_name() == "MitmProxy" || ptr->class_name() == "SocksProxy") {

                auto *curr_proxy = dynamic_cast<MitmProxy *>(ptr);
                MitmHostCX *lf = nullptr;
                MitmHostCX *rg = nullptr;

                if (curr_proxy) {
                    lf = curr_proxy->first_left();
                    rg = curr_proxy->first_right();
                } else {
                    continue;
                }

                /* apply filters */

                bool do_print = false;

                if (flag_check<int>(sl_flags, SL_IO_OSBUF_NZ)) {

                    unsigned int l_in_pending = 0;
                    unsigned int l_out_pending = 0;
                    unsigned int r_out_pending = 0;
                    unsigned int r_in_pending = 0;

                    if (lf && lf->real_socket() > 0) {
                        ::ioctl(lf->socket(), SIOCINQ, &l_in_pending);
                        ::ioctl(lf->socket(), SIOCOUTQ, &l_out_pending);
                    }
                    if (rg && rg->real_socket() > 0) {
                        ::ioctl(lf->socket(), SIOCINQ, &r_in_pending);
                        ::ioctl(lf->socket(), SIOCOUTQ, &r_out_pending);
                    }

                    if (l_in_pending + l_out_pending + r_in_pending + r_out_pending != 0) {

                        prefix = "OS";

                        if (l_in_pending) { prefix += "-Li"; }
                        if (r_in_pending) { prefix += "-Ri"; }
                        if (l_out_pending) { prefix += "-Lo"; }
                        if (r_out_pending) { prefix += "-Ro"; }

                        prefix += " ";

                        do_print = true;
                    }

                    if (lf && rg) {
                        if (lf->meter_read_bytes != rg->meter_write_bytes) {
                            prefix += "LRdeSync ";
                            do_print = true;
                        }

                        if (lf->meter_write_bytes != rg->meter_read_bytes) {
                            prefix += "RLdeSync ";
                            do_print = true;
                        }
                    }

                    if (lf && lf->writebuf() && (! lf->writebuf()->empty())) {
                        prefix += "LWrBuf ";
                        do_print = true;
                    }

                    if (rg && rg->writebuf() && (! rg->writebuf()->empty())) {
                        prefix += "RWrBuf ";
                        do_print = true;

                    }

                }

                if (flag_check<int>(sl_flags, SL_IO_EMPTY)) {

                    int both = 0;
                    std::string loc_pr;

                    if (lf && (lf->meter_read_bytes == 0 || lf->meter_write_bytes == 0)) {
                        loc_pr += "LEmp ";

                        both++;
                        do_print = true;
                    }

                    if (rg && (rg->meter_read_bytes == 0 || rg->meter_write_bytes == 0)) {
                        loc_pr += "REmp ";

                        both++;
                        do_print = true;
                    }

                    if (both > 1)
                        loc_pr = "Emp";

                    if (both > 0)
                        prefix += loc_pr;
                }

                if (sl_flags == SL_NONE) {
                    do_print = true;
                }

                if (!do_print) {
                    continue;
                }

                std::stringstream cur_obj_ss;

                socle::sobject_info *si = it.second;

                if (!prefix.empty()) {

                    if (prefix[prefix.size() - 1] != ' ')
                        prefix += " "; // separate IO flags


                    prefix += "\r\n";
                }

                cur_obj_ss << prefix << ptr->to_string(verbosity);

                if (verbosity >= DEB && si) {
                    cur_obj_ss << si->to_string(verbosity);
                }

                if (verbosity > INF) {

                    if (lf) {
                        if (verbosity > INF) ss << "\n    ";
                        if (lf->application_data) {
                            std::string desc = lf->application_data->hr();
                            if (verbosity < DEB && desc.size() > 120) {
                                desc = desc.substr(0, 117);
                                desc += "...";
                            }
                            cur_obj_ss << "\n    app_data: " << desc << "\n";
                        } else {
                            cur_obj_ss << "app_data: none\n";
                        }

                        if (verbosity > INF) {
                            cur_obj_ss << "    obj_debug: " << curr_proxy->get_this_log_level().to_string() << "\n";
                            long expiry = -1;
                            if (curr_proxy->half_holdtimer > 0) {
                                expiry = curr_proxy->half_holdtimer + MitmProxy::half_timeout() - curtime;
                            }
                            cur_obj_ss << "    half_hold: " << expiry << "\n";
                        }
                    }


                    auto print_queue_stats = [] (std::stringstream &ss, int verbosity, MitmHostCX *cx, const char *sm,
                                                 const char *bg) {
                        unsigned int in_pending, out_pending;
                        buffer::size_type in_buf, out_buf, in_cap, out_cap;

                        ::ioctl(cx->socket(), SIOCINQ, &in_pending);
                        ::ioctl(cx->socket(), SIOCOUTQ, &out_pending);

                        in_buf = cx->readbuf()->size();
                        in_cap  = cx->readbuf()->capacity();

                        out_buf = cx->writebuf()->size();
                        out_cap  = cx->writebuf()->capacity();

                        ss << "     " << sm << "_os_recv-q: " << in_pending << " " << sm << "_os_send-q: "
                           << out_pending << "\n";
                        ss << "     " << sm << "_sx_recv-q[" << in_cap << "]: " << in_buf << " " << sm << "_sx_send-q[" << out_cap << "]: " << out_buf
                           << "\n";

                        // fun stuff
                        if (verbosity >= EXT) {
                            if (in_buf) {
                                ss << "     " << bg << " last-seen read data: \n" << hex_dump(cx->readbuf(), 6) << "\n";
                            }
                        }
                    };


                    if (lf) {
                        if (verbosity > INF) {
                            if (lf->socket() > 0) {
                                print_queue_stats(cur_obj_ss, verbosity, lf, "lf", "Left");
                            }
                        }

                        if (verbosity > DIA) {
                            cur_obj_ss << "     lf_debug: " << lf->get_this_log_level().to_string() << "\n";
                            if (lf->com()) {
                                cur_obj_ss << "       lf_com: " << lf->com()->get_this_log_level().to_string() << "\n";
                            }
                        }
                    }
                    if (rg) {
                        if (verbosity > INF) {
                            if (rg->socket() > 0) {
                                print_queue_stats(cur_obj_ss, verbosity, rg, "rg", "Right");
                            }
                        }
                        if (verbosity > DIA) {
                            cur_obj_ss << "     rg_debug: " << rg->get_this_log_level().to_string() << "\n";
                            if (rg->com()) {
                                cur_obj_ss << "       rg_com: " << rg->com()->get_this_log_level().to_string() << "\n";
                            }
                        }
                    }


                }
                ss << cur_obj_ss.str() << "\n";
            }
        }
    }


    cli_print(cli,"%s",ss.str().c_str());

    if( sl_flags == SL_NONE ) {
        unsigned long l = MitmProxy::total_mtr_up().get();
        unsigned long r = MitmProxy::total_mtr_down().get();
        cli_print(cli, "\nProxy performance: upload %sbps, download %sbps in last second",
                                     number_suffixed(l * 8).c_str(), number_suffixed(r * 8).c_str());
    }
    return CLI_OK;

}

int cli_diag_proxy_session_clear(struct cli_def *cli, const char *command, char *argv[], int argc) {

    debug_cli_params(cli, command, argv, argc);

    //return cli_diag_mem_objects_clear(cli,command,argv,argc);

    cli_print(cli,"To be implemented, sorry.");
    return CLI_OK;
}

int cli_diag_proxy_policy_list(struct cli_def *cli, const char *command, char *argv[], int argc) {

    debug_cli_params(cli, command, argv, argc);

    std::string filter;
    int verbosity = 6;

    if(argc > 0) {
        if(argv[0][0] == '?') {

            cli_print(cli,"specify verbosity, default is 6s");
            return CLI_OK;
        }
        else {
        verbosity = safe_val(argv[0],6);
        }
    }
    if(argc > 1) filter = argv[1];

    std::stringstream out;

    {
        std::scoped_lock<std::recursive_mutex> l_(CfgFactory::lock());

        for (auto const& it: CfgFactory::get().db_policy) {
            out << it->to_string(verbosity);
            out << "\n\n";
        }
    }

    cli_print(cli, "%s", out.str().c_str());
    return CLI_OK;
}


int cli_diag_sig_list(struct cli_def *cli, const char *command, char *argv[], int argc) {

    debug_cli_params(cli, command, argv, argc);

    std::stringstream ss;


    ss << "\nSignatures:\n\n";

    // explicitly make shared_ptr from the list

    std::vector< std::vector<std::shared_ptr<duplexFlowMatch>>*> lists;
    lists.push_back(& SigFactory::get().tls());
    lists.push_back(& SigFactory::get().detection());

    for(auto* list: lists)
        for(std::shared_ptr<duplexFlowMatch> const& sig: *list) {

            // print refcnt one less, due to this shared_ptr serving only priting purposes
            ss << "Name: '" << sig->name() << "' refcnt: " << sig.use_count() - 1 << "\n";
            ss << "  chain size: " << sig->sig_chain().size() << "\n";

            auto sx_ptr = std::dynamic_pointer_cast<MyDuplexFlowMatch>(sig);
            if(sx_ptr) {
                ss << "  category: " << sx_ptr->category << "\n";
                ss << "  severity: " << sx_ptr->severity << "\n";
                ss << "  side: " << sx_ptr->sig_side << "\n";
            }

            ss << "\n";
        }


    cli_print(cli, "%s", ss.str().c_str());

    return CLI_OK;
}



struct cli_ext : public cli_def {
    int socket;
};


void cli_register_static(struct cli_def* cli) {

    struct cli_command *save;

    struct cli_command *exec;
    struct cli_command *exec_reload;

    struct cli_command *show;
    struct cli_command *show_config;

    struct cli_command *test;
    struct cli_command *test_dns;

    struct cli_command *debuk;
    struct cli_command *diag;

    struct cli_command *diag_ssl;
    struct cli_command *diag_ssl_cache;
    struct cli_command *diag_ssl_wl;
    struct cli_command *diag_ssl_crl;
    struct cli_command *diag_ssl_verify;
    struct cli_command *diag_ssl_ticket;
    struct cli_command *diag_ssl_memcheck;
    struct cli_command *diag_ssl_ca;

    struct cli_command *diag_mem;
    struct cli_command *diag_mem_buffers;
    struct cli_command *diag_mem_objects;
    struct cli_command *diag_mem_trace;

    struct cli_command *diag_dns;
    struct cli_command *diag_dns_cache;
    struct cli_command *diag_dns_domains;

    struct cli_command *diag_proxy;
    struct cli_command *diag_proxy_policy;
    struct cli_command *diag_proxy_session;
    struct cli_command *diag_proxy_io;

    struct cli_command *diag_identity;
    struct cli_command *diag_identity_user;

    struct cli_command *diag_sig;

    save  = cli_register_command(cli, nullptr, "save", nullptr, PRIVILEGE_PRIVILEGED, MODE_ANY, "save configs");
    cli_register_command(cli, save, "config", cli_save_config, PRIVILEGE_PRIVILEGED, MODE_ANY, "save config file");

    exec = cli_register_command(cli, nullptr, "execute", nullptr, PRIVILEGE_PRIVILEGED, MODE_ANY, "execute various tasks");
    exec_reload = cli_register_command(cli, exec, "reload", cli_exec_reload, PRIVILEGE_PRIVILEGED, MODE_ANY, "reload config file");

    show  = cli_register_command(cli, nullptr, "show", cli_show, PRIVILEGE_UNPRIVILEGED, MODE_ANY, "show basic information");
    cli_register_command(cli, show, "status", cli_show_status, PRIVILEGE_UNPRIVILEGED, MODE_EXEC, "show smithproxy status");
    show_config = cli_register_command(cli, show, "config", nullptr, PRIVILEGE_UNPRIVILEGED, MODE_ANY, "show smithproxy configuration related commands");
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

    test  = cli_register_command(cli, nullptr, "test", nullptr, PRIVILEGE_UNPRIVILEGED, MODE_EXEC, "various testing commands");
    test_dns = cli_register_command(cli, test, "dns", nullptr, PRIVILEGE_UNPRIVILEGED, MODE_EXEC, "dns related testing commands");
    cli_register_command(cli, test_dns, "genrequest", cli_test_dns_genrequest, PRIVILEGE_UNPRIVILEGED, MODE_EXEC, "generate dns request");
    cli_register_command(cli, test_dns, "sendrequest", cli_test_dns_sendrequest, PRIVILEGE_UNPRIVILEGED, MODE_EXEC, "generate and send dns request to configured nameserver");
    cli_register_command(cli, test_dns, "refreshallfqdns", cli_test_dns_refreshallfqdns, PRIVILEGE_UNPRIVILEGED, MODE_EXEC, "refresh all configured FQDN address objects against configured nameserver");

    diag  = cli_register_command(cli, nullptr, "diag", nullptr, PRIVILEGE_UNPRIVILEGED, MODE_EXEC, "diagnose commands helping to troubleshoot");
    diag_ssl = cli_register_command(cli, diag, "ssl", nullptr, PRIVILEGE_UNPRIVILEGED, MODE_EXEC, "ssl related troubleshooting commands");
    diag_ssl_cache = cli_register_command(cli, diag_ssl, "cache", nullptr, PRIVILEGE_UNPRIVILEGED, MODE_EXEC, "diagnose ssl certificate cache");
    cli_register_command(cli, diag_ssl_cache, "stats", cli_diag_ssl_cache_stats, PRIVILEGE_UNPRIVILEGED, MODE_EXEC, "display ssl cert cache statistics");
    cli_register_command(cli, diag_ssl_cache, "list", cli_diag_ssl_cache_list, PRIVILEGE_PRIVILEGED, MODE_EXEC, "list all ssl cert cache entries");
    cli_register_command(cli, diag_ssl_cache, "print", cli_diag_ssl_cache_print, PRIVILEGE_PRIVILEGED, MODE_EXEC, "print all ssl cert cache entries");
    cli_register_command(cli, diag_ssl_cache, "clear", cli_diag_ssl_cache_clear, PRIVILEGE_PRIVILEGED, MODE_EXEC, "remove all ssl cert cache entries");
    diag_ssl_wl = cli_register_command(cli, diag_ssl, "whitelist", nullptr, PRIVILEGE_UNPRIVILEGED, MODE_EXEC, "diagnose ssl temporary verification whitelist");
    cli_register_command(cli, diag_ssl_wl, "list", cli_diag_ssl_wl_list, PRIVILEGE_PRIVILEGED, MODE_EXEC, "list all verification whitelist entries");
    cli_register_command(cli, diag_ssl_wl, "clear", cli_diag_ssl_wl_clear, PRIVILEGE_PRIVILEGED, MODE_EXEC, "clear all verification whitelist entries");
    cli_register_command(cli, diag_ssl_wl, "stats", cli_diag_ssl_wl_stats, PRIVILEGE_PRIVILEGED, MODE_EXEC, "verification whitelist cache stats");
    diag_ssl_crl = cli_register_command(cli, diag_ssl, "crl", nullptr, PRIVILEGE_UNPRIVILEGED, MODE_EXEC, "diagnose dynamically downloaded CRLs");
    cli_register_command(cli, diag_ssl_crl, "list", cli_diag_ssl_crl_list, PRIVILEGE_PRIVILEGED, MODE_EXEC, "list all CRLs");
    cli_register_command(cli, diag_ssl_crl, "stats", cli_diag_ssl_crl_stats, PRIVILEGE_PRIVILEGED, MODE_EXEC, "CRLs cache stats");
    diag_ssl_verify = cli_register_command(cli, diag_ssl, "verify", nullptr, PRIVILEGE_UNPRIVILEGED, MODE_EXEC, "diagnose certificate verification status cache");
    cli_register_command(cli, diag_ssl_verify, "list", cli_diag_ssl_verify_list, PRIVILEGE_PRIVILEGED, MODE_EXEC, "list certificate verification status cache content");
    cli_register_command(cli, diag_ssl_verify, "stats", cli_diag_ssl_verify_stats, PRIVILEGE_PRIVILEGED, MODE_EXEC, "certificate verification status cache stats");
    cli_register_command(cli, diag_ssl_verify, "clear", cli_diag_ssl_verify_clear, PRIVILEGE_PRIVILEGED, MODE_EXEC, "clear certificate verification cache");
    diag_ssl_ticket = cli_register_command(cli, diag_ssl, "ticket", nullptr, PRIVILEGE_UNPRIVILEGED, MODE_EXEC, "diagnose abbreviated handshake session/ticket cache");
    cli_register_command(cli, diag_ssl_ticket, "list", cli_diag_ssl_ticket_list, PRIVILEGE_PRIVILEGED, MODE_EXEC, "list abbreviated handshake session/ticket cache");
    cli_register_command(cli, diag_ssl_ticket, "stats", cli_diag_ssl_ticket_stats, PRIVILEGE_PRIVILEGED, MODE_EXEC, "abbreviated handshake session/ticket cache stats");
    diag_ssl_ca     = cli_register_command(cli, diag_ssl, "ca", nullptr, PRIVILEGE_UNPRIVILEGED, MODE_EXEC, "diagnose SSL signing CA");
    cli_register_command(cli, diag_ssl_ca, "reload", cli_diag_ssl_ca_reload, PRIVILEGE_PRIVILEGED, MODE_EXEC, "reload signing CA key and certificate");
    diag_sig = cli_register_command(cli, diag, "sig", nullptr, PRIVILEGE_UNPRIVILEGED, MODE_EXEC, "signature engine diagnostics");
    cli_register_command(cli, diag_sig, "list", cli_diag_sig_list, PRIVILEGE_PRIVILEGED, MODE_EXEC, "list engine signatures");


    if(cfg_openssl_mem_dbg) {
#ifndef USE_OPENSSL11
        diag_ssl_memcheck = cli_register_command(cli, diag_ssl, "memcheck", nullptr, PRIVILEGE_UNPRIVILEGED, MODE_EXEC, "diagnose openssl memcheck");
                    cli_register_command(cli, diag_ssl_memcheck, "list", cli_diag_ssl_memcheck_list, PRIVILEGE_PRIVILEGED, MODE_EXEC, "print out OpenSSL memcheck status");
                    cli_register_command(cli, diag_ssl_memcheck, "enable", cli_diag_ssl_memcheck_enable, PRIVILEGE_PRIVILEGED, MODE_EXEC, "enable OpenSSL debug collection");
                    cli_register_command(cli, diag_ssl_memcheck, "disable", cli_diag_ssl_memcheck_disable, PRIVILEGE_PRIVILEGED, MODE_EXEC, "disable OpenSSL debug collection");
#endif
    }

    diag_mem = cli_register_command(cli, diag, "mem", nullptr, PRIVILEGE_UNPRIVILEGED, MODE_EXEC, "memory related troubleshooting commands");
    diag_mem_buffers = cli_register_command(cli, diag_mem, "buffers", nullptr, PRIVILEGE_UNPRIVILEGED, MODE_EXEC, "memory buffers troubleshooting commands");
    cli_register_command(cli, diag_mem_buffers, "stats", cli_diag_mem_buffers_stats, PRIVILEGE_UNPRIVILEGED, MODE_EXEC, "memory buffers statistics");
    diag_mem_objects = cli_register_command(cli, diag_mem, "objects", nullptr, PRIVILEGE_UNPRIVILEGED, MODE_EXEC, "memory object troubleshooting commands");
    cli_register_command(cli, diag_mem_objects, "stats", cli_diag_mem_objects_stats, PRIVILEGE_UNPRIVILEGED, MODE_EXEC, "memory objects statistics");
    cli_register_command(cli, diag_mem_objects, "list", cli_diag_mem_objects_list, PRIVILEGE_UNPRIVILEGED, MODE_EXEC, "memory objects list");
    cli_register_command(cli, diag_mem_objects, "search", cli_diag_mem_objects_search, PRIVILEGE_UNPRIVILEGED, MODE_EXEC, "memory objects search");
    cli_register_command(cli, diag_mem_objects, "clear", cli_diag_mem_objects_clear, PRIVILEGE_PRIVILEGED, MODE_EXEC, "clears memory object");
    diag_mem_trace = cli_register_command(cli, diag_mem, "trace", nullptr, PRIVILEGE_UNPRIVILEGED, MODE_EXEC, "memory tracing commands");
    cli_register_command(cli, diag_mem_trace, "list", cli_diag_mem_trace_list, PRIVILEGE_PRIVILEGED, MODE_EXEC, "print out memory allocation traces (arg: number of top entries to print)");
    cli_register_command(cli, diag_mem_trace, "mark", cli_diag_mem_trace_mark, PRIVILEGE_PRIVILEGED, MODE_EXEC, "mark all currently existing allocations as seen.");
    diag_dns = cli_register_command(cli, diag, "dns", nullptr, PRIVILEGE_UNPRIVILEGED, MODE_EXEC, "DNS traffic related troubleshooting commands");
    diag_dns_cache = cli_register_command(cli, diag_dns, "cache", nullptr, PRIVILEGE_UNPRIVILEGED, MODE_EXEC, "DNS traffic cache troubleshooting commands");
    cli_register_command(cli, diag_dns_cache, "list", cli_diag_dns_cache_list, PRIVILEGE_PRIVILEGED, MODE_EXEC, "list all DNS traffic cache entries");
    cli_register_command(cli, diag_dns_cache, "stats", cli_diag_dns_cache_stats, PRIVILEGE_PRIVILEGED, MODE_EXEC, "DNS traffic cache statistics");
    cli_register_command(cli, diag_dns_cache, "clear", cli_diag_dns_cache_clear, PRIVILEGE_PRIVILEGED, MODE_EXEC, "clear DNS traffic cache");
    diag_dns_domains = cli_register_command(cli, diag_dns, "domain", nullptr, PRIVILEGE_UNPRIVILEGED, MODE_EXEC, "DNS domain cache troubleshooting commands");
    cli_register_command(cli, diag_dns_domains, "list", cli_diag_dns_domain_cache_list, PRIVILEGE_PRIVILEGED, MODE_EXEC, "DNS sub-domain list");
    cli_register_command(cli, diag_dns_domains, "clear", cli_diag_dns_domain_cache_clear, PRIVILEGE_PRIVILEGED, MODE_EXEC, "clear DNS sub-domain cache");
    diag_proxy = cli_register_command(cli, diag, "proxy",nullptr, PRIVILEGE_PRIVILEGED, MODE_EXEC, "proxy related troubleshooting commands");
    diag_proxy_policy = cli_register_command(cli,diag_proxy,"policy",nullptr,PRIVILEGE_PRIVILEGED, MODE_EXEC,"proxy policy commands");
    cli_register_command(cli, diag_proxy_policy,"list",cli_diag_proxy_policy_list, PRIVILEGE_PRIVILEGED, MODE_EXEC,"proxy policy list");
    diag_proxy_session = cli_register_command(cli,diag_proxy,"session",nullptr,PRIVILEGE_PRIVILEGED, MODE_EXEC,"proxy session commands");
    cli_register_command(cli, diag_proxy_session,"list",cli_diag_proxy_session_list, PRIVILEGE_PRIVILEGED, MODE_EXEC,"proxy session list");
    cli_register_command(cli, diag_proxy_session,"clear",cli_diag_proxy_session_clear, PRIVILEGE_PRIVILEGED, MODE_EXEC,"proxy session clear");

    diag_proxy_io = cli_register_command(cli,diag_proxy,"io",nullptr,PRIVILEGE_PRIVILEGED, MODE_EXEC,"proxy I/O related commands");
    cli_register_command(cli, diag_proxy_io ,"list",cli_diag_proxy_session_io_list, PRIVILEGE_PRIVILEGED, MODE_EXEC,"active proxy sessions");

    diag_identity = cli_register_command(cli,diag,"identity",nullptr,PRIVILEGE_PRIVILEGED, MODE_EXEC,"identity related commands");
    diag_identity_user = cli_register_command(cli, diag_identity,"user",nullptr, PRIVILEGE_PRIVILEGED, MODE_EXEC,"identity commands related to users");
    cli_register_command(cli, diag_identity_user,"list",cli_diag_identity_ip_list, PRIVILEGE_PRIVILEGED, MODE_EXEC,"list all known users");
    cli_register_command(cli, diag_identity_user,"clear",cli_diag_identity_ip_clear, PRIVILEGE_PRIVILEGED, MODE_EXEC,"CLEAR all known users");

    auto diag_writer = cli_register_command(cli,diag,"writer",nullptr,PRIVILEGE_PRIVILEGED, MODE_EXEC,"file writer diags");
    auto diag_writer_stats = cli_register_command(cli,diag_writer,"stats",cli_diag_writer_stats,PRIVILEGE_PRIVILEGED, MODE_EXEC,"file writer statistics");


    debuk = cli_register_command(cli, nullptr, "debug", nullptr, PRIVILEGE_PRIVILEGED, MODE_EXEC, "diagnostic commands");
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


    // generate dynamically content of config

    auto cli_add_static_section = [](std::string const& section, int mode, CliCallbacks::callback edit_cb) {
        CliState::get().callbacks(
                section,
                CliState::callback_entry(mode, CliCallbacks()
                        .cmd_set(cli_generic_set_cb)
                        .cmd_config(edit_cb)));

    };

    CliState::get().callbacks(
            "settings",
            CliState::callback_entry(MODE_EDIT_SETTINGS, CliCallbacks()
                .cmd_set(cli_generic_set_cb)
                .cmd_config(cli_conf_edit_settings)));

    CliState::get().callbacks(
            "settings.auth_portal",
            CliState::callback_entry(MODE_EDIT_SETTINGS_AUTH, CliCallbacks()
                .cmd_set(cli_generic_set_cb)
                .cmd_config(cli_conf_edit_settings_auth)));

    CliState::get().callbacks(
            "settings.socks",
            CliState::callback_entry(MODE_EDIT_SETTINGS_SOCKS, CliCallbacks()
                .cmd_set(cli_generic_set_cb)
                .cmd_config(cli_conf_edit_settings_socks)));

    CliState::get().callbacks(
            "settings.cli",
            CliState::callback_entry(MODE_EDIT_SETTINGS_CLI, CliCallbacks()
                .cmd_set(cli_generic_set_cb)
                .cmd_config(cli_conf_edit_settings_cli)));

    cli_add_static_section("debug", MODE_EDIT_DEBUG, cli_conf_edit_debug);
    cli_add_static_section("debug.log", MODE_EDIT_DEBUG_LOG, cli_conf_edit_debug_log);

    CliState::get().callbacks(
            "proto_objects",
            CliState::callback_entry(MODE_EDIT_PROTO_OBJECTS, CliCallbacks()
                .cmd_set(cli_generic_set_cb)
                .cmd_config(cli_conf_edit_proto_objects)));

    CliState::get().callbacks(
            "address_objects",
            CliState::callback_entry(MODE_EDIT_ADDRESS_OBJECTS, CliCallbacks()
                    .cmd_set(cli_generic_set_cb)
                    .cmd_config(cli_conf_edit_address_objects)));

    CliState::get().callbacks(
            "port_objects",
            CliState::callback_entry(MODE_EDIT_PORT_OBJECTS, CliCallbacks()
                .cmd_set(cli_generic_set_cb)
                .cmd_config(cli_conf_edit_port_objects)));


    cli_add_static_section("policy", MODE_EDIT_POLICY, cli_conf_edit_policy);

    CliState::get().callbacks(
            "detection_profiles",
            CliState::callback_entry(MODE_EDIT_DETECTION_PROFILES, CliCallbacks()
                    .cmd_set(cli_generic_set_cb)
                    .cmd_config(cli_conf_edit_detection_profiles)));

    CliState::get().callbacks(
            "content_profiles",
            CliState::callback_entry(MODE_EDIT_CONTENT_PROFILES, CliCallbacks()
                    .cmd_set(cli_generic_set_cb)
                    .cmd_config(cli_conf_edit_content_profiles)));

    CliState::get().callbacks(
            "tls_profiles",
            CliState::callback_entry(MODE_EDIT_TLS_PROFILES, CliCallbacks()
                    .cmd_set(cli_generic_set_cb)
                    .cmd_config(cli_conf_edit_tls_profiles)));

    CliState::get().callbacks(
            "auth_profiles",
            CliState::callback_entry(MODE_EDIT_AUTH_PROFILES, CliCallbacks()
                    .cmd_set(cli_generic_set_cb)
                    .cmd_config(cli_conf_edit_auth_profiles)));

    CliState::get().callbacks(
            "alg_dns_profiles",
            CliState::callback_entry(MODE_EDIT_ALG_DNS_PROFILES, CliCallbacks()
                    .cmd_set(cli_generic_set_cb)
                    .cmd_config(cli_conf_edit_alg_dns_profiles)));



    cli_add_static_section("starttls_signatures", MODE_EDIT_STARTTLS_SIGNATURES, cli_conf_edit_starttls_signatures);
    cli_add_static_section("detection_signatures", MODE_EDIT_DETECTION_SIGNATURES, cli_conf_edit_detection_signatures);

    auto conft_edit = cli_register_command(cli, nullptr, "edit", nullptr, PRIVILEGE_PRIVILEGED, MODE_CONFIG, "configure smithproxy settings");


    std::vector<std::string> sections = { "settings", "debug",
                                          "proto_objects", "address_objects", "port_objects" ,
                                          "detection_profiles", "content_profiles", "tls_profiles", "auth_profiles",
                                          "alg_dns_profiles",
                                          "policy",
                                          "starttls_signatures",
                                          "detection_signatures" };
    for( auto const& section : sections) {

        if (CfgFactory::cfg_root().exists(section.c_str())) {

            std::string edit_help = string_format(" \t - edit %s", section.c_str());
            auto const& callback_entry = CliState::get().callbacks(section);

            cli_register_command(cli, conft_edit, section.c_str(), std::get<1>(callback_entry).cmd_config(),
                                                            PRIVILEGE_PRIVILEGED, MODE_CONFIG, edit_help.c_str());


            std::scoped_lock<std::recursive_mutex> l_(CfgFactory::lock());


            //std::vector<cli_command *> set_cmds = cli_generate_set_commands(cli, section);
            cli_generate_commands(cli, section, nullptr);
        }
    }

    // Pass the connection off to libcli
    get_logger()->remote_targets(string_format("cli-%d",client_socket),client_socket);

    logger_profile lp;
    lp.level_ = cfgapi_table.logging.cli_init_level;
    get_logger()->target_profiles()[(uint64_t)client_socket] = &lp;


    load_defaults();
    cli_loop(cli, client_socket);

    get_logger()->remote_targets().remove(client_socket);
    get_logger()->target_profiles().erase(client_socket);
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
    while ((client_socket = accept(s, nullptr, 0)))
    {
        auto* n = new std::thread(client_thread, client_socket);
    }
};


int cli_show(struct cli_def *cli, const char *command, char **argv, int argc) {

    debug_cli_params(cli, command, argv, argc);

    cli_print_section(cli, CliState::get().sections(cli->mode), -1, 200 * 1024);

    return CLI_OK;
}
