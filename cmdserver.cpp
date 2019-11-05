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

#include <logger.hpp>
#include <cmdserver.hpp>
#include <cfgapi.hpp>
#include <timeops.hpp>

#include <socle.hpp>
#include <sslcom.hpp>
#include <sslcertstore.hpp>

#include <main.hpp>
#include <mitmproxy.hpp>
#include <socksproxy.hpp>
#include <sobject.hpp>
#include <dns.hpp>
#include <inspectors.hpp>
#include <authfactory.hpp>


#include "socle_version.h"
#include "smithproxy_version.h"

using namespace socle;


int cli_port = 50000;
int cli_port_base = 50000;
std::string cli_enable_password;


static const char* debug_levels="\n\t0\tNONE\n\t1\tFATAL\n\t2\tCRITICAL\n\t3\tERROR\n\t4\tWARNING\n\t5\tNOTIFY\n\t6\tINFORMATIONAL\n\t7\tDIAGNOSE\t(may impact performance)\n\t8\tDEBUG\t(impacts performance)\n\t9\tEXTREME\t(severe performance drop)\n\t10\tDUMPALL\t(performance killer)\n\treset\treset back to level configured in config file";

loglevel orig_ssl_loglevel = NON;
loglevel orig_sslmitm_loglevel = NON;
loglevel orig_sslca_loglevel = NON;

loglevel orig_dns_insp_loglevel = NON;
loglevel orig_dns_packet_loglevel = NON;

loglevel orig_baseproxy_loglevel = NON;
loglevel orig_epoll_loglevel = NON;
loglevel orig_mitmproxy_loglevel = NON;
loglevel orig_mitmmasterproxy_loglevel = NON;

loglevel orig_mitmhostcx_loglevel = NON;
loglevel orig_socksproxy_loglevel =NON;

loglevel orig_auth_loglevel = NON;

extern bool cfg_openssl_mem_dbg;

void load_defaults() {
    orig_ssl_loglevel = SSLCom::log_level_ref();
    orig_sslmitm_loglevel = SSLMitmCom::log_level_ref();
    orig_sslca_loglevel = *SSLFactory::get_log().level();
    
    orig_dns_insp_loglevel = DNS_Inspector::log_level_ref();
    orig_dns_packet_loglevel = DNS_Packet::log_level_ref();
    
    orig_baseproxy_loglevel = baseProxy::log_level_ref();
    orig_epoll_loglevel = epoll::log_level;
    orig_mitmproxy_loglevel = MitmProxy::log_level_ref();
    orig_mitmmasterproxy_loglevel = MitmMasterProxy::log_level_ref();
}

std::unordered_map<std::string, std::string> cli_context_help;
std::unordered_map<std::string, std::string> cli_qmark_help;

void cli_help_add( std::string k, std::string v ) {
    cli_context_help[std::move(k)] = std::move(v);
}

void cli_qmark_add( std::string k, std::string v ) {
    cli_qmark_help[std::move(k)] = std::move(v);
}

typedef enum { HELP_CONTEXT=0, HELP_QMARK } help_type_t;

std::string& cli_help(help_type_t htype, const std::string& section, const std::string& key) {

    std::unordered_map<std::string, std::string>& ref = cli_context_help;

    switch(htype) {
        case HELP_QMARK:
            ref = cli_qmark_help;
            break;

        default:
            ;
    }

    auto i = ref.find(section + "/" + key);
    if(i != ref.end()) {
        return i->second;
    } else {

        i = ref.find("default");
        if(i != ref.end()) {
            return i->second;
        } else {
            ref["default"] = "";
            return ref["default"];
        }
    }
}

void init_cli_help() {
    cli_help_add("default","");
    cli_help_add("settings/certs_path", "directory for TLS-resigning CA certificate and key");
    cli_help_add("settings/certs_ca_key_password","TLS-resigning CA private key protection password");
    cli_help_add("settings/certs_ca_path", "trusted CA store path (to verify server-side connections)");
    cli_help_add("settings/plaintext_port", "base divert port for non-SSL TCP traffic");
    cli_help_add("settings/plaintext_workers", "non-SSL TCP traffic worker thread count");
    cli_help_add("settings/ssl_port", "base divert port for SSL TCP traffic");
    cli_help_add("settings/ssl_workers", "SSL TCP traffic worker thread count");
    cli_help_add("settings/ssl_autodetect", "Detect TLS ClientHello on unusual ports");
    cli_help_add("settings/ssl_autodetect_harder", "Detect TSL ClientHello - wait a bit longer");
    cli_help_add("settings/ssl_ocsp_status_ttl", "hardcoded TTL for OCSP response validity");
    cli_help_add("settings/ssl_crl_status_ttl", "hardcoded TTL for downloaded CRL files");
    cli_help_add("settings/udp_port", "base divert port for non-DTLS UDP traffic");
    cli_help_add("settings/udp_workers", "non-DTLS traffic worker thread count");
    cli_help_add("settings/dtls_port", "base divert port for DTLS UDP traffic");
    cli_help_add("settings/dtls_workers", "DTLS traffic worker thread count");
    cli_help_add("settings/socks_port", "base SOCKS proxy listening port");
    cli_help_add("settings/socks_workers", "SOCKS proxy traffic thread count");
    cli_help_add("settings/log_level", "file logging verbosity level");
    cli_help_add("settings/log_file", "log file");
    cli_help_add("settings/log_console", "toggle logging to standard output");
    cli_help_add("settings/syslog_server", "IP address of syslog server");
    cli_help_add("settings/syslog_port", "syslog server port");
    cli_help_add("settings/syslog_facility", "syslog facility");
    cli_help_add("settings/syslog_level", "syslog logging verbosity level");
    cli_help_add("settings/syslog_family", "IPv4 or IPv6?");
    cli_help_add("settings/sslkeylog_file", "where to dump TLS keying material");
    cli_help_add("settings/messages_dir", "replacement text directory");
    cli_help_add("settings/write_payload_dir", "root directory for packet dumps");
    cli_help_add("settings/write_payload_file_prefix", "packet dumps file prefix");
    cli_help_add("settings/write_payload_file_suffix", "packet dumps file suffix");
    cli_help_add("settings/auth_portal", "** configure authentication portal settings");
    cli_help_add("settings/cli", "** configure CLI specific settings");
    cli_help_add("settings/socks", "** configure SOCKS specific settings");


    cli_qmark_add("default", "enter <value>");
    cli_qmark_add("settings/certs_path", "<string> with path to a directory");
    cli_qmark_add("settings/certs_ca_key_password","");
    cli_qmark_add("settings/certs_ca_path", "");
    cli_qmark_add("settings/plaintext_port", "");
    cli_qmark_add("settings/plaintext_workers", "");
    cli_qmark_add("settings/ssl_port", "");
    cli_qmark_add("settings/ssl_workers", "");
    cli_qmark_add("settings/ssl_autodetect", "");
    cli_qmark_add("settings/ssl_autodetect_harder", "");
    cli_qmark_add("settings/ssl_ocsp_status_ttl", "");
    cli_qmark_add("settings/ssl_crl_status_ttl", "");
    cli_qmark_add("settings/udp_port", "");
    cli_qmark_add("settings/udp_workers", "");
    cli_qmark_add("settings/dtls_port", "");
    cli_qmark_add("settings/dtls_workers", "");
    cli_qmark_add("settings/socks_port", "");
    cli_qmark_add("settings/socks_workers", "");
    cli_qmark_add("settings/log_level", "");
    cli_qmark_add("settings/log_file", "");
    cli_qmark_add("settings/log_console", "");
    cli_qmark_add("settings/syslog_server", "");
    cli_qmark_add("settings/syslog_port", "");
    cli_qmark_add("settings/syslog_facility", "");
    cli_qmark_add("settings/syslog_level", "");
    cli_qmark_add("settings/syslog_family", "");
    cli_qmark_add("settings/sslkeylog_file", "");
    cli_qmark_add("settings/messages_dir", "");
    cli_qmark_add("settings/write_payload_dir", "");
    cli_qmark_add("settings/write_payload_file_prefix", "");
    cli_qmark_add("settings/write_payload_file_suffix", "");
    cli_qmark_add("settings/auth_portal", "");
    cli_qmark_add("settings/cli", "");
    cli_qmark_add("settings/socks", "");
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

    cli_print(cli," ");
    time_t uptime = time(nullptr) - CfgFactory::get().ts_sys_started;
    cli_print(cli,"Uptime: %s",uptime_string(uptime).c_str());
    cli_print(cli,"Objects: %ld",socle::sobjectDB::db().cache().size());
    unsigned long l = MitmProxy::total_mtr_up().get();
    unsigned long r = MitmProxy::total_mtr_down().get();
    cli_print(cli,"Proxy performance: upload %sbps, download %sbps in last second",number_suffixed(l*8).c_str(),number_suffixed(r*8).c_str());

}

int cli_show_status(struct cli_def *cli, const char *command, char *argv[], int argc)
{
    //cli_print(cli, "called %s with %s, argc %d\r\n", __FUNCTION__, command, argc);


    cmd_show_status(cli);
    return CLI_OK;
}


int cli_test_dns_genrequest(struct cli_def *cli, const char *command, char *argv[], int argc) {
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

        int s = generate_dns_request(id,b,argv[0],A);
        cli_print(cli,"DNS generated request: \n%s, %dB",hex_dump(b).c_str(), s);
    } else {
        cli_print(cli,"you need to specify hostname");
    }

    return CLI_OK;
}


DNS_Response* send_dns_request(struct cli_def *cli, std::string hostname, DNS_Record_Type t, std::string nameserver) {

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

    int s = generate_dns_request(id,b,hostname,t);
    cli_print(cli,"DNS generated request: \n%s, %dB",hex_dump(b).c_str(),s);

    // create UDP socket
    int send_socket = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    struct sockaddr_storage addr;
    memset(&addr, 0, sizeof(struct sockaddr_storage));
    addr.ss_family                = AF_INET;
    ((sockaddr_in*)&addr)->sin_addr.s_addr = inet_addr(nameserver.c_str());
    ((sockaddr_in*)&addr)->sin_port = htons(53);

    ::connect(send_socket,(sockaddr*)&addr,sizeof(sockaddr_storage));

    if(::send(send_socket,b.data(),b.size(),0) < 0) {
        std::string r = string_format("logger::write_log: cannot write remote socket: %d",send_socket);
        cli_print(cli,"%s",r.c_str());
        return CLI_OK;
    }

    int rv;
    fd_set confds;
    struct timeval tv;
    tv.tv_usec = 0;
    tv.tv_sec = 2;
    FD_ZERO(&confds);
    FD_SET(send_socket, &confds);
    rv = select(send_socket + 1, &confds, NULL, NULL, &tv);
    if(rv == 1) {
        buffer r(1500);
         int l = ::recv(send_socket,r.data(),r.capacity(),0);
        if(l > 0) {
            r.size(l);

            cli_print(cli, "received %d bytes",l);
            cli_print(cli, "\n%s\n",hex_dump(r).c_str());


            DNS_Response* resp = new DNS_Response();
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

    if(argc > 0) {

        std::string argv0(argv[0]);
        if( argv0 == "?" || argv0 == "\t") {
            cli_print(cli,"specify hostname.");
            return CLI_OK;
        }

        std::string nameserver = "8.8.8.8";
        if(CfgFactory::get().db_nameservers.size()) {
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
            FqdnAddress *fa = dynamic_cast<FqdnAddress *>(a.second);
            if (fa) {
                fqdns.push_back(fa->fqdn());
            }
        }
    }

    std::string nameserver = "8.8.8.8";
    if(CfgFactory::get().db_nameservers.size()) {
        nameserver = CfgFactory::get().db_nameservers.at(0);
    }

    DNS_Inspector di;
    for(auto a: fqdns) {
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

        for (auto x = store->cache().begin(); x != store->cache().end(); ++x) {
            std::string fqdn = x->first;
            SSLFactory::X509_PAIR* ptr = x->second;

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

        for (auto x = store->cache().begin(); x != store->cache().end(); ++x) {
            std::string fqdn = x->first;
            SSLFactory::X509_PAIR *ptr = x->second;

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

    SSLFactory* store = SSLCom::certstore();
    std::stringstream ss;


    {
        std::lock_guard<std::recursive_mutex> l_(store->lock());

        for (auto x = store->cache().begin(); x != store->cache().end(); ++x ) {
            std::string fqdn = x->first;
            ss << string_format("removing    %s\n",fqdn.c_str());
            SSLFactory::X509_PAIR* ptr = x->second;

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

    std::lock_guard<std::recursive_mutex> l_(MitmProxy::whitelist_verify().getlock());

    MitmProxy::whitelist_verify().clear();

    return CLI_OK;
}


int cli_diag_ssl_wl_stats(struct cli_def *cli, const char *command, char *argv[], int argc) {


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

    std::stringstream out;

    out << "Downloaded CRLs:\n\n";

    {
        std::lock_guard<std::recursive_mutex> l_(SSLFactory::crl_cache.getlock());
        for (auto const& x: SSLFactory::crl_cache.cache()) {
            std::string uri = x.first;
            auto cached_result = x.second;

            out << "    " + uri;
            if (cached_result) {
                int ttl = cached_result->expired_at() - ::time(nullptr);
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



int cli_diag_ssl_verify_list(struct cli_def *cli, const char *command, char *argv[], int argc) {


    std::stringstream out;

    out << "Verify status list:\n\n";

    {
        std::lock_guard<std::recursive_mutex> l_(SSLFactory::ocsp_result_cache.getlock());
        for (auto const& x: SSLFactory::ocsp_result_cache.cache()) {
            std::string cn = x.first;
            SSLFactory::expiring_ocsp_result *cached_result = x.second;
            long ttl = 0;
            if (cached_result) {
                ttl = cached_result->expired_at() - ::time(nullptr);
                out << string_format("    %s, ttl=%d", cn.c_str(), ttl);

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

    std::stringstream ss;
    {
        std::lock_guard<std::recursive_mutex> l_(SSLFactory::ocsp_result_cache.getlock());

        int n_sz_cache = SSLFactory::ocsp_result_cache.cache().size();
        int n_max_cache = SSLFactory::ocsp_result_cache.max_size();
        bool n_autorem = SSLFactory::ocsp_result_cache.auto_delete();
        std::string n_name = SSLFactory::ocsp_result_cache.name();


        ss << string_format("'%s' cache stats: \n", n_name.c_str());
        ss << string_format("    current size: %d \n", n_sz_cache);
        ss << string_format("    maximum size: %d \n", n_max_cache);
        ss << string_format("      autodelete: %d \n", n_autorem);
    }

    cli_print(cli,"\n%s",ss.str().c_str());

    return CLI_OK;
}


int cli_diag_ssl_ticket_list(struct cli_def *cli, const char *command, char *argv[], int argc) {

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

    cli_print(cli,"Not yet implemented");

    return CLI_OK;
}


int cli_diag_dns_cache_list(struct cli_def *cli, const char *command, char *argv[], int argc) {


    std::stringstream out;
    {
        std::scoped_lock<std::recursive_mutex> l_(DNS::get_dns_lock());


        out << "\nDNS cache populated from traffic: \n";

        for (auto const& it: DNS::get_dns_cache().cache()) {
            std::string s = it.first;
            DNS_Response *r = it.second;

            if (r != nullptr && r->answers().size() > 0) {
                int ttl = (r->loaded_at + r->answers().at(0).ttl_) - time(nullptr);
                out << string_format("    %s  -> [ttl:%d]%s\n", s.c_str(), ttl, r->answer_str().c_str());
            }
        }
    }

    cli_print(cli, "%s", out.str().c_str());

    return CLI_OK;
}

int cli_diag_dns_cache_stats(struct cli_def *cli, const char *command, char *argv[], int argc) {

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

    {
        std::scoped_lock<std::recursive_mutex> l_(DNS::get_dns_lock());
        DNS::get_dns_cache().clear();
    }

    cli_print(cli,"\nDNS cache cleared.");

    return CLI_OK;
}

int cli_diag_dns_domain_cache_list(struct cli_def *cli, const char *command, char *argv[], int argc) {

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
    cli_print(cli, "\n Clearing domain cache:");

    {
        std::scoped_lock<std::recursive_mutex> l_(DNS::get_domain_lock());
        DNS::get_domain_cache().clear();
    }

    cli_print(cli," done.");

    return CLI_OK;
}



int cli_diag_identity_ip_list(struct cli_def *cli, const char *command, char *argv[], int argc) {

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

    logger_profile* lp = get_logger()->target_profiles()[(uint64_t)fileno(cli->client)];
    if(argc > 0) {

        std::string a1 = argv[0];

        if(a1 == "?") {
            cli_print(cli,"valid parameters: %s",debug_levels);
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

    logger_profile* lp = get_logger()->target_profiles()[(uint64_t)fileno(cli->client)];
    if(argc > 0) {

        std::string a1 = argv[0];


        if(a1 == "?") {
            cli_print(cli,"valid parameters: %s",debug_levels);
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

    if(argc > 0) {

        std::string a1 = argv[0];

        if(a1 == "?") {
            cli_print(cli,"valid parameters: %s",debug_levels);
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
    if(argc > 0) {
        std::string a1 = argv[0];

        int newlev = 0;
        if(a1 == "?") {
            cli_print(cli,"valid parameters: %s",debug_levels);
        }
        else if(a1 == "reset") {
            SSLCom::log_level_ref() = orig_ssl_loglevel;
            SSLMitmCom::log_level_ref() = orig_sslmitm_loglevel;
            SSLFactory::get_log().level(orig_sslca_loglevel);
        }
        else {
            newlev = safe_val(argv[0]);;
            SSLCom::log_level_ref().level(newlev);
            SSLMitmCom::log_level_ref().level(newlev);
            SSLFactory::get_log().level(loglevel(newlev));

        }
    } else {
        int l = SSLCom::log_level_ref().level();
        cli_print(cli,"SSL debug level: %d",l);
        l = SSLMitmCom::log_level_ref().level();
        cli_print(cli,"SSL MitM debug level: %d",l);
        l = SSLFactory::get_log().level()->level();
        cli_print(cli,"SSL CA debug level: %d",l);
        cli_print(cli,"\n");
        cli_print(cli,"valid parameters: %s",debug_levels);
    }

    return CLI_OK;
}

int cli_debug_auth(struct cli_def *cli, const char *command, char *argv[], int argc) {
    if(argc > 0) {
        std::string a1 = argv[0];

        int newlev = 0;
        if(a1 == "?") {
            cli_print(cli,"valid parameters: %s",debug_levels);
        }
        else if(a1 == "reset") {
            AuthFactory::log_level_ref() = orig_auth_loglevel;
        }
        else {
            newlev = safe_val(a1);
            AuthFactory::log_level_ref().level(newlev);

        }
    } else {
        int l = AuthFactory::log_level_ref().level();
        cli_print(cli,"Auth debug level: %d",l);
        cli_print(cli,"\n");
        cli_print(cli,"valid parameters: %s",debug_levels);
    }

    return CLI_OK;
}

int cli_debug_dns(struct cli_def *cli, const char *command, char *argv[], int argc) {
    if(argc > 0) {
        std::string a1 = argv[0];
        if(a1 == "?") {
            cli_print(cli,"valid parameters: %s",debug_levels);
        }
        else if(a1 == "reset") {
            DNS_Inspector::log_level_ref() = orig_dns_insp_loglevel;
            DNS_Packet::log_level_ref() = orig_dns_packet_loglevel;
        }
        else {
            int lev = std::atoi(argv[0]);
            DNS_Inspector::log_level_ref().level(lev);
            DNS_Packet::log_level_ref().level(lev);

        }
    } else {
        int l = DNS_Inspector::log_level_ref().level();
        cli_print(cli,"DNS Inspector debug level: %d",l);
        l = DNS_Packet::log_level_ref().level();
        cli_print(cli,"DNS Packet debug level: %d",l);
        cli_print(cli,"\n");
        cli_print(cli,"valid parameters: %s",debug_levels);
    }

    return CLI_OK;
}

int cli_debug_sobject(struct cli_def *cli, const char *command, char *argv[], int argc) {

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
    if(argc > 0) {
        std::string a1 = argv[0];
        if(a1 == "?") {
            cli_print(cli,"valid parameters: %s",debug_levels);
        }
        else if(a1 == "reset") {
            baseProxy::log_level_ref() = orig_baseproxy_loglevel;
            epoll::log_level = orig_epoll_loglevel;

            MitmMasterProxy::log_level_ref() = orig_mitmproxy_loglevel;
            MitmHostCX::log_level_ref() = orig_mitmhostcx_loglevel;
            MitmProxy::log_level_ref() = orig_mitmproxy_loglevel;
            SocksProxy::log_level_ref() = orig_socksproxy_loglevel;
        }
        else {
            int lev = std::atoi(argv[0]);
            baseProxy::log_level_ref().level(lev);
            epoll::log_level.level(lev);

            MitmMasterProxy::log_level_ref().level(lev);
            MitmHostCX::log_level_ref().level(lev);
            MitmProxy::log_level_ref().level(lev);
            SocksProxy::log_level_ref().level(lev);

        }
    } else {
        int l = baseProxy::log_level_ref().level();
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
        cli_print(cli,"valid parameters: %s",debug_levels);
    }

    return CLI_OK;
}


int cli_debug_show(struct cli_def *cli, const char *command, char *argv[], int argc) {

    int l = baseProxy::log_level_ref().level();
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
    for(auto i: logan::get().topic_db_) {
        std::string t = i.first;
        loglevel* l = i.second;

        ss << "    [" << t << "] => level " << l->level() << " flag: " << l->topic() << "\n";
    }

    cli_print(cli, "%s", ss.str().c_str());

    return CLI_OK;
}



int cli_debug_set(struct cli_def *cli, const char *command, char *argv[], int argc) {

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

        //std::scoped_lock<std::recursive_mutex> l_(logan::get_lock());

        if(logan::get().topic_db_.find(var) != logan::get().topic_db_.end()) {
            loglevel* l = logan::get()[var];

            int old_lev = l->level();
            logan::get()[var]->level(newlev);

            cli_print(cli, "debug level changed: %s => %d => %d", var.c_str(), old_lev, newlev);
        } else {
            cli_print(cli, "variable not recognized");
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
    cli_print(cli,"Memory buffers stats: ");
    cli_print(cli,"memory alloc   bytes: %lld",buffer::alloc_bytes);
    cli_print(cli,"memory free    bytes: %lld",buffer::free_bytes);
    cli_print(cli,"memory current bytes: %lld",buffer::alloc_bytes-buffer::free_bytes);
    cli_print(cli,"\nmemory alloc   counter: %lld",buffer::alloc_count);
    cli_print(cli,"memory free    counter: %lld",buffer::free_count);
    cli_print(cli,"memory current counter: %lld",buffer::alloc_count-buffer::free_count);


    if (buffer::use_pool) {

        std::scoped_lock<std::mutex> g(memPool::pool().lock);

        cli_print(cli, "\nMemory pool API stats:");
        cli_print(cli, "acquires: %lld/%lldB", memPool::pool().stat_acq, memPool::pool().stat_acq_size);
        cli_print(cli, "releases: %lld/%lldB", memPool::pool().stat_ret, memPool::pool().stat_ret_size);

        cli_print(cli,"\nNon-API allocations:");
        cli_print(cli, "mp_allocs: %lld", stat_mempool_alloc);
        cli_print(cli, "mp_reallocs: %lld", stat_mempool_realloc);
        cli_print(cli, "mp_frees: %lld", stat_mempool_free);
        cli_print(cli, "mp_realloc cache miss: %lld", stat_mempool_realloc_miss);
        cli_print(cli, "mp_realloc fitting returns: %lld", stat_mempool_realloc_fitting);
        cli_print(cli, "mp_free cache miss: %lld", stat_mempool_free_miss);
        cli_print(cli, "mp ptr cache size: %ld", mempool_ptr_map.size());

        cli_print(cli," ");
        cli_print(cli, "API allocations above limits:");
        cli_print(cli, "allocations: %lld/%lldB", memPool::pool().stat_alloc, memPool::pool().stat_alloc_size);
        cli_print(cli, "   releases: %lld/%lldB", memPool::pool().stat_out_free, memPool::pool().stat_out_free_size);

        cli_print(cli,"\nPool capacities (available/limits):");
        cli_print(cli," 32B pool size: %ld/%ld", memPool::pool().mem_32_av(), memPool::pool().mem_32_sz());
        cli_print(cli," 64B pool size: %ld/%ld", memPool::pool().mem_64_av(), memPool::pool().mem_64_sz());
        cli_print(cli,"128B pool size: %ld/%ld", memPool::pool().mem_128_av(), memPool::pool().mem_128_sz());
        cli_print(cli,"256B pool size: %ld/%ld", memPool::pool().mem_256_av(), memPool::pool().mem_256_sz());
        cli_print(cli," 1kB pool size: %ld/%ld", memPool::pool().mem_1k_av(), memPool::pool().mem_1k_sz());
        cli_print(cli," 5kB pool size: %ld/%ld", memPool::pool().mem_5k_av(), memPool::pool().mem_5k_sz());
        cli_print(cli,"10kB pool size: %ld/%ld", memPool::pool().mem_10k_av(), memPool::pool().mem_10k_sz());
        cli_print(cli,"20kB pool size: %ld/%ld", memPool::pool().mem_20k_av(), memPool::pool().mem_20k_sz());
        cli_print(cli," big pool size: %ld", memPool::pool().mem_big_av());

        // (10 for 32 byte pool, and 3 for 64, 128 and 256 pool)
        unsigned long long total_pools = (10+3)*memPool::pool().mem_256_sz() + memPool::pool().mem_1k_sz() +
                                         memPool::pool().mem_5k_sz() + memPool::pool().mem_10k_sz() +
                                         memPool::pool().mem_20k_sz();

        cli_print(cli,"   total pools: %lld", total_pools);

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


int save_config_address_objects(Config& ex) {

    std::scoped_lock<std::recursive_mutex> l_(CfgFactory::lock());

    Setting& address_objects = ex.getRoot().add("address_objects", Setting::TypeGroup);

    int n_saved = 0;

    for (auto it: CfgFactory::get().db_address) {
        auto name = it.first;
        auto obj = it.second;

        Setting& item = address_objects.add(name, Setting::TypeGroup);

        if(obj->c_name() == std::string("FqdnAddress")) {
            Setting &s_type = item.add("type", Setting::TypeInt);
            Setting &s_fqdn = item.add("fqdn", Setting::TypeString);

            s_type = 1;
            s_fqdn = ((FqdnAddress*)(obj))->fqdn();

            n_saved++;
        }
        else
        if(obj->c_name() == std::string("CidrAddress")) {
            Setting &s_type = item.add("type", Setting::TypeInt);
            Setting &s_cidr = item.add("cidr", Setting::TypeString);

            s_type = 0;
            const char* addr = cidr_to_str(((CidrAddress*)(obj))->cidr());
            s_cidr =  addr;
            delete[] addr;

            n_saved++;
        }

    }

    return n_saved;
}


int save_config_port_objects(Config& ex) {

    std::scoped_lock<std::recursive_mutex> l_(CfgFactory::lock());

    Setting& objects = ex.getRoot().add("port_objects", Setting::TypeGroup);

    int n_saved = 0;

    for (auto it: CfgFactory::get().db_port) {
        auto name = it.first;
        auto obj = it.second;

        Setting& item = objects.add(name, Setting::TypeGroup);
        item.add("start", Setting::TypeInt) = obj.first;
        item.add("end", Setting::TypeInt) = obj.second;

        n_saved++;
    }

    return n_saved;
}


int save_config_proto_objects(Config& ex) {

    std::scoped_lock<std::recursive_mutex> l_(CfgFactory::lock());;

    Setting& objects = ex.getRoot().add("proto_objects", Setting::TypeGroup);

    int n_saved = 0;

    for (auto it: CfgFactory::get().db_proto) {
        auto name = it.first;
        auto obj = it.second;

        Setting& item = objects.add(name, Setting::TypeGroup);
        item.add("id", Setting::TypeInt) = obj;

        n_saved++;
    }

    return n_saved;
}


int save_config_debug(Config& ex) {

    if(!ex.exists("debug"))
        ex.getRoot().add("debug", Setting::TypeGroup);

    Setting& deb_objects = ex.getRoot()["debug"];

    deb_objects.add("log_data_crc", Setting::TypeBoolean) =  baseCom::debug_log_data_crc;
    deb_objects.add("log_sockets", Setting::TypeBoolean) = baseHostCX::socket_in_name;
    deb_objects.add("log_online_cx_name", Setting::TypeBoolean) = baseHostCX::online_name;
    deb_objects.add("log_srclines", Setting::TypeBoolean) = get_logger()->print_srcline();
    deb_objects.add("log_srclines_always", Setting::TypeBoolean) = get_logger()->print_srcline_always();


    Setting& deb_log_objects = deb_objects.add("log", Setting::TypeGroup);
    deb_log_objects.add("sslcom", Setting::TypeInt) = (int)SSLCom::log_level_ref().level_ref();
    deb_log_objects.add("sslmitmcom", Setting::TypeInt) = (int)baseSSLMitmCom<DTLSCom>::log_level_ref().level_ref();
    deb_log_objects.add("sslcertstore", Setting::TypeInt) = (int)SSLFactory::get_log().level()->level_ref();
    deb_log_objects.add("proxy", Setting::TypeInt) = (int)baseProxy::log_level_ref().level_ref();
    deb_log_objects.add("epoll", Setting::TypeInt) = (int)epoll::log_level.level_ref();
    deb_log_objects.add("mtrace", Setting::TypeBoolean) = cfg_mtrace_enable;
    deb_log_objects.add("openssl_mem_dbg", Setting::TypeBoolean) = cfg_openssl_mem_dbg;
    deb_log_objects.add("alg_dns", Setting::TypeInt) = (int)DNS_Inspector::log_level_ref().level_ref();
    deb_log_objects.add("pkt_dns", Setting::TypeInt) = (int)DNS_Packet::log_level_ref().level_ref();


    return 0;
}


int save_config_detection_profiles(Config& ex) {

    std::scoped_lock<std::recursive_mutex> l_(CfgFactory::lock());

    Setting& objects = ex.getRoot().add("detection_profiles", Setting::TypeGroup);

    int n_saved = 0;

    for (auto it: CfgFactory::get().db_prof_detection) {
        auto name = it.first;
        auto obj = it.second;

        Setting& item = objects.add(name, Setting::TypeGroup);
        item.add("mode", Setting::TypeInt) = obj->mode;

        n_saved++;
    }

    return n_saved;
}

int save_config_content_profiles(Config& ex) {

    std::scoped_lock<std::recursive_mutex> l_(CfgFactory::lock());

    Setting& objects = ex.getRoot().add("content_profiles", Setting::TypeGroup);

    int n_saved = 0;

    for (auto it: CfgFactory::get().db_prof_content) {
        auto name = it.first;
        auto obj = it.second;

        Setting& item = objects.add(name, Setting::TypeGroup);
        item.add("write_payload", Setting::TypeBoolean) = obj->write_payload;

        if(! obj->content_rules.empty() ) {

            Setting& cr_rules = item.add("content_rules", Setting::TypeList);

            for(auto cr: obj->content_rules) {
                Setting& cr_rule = cr_rules.add(Setting::TypeGroup);
                cr_rule.add("match", Setting::TypeString) = cr.match;
                cr_rule.add("replace", Setting::TypeString) = cr.replace;
                cr_rule.add("replace_each_nth", Setting::TypeInt) = cr.replace_each_nth;
            }
        }

        n_saved++;
    }

    return n_saved;
}


int save_config_tls_ca(Config& ex) {

    std::scoped_lock<std::recursive_mutex> l_(CfgFactory::lock());

    Setting& objects = ex.getRoot().add("tls_ca", Setting::TypeGroup);

    int n_saved = 0;

//    for (auto it: cfgapi_obj_tls_ca) {
//        auto name = it.first;
//        auto obj = it.second;
//
//        Setting& item = objects.add(name, Setting::TypeGroup);
//        item.add("path", Setting::TypeString) = obj.path;
//
//        n_saved++;
//    }

    return n_saved;
}

int save_config_tls_profiles(Config& ex) {

    std::scoped_lock<std::recursive_mutex> l_(CfgFactory::lock());

    Setting& objects = ex.getRoot().add("tls_profiles", Setting::TypeGroup);

    int n_saved = 0;

    for (auto it: CfgFactory::get().db_prof_tls) {
        auto name = it.first;
        auto obj = it.second;

        Setting& item = objects.add(name, Setting::TypeGroup);

        item.add("inspect", Setting::TypeBoolean) = obj->inspect;

        item.add("use_pfs", Setting::TypeBoolean) = obj->use_pfs;
        item.add("left_use_pfs", Setting::TypeBoolean) = obj->left_use_pfs;
        item.add("right_use_pfs", Setting::TypeBoolean) = obj->right_use_pfs;

        item.add("allow_untrusted_issuers", Setting::TypeBoolean) = obj->allow_untrusted_issuers;
        item.add("allow_invalid_certs", Setting::TypeBoolean) = obj->allow_invalid_certs;
        item.add("allow_self_signed", Setting::TypeBoolean) = obj->allow_self_signed;

        item.add("ocsp_mode", Setting::TypeInt) = obj->ocsp_mode;
        item.add("ocsp_stapling", Setting::TypeBoolean) = obj->ocsp_stapling;
        item.add("ocsp_stapling_mode", Setting::TypeInt) = obj->ocsp_stapling_mode;

        // add sni bypass list
        if(obj->sni_filter_bypass.ptr() && obj->sni_filter_bypass.ptr()->size() > 0 ) {
            Setting& sni_flist = item.add("sni_filter_bypass", Setting::TypeList);

            for( auto snif: *obj->sni_filter_bypass.ptr()) {
                sni_flist.add(Setting::TypeString) = snif;
            }
        }

        // add redirected ports (for replacements)
        if( obj->redirect_warning_ports.ptr() && obj->redirect_warning_ports.ptr()->size() > 0 ) {

            Setting& rport_list = item.add("redirect_warning_ports", Setting::TypeList);

            for( auto rport: *obj->redirect_warning_ports.ptr()) {
                rport_list.add(Setting::TypeInt) = rport;
            }
        }
        item.add("failed_certcheck_replacement", Setting::TypeBoolean) = obj->failed_certcheck_replacement;
        item.add("failed_certcheck_override", Setting::TypeBoolean) = obj->failed_certcheck_override;
        item.add("failed_certcheck_override_timeout", Setting::TypeInt) = obj->failed_certcheck_override_timeout;
        item.add("failed_certcheck_override_timeout_type", Setting::TypeInt) = obj->failed_certcheck_override_timeout_type;


        item.add("left_disable_reuse", Setting::TypeBoolean) = obj->left_disable_reuse;
        item.add("right_disable_reuse", Setting::TypeBoolean) = obj->right_disable_reuse;
        item.add("sslkeylog", Setting::TypeBoolean) = obj->sslkeylog;

        n_saved++;
    }



    return n_saved;
}


int save_config_alg_dns_profiles(Config& ex) {

    std::scoped_lock<std::recursive_mutex> l_(CfgFactory::lock());

    Setting& objects = ex.getRoot().add("alg_dns_profiles", Setting::TypeGroup);

    int n_saved = 0;

    for (auto it: CfgFactory::get().db_prof_alg_dns) {
        auto name = it.first;
        auto obj = it.second;

        Setting& item = objects.add(name, Setting::TypeGroup);
        item.add("match_request_id", Setting::TypeBoolean) = obj->match_request_id;
        item.add("randomize_id", Setting::TypeBoolean) = obj->randomize_id;
        item.add("cached_responses", Setting::TypeBoolean) = obj->cached_responses;

        n_saved++;
    }

    return n_saved;
}


int save_config_auth_profiles(Config& ex) {

    std::scoped_lock<std::recursive_mutex> l_(CfgFactory::lock());

    Setting& objects = ex.getRoot().add("auth_profiles", Setting::TypeGroup);

    int n_saved = 0;

    for (auto it: CfgFactory::get().db_prof_auth) {
        auto name = it.first;
        auto obj = it.second;

        Setting& item = objects.add(name, Setting::TypeGroup);
        item.add("authenticate", Setting::TypeBoolean) = obj->authenticate;
        item.add("resolve", Setting::TypeBoolean) = obj->resolve;

        if(obj->sub_policies.size() > 0) {

            Setting& ident = item.add("identities", Setting::TypeGroup);

            for( auto identity: obj->sub_policies) {
                Setting& subid = ident.add(identity->name, Setting::TypeGroup);

                if(identity->profile_detection)
                    subid.add("detection_profile", Setting::TypeString) = identity->profile_detection->prof_name;

                if(identity->profile_tls)
                    subid.add("tls_profile", Setting::TypeString) = identity->profile_tls->prof_name;

                if(identity->profile_content)
                    subid.add("content_profile", Setting::TypeString) = identity->profile_content->prof_name;

                if(identity->profile_alg_dns)
                    subid.add("alg_dns_profile", Setting::TypeString) = identity->profile_alg_dns->prof_name;

            }
        }

        n_saved++;
    }

    return n_saved;
}


int save_config_policy(Config& ex) {

    std::scoped_lock<std::recursive_mutex> l_(CfgFactory::lock());

    Setting& objects = ex.getRoot().add("policy", Setting::TypeList);

    int n_saved = 0;

    for (PolicyRule* pol: CfgFactory::get().db_policy) {

        if(! pol)
            continue;

        Setting& item = objects.add(Setting::TypeGroup);

        item.add("proto", Setting::TypeString) = pol->proto_name;

        // SRC
        Setting& src_list = item.add("src", Setting::TypeList);
        for(auto s: pol->src) {
            src_list.add(Setting::TypeString) = s->prof_name;
        }
        Setting& srcport_list = item.add("sport", Setting::TypeList);
        for(auto sp: pol->src_ports_names) {
            srcport_list.add(Setting::TypeString) = sp;
        }


        // DST
        Setting& dst_list = item.add("dst", Setting::TypeList);
        for(auto d: pol->dst) {
            dst_list.add(Setting::TypeString) = d->prof_name;
        }
        Setting& dstport_list = item.add("dport", Setting::TypeList);
        for(auto sp: pol->dst_ports_names) {
            dstport_list.add(Setting::TypeString) = sp;
        }

        item.add("action", Setting::TypeString) = pol->action_name;
        item.add("nat", Setting::TypeString) = pol->nat_name;

        if(pol->profile_tls)
            item.add("tls_profile", Setting::TypeString) = pol->profile_tls->prof_name;
        if(pol->profile_detection)
            item.add("detection_profile", Setting::TypeString) = pol->profile_detection->prof_name;
        if(pol->profile_content)
            item.add("content_profile", Setting::TypeString) = pol->profile_content->prof_name;
        if(pol->profile_auth)
            item.add("auth_profile", Setting::TypeString) = pol->profile_auth->prof_name;
        if(pol->profile_alg_dns)
            item.add("alg_dns_profile", Setting::TypeString) = pol->profile_alg_dns->prof_name;

        n_saved++;
    }

    return n_saved;
}

int save_config_sig(Config& ex, const std::string& sigset) {

    std::scoped_lock<std::recursive_mutex> l_(CfgFactory::lock());

    Setting& objects = ex.getRoot().add(sigset, Setting::TypeList);

    int n_saved = 0;

    auto map_sigsets = [](std::string s) {
        if(s == "starttls_signatures") return sigs_starttls;

        return sigs_detection;
    };

    const std::vector<duplexFlowMatch*>& target_ref = map_sigsets(sigset);

    for (auto sig: target_ref) {

        Setting& item = objects.add(Setting::TypeGroup);

        item.add("name", Setting::TypeString) = sig->name();


        auto my_sig = dynamic_cast<MyDuplexFlowMatch*>(sig);

        if(my_sig) {
            item.add("cat", Setting::TypeString) = my_sig->category;
            item.add("side", Setting::TypeString) = my_sig->sig_side;
        }

        if( ! sig->sig_chain().empty() ) {

            Setting& flow = item.add("flow", Setting::TypeList);

            for (auto f: sig->sig_chain()) {


                bool sig_correct = false;

                char        sig_side = f.first;
                baseMatch*        bm = f.second;


                unsigned int sig_bytes_start = bm->match_limits_offset;
                unsigned int sig_bytes_max   = bm->match_limits_bytes;
                std::string sig_type;
                std::string sig_expr;


                // follow the inheritance (regex can also be cast to simple)
                auto rm = dynamic_cast<regexMatch*>(bm);
                if(rm) {
                    sig_type = "regex";
                    sig_expr = rm->expr();
                    sig_correct = true;
                }
                else {
                    auto sm = dynamic_cast<simpleMatch*>(bm);
                    if(sm) {
                        sig_type = "simple";
                        sig_expr = sm->expr();
                        sig_correct = true;
                    }
                }


                if(sig_correct) {
                    Setting& flow_match = flow.add(Setting::TypeGroup);
                    flow_match.add("side", Setting::TypeString) = string_format("%c",sig_side);
                    flow_match.add("type", Setting::TypeString) = sig_type;
                    flow_match.add("bytes_start", Setting::TypeInt) = (int)sig_bytes_start;
                    flow_match.add("bytes_max", Setting::TypeInt) = (int)sig_bytes_max;
                    flow_match.add("signature", Setting::TypeString) = sig_expr;
                } else {
                    Setting& flow_match = flow.add(Setting::TypeGroup);
                    flow_match.add("comment", Setting::TypeString) = "???";
                }
            }
        }


        n_saved++;
    }

    return n_saved;

}

int save_config_settings(Config& ex) {

    std::scoped_lock<std::recursive_mutex> l_(CfgFactory::lock());

    if(!ex.exists("settings"))
        ex.getRoot().add("settings", Setting::TypeGroup);

    Setting& objects = ex.getRoot()["settings"];

    // nameservers
    Setting& it_ns  = objects.add("nameservers",Setting::TypeList);
    for(auto ns: CfgFactory::get().db_nameservers) {
        it_ns.add(Setting::TypeString) = ns;
    }

    objects.add("certs_path", Setting::TypeString) = SSLFactory::default_cert_path();
    objects.add("certs_ca_key_password", Setting::TypeString) = SSLFactory::default_cert_password();
    objects.add("certs_ca_path", Setting::TypeString) = SSLFactory::default_client_ca_path();

    objects.add("plaintext_port", Setting::TypeString) = CfgFactory::get().listen_tcp_port_base;
    objects.add("plaintext_workers", Setting::TypeInt) = CfgFactory::get().num_workers_tcp;

    objects.add("ssl_port", Setting::TypeString) = CfgFactory::get().listen_tls_port_base;
    objects.add("ssl_workers", Setting::TypeInt) = CfgFactory::get().num_workers_tls;
    objects.add("ssl_autodetect", Setting::TypeBoolean) = MitmMasterProxy::ssl_autodetect;
    objects.add("ssl_autodetect_harder", Setting::TypeBoolean) = MitmMasterProxy::ssl_autodetect_harder;
    objects.add("ssl_ocsp_status_ttl", Setting::TypeInt) = SSLFactory::ssl_ocsp_status_ttl;
    objects.add("ssl_crl_status_ttl", Setting::TypeInt) = SSLFactory::ssl_crl_status_ttl;

    objects.add("udp_port", Setting::TypeString) = CfgFactory::get().listen_udp_port_base;
    objects.add("udp_workers", Setting::TypeInt) = CfgFactory::get().num_workers_udp;

    objects.add("dtls_port", Setting::TypeString) = CfgFactory::get().listen_dtls_port_base;
    objects.add("dtls_workers", Setting::TypeInt) = CfgFactory::get().num_workers_dtls;

    //udp quick ports
    Setting& it_quick  = objects.add("udp_quick_ports",Setting::TypeList);
    if(CfgFactory::get().db_udp_quick_ports.empty()) {
        it_quick.add(Setting::TypeInt) = 0;
    }
    else {
        for (auto p: CfgFactory::get().db_udp_quick_ports) {
            it_quick.add(Setting::TypeInt) = p;
        }
    }

    objects.add("socks_port", Setting::TypeString) = CfgFactory::get().listen_socks_port_base;
    objects.add("socks_workers", Setting::TypeInt) = CfgFactory::get().num_workers_socks;

    Setting& socks_objects = objects.add("socks", Setting::TypeGroup);
    socks_objects.add("async_dns", Setting::TypeBoolean) = socksServerCX::global_async_dns;


    objects.add("log_level", Setting::TypeInt) = (int)cfgapi_table.logging.level.level_ref();
    objects.add("log_file", Setting::TypeString) = CfgFactory::get().log_file_base;
    objects.add("log_console", Setting::TypeBoolean)  = CfgFactory::get().log_console;

    objects.add("syslog_server", Setting::TypeString) = CfgFactory::get().syslog_server;
    objects.add("syslog_port", Setting::TypeInt) = CfgFactory::get().syslog_port;
    objects.add("syslog_facility", Setting::TypeInt) = CfgFactory::get().syslog_facility;
    objects.add("syslog_level", Setting::TypeInt) = (int)CfgFactory::get().syslog_level.level_ref();
    objects.add("syslog_family", Setting::TypeInt) = CfgFactory::get().syslog_family;

    objects.add("sslkeylog_file", Setting::TypeString) = CfgFactory::get().sslkeylog_file_base;
    objects.add("messages_dir", Setting::TypeString) = CfgFactory::get().dir_msg_templates;

    Setting& cli_objects = objects.add("cli", Setting::TypeGroup);
    cli_objects.add("port", Setting::TypeString) = string_format("%d", cli_port_base).c_str();
    cli_objects.add("enable_password", Setting::TypeString) = cli_enable_password;


    Setting& auth_objects = objects.add("auth_portal", Setting::TypeGroup);
    auth_objects.add("address",Setting::TypeString) = CfgFactory::get().auth_address;
    auth_objects.add("http_port", Setting::TypeString) = CfgFactory::get().auth_http;
    auth_objects.add("https_port", Setting::TypeString) = CfgFactory::get().auth_https;
    auth_objects.add("ssl_key", Setting::TypeString) = CfgFactory::get().auth_sslkey;
    auth_objects.add("ssl_cert", Setting::TypeString) = CfgFactory::get().auth_sslcert;
    auth_objects.add("magic_ip", Setting::TypeString) = CfgFactory::get().tenant_magic_ip;


    objects.add("write_payload_dir", Setting::TypeString) = CfgFactory::get().traflog_dir;
    objects.add("write_payload_file_prefix", Setting::TypeString) = CfgFactory::get().traflog_file_prefix;
    objects.add("write_payload_file_suffix", Setting::TypeString) = CfgFactory::get().traflog_file_suffix;


    return 0;
}

int cli_save_config(struct cli_def *cli, const char *command, char *argv[], int argc) {

    std::scoped_lock<std::recursive_mutex> l_(CfgFactory::lock());

    Config ex;
    ex.setOptions(Setting::OptionOpenBraceOnSeparateLine);
    ex.setTabWidth(4);

    int n = 0;

    n = save_config_settings(ex);
    cli_print(cli, "... common settings");

    n = save_config_debug(ex);
    cli_print(cli, "... debug settings");

    n = save_config_address_objects(ex);
    cli_print(cli, "%d address_objects", n);

    n = save_config_port_objects(ex);
    cli_print(cli, "%d port_objects", n);

    n = save_config_proto_objects(ex);
    cli_print(cli, "%d proto_objects", n);

    n = save_config_detection_profiles(ex);
    cli_print(cli, "%d detection_profiles", n);

    n = save_config_content_profiles(ex);
    cli_print(cli, "%d content_profiles", n);

    n = save_config_tls_ca(ex);
    cli_print(cli, "%d tls_ca", n);

    n = save_config_tls_profiles(ex);
    cli_print(cli, "%d tls_profiles", n);

    n = save_config_alg_dns_profiles(ex);
    cli_print(cli, "%d alg_dns_profiles", n);

    n = save_config_auth_profiles(ex);
    cli_print(cli, "%d auth_profiles", n);

    n = save_config_policy(ex);
    cli_print(cli, "%d policy", n);

    n = save_config_sig(ex, "starttls_signatures");
    cli_print(cli, "%d %s signatures", n, "starttls");

    n = save_config_sig(ex, "detection_signatures");
    cli_print(cli, "%d %s signatures", n, "detection");


    ex.writeFile(CfgFactory::get().config_file.c_str());

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

        Setting &cur_object = orig[i];


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

void cfg_generate_cli_hints(Setting& setting, std::vector<std::string>* this_level_names,
                                                std::vector<unsigned int>* this_level_indexes,
        std::vector<std::string>* next_level_names,
        std::vector<unsigned int>* next_level_indexes) {

    for (unsigned int i = 0; i < (unsigned int) setting.getLength(); i++) {
        Setting &cur_object = setting[i];

        std::string name;
        if(cur_object.getName()) {
            name = cur_object.getName();
        }

        if(cur_object.isScalar()) {
            if( ! name.empty() ) {
                if(this_level_names)
                    this_level_names->push_back(name);
            } else {
                if(this_level_indexes)
                    this_level_indexes->push_back(i);
            }
        } else {
            if( ! name.empty() ) {
                if(next_level_names)
                    next_level_names->push_back(name);
            } else {
                if(next_level_indexes)
                    next_level_indexes->push_back(i);
            }
        }
    }
}


cli_command* cfg_generate_cli_callbacks(Setting& s, struct cli_def* cli, cli_command* cli_parent,
            int(*set_cb)(struct cli_def*, const char*, char*[], int),
            int(*config_cb)(struct cli_def*, const char*, char*[], int),
                    const char* context_help) {

    if(! cli_parent)
        return nullptr;

    std::vector<std::string> here_name, next_name;
    std::vector<unsigned int> here_index, next_index;

    cli_print(cli, "calling cfg_generate_cli_hints");

    cfg_generate_cli_hints(s, &here_name, &here_index, &next_name, &next_index);

    cli_print(cli, "hint results: named: %d, indexed %d, next-level named: %d, next-level indexed: %d",
              (int)here_name.size(), (int)here_index.size(),
              (int)next_name.size(), (int)next_index.size());

    if( (! here_index.empty() ) || (! here_name.empty()) ) {

        std::string name;
        if(s.getName()) {
            cli_command* cli_here = cli_register_command(cli, cli_parent, s.getName(), set_cb, PRIVILEGE_PRIVILEGED, MODE_CONFIG, "modify variables");

            for( const auto& here_n: here_name) {

                // create type information, and (possibly) some help text

                std::string help;
                if(context_help) {
                    std::string h = cli_help(HELP_CONTEXT, context_help, here_n);
                    if(h.empty()) {
                        help = string_format("modify '%s'", here_n.c_str());
                    }
                    else {
                        help = " - " + h;
                    }
                } else {
                    help = string_format("modify '%s'", here_n.c_str());
                }

                cli_register_command(cli, cli_here, here_n.c_str(), set_cb, PRIVILEGE_PRIVILEGED, MODE_CONFIG,
                                     help.c_str() );
            }

            return cli_here;
        }
    }

    return nullptr;
}


bool cfg_write_value(Setting& parent, bool create, std::string& varname, std::string value, cli_def* cli) {

    if( parent.exists(varname.c_str()) ) {

        cli_print(cli, "config item exists %s", varname.c_str());

        Setting& s = parent[varname.c_str()];

        auto t = s.getType();

        int i;
        long long int lli;
        float f;

        std::string lvalue;

        try {
            switch (t) {
                case Setting::TypeInt:
                    i = std::stoi(value);
                    s = i;

                    break;

                case Setting::TypeInt64:
                    lli = std::stoll(value);
                    s = lli;

                    break;

                case Setting::TypeBoolean:

                    lvalue = string_tolower(value);

                    if( lvalue == "true" || lvalue == "1" ) {
                        s = true;
                    }
                    else if ( lvalue == "false" || lvalue == "0" ) {
                        s = false;
                    }

                    break;

                case Setting::TypeFloat:
                    f = std::stof(value);
                    s = f;

                    break;

                case Setting::TypeString:
                    s = value;

                    break;

                default:
                    ;
            }
        } catch(std::exception& e) {
            return false;
        }
    }
    else if(create) {

    }

    return true;
}

bool apply_setting(std::string conf, std::string varname, struct cli_def *cli) {

    cli_print(cli, "apply_setting: start");

    if( "settings" == conf ) {

        cli_print(cli, "apply_setting: %s", conf.c_str());

        return CfgFactory::get().load_settings();
    }

    return false;
}

int cli_uni_set_cb(std::string confpath, struct cli_def *cli, const char *command, char *argv[], int argc) {

    std::scoped_lock<std::recursive_mutex> l_(CfgFactory::lock());

    if (argc > 0 && CfgFactory::cfg_obj().exists(confpath)) {

        Setting& conf = CfgFactory::cfg_obj().lookup(confpath);

        auto cmd = string_split(command, ' ');
        std::string varname = cmd[cmd.size() - 1];

        cli_print(cli, "var: %s", varname.c_str());


        std::string argv0(argv[0]);

        if (argv0 != "?") {

            std::scoped_lock<std::recursive_mutex> ll_(CfgFactory::lock());

            if (cfg_write_value(conf, false, varname, argv0, cli)) {
                // cli_print(cli, "change written to current config");

                if ( apply_setting( conf.getPath(), varname , cli )) {
                    cli_print(cli, "change applied to current config");
                } else {
                    // FIXME
                    cli_print(cli, "change NOT applied to current config - reverting NYI, sorry");
                    cli_print(cli, "change will be visible in show config, but not written to mapped variables");
                    cli_print(cli, "therefore 'save config' won't write them to file.");
                }
            }

        } else {
            if (!conf.isRoot() && conf.getName()) {

                auto h = cli_help(HELP_QMARK, conf.getPath(), varname);

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


int cli_config_setting_cb(struct cli_def *cli, const char *command, char *argv[], int argc) {
    cli_set_configmode(cli, MODE_CONFIG, "settings");

    return cli_uni_set_cb("settings", cli, command, argv, argc);
}

int cli_config_setting_auth_cb(struct cli_def *cli, const char *command, char *argv[], int argc) {
    cli_set_configmode(cli, MODE_CONFIG, "settings.auth");

    return cli_uni_set_cb("settings.auth", cli, command, argv, argc);
}

int cli_config_setting_cli_cb(struct cli_def *cli, const char *command, char *argv[], int argc) {

    cli_set_configmode(cli, MODE_CONFIG, "settings.cli");

    return cli_uni_set_cb("settings.cli", cli, command, argv, argc);
}

int cli_config_setting_socks_cb(struct cli_def *cli, const char *command, char *argv[], int argc) {

    cli_set_configmode(cli, MODE_CONFIG, "settings.cli");

    return cli_uni_set_cb("settings.cli", cli, command, argv, argc);
}

// index < 0 means all
void cli_print_section(cli_def* cli, const std::string& name, int index , unsigned long pipe_sz ) {

    std::scoped_lock<std::recursive_mutex> l_(CfgFactory::lock());

    if(CfgFactory::cfg_root().exists(name.c_str())) {
        Setting &s = CfgFactory::cfg_root()[name.c_str()];

        Config nc;
        nc.getRoot().add(name.c_str(), s.getType());
        nc.setOptions(Setting::OptionOpenBraceOnSeparateLine);

        cfg_clone_setting(nc.getRoot()[name.c_str()], s , index /*, cli */ );

        cfg_write(nc, cli->client, pipe_sz);

    } else {
        cli_print(cli, "'%s' config section doesn't exist", name.c_str());
    }
}

int cli_show_config_setting(struct cli_def *cli, const char *command, char *argv[], int argc) {

    cli_print_section(cli, "settings", -1, 200 * 1024);
    return CLI_OK;
}

int cli_show_config_policy(struct cli_def *cli, const char *command, char *argv[], int argc) {

    int index = -1;
    if(argc > 0) {
        index = std::stoi(argv[0]);
    }
    cli_print_section(cli, "policy", index, 10 * 1024 * 1024);
    return CLI_OK;
}

int cli_show_config_objects(struct cli_def *cli, const char *command, char *argv[], int argc) {

    cli_print_section(cli, "proto_objects", -1,  1 * 1024 * 1024);
    cli_print_section(cli, "port_objects", -1, 1 * 1024 * 1024);
    cli_print_section(cli, "address_objects", -1,  1 * 1024 * 1024);
    return CLI_OK;
}

int cli_show_config_proto_objects(struct cli_def *cli, const char *command, char *argv[], int argc) {

    cli_print_section(cli, "proto_objects", -1, 1 * 1024 * 1024);
    return CLI_OK;
}

int cli_show_config_port_objects(struct cli_def *cli, const char *command, char *argv[], int argc) {

    cli_print_section(cli, "port_objects", -1, 1 * 1024 * 1024);
    return CLI_OK;
}

int cli_show_config_address_objects(struct cli_def *cli, const char *command, char *argv[], int argc) {

    cli_print_section(cli, "address_objects", -1, 1 * 1024 * 1024);
    return CLI_OK;
}

int cli_show_config_debug(struct cli_def *cli, const char *command, char *argv[], int argc) {

    cli_print_section(cli, "debug", -1, 1 * 1024 * 1024);
    return CLI_OK;
}


int cli_show_config_detection(struct cli_def *cli, const char *command, char *argv[], int argc) {

    cli_print_section(cli, "detection_profiles", -1, 1 * 1024 * 1024);
    return CLI_OK;
}


int cli_show_config_content(struct cli_def *cli, const char *command, char *argv[], int argc) {

    cli_print_section(cli, "content_profiles", -1, 1 * 1024 * 1024);
    return CLI_OK;
}


int cli_show_config_tls_ca(struct cli_def *cli, const char *command, char *argv[], int argc) {

    cli_print_section(cli, "tls_ca", -1, 1 * 1024 * 1024);
    return CLI_OK;
}


int cli_show_config_tls_profiles(struct cli_def *cli, const char *command, char *argv[], int argc) {

    cli_print_section(cli, "tls_profiles", -1, 1 * 1024 * 1024);
    return CLI_OK;
}

int cli_show_config_alg_dns(struct cli_def *cli, const char *command, char *argv[], int argc) {

    cli_print_section(cli, "alg_dns_profiles", -1, 1 * 1024 * 1024);
    return CLI_OK;
}

int cli_show_config_auth_profiles(struct cli_def *cli, const char *command, char *argv[], int argc) {

    cli_print_section(cli, "auth_profiles", -1,  1 * 1024 * 1024);
    return CLI_OK;
}

int cli_show_config_starttls_sig(struct cli_def *cli, const char *command, char *argv[], int argc) {

    cli_print_section(cli, "starttls_signatures", -1, 1 * 1024 * 1024);
    return CLI_OK;
}

int cli_show_config_detection_sig(struct cli_def *cli, const char *command, char *argv[], int argc) {

    cli_print_section(cli, "detection_signatures", -1, 1 * 1024 * 1024);
    return CLI_OK;
}



int cli_diag_mem_objects_stats(struct cli_def *cli, const char *command, char *argv[], int argc) {

    cli_print(cli,"Statistics:\n");
    cli_print(cli,"%s", sobjectDB::str_stats(nullptr).c_str());
    return CLI_OK;

}

int cli_diag_mem_trace_mark (struct cli_def *cli, const char *command, char **argv, int argc) {

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
                object_filter = a1.c_str();
            }
        }

        if(argc > 1) {
            std::string a2 = argv[1];
            verbosity = safe_val(a2,iINF);
        }
    }


    std::string r = sobjectDB::str_list((object_filter.size() == 0) ? nullptr : object_filter.c_str(), nullptr, verbosity);
                r += "\n" + sobjectDB::str_stats((object_filter.size() == 0) ? nullptr : object_filter.c_str());


    cli_print(cli,"Smithproxy objects (filter: %s):\n%s\nFinished.",(object_filter.size() == 0) ? "ALL" : object_filter.c_str() ,r.c_str());
    return CLI_OK;
}


int cli_diag_mem_objects_search(struct cli_def *cli, const char *command, char *argv[], int argc) {

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
                object_filter = a1.c_str();
            }
        }

        if(argc > 1) {
            std::string a2 = argv[1];
            verbosity = safe_val(a2,iINF);
        }
    }


    std::string r = sobjectDB::str_list(nullptr,nullptr,verbosity,object_filter.c_str());

    cli_print(cli,"Smithproxy objects (filter: %s):\n%s\nFinished.",(object_filter.size() == 0) ? "ALL" : object_filter.c_str() ,r.c_str());
    return CLI_OK;
}



int cli_diag_mem_objects_clear(struct cli_def *cli, const char *command, char *argv[], int argc) {
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
            cli_print(cli,"Trying to clear 0x%lx",key);


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

    return cli_diag_proxy_session_list_extra(cli, command, argv, argc, SL_NONE);
}

int cli_diag_proxy_session_io_list(struct cli_def *cli, const char *command, char *argv[], int argc) {

    int f;
    flag_set<int>(&f, SL_IO_OSBUF_NZ);
    flag_set<int>(&f, SL_IO_EMPTY);

    return cli_diag_proxy_session_list_extra(cli, command, argv, argc, f);
}


int cli_diag_proxy_session_list_extra(struct cli_def *cli, const char *command, char *argv[], int argc, int sl_flags) {

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

                MitmProxy *curr_proxy = dynamic_cast<MitmProxy *>(ptr);
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

                    if (lf && lf->writebuf() && lf->writebuf()->size() > 0) {
                        prefix += "LWrBuf ";
                        do_print = true;
                    }

                    if (rg && rg->writebuf() && rg->writebuf()->size() > 0) {
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
                            int expiry = -1;
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

    //return cli_diag_mem_objects_clear(cli,command,argv,argc);

    cli_print(cli,"To be implemented, sorry.");
    return CLI_OK;
}

int cli_diag_proxy_policy_list(struct cli_def *cli, const char *command, char *argv[], int argc) {

    std::string filter = "";
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

        for (auto it: CfgFactory::get().db_policy) {
            out << it->to_string(verbosity);
            out << "\n\n";
        }
    }

    cli_print(cli, "%s", out.str().c_str());
    return CLI_OK;
}




struct cli_ext : public cli_def {
    int socket;
};


void cli_generate_set_settings(cli_def* cli, cli_command* set_settings) {
    std::scoped_lock<std::recursive_mutex> l_(CfgFactory::lock());


    if (CfgFactory::cfg_root()["settings"].exists("auth_portal")) {
        cfg_generate_cli_callbacks(CfgFactory::cfg_root()["settings"]["auth_portal"], cli,
                                                       set_settings,
                                                       cli_config_setting_auth_cb,
                                                       cli_config_setting_auth_cb, "settings/auth_portal");
    }

    if (CfgFactory::cfg_root()["settings"].exists("cli")) {
        cfg_generate_cli_callbacks(CfgFactory::cfg_root()["settings"]["cli"], cli,
                                                      set_settings,
                                                      cli_config_setting_cli_cb,
                                                      cli_config_setting_cli_cb, "settings/cli");
    }

    if (CfgFactory::cfg_root()["settings"].exists("socks")) {
        cfg_generate_cli_callbacks(CfgFactory::cfg_root()["settings"]["socks"], cli,
                                                      set_settings,
                                                      cli_config_setting_socks_cb,
                                                      cli_config_setting_socks_cb, "settings/socks");
    }

}


void client_thread(int client_socket) {
        struct cli_command *save;
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

        struct cli_command *conft_configure;
            struct cli_command *conft_settings_auth;

        struct cli_def *cli;

        char hostname[64]; memset(hostname,0,64);
        gethostname(hostname,63);


        // Must be called first to setup data structures
        cli = cli_init();

        // init contextual help
        init_cli_help();

        // Set the hostname (shown in the the prompt)
        cli_set_hostname(cli, string_format("smithproxy(%s) ",hostname).c_str());

        // Set the greeting
        cli_set_banner(cli, "--==[ Smithproxy command line utility ]==--");

        cli_allow_enable(cli, cli_enable_password.c_str());

        // Set up 2 commands "show counters" and "show junk"

        save  = cli_register_command(cli, nullptr, "save", nullptr, PRIVILEGE_PRIVILEGED, MODE_ANY, "save configs");
            cli_register_command(cli, save, "config", cli_save_config, PRIVILEGE_PRIVILEGED, MODE_ANY, "save config file");

        show  = cli_register_command(cli, nullptr, "show", nullptr, PRIVILEGE_UNPRIVILEGED, MODE_ANY, "show basic information");
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
                diag_ssl_ticket = cli_register_command(cli, diag_ssl, "ticket", nullptr, PRIVILEGE_UNPRIVILEGED, MODE_EXEC, "diagnose abbreviated handshake session/ticket cache");
                    cli_register_command(cli, diag_ssl_ticket, "list", cli_diag_ssl_ticket_list, PRIVILEGE_PRIVILEGED, MODE_EXEC, "list abbreviated handshake session/ticket cache");
                    cli_register_command(cli, diag_ssl_ticket, "stats", cli_diag_ssl_ticket_stats, PRIVILEGE_PRIVILEGED, MODE_EXEC, "abbreviated handshake session/ticket cache stats");
                diag_ssl_ca     = cli_register_command(cli, diag_ssl, "ca", nullptr, PRIVILEGE_UNPRIVILEGED, MODE_EXEC, "diagnose SSL signing CA");
                    cli_register_command(cli, diag_ssl_ca, "reload", cli_diag_ssl_ca_reload, PRIVILEGE_PRIVILEGED, MODE_EXEC, "reload signing CA key and certificate");



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




        // generate dynamically content of config

        conft_configure = cli_register_command(cli, nullptr, "set", nullptr, PRIVILEGE_PRIVILEGED, MODE_CONFIG, "configure smithproxy settings");
        cli_command* set_settings = nullptr;
            cli_command* set_settings_auth = nullptr;
            cli_command* set_settings_cli = nullptr;
            cli_command* set_settings_socks = nullptr;


        if( CfgFactory::cfg_root().exists("settings") ) {
            std::scoped_lock<std::recursive_mutex> l_(CfgFactory::lock());

            set_settings = cfg_generate_cli_callbacks(CfgFactory::cfg_root()["settings"], cli, conft_configure,
                                       cli_config_setting_cb,
                                       cli_config_setting_cb, "settings");
            if(set_settings){
                cli_generate_set_settings(cli, set_settings);
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
    struct sockaddr_in servaddr;
    int on = 1;

    // Create a socket
    int s = socket(AF_INET, SOCK_STREAM, 0);
    setsockopt(s, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on));

    memset(&servaddr, 0, sizeof(servaddr));
    servaddr.sin_family = AF_INET;
    servaddr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    servaddr.sin_port = htons(port);
    bind(s, (struct sockaddr *)&servaddr, sizeof(servaddr));

    // Wait for a connection
    listen(s, 50);

    int client_socket = 0;
    while ((client_socket = accept(s, nullptr, 0)))
    {
        std::thread* n = new std::thread(client_thread,client_socket);
    }
};
