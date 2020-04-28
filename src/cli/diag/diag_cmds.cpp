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


#include <cstdlib>
#include <ctime>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <linux/sockios.h>
#include <unistd.h>

#include <biostring.hpp>

#include <log/logger.hpp>
#include <traflog.hpp>

#include <cli/cmdserver.hpp>

#include <cfgapi.hpp>
#include <sslcom.hpp>
#include <sslcertstore.hpp>

#include <sobject.hpp>
#include <proxy/mitmproxy.hpp>
#include <policy/inspectors.hpp>
#include <policy/authfactory.hpp>

#include <inspect/sigfactory.hpp>

#include <cli/diag/diag_cmds.hpp>

extern bool cfg_openssl_mem_dbg;

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

int cli_diag_ssl_cache_stats(struct cli_def *cli, const char *command, char *argv[], int argc) {

    debug_cli_params(cli, command, argv, argc);

    SSLFactory* store = SSLCom::certstore();


    int n_cache = 0;
    {
        std::lock_guard<std::recursive_mutex> l(store->lock());
        n_cache = store->cache().size();
    }


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

        for (auto const& x: store->cache()) {
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

        for (auto const& x: store->cache()) {
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

        long ttl = we.second->expired_at() - ::time(nullptr);

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

            if (r != nullptr && (! r->answers().empty()) ) {
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

            for (auto const& sub_e: sub_domain_cache.second->cache()) {
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
        for (auto const& ip: AuthFactory::get_ip4_map()) {

            IdentityInfo const& id = ip.second;

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
        for (auto const& ip: AuthFactory::get_ip6_map()) {

            IdentityInfo6 const& id = ip.second;

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

    auto wr = socle::threadedPoolFileWriter::instance();

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
    }
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
            {
                std::scoped_lock<std::mutex> g(memPool::pool().lock);

                auto stat_acq = memPool::pool().stat_acq.load();
                auto stat_acq_size = memPool::pool().stat_acq_size.load();
                auto stat_ret = memPool::pool().stat_ret.load();
                auto stat_ret_size = memPool::pool().stat_ret_size.load();

                cli_print(cli, "\nMemory pool API stats:");
                cli_print(cli, "acquires: %lld/%lldB", stat_acq, stat_acq_size);
                cli_print(cli, "releases: %lld/%lldB", stat_ret, stat_ret_size);
            }


            cli_print(cli, "\nNon-API allocations:");
            cli_print(cli, "mp_allocs: %lld", mp_stats::get().stat_mempool_alloc.load());
            cli_print(cli, "mp_reallocs: %lld", mp_stats::get().stat_mempool_realloc.load());
            cli_print(cli, "mp_frees: %lld", mp_stats::get().stat_mempool_free.load());
            cli_print(cli, "mp_realloc cache miss: %lld", mp_stats::get().stat_mempool_realloc_miss.load());
            cli_print(cli, "mp_realloc fitting returns: %lld", mp_stats::get().stat_mempool_realloc_fitting.load());
            cli_print(cli, "mp_free cache miss: %lld", mp_stats::get().stat_mempool_free_miss.load());
        }
        size_t mp_size = 0L;
        {
            std::scoped_lock<std::mutex> l(mpdata::lock());
            mp_size = mpdata::map().size();
        }
        cli_print(cli, "mp ptr cache size: %lu", static_cast<unsigned long>(mp_size));

        cli_print(cli," ");
        cli_print(cli, "API allocations above limits:");
        {
            std::scoped_lock<std::mutex> g(memPool::pool().lock);
            cli_print(cli, "allocations: %lld/%lldB", memPool::pool().stat_alloc.load(), memPool::pool().stat_alloc_size.load());
            cli_print(cli, "   releases: %lld/%lldB", memPool::pool().stat_out_free.load(),
                      memPool::pool().stat_out_free_size.load());

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


int cli_diag_mem_objects_stats(struct cli_def *cli, const char *command, char *argv[], int argc) {

    debug_cli_params(cli, command, argv, argc);

    cli_print(cli,"Statistics:\n");
    cli_print(cli,"%s", socle::sobjectDB::str_stats(nullptr).c_str());
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


    std::string r = socle::sobjectDB::str_list((object_filter.empty()) ? nullptr : object_filter.c_str(), nullptr, verbosity);
    r += "\n" + socle::sobjectDB::str_stats((object_filter.empty()) ? nullptr : object_filter.c_str());


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


    std::string r = socle::sobjectDB::str_list(nullptr,nullptr,verbosity,object_filter.c_str());

    cli_print(cli,"Smithproxy objects (filter: %s):\n%s\nFinished.",(object_filter.empty()) ? "ALL" : object_filter.c_str() ,r.c_str());
    return CLI_OK;
}



int cli_diag_mem_objects_clear(struct cli_def *cli, const char *command, char *argv[], int argc) {

    debug_cli_params(cli, command, argv, argc);

    std::string address;

    if(argc > 0) {
        address = argv[0];
        if(address == "?") {
            cli_print(cli,"valid parameters:");
            cli_print(cli,"         <object id>");

            return CLI_OK;
        } else {
            unsigned long key = strtol(address.c_str(),nullptr,16);
            cli_print(cli,"Trying to clear 0x%lx", key);


            int ret = -1;
            {
                std::scoped_lock<std::recursive_mutex> l_(socle::sobjectDB::db().getlock());
                ret = socle::sobjectDB::ask_destroy((void *) key);
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

int cli_diag_proxy_tls_list(struct cli_def *cli, const char *command, char *argv[], int argc) {

    debug_cli_params(cli, command, argv, argc);

    return cli_diag_proxy_session_list_extra(cli, command, argv, argc, SL_TLS_DETAILS);
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
        std::scoped_lock<std::recursive_mutex> l_(socle::sobjectDB::db().getlock());

        for (auto it: socle::sobjectDB::db().cache()) {

            socle::sobject *ptr = it.first;
            std::string prefix;
            std::string suffix;


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

                if (flag_check<int>(sl_flags, SL_TLS_DETAILS)) {
                    std::stringstream tls_ss;

                    std::vector<std::pair<std::string, SSLCom*>> tup;
                    if(lf)
                        tup.emplace_back(std::make_pair("Left ",dynamic_cast<SSLCom*>(lf->com())));
                    if(rg)
                        tup.emplace_back(std::make_pair("Right",dynamic_cast<SSLCom*>(rg->com())));

                    for(auto const& side: tup) {
                        auto com = side.second;

                        if(com) {
                            auto ssl = com->get_SSL();
                            if (ssl) {
                                auto *session = SSL_get_session(ssl);

                                auto *cipher_str = SSL_CIPHER_get_name(SSL_SESSION_get0_cipher(session));
                                int has_ticket = SSL_SESSION_has_ticket(session);
                                unsigned long lifetime_hint = -1;
                                if (has_ticket > 0) {
                                    lifetime_hint = SSL_SESSION_get_ticket_lifetime_hint(session);
                                }

                                auto tls_ver = SSL_get_version(ssl);
                                bool tls_rsm = (side.second->target_cert() == nullptr);

                                tls_ss << "\n  " << side.first << ": version: " << tls_ver << ", cipher: ";
                                tls_ss << cipher_str << ", resumed/ticket: "
                                       << tls_rsm << "/" << has_ticket;
                                if (has_ticket) {
                                    tls_ss << " , ticket_hint: " << lifetime_hint << "s";
                                }

                                if(! com->is_server()) {
                                   tls_ss << "\n    verify(" << SSLCom::verify_origin_str(com->verify_origin()) << "): "
                                          << MitmProxy::verify_flag_string(com->verify_get());

                                   if(! com->verify_extended_info().empty()) {
                                       for (auto const &ei: com->verify_extended_info()) {
                                           tls_ss << "\n    verify: " <<  MitmProxy::verify_flag_string_extended(ei);
                                       }
                                   }
                                }

                                const char* sni = SSL_get_servername(ssl, TLSEXT_NAMETYPE_host_name);
                                if(sni) {
                                    tls_ss << "\n    sni: " << sni;

                                    if(lf) {
                                        auto* app = lf->application_data;
                                        auto http_app = dynamic_cast<app_HttpRequest*>(app);
                                        if(http_app) {

                                            if(! http_app->host.empty()) {
                                                if (sni == http_app->host) {
                                                    tls_ss << " -> http host ok";
                                                }
                                                else {
                                                    tls_ss << " -> http host DOESN'T MATCH";
                                                }
                                            }

                                            if(verbosity > iINF) {
                                                tls_ss << "\n  http host: " << http_app->host;
                                            }
                                        }
                                    }
                                }

                                auto scts = SSL_get0_peer_scts(ssl);
                                int scts_len = sk_SCT_num(scts);
                                if(scts_len > 0) {

                                    tls_ss << "\n    sct: " << scts_len << " entries";

                                    if(verbosity > iDIA) {
                                        for (int i = 0; i < scts_len; i++) {
                                            auto sct = sk_SCT_value(scts, i);

                                            unsigned char* sct_logid {};
                                            size_t sct_logid_len = 0;
                                            sct_logid_len = SCT_get0_log_id(sct, &sct_logid);
                                            if(sct_logid_len > 0)
                                                tls_ss << "\n        sct log." << i << ": " << hex_print(sct_logid, sct_logid_len);
                                        }
                                    }
                                }

                            } else {
                                tls_ss << "\n  " << side.first << ": tls, but no info";
                            }
                        } else {
                            tls_ss << "\n  " << side.first << ": not a TLS session";
                        }
                    }
                    tls_ss << "\n";
                    do_print = true;
                    suffix += tls_ss.str();
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

                cur_obj_ss << prefix << ptr->to_string(verbosity) << suffix;

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
                        int in_pending, out_pending;
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
        cli_print(cli, "\nProxy performance: upload %sbps, download %sbps in last 60 seconds",
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

bool register_diags(cli_def* cli, cli_command* diag) {
    auto diag_ssl = cli_register_command(cli, diag, "ssl", nullptr, PRIVILEGE_UNPRIVILEGED, MODE_EXEC, "ssl related troubleshooting commands");
    auto diag_ssl_cache = cli_register_command(cli, diag_ssl, "cache", nullptr, PRIVILEGE_UNPRIVILEGED, MODE_EXEC, "diagnose ssl certificate cache");
    cli_register_command(cli, diag_ssl_cache, "stats", cli_diag_ssl_cache_stats, PRIVILEGE_UNPRIVILEGED, MODE_EXEC, "display ssl cert cache statistics");
    cli_register_command(cli, diag_ssl_cache, "list", cli_diag_ssl_cache_list, PRIVILEGE_PRIVILEGED, MODE_EXEC, "list all ssl cert cache entries");
    cli_register_command(cli, diag_ssl_cache, "print", cli_diag_ssl_cache_print, PRIVILEGE_PRIVILEGED, MODE_EXEC, "print all ssl cert cache entries");
    cli_register_command(cli, diag_ssl_cache, "clear", cli_diag_ssl_cache_clear, PRIVILEGE_PRIVILEGED, MODE_EXEC, "remove all ssl cert cache entries");

    auto diag_ssl_wl = cli_register_command(cli, diag_ssl, "whitelist", nullptr, PRIVILEGE_UNPRIVILEGED, MODE_EXEC, "diagnose ssl temporary verification whitelist");
    cli_register_command(cli, diag_ssl_wl, "list", cli_diag_ssl_wl_list, PRIVILEGE_PRIVILEGED, MODE_EXEC, "list all verification whitelist entries");
    cli_register_command(cli, diag_ssl_wl, "clear", cli_diag_ssl_wl_clear, PRIVILEGE_PRIVILEGED, MODE_EXEC, "clear all verification whitelist entries");
    cli_register_command(cli, diag_ssl_wl, "stats", cli_diag_ssl_wl_stats, PRIVILEGE_PRIVILEGED, MODE_EXEC, "verification whitelist cache stats");

    auto diag_ssl_crl = cli_register_command(cli, diag_ssl, "crl", nullptr, PRIVILEGE_UNPRIVILEGED, MODE_EXEC, "diagnose dynamically downloaded CRLs");
    cli_register_command(cli, diag_ssl_crl, "list", cli_diag_ssl_crl_list, PRIVILEGE_PRIVILEGED, MODE_EXEC, "list all CRLs");
    cli_register_command(cli, diag_ssl_crl, "stats", cli_diag_ssl_crl_stats, PRIVILEGE_PRIVILEGED, MODE_EXEC, "CRLs cache stats");

    auto diag_ssl_verify = cli_register_command(cli, diag_ssl, "verify", nullptr, PRIVILEGE_UNPRIVILEGED, MODE_EXEC, "diagnose certificate verification status cache");
    cli_register_command(cli, diag_ssl_verify, "list", cli_diag_ssl_verify_list, PRIVILEGE_PRIVILEGED, MODE_EXEC, "list certificate verification status cache content");
    cli_register_command(cli, diag_ssl_verify, "stats", cli_diag_ssl_verify_stats, PRIVILEGE_PRIVILEGED, MODE_EXEC, "certificate verification status cache stats");
    cli_register_command(cli, diag_ssl_verify, "clear", cli_diag_ssl_verify_clear, PRIVILEGE_PRIVILEGED, MODE_EXEC, "clear certificate verification cache");

    auto diag_ssl_ticket = cli_register_command(cli, diag_ssl, "ticket", nullptr, PRIVILEGE_UNPRIVILEGED, MODE_EXEC, "diagnose abbreviated handshake session/ticket cache");
    cli_register_command(cli, diag_ssl_ticket, "list", cli_diag_ssl_ticket_list, PRIVILEGE_PRIVILEGED, MODE_EXEC, "list abbreviated handshake session/ticket cache");
    cli_register_command(cli, diag_ssl_ticket, "stats", cli_diag_ssl_ticket_stats, PRIVILEGE_PRIVILEGED, MODE_EXEC, "abbreviated handshake session/ticket cache stats");

    auto diag_ssl_ca     = cli_register_command(cli, diag_ssl, "ca", nullptr, PRIVILEGE_UNPRIVILEGED, MODE_EXEC, "diagnose SSL signing CA");
    cli_register_command(cli, diag_ssl_ca, "reload", cli_diag_ssl_ca_reload, PRIVILEGE_PRIVILEGED, MODE_EXEC, "reload signing CA key and certificate");

    auto diag_sig = cli_register_command(cli, diag, "sig", nullptr, PRIVILEGE_UNPRIVILEGED, MODE_EXEC, "signature engine diagnostics");
    cli_register_command(cli, diag_sig, "list", cli_diag_sig_list, PRIVILEGE_PRIVILEGED, MODE_EXEC, "list engine signatures");


    if(cfg_openssl_mem_dbg) {
#ifndef USE_OPENSSL11
        auto diag_ssl_memcheck = cli_register_command(cli, diag_ssl, "memcheck", nullptr, PRIVILEGE_UNPRIVILEGED, MODE_EXEC, "diagnose openssl memcheck");
            cli_register_command(cli, diag_ssl_memcheck, "list", cli_diag_ssl_memcheck_list, PRIVILEGE_PRIVILEGED, MODE_EXEC, "print out OpenSSL memcheck status");
            cli_register_command(cli, diag_ssl_memcheck, "enable", cli_diag_ssl_memcheck_enable, PRIVILEGE_PRIVILEGED, MODE_EXEC, "enable OpenSSL debug collection");
            cli_register_command(cli, diag_ssl_memcheck, "disable", cli_diag_ssl_memcheck_disable, PRIVILEGE_PRIVILEGED, MODE_EXEC, "disable OpenSSL debug collection");
#endif
    }

    auto diag_mem = cli_register_command(cli, diag, "mem", nullptr, PRIVILEGE_UNPRIVILEGED, MODE_EXEC, "memory related troubleshooting commands");
    auto diag_mem_buffers = cli_register_command(cli, diag_mem, "buffers", nullptr, PRIVILEGE_UNPRIVILEGED, MODE_EXEC, "memory buffers troubleshooting commands");
    cli_register_command(cli, diag_mem_buffers, "stats", cli_diag_mem_buffers_stats, PRIVILEGE_UNPRIVILEGED, MODE_EXEC, "memory buffers statistics");
    auto diag_mem_objects = cli_register_command(cli, diag_mem, "objects", nullptr, PRIVILEGE_UNPRIVILEGED, MODE_EXEC, "memory object troubleshooting commands");
    cli_register_command(cli, diag_mem_objects, "stats", cli_diag_mem_objects_stats, PRIVILEGE_UNPRIVILEGED, MODE_EXEC, "memory objects statistics");
    cli_register_command(cli, diag_mem_objects, "list", cli_diag_mem_objects_list, PRIVILEGE_UNPRIVILEGED, MODE_EXEC, "memory objects list");
    cli_register_command(cli, diag_mem_objects, "search", cli_diag_mem_objects_search, PRIVILEGE_UNPRIVILEGED, MODE_EXEC, "memory objects search");
    cli_register_command(cli, diag_mem_objects, "clear", cli_diag_mem_objects_clear, PRIVILEGE_PRIVILEGED, MODE_EXEC, "clears memory object");
    auto diag_mem_trace = cli_register_command(cli, diag_mem, "trace", nullptr, PRIVILEGE_UNPRIVILEGED, MODE_EXEC, "memory tracing commands");
    cli_register_command(cli, diag_mem_trace, "list", cli_diag_mem_trace_list, PRIVILEGE_PRIVILEGED, MODE_EXEC, "print out memory allocation traces (arg: number of top entries to print)");
    cli_register_command(cli, diag_mem_trace, "mark", cli_diag_mem_trace_mark, PRIVILEGE_PRIVILEGED, MODE_EXEC, "mark all currently existing allocations as seen.");

    auto diag_dns = cli_register_command(cli, diag, "dns", nullptr, PRIVILEGE_UNPRIVILEGED, MODE_EXEC, "DNS traffic related troubleshooting commands");
    auto diag_dns_cache = cli_register_command(cli, diag_dns, "cache", nullptr, PRIVILEGE_UNPRIVILEGED, MODE_EXEC, "DNS traffic cache troubleshooting commands");
    cli_register_command(cli, diag_dns_cache, "list", cli_diag_dns_cache_list, PRIVILEGE_PRIVILEGED, MODE_EXEC, "list all DNS traffic cache entries");
    cli_register_command(cli, diag_dns_cache, "stats", cli_diag_dns_cache_stats, PRIVILEGE_PRIVILEGED, MODE_EXEC, "DNS traffic cache statistics");
    cli_register_command(cli, diag_dns_cache, "clear", cli_diag_dns_cache_clear, PRIVILEGE_PRIVILEGED, MODE_EXEC, "clear DNS traffic cache");

    auto diag_dns_domains = cli_register_command(cli, diag_dns, "domain", nullptr, PRIVILEGE_UNPRIVILEGED, MODE_EXEC, "DNS domain cache troubleshooting commands");
    cli_register_command(cli, diag_dns_domains, "list", cli_diag_dns_domain_cache_list, PRIVILEGE_PRIVILEGED, MODE_EXEC, "DNS sub-domain list");
    cli_register_command(cli, diag_dns_domains, "clear", cli_diag_dns_domain_cache_clear, PRIVILEGE_PRIVILEGED, MODE_EXEC, "clear DNS sub-domain cache");

    auto diag_proxy = cli_register_command(cli, diag, "proxy",nullptr, PRIVILEGE_PRIVILEGED, MODE_EXEC, "proxy related troubleshooting commands");
    auto diag_proxy_policy = cli_register_command(cli,diag_proxy,"policy",nullptr,PRIVILEGE_PRIVILEGED, MODE_EXEC,"proxy policy commands");
    cli_register_command(cli, diag_proxy_policy,"list",cli_diag_proxy_policy_list, PRIVILEGE_PRIVILEGED, MODE_EXEC,"proxy policy list");

    auto diag_proxy_session = cli_register_command(cli,diag_proxy,"session",nullptr,PRIVILEGE_PRIVILEGED, MODE_EXEC,"proxy session commands");
    cli_register_command(cli, diag_proxy_session,"list", cli_diag_proxy_session_list, PRIVILEGE_PRIVILEGED, MODE_EXEC,"proxy session list");
    cli_register_command(cli, diag_proxy_session,"clear", cli_diag_proxy_session_clear, PRIVILEGE_PRIVILEGED, MODE_EXEC,"proxy session clear");

    cli_register_command(cli, diag_proxy_session,"tls-info", cli_diag_proxy_tls_list, PRIVILEGE_PRIVILEGED, MODE_EXEC,"connection TLS details");

    auto diag_proxy_io = cli_register_command(cli,diag_proxy,"io",nullptr,PRIVILEGE_PRIVILEGED, MODE_EXEC,"proxy I/O related commands");
    cli_register_command(cli, diag_proxy_io ,"list",cli_diag_proxy_session_io_list, PRIVILEGE_PRIVILEGED, MODE_EXEC,"active proxy sessions");

    auto diag_identity = cli_register_command(cli,diag,"identity",nullptr,PRIVILEGE_PRIVILEGED, MODE_EXEC,"identity related commands");
    auto diag_identity_user = cli_register_command(cli, diag_identity,"user",nullptr, PRIVILEGE_PRIVILEGED, MODE_EXEC,"identity commands related to users");
    cli_register_command(cli, diag_identity_user,"list",cli_diag_identity_ip_list, PRIVILEGE_PRIVILEGED, MODE_EXEC,"list all known users");
    cli_register_command(cli, diag_identity_user,"clear",cli_diag_identity_ip_clear, PRIVILEGE_PRIVILEGED, MODE_EXEC,"CLEAR all known users");


    auto diag_writer = cli_register_command(cli,diag,"writer",nullptr,PRIVILEGE_PRIVILEGED, MODE_EXEC,"file writer diags");
    cli_register_command(cli,diag_writer,"stats",cli_diag_writer_stats,PRIVILEGE_PRIVILEGED, MODE_EXEC,"file writer statistics");

    return true;
}

