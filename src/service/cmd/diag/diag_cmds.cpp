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
#include <sys/ioctl.h>
#include <linux/sockios.h>
#include <unistd.h>

#include <biostring.hpp>

#include <log/logger.hpp>
#include <traflog/traflog.hpp>

#include <service/core/smithproxy.hpp>
#include <service/cmd/cmdserver.hpp>
#include <service/cmd/diag/diag_cmds.hpp>
#include <service/httpd/httpd.hpp>
#include <service/cfgapi/cfgapi.hpp>
#include <service/tpool.hpp>

#include <sslcom.hpp>
#include <sslcertstore.hpp>

#include <sobject.hpp>
#include <proxy/mitmproxy.hpp>
#include <proxy/filters/filterproxy.hpp>
#include <proxy/nbrhood.hpp>

#include <policy/inspectors.hpp>
#include <policy/authfactory.hpp>

#include <inspect/sigfactory.hpp>
#include <inspect/sxsignature.hpp>

#include <varmem.hpp>

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



    SSLFactory* store = SSLCom::factory();

    auto print_cache_stats = [&](auto& cache) {

        size_t n_cache = 0;
        int n_maxsize = 0;
        bool ver_bundle = store->stats.ca_verify_use_file;
        bool sto_bundle = store->stats.ca_store_use_file;

        {
            auto lc_ = std::scoped_lock(store->lock());

            n_cache = cache.cache().size();
            n_maxsize = cache.max_size();
        }


        cli_print(cli, "'%s' certificate store stats: ", cache.info.c_str());
        cli_print(cli, "    cache size: %zu ", n_cache);
        cli_print(cli, "      max size: %d ", n_maxsize);
        cli_print(cli, "    cert verify from bundle: %d", ver_bundle);
        cli_print(cli, "    cert store from bundle: %d", sto_bundle);
    };

    print_cache_stats(store->cache_mitm());
    print_cache_stats(store->cache_custom());

    return CLI_OK;
}


int cli_diag_ssl_cache_list(struct cli_def *cli, const char *command, char *argv[], int argc) {

    debug_cli_params(cli, command, argv, argc);

    auto* store = SSLCom::factory();
    bool print_refs = false;

    if(argc > 0) {
        int lev = safe_val(argv[0]);
        if(lev >= 7) {
            print_refs = true;
        }
    }

    auto print_cache_list = [&] (auto& cache) {

        std::stringstream out;
        cli_print(cli,"'%s' certificate store entries: ", cache.info.c_str());

        auto lc_ = std::scoped_lock(store->lock());

        for (auto const& [ fqdn, inner_cache ]: cache.cache()) {
            auto chain = inner_cache->ptr()->entry();

            out << string_format("    %s\n", fqdn.c_str());

            if(print_refs) {
                out << string_format("        : keyptr=0x%x certptr=0x%x, ctxptr=0x%x\n",
                        chain.chain.key,
                        chain.chain.cert,
                        chain.ctx);
            }

#ifndef USE_OPENSSL11
            if(print_refs)
                ss << string_format("            refcounts: key=%d cert=%d\n",ptr->first->references, ptr->second->references);
#endif
        }
        cli_print(cli, "%s", out.str().c_str());
    };


    print_cache_list(store->cache_mitm());
    print_cache_list(store->cache_custom());

    return CLI_OK;
}

int cli_diag_ssl_cache_print(struct cli_def *cli, const char *command, char *argv[], int argc) {

    debug_cli_params(cli, command, argv, argc);

    SSLFactory *store = SSLCom::factory();
    bool print_refs = false;

    if (argc > 0) {
        int lev = safe_val(argv[0]);
        if (lev >= 7) {
            print_refs = true;
        }
    }

    auto print_cache_entries = [&](auto& cache) {

        std::stringstream out;
        cli_print(cli, "'%s' certificate store entries: \n", cache.info.c_str());

        auto lc_ = std::scoped_lock(store->lock());

        for (auto const& [ fqdn, inner_cache ]: cache.cache()) {
            auto chain = inner_cache->ptr()->entry();

            std::regex reg("\\+san:");
            std::string nice_fqdn = std::regex_replace(fqdn, reg, "\n     san: ");

            out << "\n--------: " << nice_fqdn << "\n";

            if(print_refs) {
                out << string_format("        : keyptr=0x%x certptr=0x%x ctxptr=0x%x\n",
                                    chain.chain.key,
                                    chain.chain.cert,
                                    chain.ctx);
                auto counter = inner_cache->count();
                auto age = inner_cache->age();
                out << string_format("        : access_counter=%d, age=%d\n", counter, age);
            }

            out << SSLFactory::print_cert(chain.chain.cert);
            out << "\n--------";

            out << "\n\n";
        }

        cli_print(cli, "%s", out.str().c_str());
    };

    print_cache_entries(store->cache_mitm());
    print_cache_entries(store->cache_custom());


    return CLI_OK;
}


int cli_diag_ssl_cache_clear(struct cli_def *cli, const char *command, char *argv[], int argc) {

    debug_cli_params(cli, command, argv, argc);

    auto* store = SSLCom::factory();



    auto erase_cache = [&](auto& cache) {
        std::stringstream out;
        auto lc_ = std::scoped_lock(store->lock());

        for (auto const& [ fqdn, inner_cache ]: cache.cache()) {

            out << string_format("removing    %s\n", fqdn.c_str());

            if(argc > 0) {
                std::string arg1 = argv[0];
                if(arg1 == "7") {
#ifndef USE_OPENSSL11
                    ss << string_format("            refcounts: key=%d cert=%d\n",
                                        ptr->first->references,
                                        ptr->second->references);
#endif
                }
            }
        }
        cache.clear();

        cli_print(cli, "%s", out.str().c_str());
    };

    erase_cache(store->cache_mitm());
    erase_cache(store->cache_custom());

    store->load_custom_certificates();

    return CLI_OK;
}

int cli_diag_ssl_wl_list(struct cli_def *cli, const char *command, char *argv[], int argc) {

    debug_cli_params(cli, command, argv, argc);

    cli_print(cli,"\nSSL whitelist:");
    std::string out;

    auto lc_ = std::scoped_lock(MitmProxy::whitelist_verify().getlock());

    for(auto const& [label, entry]: MitmProxy::whitelist_verify().cache()) {
        out += "\n\t" + label;

        long ttl = entry->ptr()->expired_at() - ::time(nullptr);

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

    auto lc_ = std::scoped_lock(MitmProxy::whitelist_verify().getlock());

    MitmProxy::whitelist_verify().clear();

    return CLI_OK;
}

void whitelist_add_entry(std::string const& key, unsigned int timeout) {
    auto lc_ = std::scoped_lock(MitmProxy::whitelist_verify().getlock());
    whitelist_verify_entry v;
    MitmProxy::whitelist_verify().set(key, new MitmProxy::whitelist_verify_entry_t(v, timeout));
}

int cli_diag_ssl_wl_insert_fingerprint(struct cli_def *cli, const char *command, char *argv[], int argc) {

    debug_cli_params(cli, command, argv, argc);

    std::string fingerprint;
    unsigned int timeout = 600;

    auto args = args_to_vec(argv,argc);
    if(not args.empty()) { fingerprint = args[0]; }
    if(args.size() > 1) { timeout = safe_val(args[1], 600); }

    whitelist_add_entry(fingerprint, timeout);

    return CLI_OK;
}

int cli_diag_ssl_wl_insert_l4(struct cli_def *cli, const char *command, char *argv[], int argc) {

    debug_cli_params(cli, command, argv, argc);

    std::string l4key;
    unsigned int timeout = 600;

    auto args = args_to_vec(argv,argc);
    if(not args.empty()) { l4key = args[0]; }
    if(args.size() > 1) { timeout = safe_val(args[1], 600); }

    whitelist_add_entry(l4key, timeout);

    return CLI_OK;
}


int cli_diag_ssl_wl_stats(struct cli_def *cli, const char *command, char *argv[], int argc) {

    debug_cli_params(cli, command, argv, argc);

    std::stringstream out;

    auto lc_ = std::scoped_lock(MitmProxy::whitelist_verify().getlock());
    {
        auto n_sz_cache = MitmProxy::whitelist_verify().cache().size();
        auto n_max_cache = MitmProxy::whitelist_verify().max_size();
        std::string n_name = MitmProxy::whitelist_verify().c_type();

        out << string_format("'%s' cache stats: \n", n_name.c_str());
        out << string_format("    current size: %d\n", n_sz_cache);
        out << string_format("    maximum size: %d\n", n_max_cache);
    }


    cli_print(cli, "%s", out.str().c_str());

    return CLI_OK;
}

int cli_diag_ssl_crl_list(struct cli_def *cli, const char *command, char *argv[], int argc) {

    debug_cli_params(cli, command, argv, argc);

    std::stringstream out;

    out << "Downloaded CRLs:\n\n";

    {
        auto& fac = SSLFactory::factory();
        auto lc_ = std::scoped_lock(fac.crl_cache().getlock());

        for (auto const& [uri, cache] : fac.crl_cache().cache()) {
            auto cached_result = cache->ptr();

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

    cli_print(cli, "\n%s", out.str().c_str());

    return CLI_OK;
}

int cli_diag_ssl_crl_stats(struct cli_def *cli, const char *command, char *argv[], int argc) {

    debug_cli_params(cli, command, argv, argc);

    std::stringstream out;

    {
        auto& fac = SSLFactory::factory();
        auto lc_ = std::scoped_lock(fac.crl_cache().getlock());

        auto n_sz_cache = fac.crl_cache().cache().size();
        auto n_max_cache = fac.crl_cache().max_size();
        std::string n_name = fac.crl_cache().c_type();


        out << string_format("'%s' cache stats: ", n_name.c_str());
        out << string_format("    current size: %d \n", n_sz_cache);
        out << string_format("    maximum size: %d \n", n_max_cache);
    }

    cli_print(cli, "\n%s", out.str().c_str());

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

    auto& fac = SSLFactory::factory();
    auto lc_ = std::scoped_lock(fac.verify_cache().getlock());

    if(to_delete.empty()) {

        auto n_size = fac.verify_cache().cache().size();
        fac.verify_cache().clear();

        cli_print(cli, "erased %zu entries", n_size);

        return CLI_OK;
    }

    mp::vector<std::string> to_delete_keys;

    for(auto const& [ key, cache]: SSLFactory::factory().verify_cache().cache()) {
        for(auto const& del_entry: to_delete)
            if(key.find(del_entry, 0) == 0) {
                to_delete_keys.push_back(key);
            }
    }

    for(auto const& del_entry: to_delete_keys) {
        out << "erasing key: " << del_entry << "\n";
        SSLFactory::factory().verify_cache().erase(del_entry);
    }

    cli_print(cli, "%s", out.str().c_str());

    return CLI_OK;
}


int cli_diag_ssl_verify_list(struct cli_def *cli, const char *command, char *argv[], int argc) {

    debug_cli_params(cli, command, argv, argc);

    std::stringstream out;

    out << "Verify status list:\n\n";

    {
        auto lc_ = std::scoped_lock(SSLFactory::factory().verify_cache().getlock());

        for (auto const& [cn, cache]: SSLFactory::factory().verify_cache().cache()) {

            auto cached_result = cache->ptr();

            if (cached_result) {
                auto ttl = cached_result->expired_at() - ::time(nullptr);
                auto revoked_str = string_format("%s(%d)", cached_result->value().revoked > 0 ? "revoked" : "ok", cached_result->value().revoked );
                out << string_format("    %s, ttl=%d, status=%s", cn.c_str(), ttl, revoked_str.c_str());

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

    std::stringstream out;
    {
        auto const& verify_cache = SSLFactory::factory().verify_cache();

        auto lc_ = std::scoped_lock(verify_cache.getlock());

        auto n_sz_cache  = verify_cache.cache().size();
        auto n_max_cache = verify_cache.max_size();
        std::string n_name = verify_cache.c_type();


        out << string_format("'%s' cache stats: \n", n_name.c_str());
        out << string_format("    current size: %d \n", n_sz_cache);
        out << string_format("    maximum size: %d \n", n_max_cache);
    }

    cli_print(cli, "\n%s", out.str().c_str());

    return CLI_OK;
}



int cli_diag_ssl_ticket_list(struct cli_def *cli, const char *command, char *argv[], int argc) {


    auto print_session_ticket = [](SSL_SESSION const* ses, std::string_view label, std::stringstream& out, int lev) {
        if (SSL_SESSION_has_ticket(ses)) {
            size_t ticket_len = 0;
            const unsigned char *ticket_ptr = nullptr;

            SSL_SESSION_get0_ticket(ses, &ticket_ptr, &ticket_len);
            auto ticket_copy = raw::temp_clone(ticket_ptr, ticket_len);

            if (ticket_ptr && ticket_len) {

                std::string tick = hex_print(ticket_copy.value, (unsigned int)ticket_len);
                out << string_format("    %s,    ticket", label.data());

                if (lev > 6) {
                    out << string_format(": %s", tick.c_str());
                } else {
                    out << string_format(": %s", string_shorten(tick, 9).c_str());
                }
                return true;
            }
        }
        return false;
    };

    auto print_session_id = [](SSL_SESSION const* ses, std::string_view label, std::stringstream& out, int lev) {

        unsigned int session_id_len = 0;
        const unsigned char *session_id = SSL_SESSION_get_id(ses, &session_id_len);
        auto session_id_copy = raw::temp_clone(session_id, session_id_len);

        if (session_id_len > 0) {
            std::string sessionid = hex_print(session_id_copy.value, session_id_len);
            out << string_format("    %s, sessionid", label.data());

            if(lev > 6) {
                out << string_format(": %s", sessionid.c_str());
            } else {
                out << string_format(": %s", string_shorten(sessionid, 9).c_str());
            }

            return true;
        }

        return false;
    };

    debug_cli_params(cli, command, argv, argc);

    std::stringstream out;
    int lev = 6;
    bool show_all = false;


    if (argc > 0) {
        lev = safe_val(argv[0]);
        if (lev >= 7) {
            show_all = true;
        }
    }
    bool ticket = false;

    auto& fac = SSLFactory::factory();
    auto lc_ = std::scoped_lock(fac.session_cache().getlock());

    out << "SSL ticket/sessionid list:\n\n";

    for (auto const& [ key, session_keys ]: fac.session_cache().cache()) {

        #ifdef USE_OPENSSL11

        if (session_keys->ptr()) {

            bool printed = false;


            ticket = printed = print_session_ticket(session_keys->ptr()->ptr, key, out, lev);


            if (!ticket || show_all) {
                printed = print_session_id(session_keys->ptr()->ptr, key, out, lev);
            }

            if(printed) {
                out << string_format(", usage cnt: %d", session_keys->ptr()->cnt_loaded);
                out << "\n";
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


    cli_print(cli,"\n%s",out.str().c_str());

    return CLI_OK;
}

int cli_diag_ssl_ticket_stats(struct cli_def *cli, const char *command, char *argv[], int argc) {

    debug_cli_params(cli, command, argv, argc);

    std::stringstream out;
    std::size_t n_sz_cache = 0;
    int n_max_cache = 0;
    std::string n_name;


    {
        auto& fac = SSLFactory::factory();
        auto lc_ = std::scoped_lock(fac.session_cache().getlock());

        n_sz_cache = fac.session_cache().cache().size();
        n_max_cache = fac.session_cache().max_size();
        n_name = fac.session_cache().c_type();
    }

    out << string_format("'%s' cache stats: \n", n_name.c_str());
    out << string_format("    current size: %zu \n", n_sz_cache);
    out << string_format("    maximum size: %d \n", n_max_cache);


    cli_print(cli, "%s", out.str().c_str());
    return CLI_OK;
}

int cli_diag_ssl_ticket_clear(struct cli_def *cli, const char *command, char *argv[], int argc) {

    debug_cli_params(cli, command, argv, argc);

    std::stringstream out;
    std::size_t n_sz_cache = 0;

    {
        auto& fac = SSLFactory::factory();
        auto lc_ = std::scoped_lock(fac.session_cache().getlock());

        n_sz_cache = fac.session_cache().cache().size();

        fac.session_cache().clear();
    }


    out << string_format("\n    %zu session data cleared\n", n_sz_cache);


    cli_print(cli, "%s", out.str().c_str());
    return CLI_OK;
}


int cli_diag_ssl_ca_reload(struct cli_def *cli, const char *command, char *argv[], int argc) {

    debug_cli_params(cli, command, argv, argc);

    cli_print(cli,"Not yet implemented");

    return CLI_OK;
}


int cli_diag_dns_cache_list(struct cli_def *cli, const char *command, char *argv[], int argc) {

    debug_cli_params(cli, command, argv, argc);

    std::stringstream out;
    {
        auto lc_ = std::scoped_lock(DNS::get_dns_lock());


        out << "\nDNS cache populated from traffic: \n";

        for (auto const& [ key, resp ]: DNS::get_dns_cache().cache()) {

            auto response = resp->ptr();
            if (response != nullptr && (! response->answers().empty()) ) {

                long ttl = (response->loaded_at + response->answers().at(0).ttl_) - time(nullptr);
                out << string_format("    %s  -> [ttl:%d]%s\n", key.c_str(), ttl, response->answer_str_A().c_str());
            }
        }
    }

    cli_print(cli, "%s", out.str().c_str());

    return CLI_OK;
}

int cli_diag_dns_cache_stats(struct cli_def *cli, const char *command, char *argv[], int argc) {

    debug_cli_params(cli, command, argv, argc);

    std::stringstream out;
    std::size_t cache_size = 0;
    int max_size = 0;

    {
        auto lc_ = std::scoped_lock(DNS::get_dns_lock());

        out << "\nDNS cache statistics: \n";
        cache_size = DNS::get_dns_cache().cache().size();
        max_size = DNS::get_dns_cache().max_size();
    }

    out << string_format("  Current size: %5d\n", cache_size);
    out << string_format("  Maximum size: %5d\n", max_size);

    cli_print(cli, "%s", out.str().c_str());
    return CLI_OK;
}

int cli_diag_dns_cache_clear(struct cli_def *cli, const char *command, char *argv[], int argc) {

    debug_cli_params(cli, command, argv, argc);

    {
        auto lc_ = std::scoped_lock(DNS::get_dns_lock());
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
        auto lc_ = std::scoped_lock(DNS::get_domain_lock());

        for (auto const& [ domain_main, cache_main ]: DNS::get_domain_cache().cache()) {

            std::string str;

            for (auto const& [ domain, cache]: cache_main->ptr()->cache()) {
                str += " " + domain;
            }
            out << string_format("\n\t%s: \t%s", domain_main.c_str(), str.c_str());

        }
    }

    cli_print(cli,"%s",out.str().c_str());

    return CLI_OK;
}

int cli_diag_dns_domain_cache_clear(struct cli_def *cli, const char *command, char *argv[], int argc) {
    debug_cli_params(cli, command, argv, argc);

    cli_print(cli, "\n Clearing domain cache:");

    {
        auto lc_ = std::scoped_lock(DNS::get_domain_lock());
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
        auto lc_ = std::scoped_lock(AuthFactory::get_ip4_lock());

        for (auto const& [ ip_address, identity]: AuthFactory::get_ip4_map()) {

            ss4 << "\n";
            ss4 << "    ipv4: " << ip_address << ", user: " << identity.username << ", groups: " << identity.groups << ", rx/tx: ";
            ss4 << number_suffixed(identity.tx_bytes) << "/" << number_suffixed(identity.rx_bytes);

            ss4 << "\n          uptime: " << std::to_string(identity.uptime()) << ", idle: " << std::to_string(identity.i_time());
            ss4 << "\n          status: " << std::to_string(!identity.i_timeout()) << ", last policy: ";
            ss4 <<   std::to_string(identity.last_seen_policy);
            ss4 << "\n";
        }

    }
    cli_print(cli, "%s", ss4.str().c_str());


    cli_print(cli, "\nIPv6 identities:");
    std::stringstream ss6;
    {
        auto lc_ = std::scoped_lock(AuthFactory::get_ip6_lock());

        for (auto const& [ ip_address, identity]: AuthFactory::get_ip6_map()) {

            ss6 << "\n";
            ss6 << "    ipv6: " << ip_address << ", user: " << identity.username << ", groups: " << identity.groups << ", rx/tx: ";
            ss6 << number_suffixed(identity.tx_bytes) << "/" << number_suffixed(identity.rx_bytes);
            ss6 << "\n          uptime: " << std::to_string(identity.uptime()) << ", idle: " << std::to_string(identity.i_time());
            ss6 << "\n          status: " << std::to_string(!identity.i_timeout()) << ", last policy: ";
            ss6 <<   std::to_string(identity.last_seen_policy);
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
        auto lc_ = std::scoped_lock(AuthFactory::get_ip4_lock());

        AuthFactory::get_ip4_map().clear();
        AuthFactory::get().shm_ip4_map.acquire();
        AuthFactory::get().shm_ip4_map.map_entries().clear();
        AuthFactory::get().shm_ip4_map.entries().clear();
        AuthFactory::get().shm_ip4_map.save(true);


        AuthFactory::get().shm_ip4_map.seen_version(0);
        AuthFactory::get().shm_ip4_map.release();
    }

    {
        auto lc_ = std::scoped_lock(AuthFactory::get_ip6_lock());

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

    auto wrt = socle::threadedPoolFileWriter::instance();

    std::stringstream out;

    {
        auto lc_ = std::scoped_lock(wrt->queue_lock());

        out << "Pending ops: " << wrt->queue().size() << "\n";
    }
    {
        auto lc_ = std::scoped_lock(wrt->ofstream_lock());

        out << "Recent (opened files):\n";
        for (auto const& [ fnm, x] : wrt->ofstream_cache().cache()) {
            out << "    " << fnm << "\n";
        }
    }

    out << "PCAP stats: \n";
    out << "current file: written " << traflog::PcapLog::single_instance().stat_bytes_written
        << " quota " << traflog::PcapLog::single_instance().stat_bytes_quota << "\n";

    cli_print(cli, "%s", out.str().c_str());

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
                auto stat_acq = memPool::pool().stats.acq.load();
                auto stat_acq_size = memPool::pool().stats.acq_size.load();
                auto stat_ret = memPool::pool().stats.ret.load();
                auto stat_ret_size = memPool::pool().stats.ret_size.load();

                cli_print(cli, "\nMemory pool API stats:");
                cli_print(cli, "acquires: %lld/%lldB", stat_acq, stat_acq_size);
                cli_print(cli, "releases: %lld/%lldB", stat_ret, stat_ret_size);
                cli_print(cli, "active->: %lld/%s", stat_acq - stat_ret,
                                                    number_suffixed(stat_acq_size - stat_ret_size).c_str());
            }


            cli_print(cli, "\nNon-API allocations:");
            cli_print(cli, "mp_allocs: %lld", mp_stats::get().stat_mempool_alloc.load());
            cli_print(cli, "mp_reallocs: %lld", mp_stats::get().stat_mempool_realloc.load());
            cli_print(cli, "mp_frees: %lld", mp_stats::get().stat_mempool_free.load());
            cli_print(cli, "mp_realloc cache miss: %lld", mp_stats::get().stat_mempool_realloc_miss.load());
            cli_print(cli, "mp_realloc fitting returns: %lld", mp_stats::get().stat_mempool_realloc_fitting.load());
            cli_print(cli, "mp_free cache miss: %lld", mp_stats::get().stat_mempool_free_miss.load());
        }

        cli_print(cli," ");
        cli_print(cli, "API allocations above limits:");
        {
            cli_print(cli, "      allocations: %lld/%lldB", memPool::pool().stats.heap_alloc.load(), memPool::pool().stats.heap_alloc_size.load());
            cli_print(cli, "         releases: %lld/%lldB", memPool::pool().stats.out_free.load(), memPool::pool().stats.out_free_size.load());
            cli_print(cli, "\nrelease pool miss: %lld/%lldB", memPool::pool().stats.out_pool_miss.load(),
                      memPool::pool().stats.out_pool_miss_size.load());

            cli_print(cli, "\nPool capacities (available/limits):");

            for(auto const* buck: memPool::pool().get_buckets()) {
                cli_print(cli, "%5luB pool size: %lu/%lu", static_cast<unsigned long>(buck->chunk_size()),
                                                            static_cast<unsigned long>(buck->size()),
                                                            static_cast<unsigned long>(buck->total_count()));
            }
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

int cli_diag_mem_udp_stats(struct cli_def *cli, const char *command, char **argv, int argc) {

    debug_cli_params(cli, command, argv, argc);

    cli_print(cli,"UDP Statistics:\n");
    {
        {
            auto udpc = UDPCom::datagram_com_static();
            auto lc_ = std::scoped_lock(udpc->lock);
            cli_print(cli, "Embryonic entries:    %zd", udpc->datagrams_received.size());
            cli_print(cli, "Embryonic inset sz:   %zd", udpc->in_virt_set.size());
        }

        {
            auto lc_ = std::scoped_lock(UDPCom::ConnectionsCache::lock);
            cli_print(cli, "Connect cache size:   %zd", UDPCom::ConnectionsCache::cache.size());
        }
    }

    return CLI_OK;


}

int cli_diag_mem_trace_mark (struct cli_def *cli, const char *command, char **argv, int argc) {

    debug_cli_params(cli, command, argv, argc);

#ifdef MEMPOOL_DEBUG

    std::scoped_lock<std::mutex> l(mpdata::trace_lock());

    for (auto& it: mpdata::trace_map()) {
        it.second.mark = 1;
    }


#else

    cli_print(cli, "memory tracing not enabled.");
#endif

    return CLI_OK;
}


#ifdef MEMPOOL_ALL

// template specializations for MEMPOOL_ALL + MEMPOOL_DEBUG debugs - it's tricky - we MUST use ::malloc and ::free,
// because strings and maps will alloc and trigger deadlock

template <typename K, typename V>
using unordered_map_malloc = std::unordered_map<K, V, std::hash<K>, std::equal_to<>, mp::malloc::allocator<std::pair<const K, V>>>;

template <typename K, typename V, class H>
using  unordered_map_malloc_h = std::unordered_map<K, V, H, std::equal_to<>, mp::malloc::allocator<std::pair<const K, V>>>;

template <typename K, typename V>
using  map_malloc_h = std::map<K, V, std::less<>, mp::malloc::allocator<std::pair<const K, V>>>;

#endif


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
        struct bt_stat {
            bt_stat() = default;
            bt_stat(bt_stat const&) = default;
            bt_stat& operator=(bt_stat const&) = default;

            unsigned long long counter;
            unsigned long long size;

            bool operator<(bt_stat const& b) const {
                return counter < b.counter;
            }
        };

        struct bt_stat_hash {
            std::size_t operator()(const bt_stat &v) {
                return std::hash<unsigned long long>()(v.counter) ^ std::hash<unsigned long long>()(v.size);
            }
        };

#ifdef MEMPOOL_ALL
        using used_string_type = mp::malloc::string;
        using used_hashmap1 = unordered_map_malloc_h<mp::malloc::string, bt_stat, mp::malloc::hash>;
        using used_hashmap2 = map_malloc_h<bt_stat, used_string_type>;
#else
        using used_string_type = std::string;
        using used_hashmap1 = std::unordered_map<std::string, bt_stat>;
        using used_hashmap2 = std::map<bt_stat, used_string_type>;
#endif
        used_hashmap1 occ;
        {
            std::scoped_lock<std::mutex> l(mpdata::trace_lock());

            for (auto const& mem: mpdata::trace_map()) {
                auto mch = mem.second;
                if ( (!mch.in_pool) && mch.mark == filter) {
                    used_string_type k;

                    //k = mch.str_trace();
                    k.resize((size_t)(sizeof(void*))*mch.trace_size);
                    ::memcpy((void*)k.data(), mch.trace, (size_t)(sizeof(void*))*mch.trace_size);


                    auto i = occ.find(k);
                    if (i != occ.end()) {

                        occ[k].counter++;
                        occ[k].size += mch.capacity;
                    } else {
                        occ[k] =  { .counter = 1, .size = mch.capacity } ;
                    }
                }
            }

            cli_print(cli, "Allocation traces: processed %ld used mempool entries", mpdata::trace_map().size());
        }
        cli_print(cli, "Allocation traces: parsed %ld unique entries.", occ.size());

        used_hashmap2 ordered;
        for(auto [ bt, bt_stat ]: occ) {
            ordered[bt_stat] = bt;
        }

        cli_print(cli, "\nAllocation traces (top-%d):", n);

        auto i = ordered.rbegin();
        while(i != ordered.rend() && n > 0) {
            mem_chunk_t m;

            memcpy(&m.trace, i->second.data(), i->second.size());
            m.trace_size = static_cast<int>(i->second.size()/sizeof(void*));

            cli_print(cli, "\nNumber of traces: %lld [%lldB]\n%s", i->first.counter, i->first.size , m.str_trace().c_str());
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
        std::string arg1 = argv[0];
        if(arg1 == "?") {
            cli_print(cli,"valid parameters:");
            cli_print(cli,"         <empty> - all entries will be printed out");
            cli_print(cli,"         0x prefixed string - only object with matching Id will be printed out");
            cli_print(cli,"         any other string   - only objects with class matching this string will be printed out");

            return CLI_OK;
        } else {
            // a1 is param for the lookup
            if("*" == arg1 || "ALL" == arg1) {
                object_filter = "";
            } else {
                object_filter = arg1;
            }
        }

        if(argc > 1) {
            std::string arg2 = argv[1];
            verbosity = safe_val(arg2,iINF);
        }
    }


    std::string ret = socle::sobjectDB::str_list((object_filter.empty()) ? nullptr : object_filter.c_str(), nullptr, verbosity);
    ret += "\n" + socle::sobjectDB::str_stats((object_filter.empty()) ? nullptr : object_filter.c_str());


    cli_print(cli, "Smithproxy objects (filter: %s):\n%s\nFinished.",(object_filter.empty()) ? "ALL" : object_filter.c_str() , ret.c_str());
    return CLI_OK;
}


int cli_diag_mem_objects_search(struct cli_def *cli, const char *command, char *argv[], int argc) {

    debug_cli_params(cli, command, argv, argc);

    std::string object_filter;
    int verbosity = iINF;

    if(argc > 0) {
        std::string arg1 = argv[0];
        if(arg1 == "?") {
            cli_print(cli,"valid parameters:");
            cli_print(cli,"         <empty>     - all entries will be printed out");
            cli_print(cli,"         any string  - objects with descriptions containing this string will be printed out");

            return CLI_OK;
        } else {
            // a1 is param for the lookup
            if("*" == arg1 || "ALL" == arg1) {
                object_filter = "";
            } else {
                object_filter = arg1;
            }
        }

        if(argc > 1) {
            std::string arg2 = argv[1];
            verbosity = safe_val(arg2,iINF);
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

    int flags = SL_NONE;
    std::vector<std::string> args;

    for (int i = 0; i < argc; ++i) {
        std::string arg = argv[i];

        if(arg == "active") flags = flag_set<int>(flags, SL_ACTIVE);
        else if(arg == "tls") flags = flag_set<int>(flags, SL_TLS_DETAILS);
        else if(arg == "io")  { flags = flag_set<int>(flags, SL_IO_EMPTY); flags = flag_set<int>(flags, SL_IO_OSBUF_NZ); }
        else if(arg == "io-all")  {
            flags = flag_set<int>(flags, SL_IO_EMPTY);
            flags = flag_set<int>(flags, SL_IO_OSBUF_NZ);
            flags = flag_set<int>(flags, SL_IO_ALL);
        }
        else if(arg == "nonames")  flags = flag_set<int>(flags, SL_NO_NAMES);
        else if(arg == "ips")  flags = flag_set<int>(flags, SL_IPS);
        else {
            args.emplace_back(arg);
        }
    }

    return cli_diag_proxy_session_list_extra(cli, command, args, flags);
}


int cli_diag_proxy_tls_list(struct cli_def *cli, const char *command, char *argv[], int argc) {

    debug_cli_params(cli, command, argv, argc);

    return cli_diag_proxy_session_list_extra(cli, command, args_to_vec(argv, argc), SL_TLS_DETAILS);
}

int cli_diag_proxy_list_active(struct cli_def *cli, const char *command, char *argv[], int argc) {

    debug_cli_params(cli, command, argv, argc);

    return cli_diag_proxy_session_list_extra(cli, command, args_to_vec(argv, argc), SL_ACTIVE);
}


int cli_diag_proxy_session_io_list(struct cli_def *cli, const char *command, char *argv[], int argc) {

    debug_cli_params(cli, command, argv, argc);

    int f = 0;
    flag_set<int>(&f, SL_IO_OSBUF_NZ);
    flag_set<int>(&f, SL_IO_EMPTY);

    return cli_diag_proxy_session_list_extra(cli, command, args_to_vec(argv, argc), f);
}

int cli_diag_proxy_list_nonames(struct cli_def *cli, const char *command, char *argv[], int argc) {

    debug_cli_params(cli, command, argv, argc);

    return cli_diag_proxy_session_list_extra(cli, command, args_to_vec(argv, argc), SL_NO_NAMES);
}


void print_queue_stats(std::stringstream &ss, int verbosity, MitmHostCX *cx, const char *sm,
                             const char *bg) {
    int in_pending;
    int out_pending;

    buffer::size_type in_buf;
    buffer::size_type out_buf;

    buffer::size_type in_cap;
    buffer::size_type out_cap;

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
    if(verbosity >= EXT and in_buf) {
        ss << "     " << bg << " last-seen read data: \n" << hex_dump(cx->readbuf(), 6) << "\n";
    }
}


auto get_io_info(MitmHostCX* lf, MitmHostCX* rg, int sl_flags) {

    bool do_print = false;
    std::string prefix;
    std::string suffix;

    bool do_all = flag_check<int>(sl_flags, SL_IO_ALL);

    if (flag_check<int>(sl_flags, SL_IO_OSBUF_NZ) or do_all) {

        unsigned int l_in_pending = 0;
        unsigned int l_out_pending = 0;
        unsigned int r_out_pending = 0;
        unsigned int r_in_pending = 0;

        if (lf && lf->real_socket() > 0) {
            ::ioctl(lf->socket(), SIOCINQ, &l_in_pending);
            ::ioctl(lf->socket(), SIOCOUTQ, &l_out_pending);
        }
        if (rg && rg->real_socket() > 0 && lf) {
            ::ioctl(lf->socket(), SIOCINQ, &r_in_pending);
            ::ioctl(lf->socket(), SIOCOUTQ, &r_out_pending);
        }

        suffix += " i/o: ";

        if (l_in_pending + l_out_pending + r_in_pending + r_out_pending != 0) {

            suffix += "sio-";

            if (l_in_pending) { suffix += string_format("-Li(%d)", l_in_pending); }
            if (l_out_pending) { suffix += string_format("-Lo(%d)", l_out_pending); }
            if (r_in_pending) { suffix += string_format("-Ri(%d)", r_in_pending); }
            if (r_out_pending) { suffix += string_format("-Ro(%d)", r_out_pending); }


            suffix += " ";

            do_print = true;
        } else {
            suffix += "sio-ok ";
        }

        if (lf && rg) {
            if (lf->meter_read_bytes != rg->meter_write_bytes) {
                suffix += string_format("L(%d)->R ", lf->meter_read_bytes - rg->meter_write_bytes);
                do_print = true;
            }

            if (lf->meter_write_bytes != rg->meter_read_bytes) {
                suffix += string_format("R(%d)->L ", rg->meter_read_bytes - lf->meter_write_bytes);
                do_print = true;
            }
        }

        if (lf && lf->writebuf() && (!lf->writebuf()->empty())) {
            suffix += string_format("LWrBuf(%d) ", lf->writebuf()->size());
            do_print = true;
        }

        if (rg && rg->writebuf() && (!rg->writebuf()->empty())) {
            suffix += string_format("RWrBuf(%d) ", rg->writebuf()->size());
            do_print = true;

        }
    }

    if (flag_check<int>(sl_flags, SL_IO_EMPTY) or do_all) {

        int both = 0;
        std::string loc_pr;

        if (lf && (lf->meter_read_bytes == 0 || lf->meter_write_bytes == 0)) {
            loc_pr += "L-no-transfer ";

            both++;
            do_print = true;
        }

        if (rg && (rg->meter_read_bytes == 0 || rg->meter_write_bytes == 0)) {
            loc_pr += "R-no-transfer ";

            both++;
            do_print = true;
        }

        if (both > 1)
            loc_pr = "no-transfer ";

        if (both > 0)
            suffix += loc_pr;
    }

    if(flag_check<int>(sl_flags, SL_IO_ALL)) {
        if(not do_print)
            suffix += "proxy-ok";
        do_print = true;
    }

    return std::make_tuple(do_print, prefix, suffix);
}



auto get_tls_info(MitmHostCX const* lf, MitmHostCX const* rg, int sl_flags, int verbosity) {

    bool do_print = false;
    std::string prefix;
    std::string suffix;

    if (flag_check<int>(sl_flags, SL_TLS_DETAILS)) {
        std::stringstream tls_ss;

        std::vector<std::pair<std::string, SSLCom *>> tup;
        if (lf)
            tup.emplace_back("Left ", dynamic_cast<SSLCom *>(lf->com()));
        if (rg)
            tup.emplace_back("Right", dynamic_cast<SSLCom *>(rg->com()));

        for (auto const&[label, com]: tup) {

            if (com && not com->opt.bypass) {
                auto ssl = com->get_SSL();
                if (ssl) {
                    auto const *session = SSL_get_session(ssl);

                    auto *cipher_str = SSL_CIPHER_get_name(SSL_SESSION_get0_cipher(session));
                    int has_ticket = SSL_SESSION_has_ticket(session);
                    unsigned long lifetime_hint = -1;
                    if (has_ticket > 0) {
                        lifetime_hint = SSL_SESSION_get_ticket_lifetime_hint(session);
                    }

                    auto tls_ver = SSL_get_version(ssl);
                    bool tls_rsm = (com->target_cert() == nullptr);

                    tls_ss << "\n  " << label << ": version: " << tls_ver << ", cipher: ";
                    tls_ss << cipher_str;
#ifdef USE_OPENSSL300
                    auto ktls_r = BIO_get_ktls_recv(SSL_get_rbio(ssl));
                    auto ktls_w = BIO_get_ktls_send(SSL_get_wbio(ssl));
                    tls_ss << " ktls: r:" << ktls_r << "/w:" << ktls_w;
#endif
                    tls_ss << ", resumed/ticket: "
                           << tls_rsm << "/" << has_ticket;
                    if (has_ticket) {
                        tls_ss << " , ticket_hint: " << lifetime_hint << "s";
                    }

                    if (!com->is_server()) {
                        tls_ss << "\n    verify(" << SSLCom::verify_origin_str(com->verify_origin())
                               << "): "
                               << MitmProxy::verify_flag_string(com->verify_get());

                        if (!com->verify_extended_info().empty()) {
                            for (auto const &ei: com->verify_extended_info()) {
                                tls_ss << "\n    verify: "
                                       << MitmProxy::verify_flag_string_extended(ei);
                            }
                        }
                    }

                    const char *sni = SSL_get_servername(ssl, TLSEXT_NAMETYPE_host_name);
                    if (sni) {
                        tls_ss << "\n    sni: " << sni;

                        if (lf) {
                            auto *app = lf->engine_ctx.application_data.get();
                            auto http_app = dynamic_cast<sx::engine::http::app_HttpRequest *>(app);
                            if (http_app) {

                                if (!http_app->host.empty()) {
                                    if (sni == http_app->host) {
                                        tls_ss << " -> http host ok";
                                    } else {
                                        tls_ss << " -> http host DOESN'T MATCH";
                                    }
                                }

                                if (verbosity > iINF) {
                                    tls_ss << "\n  http host: " << http_app->host;
                                }
                            }
                        }
                    }

                    if (not com->alpn().empty()) {
                        tls_ss << "\n    alpn: " << com->alpn();
                    }

                    auto scts = SSL_get0_peer_scts(ssl);
                    int scts_len = sk_SCT_num(scts);
                    tls_ss << "\n    sct: " << scts_len << " entries";

                    if (scts_len > 0 and verbosity > iDIA) {
                        const CTLOG_STORE *log_store = SSL_CTX_get0_ctlog_store(SSLFactory::factory().default_tls_client_cx());

                        for (int i = 0; i < scts_len; i++) {
                            auto sct = sk_SCT_value(scts, i);

                            unsigned char *sct_logid{};
                            std::size_t sct_logid_len = 0;

                            sct_logid_len = SCT_get0_log_id(sct, &sct_logid);
                            if (sct_logid_len > 0)
                                tls_ss << "\n        sct log." << i << ": "
                                       << hex_print(sct_logid, sct_logid_len);
                            auto val_stat = SCT_get_validation_status(sct);
                            tls_ss << "\n        sct log." << i << ": "
                                   << socle::com::ssl::SCT_validation_status_str(val_stat);

                            BioMemory bm;
                            SCT_print(sct, bm, 4, log_store);
                            auto v_of_s = string_split(bm.str(), '\n');
                            for (auto const &s: v_of_s) {
                                tls_ss << "\n        sct log." << i << ": " << s;
                            }
                        }
                    }
                }
                else {
                    tls_ss << "\n  " << label << ": tls, but no info";
                }
            } else {
                tls_ss << "\n  " << label << ": not a TLS session";
                if (com && com->opt.bypass)
                    tls_ss << " (bypassed)";
            }
        }
        tls_ss << "\n";
        do_print = true;
        suffix += tls_ss.str();

    }
    return std::make_tuple(do_print, prefix, suffix);
}



auto replace_proxy_title_target(std::string const &title, MitmHostCX const* right_cx, int verbosity, int sl_flags) {

    auto scom = dynamic_cast<SSLCom *>(right_cx->com());
    if (scom) {
        std::stringstream replacement;

        std::string tgt = (scom->get_sni().empty() ? scom->shortname() + "_" +
                                                     right_cx->host()
                                                   : scom->get_sni());
        replacement << "$1" << (verbosity > iINF ? "[sni]" : "") << tgt;

        // add IP only if sni was filled in
        if(flag_check<int>(sl_flags, SL_IPS) and not scom->get_sni().empty()) {
            replacement << '(' << right_cx->host() << ')';
        }

        replacement << ":" << right_cx->port();

        auto rmatch = std::regex("(r:[^_]+)ssli_[0-9a-fA-F:.]+");

        return std::regex_replace(title, rmatch, replacement.str());

    } else {
        return title;
    }
}

auto get_proxy_title(MitmProxy* proxy, int sl_flags, int verbosity) {

    if (flag_check<int>(sl_flags, SL_NO_NAMES)) {
        return proxy->to_string(verbosity);
    } else {
        if (auto const* rg = proxy->first_right(); rg) {
            return replace_proxy_title_target(proxy->to_string(verbosity), rg, verbosity, sl_flags);
        } else {
            return proxy->to_string(verbosity);
        }
    }
}


auto get_more_info(sobject_info const* so_info, MitmProxy const* curr_proxy, MitmHostCX* lf, MitmHostCX* rg, int verbosity) {

    std::stringstream info_ss;

    if (verbosity >= DEB && so_info) {
        info_ss << so_info->to_string(verbosity);
    }

    if (verbosity > INF) {

        if (lf) {
            if (verbosity > INF) info_ss << "\n    ";

            if( curr_proxy and not curr_proxy->filters_.empty()) {
                info_ss << "\n    Filters:";
                for(auto& [ name, filter_ptr ]: curr_proxy->filters_) {
                    if(filter_ptr) {
                        if(filter_ptr->update_states()) {
                            info_ss << "\n        " << name << ": " << filter_ptr->to_string(verbosity);
                        }
                        else {
                            info_ss << "\n        " << name << ": invalid state";
                        }
                    }
                }
            }
            if (lf->engine_ctx.signature) {

                auto mysig = std::dynamic_pointer_cast<MyDuplexFlowMatch>(lf->engine_ctx.signature);

                info_ss << "\n    L7_engine: " << mysig->sig_engine;
                info_ss << "\n    L7_signature: " << mysig->name() << ", group: "
                        << mysig->sig_group;
            } else {
                info_ss << "\n    L7_engine: none";
            }

            if (lf->engine_ctx.application_data) {
                std::string desc = lf->engine_ctx.application_data->str();
                if (verbosity < DEB && desc.size() > 120) {
                    desc = desc.substr(0, 117);
                    desc += "...";
                }
                info_ss << "\n    L7_params: " << desc << "\n";
            } else {
                info_ss << "\n    L7_params: none\n";
            }


            if (verbosity > INF) {
                long expiry = -1;
                if (curr_proxy->half_holdtimer > 0) {
                    expiry = curr_proxy->half_holdtimer + MitmProxy::half_timeout() - time(nullptr);
                }
                info_ss << "    half_hold: " << expiry << "\n";
            }
        }

        if (verbosity > INF) {
            if(lf and lf->socket() > 0) {
                print_queue_stats(info_ss, verbosity, lf, "lf", "Left");
            }
            if(rg and rg->socket() > 0) {
                print_queue_stats(info_ss, verbosity, rg, "rg", "Right");
            }
        }
    }

    return info_ss.str();
}


int cli_diag_proxy_session_list_extra (struct cli_def *cli, const char *command, std::vector<std::string> const &args,
                                       int sl_flags) {

    debug_cli_params(cli, command, args);

    std::string arg1;
    std::string arg2;
    int verbosity = iINF;
    if(not args.empty()) {
        arg1 = args.at(0);
        verbosity = safe_val(arg1, iINF);

        if(args.size() > 1) arg2 = args.at(1);
    }

    std::stringstream out;

    {
        auto lc_ = std::scoped_lock(socle::sobjectDB::getlock());

        for (auto const& [ so_ptr, so_info]: socle::sobjectDB::db()) {

            std::string prefix;
            std::string suffix;


            if (!so_ptr) continue;

            std::string what = so_ptr->c_type();
            if ( what == "MitmProxy" || what == "SocksProxy") {

                auto *curr_proxy = dynamic_cast<MitmProxy *>(so_ptr);
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

                if (flag_check<int>(sl_flags, SL_ACTIVE)) {
                    if(curr_proxy->stats().mtr_down.get() + curr_proxy->stats().mtr_up.get() == 0) {
                        continue;
                    }
                    do_print = true;
                }

                if(lf and lf->engine_ctx.application_data) {
                    suffix += string_format(" (%s)", lf->engine_ctx.application_data->protocol().c_str());
                }
                if(curr_proxy and not curr_proxy->filters_.empty()) {
                    for(auto const& fi: curr_proxy->filters_) {
                        suffix += string_format(" !%s", fi.first.c_str());
                    }
                }

                auto const& io_info = get_io_info(lf, rg, sl_flags);

                do_print |= std::get<0>(io_info);
                prefix += std::get<1>(io_info);
                suffix += std::get<2>(io_info);


                auto tls_info = get_tls_info(lf, rg, sl_flags, verbosity);

                do_print |= std::get<0>(tls_info);
                prefix += std::get<1>(tls_info);
                suffix += std::get<2>(tls_info);


                if (sl_flags == SL_NONE) { do_print = true;  }
                if (sl_flags == SL_NO_NAMES) { do_print = true;  }
                if (sl_flags == SL_IPS) { do_print = true;  }

                if (!do_print) {
                    continue;
                }

                // adjust prefix spacing
                if (!prefix.empty()) {

                    if (prefix[prefix.size() - 1] != ' ')
                        prefix += " "; // separate IO flags


                    prefix += "\r\n";
                }

                std::stringstream cur_obj_ss;
                cur_obj_ss << prefix << get_proxy_title(curr_proxy, sl_flags, verbosity) << suffix;

                cur_obj_ss << get_more_info(so_info.get(), curr_proxy, lf, rg, verbosity);

                out << cur_obj_ss.str() << "\n";
            }
        }
    }


    cli_print(cli, "%s", out.str().c_str());

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

        for (auto const& it: CfgFactory::get()->db_policy_list) {
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

    std::vector< std::shared_ptr<SignatureTree::sensorType> > lists;
    for(auto next: SigFactory::get().signature_tree().sensors_) {
        if(next) lists.push_back(next);
    }

    for(auto const& list: lists)
        for(auto const& [ _, sig]: *list) {

            // print refcnt one less, due to this shared_ptr serving only priting purposes
            ss << "Name: '" << sig->name() << "' refcnt: " << sig.use_count() - 1 << "\n";
            ss << "  chain size: " << sig->sig_chain().size() << "\n";

            auto sx_ptr = std::dynamic_pointer_cast<MyDuplexFlowMatch>(sig);
            if(sx_ptr) {
                ss << "  category: " << sx_ptr->sig_category << "\n";
                ss << "  severity: " << sx_ptr->sig_severity << "\n";
                ss << "  side: " << sx_ptr->sig_side << "\n";
                ss << "  group: " << sx_ptr->sig_group << "\n";
                ss << "  enables: " << sx_ptr->sig_enables << "\n";
                ss << "  engine: " << sx_ptr->sig_engine << "\n";
            }

            ss << "\n";
        }


    cli_print(cli, "%s", ss.str().c_str());

    return CLI_OK;
}


int cli_diag_worker_proxy_list(struct cli_def *cli, [[maybe_unused]] const char *command, [[maybe_unused]] char *argv[], [[maybe_unused]] int argc) {

    int verbosity = iINF;
    if(argc > 0) {
        std::string arg1 = argv[0];
        verbosity = safe_val(arg1, iINF);
    }

    auto& sx = SmithProxy::instance();

    auto list_worker = [&cli] (auto const& wrk, std::size_t index, int verbosity) {

        std::stringstream out;

        if(verbosity > iINF) {
            out << string_format("        `- worker[%zu]: %s", index, wrk.second->str().c_str());
            out << ", thread " << std::hex << wrk.first->get_id();
        }
        else {
            out << string_format( "        `- worker[%zu]: ", index);
        }

        auto const& proxies = wrk.second->proxies();

        if (proxies.empty()) {
            if(verbosity > iINF)
                out << "\n          `- idle";
            else
                out << " [> idle";

            auto sss = out.str();
            cli_print(cli, "%s", sss.c_str());
            return false;
        }

        unsigned long up = 0;
        unsigned long down = 0;

        {
            // skim proxies for speed stats
            auto lc_ = std::scoped_lock(wrk.second->proxy_lock());
            for (auto& [ proxy, thr ]: proxies) {
                up += proxy->stats().mtr_up.get()*8;
                down += proxy->stats().mtr_down.get()*8;
            }
        }

        std::string sp_str = number_suffixed(up) + "/" + number_suffixed(down);

        auto speed_str = (sp_str == "0.0/0.0") ? "up/dw: --" : string_format("up/dw: %s", sp_str.c_str());

        if(verbosity > iINF) {
            {
                auto lc_ = std::scoped_lock(wrk.second->proxy_lock());


                for (std::size_t p_i = 0; p_i < proxies.size(); ++p_i) {
                    auto const& proxy = proxies.at(p_i).first;
                    out << string_format("\n          `- proxy[%d]: %s", p_i, proxy->str().c_str());
                }
                out << "\n          `- " << speed_str;
            }
        } else {
            auto num_proxies = proxies.size();
            out << " [";
            for (std::size_t prin = 0; prin < num_proxies; ++prin) out << "=";
            out << ">";

            out << string_format(" : %d proxies, %s", num_proxies, speed_str.c_str());
        }

        auto sss = out.str();
        cli_print(cli, "%s", sss.c_str());

        return true;
    };


    auto get_thread_id_str = [](auto const& thread_ptr) {
        if (thread_ptr) {
            std::stringstream threadss;
            threadss << std::hex << thread_ptr->get_id();

            return threadss.str();
        }
        return std::string();
    };


    struct {
        int workers_busy = 0;
        int workers_idle = 0;
    } stats;

    auto list_acceptor = [&cli, &list_worker, &get_thread_id_str, &stats](const char* title, auto& listener, auto const& threads, int verbosity) {

        if(listener.empty() and verbosity <= iINF) return;

        cli_print(cli, title);
        bool thread_len_ok = (listener.size() == threads.size());

        for (std::size_t idx = 0; idx < listener.size(); ++idx) {

            auto const& acceptor = listener.at(idx);
            std::string thread_id;

            if(thread_len_ok) {
                thread_id = get_thread_id_str(threads.at(idx));
            }

            cli_print(cli, "    %s%s%s", acceptor->hr().c_str(),
                                (verbosity > iINF ? string_format(", type %s", acceptor->proxy_type().str().c_str()).c_str() : ""),
                                ( (verbosity > iINF and not thread_id.empty() ) ? string_format(", thread %s", thread_id.c_str()).c_str() : ""));



            for(std::size_t i = 0; i < acceptor->tasks().size(); ++i) {
                if(not list_worker(acceptor->tasks().at(i), i, verbosity)) {
                    stats.workers_idle++;
                }
                else {
                    stats.workers_busy++;
                }
            }
        }
    };

    list_acceptor("== plain acceptor", sx.plain_proxies, sx.plain_threads, verbosity);
    list_acceptor("== tls acceptor", sx.ssl_proxies, sx.ssl_threads, verbosity);

    list_acceptor("== udp receiver", sx.udp_proxies, sx.udp_threads, verbosity);
    list_acceptor("== dtls receiver", sx.dtls_proxies, sx.dtls_threads, verbosity);

    list_acceptor("== socks acceptor", sx.socks_proxies, sx.socks_threads, verbosity);
    list_acceptor("== socks receiver", sx.socks_udp_proxies, sx.socks_udp_threads, verbosity);

    list_acceptor("== plain redirect acceptor", sx.redir_plain_proxies, sx.redir_plain_threads, verbosity);
    list_acceptor("== dns redirect receiver", sx.redir_udp_proxies, sx.redir_udp_threads, verbosity);
    list_acceptor("== tls redirect acceptor", sx.redir_ssl_proxies, sx.redir_ssl_threads, verbosity);

    cli_print(cli, "\nThreading load: %d total busy workers, %.2f per CPU", stats.workers_busy, stats.workers_busy/(float)std::thread::hardware_concurrency());

    return CLI_OK;
}


int cli_diag_worker_pool_list(struct cli_def *cli, const char *command, char *argv[], int argc) {

    std::stringstream ss;

    auto ts = ThreadPool::instance::get().tasks_size();
    auto tr = ThreadPool::instance::get().tasks_running();
    auto wc = ThreadPool::instance::get().worker_count();

    ss << "Utility thread pool stats: \n";
    ss << "  enqueued tasks: " << ts << ", active workers: " << tr << "/" << wc << "\n";

    cli_print(cli, "%s", ss.str().c_str());

    return CLI_OK;
}

int cli_diag_api_list(struct cli_def *cli, const char *command, char *argv[], int argc) {

    std::stringstream ss;
    {
        using namespace sx::webserver;
        auto lc_ = std::scoped_lock(HttpSessions::lock);

        for (auto const& ak: HttpSessions::access_keys) {
            for(auto const& to: ak.second) {
                ss << "access_token: " << ak.first << " csrf_token: ";

                auto const& csrf = to.second.stored_optional();
                if(csrf.has_value()) {
                    auto exp = to.second.expired_at() - time(nullptr);
                    ss << csrf.value() << " expiring: " << exp << ( exp < 0 ? " *expired*" : "" );
                }
            }

            ss << "\r\n";
        }
    }

    cli_print(cli, "%s", ss.str().c_str());
    return CLI_OK;
}


int cli_diag_neighbor_list(struct cli_def *cli, const char *command, char *argv[], int argc) {
    std::stringstream ss;
    {
        auto& nb = NbrHood::instance();
        auto _lc = std::scoped_lock(nb.cache().lock());

        ss << "Neighbors seen:\n";

        for(auto const& e: nb.cache().get_map_ul()) {
            auto delta = time(nullptr) - e.second.first->last_seen;
            ss << e.first << " last seen: " << uptime_string(delta) << "\n";
        }
    }
    cli_print(cli, "%s", ss.str().c_str());
    return CLI_OK;
}

int cli_diag_neighbor_clear(struct cli_def *cli, const char *command, char *argv[], int argc) {

    size_t sz = 0;
    {
        auto& nb = NbrHood::instance();
        auto _lc = std::scoped_lock(nb.cache().lock());
        sz = nb.cache().get_map_ul().size();
        nb.cache().clear_ul();
    }
    cli_print(cli, "cleared %ld entries", sz);
    return CLI_OK;
}


bool register_diags(cli_def* cli, cli_command* diag) {
    auto diag_ssl = cli_register_command(cli, diag, "tls", nullptr, PRIVILEGE_UNPRIVILEGED, MODE_EXEC, "ssl related troubleshooting commands");
    auto diag_ssl_cache = cli_register_command(cli, diag_ssl, "cache", nullptr, PRIVILEGE_UNPRIVILEGED, MODE_EXEC, "diagnose ssl certificate cache");
    cli_register_command(cli, diag_ssl_cache, "stats", cli_diag_ssl_cache_stats, PRIVILEGE_UNPRIVILEGED, MODE_EXEC, "display ssl cert cache statistics");
    cli_register_command(cli, diag_ssl_cache, "list", cli_diag_ssl_cache_list, PRIVILEGE_PRIVILEGED, MODE_EXEC, "list all ssl cert cache entries");
    cli_register_command(cli, diag_ssl_cache, "print", cli_diag_ssl_cache_print, PRIVILEGE_PRIVILEGED, MODE_EXEC, "print all ssl cert cache entries");
    cli_register_command(cli, diag_ssl_cache, "clear", cli_diag_ssl_cache_clear, PRIVILEGE_PRIVILEGED, MODE_EXEC, "remove all ssl cert cache entries and reload custom certificates");

    auto diag_ssl_wl = cli_register_command(cli, diag_ssl, "whitelist", nullptr, PRIVILEGE_UNPRIVILEGED, MODE_EXEC, "diagnose ssl temporary verification whitelist");
    cli_register_command(cli, diag_ssl_wl, "list", cli_diag_ssl_wl_list, PRIVILEGE_PRIVILEGED, MODE_EXEC, "list all verification whitelist entries");
    cli_register_command(cli, diag_ssl_wl, "insert_fingerprint", cli_diag_ssl_wl_insert_fingerprint, PRIVILEGE_PRIVILEGED, MODE_EXEC, "insert end certificate fingerprint to whitelist (lowcase)");
    cli_register_command(cli, diag_ssl_wl, "insert_l4", cli_diag_ssl_wl_insert_l4, PRIVILEGE_PRIVILEGED, MODE_EXEC, "insert L4 key to whitelist (sip:dip:dport)");
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
    cli_register_command(cli, diag_ssl_ticket, "clear", cli_diag_ssl_ticket_clear, PRIVILEGE_PRIVILEGED, MODE_EXEC, "clear abbreviated handshake session/ticket cache");

    auto diag_ssl_ca     = cli_register_command(cli, diag_ssl, "ca", nullptr, PRIVILEGE_UNPRIVILEGED, MODE_EXEC, "diagnose SSL signing CA");
    cli_register_command(cli, diag_ssl_ca, "reload", cli_diag_ssl_ca_reload, PRIVILEGE_PRIVILEGED, MODE_EXEC, "reload signing CA key and certificate");

    auto diag_sig = cli_register_command(cli, diag, "sig", nullptr, PRIVILEGE_UNPRIVILEGED, MODE_EXEC, "signature engine diagnostics");
    cli_register_command(cli, diag_sig, "list", cli_diag_sig_list, PRIVILEGE_PRIVILEGED, MODE_EXEC, "list engine signatures");

    auto diag_workers = cli_register_command(cli, diag, "workers", nullptr, PRIVILEGE_UNPRIVILEGED, MODE_EXEC, "worker and threads diagnostics");
        auto diag_workers_proxy = cli_register_command(cli, diag_workers, "proxy", nullptr, PRIVILEGE_UNPRIVILEGED, MODE_EXEC, "proxy worker and threads diagnostics");
            cli_register_command(cli, diag_workers_proxy, "list", cli_diag_worker_proxy_list, PRIVILEGE_PRIVILEGED, MODE_EXEC,  "list worker threads");
        auto diag_workers_pool = cli_register_command(cli, diag_workers, "pool", nullptr, PRIVILEGE_UNPRIVILEGED, MODE_EXEC, "misc task worker and threads diagnostics");
            cli_register_command(cli, diag_workers_pool, "list", cli_diag_worker_pool_list, PRIVILEGE_PRIVILEGED, MODE_EXEC,  "list misc pool worker threads");



#ifndef USE_OPENSSL11
        auto diag_ssl_memcheck = cli_register_command(cli, diag_ssl, "memcheck", nullptr, PRIVILEGE_UNPRIVILEGED, MODE_EXEC, "diagnose openssl memcheck");
            cli_register_command(cli, diag_ssl_memcheck, "list", cli_diag_ssl_memcheck_list, PRIVILEGE_PRIVILEGED, MODE_EXEC, "print out OpenSSL memcheck status");
            cli_register_command(cli, diag_ssl_memcheck, "enable", cli_diag_ssl_memcheck_enable, PRIVILEGE_PRIVILEGED, MODE_EXEC, "enable OpenSSL debug collection");
            cli_register_command(cli, diag_ssl_memcheck, "disable", cli_diag_ssl_memcheck_disable, PRIVILEGE_PRIVILEGED, MODE_EXEC, "disable OpenSSL debug collection");
#endif

    auto diag_mem = cli_register_command(cli, diag, "mem", nullptr, PRIVILEGE_UNPRIVILEGED, MODE_EXEC, "memory related troubleshooting commands");
        auto diag_mem_buffers = cli_register_command(cli, diag_mem, "buffers", nullptr, PRIVILEGE_UNPRIVILEGED, MODE_EXEC, "memory buffers troubleshooting commands");
            cli_register_command(cli, diag_mem_buffers, "stats", cli_diag_mem_buffers_stats, PRIVILEGE_UNPRIVILEGED, MODE_EXEC, "memory buffers statistics");
        auto diag_mem_udp = cli_register_command(cli, diag_mem, "udp", nullptr, PRIVILEGE_UNPRIVILEGED, MODE_EXEC, "udp related structures troubleshooting commands");
            cli_register_command(cli, diag_mem_udp, "stats", cli_diag_mem_udp_stats, PRIVILEGE_UNPRIVILEGED, MODE_EXEC, "udp structures statistics");

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
    cli_register_command(cli, diag_proxy_session,"list-nonames", cli_diag_proxy_list_nonames, PRIVILEGE_PRIVILEGED, MODE_EXEC,"list sessions without resolved destination names");
    cli_register_command(cli, diag_proxy_session,"clear", cli_diag_proxy_session_clear, PRIVILEGE_PRIVILEGED, MODE_EXEC,"proxy session clear");

    cli_register_command(cli, diag_proxy_session,"tls-info", cli_diag_proxy_tls_list, PRIVILEGE_PRIVILEGED, MODE_EXEC,"connection TLS details");
    cli_register_command(cli, diag_proxy_session,"active", cli_diag_proxy_list_active, PRIVILEGE_PRIVILEGED, MODE_EXEC,"list only sessions active last 5s");


    auto diag_proxy_io = cli_register_command(cli,diag_proxy,"io",nullptr,PRIVILEGE_PRIVILEGED, MODE_EXEC,"proxy I/O related commands");
    cli_register_command(cli, diag_proxy_io ,"list",cli_diag_proxy_session_io_list, PRIVILEGE_PRIVILEGED, MODE_EXEC,"active proxy sessions");

    auto diag_identity = cli_register_command(cli,diag,"identity",nullptr,PRIVILEGE_PRIVILEGED, MODE_EXEC,"identity related commands");
    auto diag_identity_user = cli_register_command(cli, diag_identity,"user",nullptr, PRIVILEGE_PRIVILEGED, MODE_EXEC,"identity commands related to users");
    cli_register_command(cli, diag_identity_user,"list",cli_diag_identity_ip_list, PRIVILEGE_PRIVILEGED, MODE_EXEC,"list all known users");
    cli_register_command(cli, diag_identity_user,"clear",cli_diag_identity_ip_clear, PRIVILEGE_PRIVILEGED, MODE_EXEC,"CLEAR all known users");


    auto diag_writer = cli_register_command(cli,diag,"writer",nullptr,PRIVILEGE_PRIVILEGED, MODE_EXEC,"file writer diags");
    cli_register_command(cli,diag_writer,"stats",cli_diag_writer_stats,PRIVILEGE_PRIVILEGED, MODE_EXEC,"file writer statistics");

    auto diag_api = cli_register_command(cli,diag,"api",nullptr,PRIVILEGE_PRIVILEGED, MODE_EXEC,"http api info");
        cli_register_command(cli,diag_api,"list-keys",cli_diag_api_list,PRIVILEGE_PRIVILEGED, MODE_EXEC,"list API active keys");

    auto diag_neighbor = cli_register_command(cli,diag,"neighbor",nullptr,PRIVILEGE_PRIVILEGED, MODE_EXEC,"proxy neighbors diag");
            cli_register_command(cli,diag_neighbor,"list",cli_diag_neighbor_list,PRIVILEGE_PRIVILEGED, MODE_EXEC,"list active neighbors");
            cli_register_command(cli,diag_neighbor,"clear",cli_diag_neighbor_clear,PRIVILEGE_PRIVILEGED, MODE_EXEC,"clear neighbors database");

    return true;
}

