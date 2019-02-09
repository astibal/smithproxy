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
    
*/    

#include <string>
#include <thread>
#include <set>

#include <cstring>
#include <cstdlib>
#include <ctime>
#include <csignal>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <linux/sockios.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <fcntl.h>
#include <time.h>
#include <unistd.h>

#include <openssl/rand.h>

#include <logger.hpp>
#include <cmdserver.hpp>
#include <cfgapi.hpp>
#include <timeops.hpp>

#include <socle.hpp>
#include <sslcom.hpp>
#include <sslcertstore.hpp>

#include <smithproxy.hpp>
#include <mitmproxy.hpp>
#include <sobject.hpp>
#include <dns.hpp>
#include <inspectors.hpp>

int cli_port = 50000;
std::string cli_enable_password = "";


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

extern bool cfg_openssl_mem_dbg;

void load_defaults() {
    orig_ssl_loglevel = SSLCom::log_level_ref();
    orig_sslmitm_loglevel = SSLMitmCom::log_level_ref();
    orig_sslca_loglevel= SSLCertStore::log_level_ref();
    
    orig_dns_insp_loglevel = DNS_Inspector::log_level_ref();
    orig_dns_packet_loglevel = DNS_Packet::log_level_ref();
    
    orig_baseproxy_loglevel = baseProxy::log_level_ref();
    orig_epoll_loglevel = epoll::log_level;
    orig_mitmproxy_loglevel = MitmProxy::log_level_ref();
    orig_mitmmasterproxy_loglevel = MitmMasterProxy::log_level_ref();
}




void cmd_show_status(struct cli_def* cli) {
    
    //cli_print(cli,":connected using socket %d",fileno(cli->client));
  
    cli_print(cli,"Version: %s%s",SMITH_VERSION,SMITH_DEVEL ? " (dev)" : "");
    cli_print(cli,"Socle: %s%s",SOCLE_VERSION,SOCLE_DEVEL ? " (dev)" : "");
    cli_print(cli," ");
    time_t uptime = time(nullptr) - system_started;
    cli_print(cli,"Uptime: %s",uptime_string(uptime).c_str());
    cli_print(cli,"Objects: %ld",socle::sobject_db.cache().size());
    unsigned long l = MitmProxy::total_mtr_up.get();
    unsigned long r = MitmProxy::total_mtr_down.get();
    cli_print(cli,"Proxy performance: upload %sbps, download %sbps in last second",number_suffixed(l*8).c_str(),number_suffixed(r*8).c_str());    
 
}

int cli_show_status(struct cli_def *cli, const char *command, char *argv[], int argc)
{
    //cli_print(cli, "called %s with %s, argc %d\r\n", __FUNCTION__, command, argc);

    
    cmd_show_status(cli);
    return CLI_OK;
}


int cli_test_dns_genrequest(struct cli_def *cli, const char *command, char *argv[], int argc) {
    buffer b(0);
    
    if(argc > 0) {
        std::string argv0(argv[0]);
        if( argv0 == "?" || argv0 == "\t") {
            cli_print(cli,"specify hostname.");
            return CLI_OK;
        }

        unsigned char rand_pool[2];
        RAND_pseudo_bytes(rand_pool,2);
        unsigned short id = *(unsigned short*)rand_pool;        
        
        int s = generate_dns_request(id,b,argv[0],A);
        cli_print(cli,"DNS generated request: \n%s",hex_dump(b).c_str());
    } else {
        cli_print(cli,"you need to specify hostname");
    }
    
    return CLI_OK;
}


DNS_Response* send_dns_request(struct cli_def *cli, std::string hostname, DNS_Record_Type t, std::string nameserver) {
    
    buffer b(0);
    int parsed = -1;
    DNS_Response* ret = nullptr;
    
    unsigned char rand_pool[2];
    RAND_pseudo_bytes(rand_pool,2);
    unsigned short id = *(unsigned short*)rand_pool;
    
    int s = generate_dns_request(id,b,hostname,t);
    cli_print(cli,"DNS generated request: \n%s",hex_dump(b).c_str());
    
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
        if(cfgapi_obj_nameservers.size()) {
            nameserver = cfgapi_obj_nameservers.at(0);
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
    cfgapi_write_lock.lock();
    for (auto a: cfgapi_obj_address) {
        FqdnAddress* fa = dynamic_cast<FqdnAddress*>(a.second);
        if(fa) {
            fqdns.push_back(fa->fqdn());
        }
    }
    cfgapi_write_lock.unlock();
    

    std::string nameserver = "8.8.8.8";
    if(cfgapi_obj_nameservers.size()) {
        nameserver = cfgapi_obj_nameservers.at(0);
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
    
    SSLCertStore* store = SSLCom::certstore();

    store->lock();
    int n_cache = store->cache().size();
    int n_fqdn_cache = store->fqdn_cache().size();
    store->unlock();

    cli_print(cli,"certificate store stats: ");
    cli_print(cli,"    CN cert cache size: %d ",n_cache);
    cli_print(cli,"    FQDN to CN cache size: %d ",n_fqdn_cache);
    
    return CLI_OK;
}


int cli_diag_ssl_cache_list(struct cli_def *cli, const char *command, char *argv[], int argc) {
    
    SSLCertStore* store = SSLCom::certstore();
    bool print_refs = false;
    
    if(argc > 0) {
        std::string a1 = argv[0];
        if(a1 == "7") print_refs = true;
    }
    
    
    store->lock();
    
    cli_print(cli,"certificate store entries: ");
    
    for (auto x = store->cache().begin(); x != store->cache().end(); ++x ) {
        std::string fqdn = x->first;
        X509_PAIR* ptr = x->second;
        
        cli_print(cli,"    %s",fqdn.c_str());
        if(print_refs)
            cli_print(cli,"            refcounts: key=%d cert=%d",ptr->first->references, ptr->second->references);

    }
        
    cli_print(cli,"\ncertificate fqdn cache: ");
    for (auto x = store->fqdn_cache().begin(); x != store->fqdn_cache().end(); ++x ) {
        std::string fqdn = x->first;
        std::string cn = x->second;
        cli_print(cli,"    %s -> %s",fqdn.c_str(), cn.c_str());
    }

    store->unlock();
    
    return CLI_OK;
}

int cli_diag_ssl_cache_clear(struct cli_def *cli, const char *command, char *argv[], int argc) {
    
    SSLCertStore* store = SSLCom::certstore();
    store->lock();
    
    for (auto x = store->cache().begin(); x != store->cache().end(); ++x ) {
        std::string fqdn = x->first;
        cli_print(cli,"removing    %s",fqdn.c_str());
        X509_PAIR* ptr = x->second;
        
        if(argc > 0) {
            std::string a1 = argv[0];
            if(a1 == "7") cli_print(cli,"            refcounts: key=%d cert=%d",ptr->first->references, ptr->second->references);
        }
        
        EVP_PKEY_free(ptr->first);
        X509_free(ptr->second);
    }
    store->cache().clear();
        
    for (auto x = store->fqdn_cache().begin(); x != store->fqdn_cache().end(); ++x ) {
        std::string fqdn = x->first;
        std::string cn = x->second;
    }
    store->fqdn_cache().clear();

    store->unlock();
    
    return CLI_OK;
}

int cli_diag_ssl_wl_list(struct cli_def *cli, const char *command, char *argv[], int argc) {
    
    cli_print(cli,"\nSSL whitelist:");
    std::string out;
    
    MitmProxy::whitelist_verify.lock();
    for(auto we: MitmProxy::whitelist_verify.cache()) {
        out += "\n\t" + we.first;
    }
    MitmProxy::whitelist_verify.unlock();
    
    cli_print(cli,"%s",out.c_str());
    return CLI_OK;
}

int cli_diag_ssl_wl_clear(struct cli_def *cli, const char *command, char *argv[], int argc) {
    
    
    MitmProxy::whitelist_verify.lock();
    MitmProxy::whitelist_verify.clear();
    MitmProxy::whitelist_verify.unlock();
    return CLI_OK;
}


int cli_diag_ssl_wl_stats(struct cli_def *cli, const char *command, char *argv[], int argc) {
    
    MitmProxy::whitelist_verify.lock();
    int n_sz_cache = MitmProxy::whitelist_verify.cache().size();
    int n_max_cache = MitmProxy::whitelist_verify.max_size();
    bool n_autorem = MitmProxy::whitelist_verify.auto_delete();
    std::string n_name = MitmProxy::whitelist_verify.name();
    
    MitmProxy::whitelist_verify.unlock();

    cli_print(cli,"'%s' cache stats: ",n_name.c_str());
    cli_print(cli,"    current size: %d ",n_sz_cache);
    cli_print(cli,"    maximum size: %d ",n_max_cache);
    cli_print(cli,"      autodelete: %d ",n_autorem);
    
    return CLI_OK;
}

int cli_diag_ssl_crl_list(struct cli_def *cli, const char *command, char *argv[], int argc) {
    
    SSLCertStore* store = SSLCom::certstore();
    std::string out;
    
    out += "Downloaded CRLs:\n\n";
    
    store->crl_cache.lock();
    for (auto x: store->crl_cache.cache()) {
        std::string uri = x.first;
        auto cached_result = x.second;
       
        out += "    " + uri;
        if (cached_result) {
            int ttl = cached_result->expired_at - ::time(nullptr);
            out += string_format(", ttl=%d",ttl);

            if (ttl <= 0) {
                out += "  *expired*";
            }
        }
        else {
            out += string_format(", ttl=?");
        }

        out  + "\n";
    }
    int ttl = 0;


    store->crl_cache.unlock();
    
    cli_print(cli,"\n%s",out.c_str());
    
    return CLI_OK;
}

int cli_diag_ssl_crl_stats(struct cli_def *cli, const char *command, char *argv[], int argc) {
    
    ptr_cache<std::string, expiring_crl>& cache = SSLCertStore::crl_cache;
    
    cache.lock();
    int n_sz_cache = cache.cache().size();
    int n_max_cache = cache.max_size();
    bool n_autorem = cache.auto_delete();
    std::string n_name = cache.name();
    
    cache.unlock();

    cli_print(cli,"'%s' cache stats: ",n_name.c_str());
    cli_print(cli,"    current size: %d ",n_sz_cache);
    cli_print(cli,"    maximum size: %d ",n_max_cache);
    cli_print(cli,"      autodelete: %d ",n_autorem);
    
    return CLI_OK;
}



int cli_diag_ssl_verify_list(struct cli_def *cli, const char *command, char *argv[], int argc) {
    
    SSLCertStore* store = SSLCom::certstore();
    std::string out;
    
    out += "Verify status list:\n\n";
    
    store->ocsp_result_cache.lock();
    for (auto x: store->ocsp_result_cache.cache()) {
       std::string cn = x.first;
       expiring_ocsp_result* cached_result = x.second;
       int ttl = 0;
       if (cached_result) {
           ttl = cached_result->expired_at - ::time(nullptr);
           out += string_format("    %s, ttl=%d",cn.c_str(),ttl);
           
           if (ttl <= 0) {
               out += "  *expired*";
           }
           out += "\n";
       }
       else {
           out += string_format("    %s, ttl=?\n",cn.c_str());
       }
       
    }
    store->ocsp_result_cache.unlock();
    
    cli_print(cli,"\n%s",out.c_str());
    
    return CLI_OK;
}

int cli_diag_ssl_verify_stats(struct cli_def *cli, const char *command, char *argv[], int argc) {
    
    ptr_cache<std::string, expiring_ocsp_result>& cache = SSLCom::certstore()->ocsp_result_cache;
    
    cache.lock();
    int n_sz_cache = cache.cache().size();
    int n_max_cache = cache.max_size();
    bool n_autorem = cache.auto_delete();
    std::string n_name = cache.name();
    
    cache.unlock();

    cli_print(cli,"'%s' cache stats: ",n_name.c_str());
    cli_print(cli,"    current size: %d ",n_sz_cache);
    cli_print(cli,"    maximum size: %d ",n_max_cache);
    cli_print(cli,"      autodelete: %d ",n_autorem);
    
    return CLI_OK;
}


int cli_diag_ssl_ticket_list(struct cli_def *cli, const char *command, char *argv[], int argc) {
    
    SSLCertStore* store = SSLCom::certstore();
    std::string out;
    
    out += "SSL ticket/sessionid list:\n\n";
    
    store->session_cache.lock();
    for (auto x: store->session_cache.cache()) {
        std::string key = x.first;
        session_holder* session_keys = x.second;

        bool showall = false;

        if(argc > 0) {
            int lev = safe_val(argv[0]);
            if(lev >= 7) {
                showall = true;
            }
        }
        bool ticket = false;
        
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
        
        
       
    }
    store->session_cache.unlock();
    
    cli_print(cli,"\n%s",out.c_str());
    
    return CLI_OK;
}

int cli_diag_ssl_ticket_stats(struct cli_def *cli, const char *command, char *argv[], int argc) {
    
    ptr_cache<std::string, session_holder>& cache = SSLCom::certstore()->session_cache;
    
    cache.lock();
    int n_sz_cache = cache.cache().size();
    int n_max_cache = cache.max_size();
    bool n_autorem = cache.auto_delete();
    std::string n_name = cache.name();
    
    cache.unlock();

    cli_print(cli,"'%s' cache stats: ",n_name.c_str());
    cli_print(cli,"    current size: %d ",n_sz_cache);
    cli_print(cli,"    maximum size: %d ",n_max_cache);
    cli_print(cli,"      autodelete: %d ",n_autorem);
    
    return CLI_OK;
}

int cli_diag_ssl_ticket_size(struct cli_def *cli, const char *command, char *argv[], int argc) {
    
    ptr_cache<std::string, session_holder>& cache = SSLCom::certstore()->session_cache;
    
    cache.lock();
    int n_sz_cache = cache.cache().size();
    int n_max_cache = cache.max_size();
    bool n_autorem = cache.auto_delete();
    std::string n_name = cache.name();
    
    cache.unlock();

    cli_print(cli,"'%s' cache stats: ",n_name.c_str());
    cli_print(cli,"    current size: %d ",n_sz_cache);
    cli_print(cli,"    maximum size: %d ",n_max_cache);
    cli_print(cli,"      autodelete: %d ",n_autorem);
    
    return CLI_OK;
}

#include <biostring.hpp>

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


int cli_diag_dns_cache_list(struct cli_def *cli, const char *command, char *argv[], int argc) {
    inspect_dns_cache.lock();
    
    cli_print(cli,"\nDNS cache populated from traffic: ");
    std::string out; 
    
    for(auto it = inspect_dns_cache.cache().begin(); it != inspect_dns_cache.cache().end() ; ++it ) {
        std::string s = it->first;
        DNS_Response* r = it->second;

        if (r != nullptr && r->answers().size() > 0) {
            int ttl = (r->loaded_at + r->answers().at(0).ttl_) - time(nullptr);
            std::string t = string_format("    %s  -> [ttl:%d]%s",s.c_str(),ttl,r->answer_str().c_str());
            out += t + "\n";
        }
    }
    inspect_dns_cache.unlock();
    
    cli_print(cli, "%s", out.c_str());
    
    return CLI_OK;
}

int cli_diag_dns_cache_stats(struct cli_def *cli, const char *command, char *argv[], int argc) {

    cli_print(cli,"\nDNS cache statistics: ");
    inspect_dns_cache.lock();
    int cache_size = inspect_dns_cache.cache().size();
    int max_size = inspect_dns_cache.max_size();
    bool del = inspect_dns_cache.auto_delete();
    inspect_dns_cache.unlock();

    cli_print(cli,"  Current size: %5d",cache_size);
    cli_print(cli,"  Maximum size: %5d",max_size);
    cli_print(cli,"\n    Autodelete: %5d",del);

    return CLI_OK;
}

int cli_diag_dns_cache_clear(struct cli_def *cli, const char *command, char *argv[], int argc) {
    inspect_dns_cache.lock();
    
    inspect_dns_cache.clear();
    
    cli_print(cli,"\nDNS cache cleared.");
    inspect_dns_cache.unlock();
    
    return CLI_OK;
}

int cli_diag_dns_domain_cache_list(struct cli_def *cli, const char *command, char *argv[], int argc) {
    cli_print(cli, "\n Domain cache list:");
    std::string out;
    domain_cache.lock();
    
    for(auto sub_domain_cache: domain_cache.cache()) {
        
        std::string domain = sub_domain_cache.first;
        std::string str;
        
        for(auto sub_e: sub_domain_cache.second->cache()) {
           str += " " + sub_e.first;
        }
        out += string_format("\n\t%s: \t%s",domain.c_str(),str.c_str());
        
    }
    
    domain_cache.unlock();
    cli_print(cli,"%s",out.c_str());
    
    return CLI_OK;
}

int cli_diag_dns_domain_cache_clear(struct cli_def *cli, const char *command, char *argv[], int argc) {
    cli_print(cli, "\n Clearing domain cache:");
    std::string out;
    domain_cache.lock();
    
    domain_cache.clear();
    
    domain_cache.unlock();
    cli_print(cli," done.");
    
    return CLI_OK;
}



int cli_diag_identity_ip_list(struct cli_def *cli, const char *command, char *argv[], int argc) {
    
    cli_print(cli, "\nIPv4 identities:");
    std::string out;
    
    cfgapi_identity_ip_lock.lock();
    for (auto ip: auth_ip_map) {
        std::string s;
        IdentityInfo& id = ip.second;
        
        s +=   "    ipv4: " + ip.first + ", user: " + id.username + ", groups: " + id.groups + ", rx/tx: " + number_suffixed(id.tx_bytes) + "/" + number_suffixed(id.rx_bytes);
        s += "\n          uptime: " + std::to_string(id.uptime()) + ", idle: " + std::to_string(id.i_time());
        s += "\n          status: " + std::to_string(!id.i_timeout()) + ", last policy: " + std::to_string(id.last_seen_policy);
        out += s;
    }
    cfgapi_identity_ip_lock.unlock();
    cli_print(cli, "%s", out.c_str());
    

    out.clear();
    
    cli_print(cli, "\nIPv6 identities:");
    

    cfgapi_identity_ip6_lock.lock();
    for (auto ip: auth_ip6_map) {
        std::string s;
        IdentityInfo6& id = ip.second;
        
        s +=   "    ipv6: " + ip.first + ", user: " + id.username + ", groups: " + id.groups + ", rx/tx: " + number_suffixed(id.tx_bytes) + "/" + number_suffixed(id.rx_bytes);
        s += "\n          uptime: " + std::to_string(id.uptime()) + ", idle: " + std::to_string(id.i_time());        
        s += "\n          status: " + std::to_string(!id.i_timeout()) + ", last policy: " + std::to_string(id.last_seen_policy);
        out += s;
    }
    cfgapi_identity_ip6_lock.unlock();
    cli_print(cli, "%s", out.c_str());    
    
    return CLI_OK;
}


void cli_print_log_levels(struct cli_def *cli) {
    logger_profile* lp = get_logger()->target_profiles()[(uint64_t)fileno(cli->client)];
    
    cli_print(cli,"THIS cli logging level set to: %d",lp->level_.level());
    cli_print(cli,"Internal logging level set to: %d",get_logger()->level().level());
    cli_print(cli,"\n");
    for(auto i = get_logger()->remote_targets().begin(); i != get_logger()->remote_targets().end(); ++i) {
        cli_print(cli, "Logging level for remote: %s: %d",get_logger()->target_name((uint64_t)(*i)),get_logger()->target_profiles()[(uint64_t)(*i)]->level_.level());
    }
    for(auto i = get_logger()->targets().begin(); i != get_logger()->targets().end(); ++i) {
        cli_print(cli, "Logging level for target: %s: %d",get_logger()->target_name((uint64_t)(*i)),get_logger()->target_profiles()[(uint64_t)(*i)]->level_.level());
    }         
}

int cli_debug_terminal(struct cli_def *cli, const char *command, char *argv[], int argc) {
    
    logger_profile* lp = get_logger()->target_profiles()[(uint64_t)fileno(cli->client)];
    if(argc > 0) {
        
        std::string a1 = argv[0];

        int lev_diff = 0;
        
        if(a1 == "?") {
            cli_print(cli,"valid parameters: %s",debug_levels);
        } 
        else if(a1 == "reset") {
            lp->level_ = NON;
            lev_diff = get_logger()->adjust_level().level();
        }
        else {
            //cli_print(cli, "called %s with %s, argc %d\r\n", __FUNCTION__, command, argc);
            int newlev = safe_val(argv[0]);
            if(newlev >= 0) {
                lp->level_.level(newlev);
                lev_diff = get_logger()->adjust_level().level();
                
            } else {
                cli_print(cli,"Incorrect value for logging level: %d",newlev);
            }
        }
        if(lev_diff != 0) cli_print(cli, "internal logging level changed by %d",lev_diff);
        
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
                for(auto i = get_logger()->targets().begin(); i != get_logger()->targets().end(); ++i) {
                    get_logger()->target_profiles()[(uint64_t)(*i)]->level_.level(newlev);
                }
                
                int lev_diff = get_logger()->adjust_level().level();
                if(lev_diff != 0) cli_print(cli, "internal logging level changed by %d",lev_diff);
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
        if(a1 == "?") {
            cli_print(cli,"valid parameters: %s",debug_levels);
        } 
        else if(a1 == "reset") {
            SSLCom::log_level_ref() = orig_ssl_loglevel;
            SSLMitmCom::log_level_ref() = orig_sslmitm_loglevel;
            SSLCertStore::log_level_ref() = orig_sslca_loglevel;
        }
        else {
            int lev = std::atoi(argv[0]);
            SSLCom::log_level_ref().level(lev);
            SSLMitmCom::log_level_ref().level(lev);
            SSLCertStore::log_level_ref().level(lev);
            
        }
    } else {
        int l = SSLCom::log_level_ref().level();
        cli_print(cli,"SSL debug level: %d",l);
        l = SSLMitmCom::log_level_ref().level();
        cli_print(cli,"SSL MitM debug level: %d",l);
        l = SSLCertStore::log_level_ref().level();
        cli_print(cli,"SSL CA debug level: %d",l);
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
            MitmProxy::log_level_ref() = orig_mitmproxy_loglevel;
        }
        else {
            int lev = std::atoi(argv[0]);
            baseProxy::log_level_ref().level(lev);
            epoll::log_level.level(lev);
            MitmMasterProxy::log_level_ref().level(lev);
            MitmProxy::log_level_ref().level(lev);
            
            
        }
    } else {
        int l = baseProxy::log_level_ref().level();
        cli_print(cli,"baseProxy debug level: %d",l);

        l = epoll::log_level.level();
        cli_print(cli,"epoll debug level: %d",l);

        l = MitmMasterProxy::log_level_ref().level();
        cli_print(cli,"MitmMasterProxy debug level: %d",l);

        l = MitmProxy::log_level_ref().level();
        cli_print(cli,"MitmProxy debug level: %d",l);


        cli_print(cli,"\n");
        cli_print(cli,"valid parameters: %s",debug_levels);
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
    
    cli_print(cli,"Statistics:\n");
    cli_print(cli,"%s",socle::sobject_db_stats_string(nullptr).c_str());
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
    
    
    std::string r = socle::sobject_db_list((object_filter.size() == 0) ? nullptr : object_filter.c_str(),nullptr,verbosity);
                r += "\n" + socle::sobject_db_stats_string((object_filter.size() == 0) ? nullptr : object_filter.c_str());

    
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
    
    
    std::string r = socle::sobject_db_list(nullptr,nullptr,verbosity,object_filter.c_str());
    
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
            
            socle::sobject_db.lock();
            int ret = socle::sobject_db_ask_destroy((void*)key);
            socle::sobject_db.unlock();
            
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
    
    std::string a1,a2;
    int verbosity = iINF;
    if(argc > 0) { 
        a1 = argv[0];
        verbosity = safe_val(a1,iINF);
    }
    if(argc > 1) a2 = argv[1];
    
    std::stringstream ss;
    
    time_t  curtime = time(nullptr);
    
    socle::sobject_db.lock();
    for(auto it: socle::sobject_db.cache()) {
        socle::sobject*       ptr = it.first;

        if(!ptr) continue;
        
        if(ptr->class_name() == "MitmProxy") {
            socle::sobject_info*  si = it.second;
            ss << ptr->to_string(verbosity);
            
            if(verbosity >= DEB && si) {
                    ss <<  si->to_string(verbosity);
            }

            if(verbosity > INF) {
                MitmProxy* curr_proxy = dynamic_cast<MitmProxy*>(ptr);
                if(curr_proxy) {
                    MitmHostCX* lf = curr_proxy->first_left();
                    MitmHostCX* rg = curr_proxy->first_right();
                    if(lf) {
                        if(verbosity > INF) ss << "\n    ";
                        if(lf->application_data) {
                            std::string desc = lf->application_data->hr();
                            if (verbosity < DEB && desc.size() > 120) {
                             desc = desc.substr(0,117);
                             desc += "...";
                            }
                            ss << "app_data: " << desc << "\n";
                        } else {
                            ss << "app_data: none\n";
                        }
                        
                        if(verbosity > INF) {
                            ss << "    obj_debug: " << curr_proxy->get_this_log_level().to_string() << "\n";
                            int expiry = -1;
                            if(curr_proxy->half_holdtimer > 0) {
                                expiry = curr_proxy->half_holdtimer + MitmProxy::half_timeout - curtime;
                            }
                            ss << "    half_hold: " << expiry << "\n";
                        }
                    }
                    
                    
                    auto print_queue_stats = [](std::stringstream &ss, int verbosity, MitmHostCX* cx, const char* sm, const char* bg) {
                        unsigned int in_pending, out_pending;
                        buffer::size_type in_buf, out_buf;
                        
                        ::ioctl(cx->socket(), SIOCINQ, &in_pending);
                        ::ioctl(cx->socket(), SIOCOUTQ, &out_pending);
                        
                        in_buf  = cx->readbuf()->size();
                        out_buf = cx->writebuf()->size();
                        
                        ss << "     " << sm << "_os_recv-q: " <<  in_pending << " " << sm << "_os_send-q: " <<  out_pending << "\n";
                        ss << "     " << sm << "_sx_recv-q: " <<  in_buf     << " " << sm << "_sx_send-q: " <<  out_buf << "\n";
                        
                        // fun stuff
                        if(verbosity >= EXT) {
                            if(in_buf) {
                                ss << "     " << bg << " last-seen read data: \n" << hex_dump(cx->readbuf(),6) << "\n";
                            }
                        }                        
                    };
                    
                    
                    if(lf) {
                        if(verbosity > INF) {
                            if(lf->socket() > 0) {
                                print_queue_stats(ss, verbosity, lf,"lf","Left");
                            }
                        }
                            
                        if(verbosity > DIA) {
                            ss << "     lf_debug: " << lf->get_this_log_level().to_string() << "\n";
                            if(lf->com()) {
                                ss << "       lf_com: " << lf->com()->get_this_log_level().to_string() << "\n";
                            }
                        }
                    }
                    if(rg) {
                        if(verbosity > INF) {
                            if(rg->socket() > 0) {
                                print_queue_stats(ss,verbosity, rg,"rg","Right");
                            }
                        }
                        if(verbosity > DIA) {
                            ss << "     rg_debug: " << rg->get_this_log_level().to_string() << "\n";
                            if(rg->com()) {
                                ss << "       rg_com: " << rg->com()->get_this_log_level().to_string() << "\n";
                            }
                        }
                    }

                }
            }
            ss << "\n";
        }
    }
    socle::sobject_db.unlock();

    cli_print(cli,"%s",ss.str().c_str());
    
    
    unsigned long l = MitmProxy::total_mtr_up.get();
    unsigned long r = MitmProxy::total_mtr_down.get();
    cli_print(cli,"\nProxy performance: upload %sbps, download %sbps in last second",number_suffixed(l*8).c_str(),number_suffixed(r*8).c_str());
    
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
    
    std::string out;
    
    cfgapi_write_lock.lock();
    for(auto it: cfgapi_obj_policy) {
        out += it->to_string(verbosity);
        out += "\n\n";
    }
    cfgapi_write_lock.unlock();
    
    cli_print(cli, "%s", out.c_str());
    return CLI_OK;
}




struct cli_ext : public cli_def {
    int socket;
};


void client_thread(int client_socket) {
        struct cli_command *show;
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
            struct cli_command *diag_mem;
                struct cli_command *diag_mem_buffers;
                struct cli_command *diag_mem_objects;
            struct cli_command *diag_dns;
                struct cli_command *diag_dns_cache;
                struct cli_command *diag_dns_domains;
            struct cli_command *diag_proxy;
                struct cli_command *diag_proxy_policy;
                struct cli_command *diag_proxy_session;
            struct cli_command *diag_identity;
                struct cli_command *diag_identity_user;
        
        struct cli_def *cli;
        
        char hostname[64]; memset(hostname,0,64);
        gethostname(hostname,63);
        

        // Must be called first to setup data structures
        cli = cli_init();


        // Set the hostname (shown in the the prompt)
        cli_set_hostname(cli, string_format("smithproxy(%s) ",hostname).c_str());

        // Set the greeting
        cli_set_banner(cli, "--==[ Smithproxy command line utility ]==--");

        cli_allow_enable(cli, cli_enable_password.c_str());

        // Set up 2 commands "show counters" and "show junk"
        show  = cli_register_command(cli, NULL, "show", NULL, PRIVILEGE_UNPRIVILEGED, MODE_EXEC, "show basic information");
                cli_register_command(cli, show, "status", cli_show_status, PRIVILEGE_UNPRIVILEGED, MODE_EXEC, "show smithproxy status");

        test  = cli_register_command(cli, NULL, "test", NULL, PRIVILEGE_UNPRIVILEGED, MODE_EXEC, "various testing commands");
                test_dns = cli_register_command(cli, test, "dns", NULL, PRIVILEGE_UNPRIVILEGED, MODE_EXEC, "dns related testing commands");
                    cli_register_command(cli, test_dns, "genrequest", cli_test_dns_genrequest, PRIVILEGE_UNPRIVILEGED, MODE_EXEC, "generate dns request");
                    cli_register_command(cli, test_dns, "sendrequest", cli_test_dns_sendrequest, PRIVILEGE_UNPRIVILEGED, MODE_EXEC, "generate and send dns request to configured nameserver");
                    cli_register_command(cli, test_dns, "refreshallfqdns", cli_test_dns_refreshallfqdns, PRIVILEGE_UNPRIVILEGED, MODE_EXEC, "refresh all configured FQDN address objects against configured nameserver");
                
        diag  = cli_register_command(cli, NULL, "diag", NULL, PRIVILEGE_UNPRIVILEGED, MODE_EXEC, "diagnose commands helping to troubleshoot");
            diag_ssl = cli_register_command(cli, diag, "ssl", NULL, PRIVILEGE_UNPRIVILEGED, MODE_EXEC, "ssl related troubleshooting commands");
                diag_ssl_cache = cli_register_command(cli, diag_ssl, "cache", NULL, PRIVILEGE_UNPRIVILEGED, MODE_EXEC, "diagnose ssl certificate cache");
                        cli_register_command(cli, diag_ssl_cache, "stats", cli_diag_ssl_cache_stats, PRIVILEGE_UNPRIVILEGED, MODE_EXEC, "display ssl cert cache statistics");
                        cli_register_command(cli, diag_ssl_cache, "list", cli_diag_ssl_cache_list, PRIVILEGE_PRIVILEGED, MODE_EXEC, "list all ssl cert cache entries");
                        cli_register_command(cli, diag_ssl_cache, "clear", cli_diag_ssl_cache_clear, PRIVILEGE_PRIVILEGED, MODE_EXEC, "remove all ssl cert cache entries");
                diag_ssl_wl = cli_register_command(cli, diag_ssl, "whitelist", NULL, PRIVILEGE_UNPRIVILEGED, MODE_EXEC, "diagnose ssl temporary verification whitelist");                        
                        cli_register_command(cli, diag_ssl_wl, "list", cli_diag_ssl_wl_list, PRIVILEGE_PRIVILEGED, MODE_EXEC, "list all verification whitelist entries");
                        cli_register_command(cli, diag_ssl_wl, "clear", cli_diag_ssl_wl_clear, PRIVILEGE_PRIVILEGED, MODE_EXEC, "clear all verification whitelist entries");
                        cli_register_command(cli, diag_ssl_wl, "stats", cli_diag_ssl_wl_stats, PRIVILEGE_PRIVILEGED, MODE_EXEC, "verification whitelist cache stats");
                diag_ssl_crl = cli_register_command(cli, diag_ssl, "crl", NULL, PRIVILEGE_UNPRIVILEGED, MODE_EXEC, "diagnose dynamically downloaded CRLs");                           
                        cli_register_command(cli, diag_ssl_crl, "list", cli_diag_ssl_crl_list, PRIVILEGE_PRIVILEGED, MODE_EXEC, "list all CRLs");
                        cli_register_command(cli, diag_ssl_crl, "stats", cli_diag_ssl_crl_stats, PRIVILEGE_PRIVILEGED, MODE_EXEC, "CRLs cache stats");
                diag_ssl_verify = cli_register_command(cli, diag_ssl, "verify", NULL, PRIVILEGE_UNPRIVILEGED, MODE_EXEC, "diagnose certificate verification status cache");                           
                        cli_register_command(cli, diag_ssl_verify, "list", cli_diag_ssl_verify_list, PRIVILEGE_PRIVILEGED, MODE_EXEC, "list certificate verification status cache content");
                        cli_register_command(cli, diag_ssl_verify, "stats", cli_diag_ssl_verify_stats, PRIVILEGE_PRIVILEGED, MODE_EXEC, "certificate verification status cache stats");
                diag_ssl_ticket = cli_register_command(cli, diag_ssl, "ticket", NULL, PRIVILEGE_UNPRIVILEGED, MODE_EXEC, "diagnose abbreviated handshake session/ticket cache");
                        cli_register_command(cli, diag_ssl_ticket, "list", cli_diag_ssl_ticket_list, PRIVILEGE_PRIVILEGED, MODE_EXEC, "list abbreviated handshake session/ticket cache");
                        cli_register_command(cli, diag_ssl_ticket, "stats", cli_diag_ssl_ticket_stats, PRIVILEGE_PRIVILEGED, MODE_EXEC, "abbreviated handshake session/ticket cache stats");
                        

            if(cfg_openssl_mem_dbg) {
                diag_ssl_memcheck = cli_register_command(cli, diag_ssl, "memcheck", NULL, PRIVILEGE_UNPRIVILEGED, MODE_EXEC, "diagnose openssl memcheck");                           
                        cli_register_command(cli, diag_ssl_memcheck, "list", cli_diag_ssl_memcheck_list, PRIVILEGE_PRIVILEGED, MODE_EXEC, "print out OpenSSL memcheck status");
                        cli_register_command(cli, diag_ssl_memcheck, "enable", cli_diag_ssl_memcheck_enable, PRIVILEGE_PRIVILEGED, MODE_EXEC, "enable OpenSSL debug collection");
                        cli_register_command(cli, diag_ssl_memcheck, "disable", cli_diag_ssl_memcheck_disable, PRIVILEGE_PRIVILEGED, MODE_EXEC, "disable OpenSSL debug collection");
            }
                
            diag_mem = cli_register_command(cli, diag, "mem", NULL, PRIVILEGE_UNPRIVILEGED, MODE_EXEC, "memory related troubleshooting commands");
                diag_mem_buffers = cli_register_command(cli, diag_mem, "buffers", NULL, PRIVILEGE_UNPRIVILEGED, MODE_EXEC, "memory buffers troubleshooting commands");
                        cli_register_command(cli, diag_mem_buffers, "stats", cli_diag_mem_buffers_stats, PRIVILEGE_UNPRIVILEGED, MODE_EXEC, "memory buffers statistics");
                diag_mem_objects = cli_register_command(cli, diag_mem, "objects", NULL, PRIVILEGE_UNPRIVILEGED, MODE_EXEC, "memory object troubleshooting commands");                        
                        cli_register_command(cli, diag_mem_objects, "stats", cli_diag_mem_objects_stats, PRIVILEGE_UNPRIVILEGED, MODE_EXEC, "memory objects statistics");
                        cli_register_command(cli, diag_mem_objects, "list", cli_diag_mem_objects_list, PRIVILEGE_UNPRIVILEGED, MODE_EXEC, "memory objects list");
                        cli_register_command(cli, diag_mem_objects, "search", cli_diag_mem_objects_search, PRIVILEGE_UNPRIVILEGED, MODE_EXEC, "memory objects search");
                        cli_register_command(cli, diag_mem_objects, "clear", cli_diag_mem_objects_clear, PRIVILEGE_PRIVILEGED, MODE_EXEC, "clears memory object");
            diag_dns = cli_register_command(cli, diag, "dns", NULL, PRIVILEGE_UNPRIVILEGED, MODE_EXEC, "DNS traffic related troubleshooting commands");
                diag_dns_cache = cli_register_command(cli, diag_dns, "cache", NULL, PRIVILEGE_UNPRIVILEGED, MODE_EXEC, "DNS traffic cache troubleshooting commands");
                        cli_register_command(cli, diag_dns_cache, "list", cli_diag_dns_cache_list, PRIVILEGE_PRIVILEGED, MODE_EXEC, "list all DNS traffic cache entries");
                        cli_register_command(cli, diag_dns_cache, "stats", cli_diag_dns_cache_stats, PRIVILEGE_PRIVILEGED, MODE_EXEC, "DNS traffic cache statistics");
                        cli_register_command(cli, diag_dns_cache, "clear", cli_diag_dns_cache_clear, PRIVILEGE_PRIVILEGED, MODE_EXEC, "clear DNS traffic cache");
                diag_dns_domains = cli_register_command(cli, diag_dns, "domain", NULL, PRIVILEGE_UNPRIVILEGED, MODE_EXEC, "DNS domain cache troubleshooting commands");
                        cli_register_command(cli, diag_dns_domains, "list", cli_diag_dns_domain_cache_list, PRIVILEGE_PRIVILEGED, MODE_EXEC, "DNS sub-domain list");
                        cli_register_command(cli, diag_dns_domains, "clear", cli_diag_dns_domain_cache_clear, PRIVILEGE_PRIVILEGED, MODE_EXEC, "clear DNS sub-domain cache");
            diag_proxy = cli_register_command(cli, diag, "proxy",NULL, PRIVILEGE_PRIVILEGED, MODE_EXEC, "proxy related troubleshooting commands");
                diag_proxy_policy = cli_register_command(cli,diag_proxy,"policy",NULL,PRIVILEGE_PRIVILEGED, MODE_EXEC,"proxy policy commands");
                        cli_register_command(cli, diag_proxy_policy,"list",cli_diag_proxy_policy_list, PRIVILEGE_PRIVILEGED, MODE_EXEC,"proxy policy list");
                diag_proxy_session = cli_register_command(cli,diag_proxy,"session",NULL,PRIVILEGE_PRIVILEGED, MODE_EXEC,"proxy session commands");
                        cli_register_command(cli, diag_proxy_session,"list",cli_diag_proxy_session_list, PRIVILEGE_PRIVILEGED, MODE_EXEC,"proxy session list");
                        cli_register_command(cli, diag_proxy_session,"clear",cli_diag_proxy_session_clear, PRIVILEGE_PRIVILEGED, MODE_EXEC,"proxy session clear");
            diag_identity = cli_register_command(cli,diag,"identity",NULL,PRIVILEGE_PRIVILEGED, MODE_EXEC,"identity related commands");
                diag_identity_user = cli_register_command(cli, diag_identity,"user",NULL, PRIVILEGE_PRIVILEGED, MODE_EXEC,"identity commands related to users");
                        cli_register_command(cli, diag_identity_user,"list",cli_diag_identity_ip_list, PRIVILEGE_PRIVILEGED, MODE_EXEC,"list all known users");
                        
                        
        debuk = cli_register_command(cli, NULL, "debug", NULL, PRIVILEGE_PRIVILEGED, MODE_EXEC, "diagnostic commands");
            cli_register_command(cli, debuk, "term", cli_debug_terminal, PRIVILEGE_PRIVILEGED, MODE_EXEC, "set level of logging to this terminal");
            cli_register_command(cli, debuk, "file", cli_debug_logfile, PRIVILEGE_PRIVILEGED, MODE_EXEC, "set level of logging of standard log file");
            cli_register_command(cli, debuk, "ssl", cli_debug_ssl, PRIVILEGE_PRIVILEGED, MODE_EXEC, "set ssl file logging level");
            cli_register_command(cli, debuk, "dns", cli_debug_dns, PRIVILEGE_PRIVILEGED, MODE_EXEC, "set dns file logging level");
            cli_register_command(cli, debuk, "proxy", cli_debug_proxy, PRIVILEGE_PRIVILEGED, MODE_EXEC, "set proxy file logging level");
            cli_register_command(cli, debuk, "sobject", cli_debug_sobject, PRIVILEGE_PRIVILEGED, MODE_EXEC, "toggle on/off sobject creation tracing (affect performance)");
        
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
    while ((client_socket = accept(s, NULL, 0)))
    {
        std::thread* n = new std::thread(client_thread,client_socket);
    }
}