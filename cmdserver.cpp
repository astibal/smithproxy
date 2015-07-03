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
#include <ctime>
#include <csignal>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <fcntl.h>
#include <time.h>
#include <unistd.h>

#include <logger.hpp>
#include <cmdserver.hpp>
#include <cfgapi.hpp>

#include <socle.hpp>
#include <sslcom.hpp>
#include <sslcertstore.hpp>

#include <smithproxy.hpp>
#include <dns.hpp>
#include <inspectors.hpp>

int cli_port = 50000;
std::string cli_enable_password = "";


static const char* debug_levels="\n\t0\tNONE\n\t1\tFATAL\n\t2\tCRITICAL\n\t3\tERROR\n\t4\tWARNING\n\t5\tNOTIFY\n\t6\tINFORMATIONAL\n\t7\tDIAGNOSE\t(may impact performance)\n\t8\tDEBUG\t(impacts performance)\n\t9\tEXTREME\t(severe performance drop)\n\t10\tDUMPALL\t(performance killer)\n\treset\treset back to level configured in config file";

int orig_ssl_loglevel = 0;
int orig_sslmitm_loglevel = 0;
int orig_sslca_loglevel = 0;


void load_defaults() {
    orig_ssl_loglevel = SSLCom::log_level_ref();
    orig_sslmitm_loglevel = SSLMitmCom::log_level_ref();
    orig_sslca_loglevel= SSLCertStore::log_level_ref();
}

void cmd_show_version(struct cli_def* cli) {
    
    cli_print(cli,":connected using socket %d",cli->client->_fileno);
    cli_print(cli,"Smithproxy: %s%s",SMITH_VERSION,SMITH_DEVEL ? " -- !! development version !!" : "");
    cli_print(cli, "Socle     : %s%s",SOCLE_VERSION,SOCLE_DEVEL ? " -- !! development version !!" : "");
}

int cli_show_version(struct cli_def *cli, const char *command, char *argv[], int argc)
{
    //cli_print(cli, "called %s with %s, argc %d\r\n", __FUNCTION__, command, argc);

    
    cmd_show_version(cli);
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
    store->lock();
    
    cli_print(cli,"certificate store entries: ");

    for (auto x = store->cache().begin(); x != store->cache().end(); ++x ) {
        std::string fqdn = x->first;
        X509_PAIR* ptr = x->second;
        cli_print(cli,"    %s",fqdn.c_str());
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

int cli_diag_dns_cache_list(struct cli_def *cli, const char *command, char *argv[], int argc) {
    inspect_dns_cache.lock();
    
    cli_print(cli,"\nDNS cache populated from traffic: ");
    for(auto it = inspect_dns_cache.cache().begin(); it != inspect_dns_cache.cache().end() ; ++it ) {
        std::string s = it->first;
        DNS_Response* r = it->second;
        
        cli_print(cli,"    %s  ->%s",s.c_str(),r->answer_str().c_str());
    }
    
    inspect_dns_cache.unlock();
}

void cli_print_log_levels(struct cli_def *cli) {
    logger_profile* lp = lout.target_profiles()[(uint64_t)cli->client->_fileno];
    
    cli_print(cli,"This cli debug level is set to: %d",lp->level_);
    cli_print(cli,"General logging level set to: %d",lout.level());
    for(auto i = lout.remote_targets().begin(); i != lout.remote_targets().end(); ++i) {
        cli_print(cli, "Logging level for: %s: %d",lout.target_name((uint64_t)(*i)),lout.target_profiles()[(uint64_t)(*i)]->level_);
    }
    for(auto i = lout.targets().begin(); i != lout.targets().end(); ++i) {
        cli_print(cli, "Logging level for: %s: %d",lout.target_name((uint64_t)(*i)),lout.target_profiles()[(uint64_t)(*i)]->level_);
    }         
}

int cli_debug_terminal(struct cli_def *cli, const char *command, char *argv[], int argc) {
    
    logger_profile* lp = lout.target_profiles()[(uint64_t)cli->client->_fileno];
    if(argc > 0) {
        
        std::string a1 = argv[0];

        if(a1 == "?") {
            cli_print(cli,"valid parameters: %s",debug_levels);
        } 
        else if(a1 == "reset") {
            lp->level_ = NON;
            //lout.level(cfgapi_table.logging.level);
        }
        else {
            //cli_print(cli, "called %s with %s, argc %d\r\n", __FUNCTION__, command, argc);
            lp->level_ = std::atoi(argv[0]);
            //lout.level(lp->level_);
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
        else if(a1 == "reset") {
            lout.level(cfgapi_table.logging.level);
        }
        else {
            lout.level(std::atoi(argv[0]));
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
            SSLCom::log_level_ref() = lev;
            SSLMitmCom::log_level_ref() = lev;
            SSLCertStore::log_level_ref() = lev;
            
        }
    } else {
        int l = SSLCom::log_level_ref();
        cli_print(cli,"SSL debug level: %d",l);
        l = SSLMitmCom::log_level_ref();
        cli_print(cli,"SSL MitM debug level: %d",l);
        l = SSLCertStore::log_level_ref();
        cli_print(cli,"SSL CA debug level: %d",l);
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

struct cli_ext : public cli_def {
    int socket;
};


void client_thread(int client_socket) {
        struct cli_command *show;
        struct cli_command *debuk;
        struct cli_command *diag;
            struct cli_command *diag_ssl;
                struct cli_command *diag_ssl_cache;
            struct cli_command *diag_mem;
                struct cli_command *diag_mem_buffers;
            struct cli_command *diag_dns;
                struct cli_command *diag_dns_cache;
        
        struct cli_def *cli;
        
        char hostname[64]; memset(hostname,0,64);
        gethostname(hostname,63);
        

        // Must be called first to setup data structures
        cli = cli_init();

        // Set the hostname (shown in the the prompt)
        cli_set_hostname(cli, string_format("smithproxy(%s) ",hostname).c_str());

        // Set the greeting
        cli_set_banner(cli, "--== Smithproxy command line utility ==--");

        cli_allow_enable(cli, cli_enable_password.c_str());

        // Set up 2 commands "show counters" and "show junk"
        show  = cli_register_command(cli, NULL, "show", NULL, PRIVILEGE_UNPRIVILEGED, MODE_EXEC, "show basic information");
                cli_register_command(cli, show, "version", cli_show_version, PRIVILEGE_UNPRIVILEGED, MODE_EXEC, "show smithproxy version");
        diag  = cli_register_command(cli, NULL, "diag", NULL, PRIVILEGE_UNPRIVILEGED, MODE_EXEC, "diagnose commands helping to troubleshoot");
            diag_ssl = cli_register_command(cli, diag, "ssl", NULL, PRIVILEGE_UNPRIVILEGED, MODE_EXEC, "ssl related troubleshooting commands");
                diag_ssl_cache = cli_register_command(cli, diag_ssl, "cache", NULL, PRIVILEGE_UNPRIVILEGED, MODE_EXEC, "diagnose ssl certificate cache");
                        cli_register_command(cli, diag_ssl_cache, "stats", cli_diag_ssl_cache_stats, PRIVILEGE_UNPRIVILEGED, MODE_EXEC, "display ssl cert cache statistics");
                        cli_register_command(cli, diag_ssl_cache, "list", cli_diag_ssl_cache_list, PRIVILEGE_PRIVILEGED, MODE_EXEC, "list all ssl cert cache entries");
            diag_mem = cli_register_command(cli, diag, "mem", NULL, PRIVILEGE_UNPRIVILEGED, MODE_EXEC, "memory related troubleshooting commands");
                diag_mem_buffers = cli_register_command(cli, diag_mem, "buffers", NULL, PRIVILEGE_UNPRIVILEGED, MODE_EXEC, "memory buffers troubleshooting commands");
                        cli_register_command(cli, diag_mem_buffers, "stats", cli_diag_mem_buffers_stats, PRIVILEGE_UNPRIVILEGED, MODE_EXEC, "memory buffers statistics");
            diag_dns = cli_register_command(cli, diag, "dns", NULL, PRIVILEGE_UNPRIVILEGED, MODE_EXEC, "DNS traffic related troubleshooting commands");
                diag_dns_cache = cli_register_command(cli, diag_dns, "cache", NULL, PRIVILEGE_UNPRIVILEGED, MODE_EXEC, "DNS traffic cache troubleshooting commands");
                        cli_register_command(cli, diag_dns_cache, "list", cli_diag_dns_cache_list, PRIVILEGE_PRIVILEGED, MODE_EXEC, "list all DNS traffic cache entries");
            
        debuk = cli_register_command(cli, NULL, "debug", NULL, PRIVILEGE_PRIVILEGED, MODE_EXEC, "diagnostic commands");
            cli_register_command(cli, debuk, "term", cli_debug_terminal, PRIVILEGE_PRIVILEGED, MODE_EXEC, "set level of logging to this terminal");
            cli_register_command(cli, debuk, "file", cli_debug_logfile, PRIVILEGE_PRIVILEGED, MODE_EXEC, "set level of logging of standard log file");
            cli_register_command(cli, debuk, "ssl", cli_debug_ssl, PRIVILEGE_PRIVILEGED, MODE_EXEC, "set ssl file logging level");
        
        // Pass the connection off to libcli
        lout.remote_targets(string_format("cli-%d",client_socket),client_socket);

        logger_profile lp;
        lp.level_ = cfgapi_table.logging.cli_init_level;
        lout.target_profiles()[(uint64_t)client_socket] = &lp;
        
        
        load_defaults();
        cli_loop(cli, client_socket);
        
        lout.remote_targets().remove(client_socket);
        lout.target_profiles().erase(client_socket);
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