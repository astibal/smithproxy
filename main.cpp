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


//#define MEM_DEBUG 1
#ifdef MEM_DEBUG
    #include <mcheck.h>
    #define SOCLE_MEM_PROFILE
#endif


#include <vector>

#include <ctime>
#include <cstdlib>
#include <sys/stat.h>
#include <sys/types.h>

#include <ostream>
#include <ios>

#include <getopt.h>
#include <execinfo.h>

#include <openssl/crypto.h>

#include <socle.hpp>

#include <logger.hpp>
#include <hostcx.hpp>
#include <apphostcx.hpp>
#include <baseproxy.hpp>
#include <masterproxy.hpp>
#include <threadedacceptor.hpp>
#include <threadedreceiver.hpp>
#include <sslcom.hpp>
#include <sslmitmcom.hpp>
#include <udpcom.hpp>
#include <display.hpp>

#include <main.hpp>
#include <traflog.hpp>
#include <display.hpp>

#include <libconfig.h++>

#include <mitmhost.hpp>
#include <mitmproxy.hpp>
#include <socksproxy.hpp>

#include <cfgapi.hpp>
#include <daemon.hpp>
#include <cmdserver.hpp>
#include <srvutils.hpp>
#include <staticcontent.hpp>
#include <smithlog.hpp>
#include <smithdnsupd.hpp>

#include <smithproxy.hpp>







int main(int argc, char *argv[]) {

    static struct option long_options[] =
            {
                    /* These options set a flag. */
                    {"debug",   no_argument,        (int*) &CfgFactory::get().args_debug_flag.level_ref(), iDEB},
                    {"diagnose",   no_argument,     (int*) &CfgFactory::get().args_debug_flag.level_ref(), iDIA},
                    {"dump",   no_argument,         (int*) &CfgFactory::get().args_debug_flag.level_ref(), iDUM},
                    {"extreme",   no_argument,      (int*) &CfgFactory::get().args_debug_flag.level_ref(), iEXT},

                    {"config-file", required_argument, 0, 'c'},
                    {"config-check-only",no_argument,0,'o'},
                    {"daemonize", no_argument, 0, 'D'},
                    {"version", no_argument, 0, 'v'},

                    // multi-tenancy support: listening ports will be shifted by number 'i', while 't' controls logging, pidfile, etc.
                    // both, or none of them have to be set
                    {"tenant-index", required_argument, 0, 'i'},
                    {"tenant-name", required_argument, 0, 't'},
                    {0, 0, 0, 0}
            };


    DaemonFactory& this_daemon = DaemonFactory::instance();

    if(buffer::use_pool)
        CRYPTO_set_mem_functions(mempool_alloc, mempool_realloc, mempool_free);


    CfgFactory::get().config_file = "/etc/smithproxy/smithproxy.cfg";
    bool custom_config_file = false;
    
    std::string config_file_tenant = "/etc/smithproxy/smithproxy.%s.cfg";

    while(1) {
    /* getopt_long stores the option index here. */
        int option_index = 0;
    
        char c = getopt_long (argc, argv, "p:vo",
                        long_options, &option_index);
        if (c < 0) break;

        switch(c) {
            case 0:
                break;
                
            case 'c':
                CfgFactory::get().config_file = std::string(optarg);
                custom_config_file = true;
                break;      
                
            case 'o':
                CfgFactory::get().config_file_check_only = true;
                get_logger()->dup2_cout(true);
                
            case 'D':
                SmithProxy::instance().cfg_daemonize = true;
                break;
                
            case 'i':
                CfgFactory::get().tenant_index = std::stoi(std::string(optarg));
                break;
                
            case 't':
                CfgFactory::get().tenant_name = std::string(optarg);
                break;

                
            case 'v':
                std::cout << SMITH_VERSION << "+" << SOCLE_VERSION << std::endl;
                exit(0);
                
                
            default:
                ERR_("unknown option: '%c'",c);
                exit(1);                 
        }
    }

    if(CfgFactory::get().config_file_check_only) {

        // set synchronous logger for config-check
        set_logger(new logger());

    } else {
        set_logger(new QueueLogger());
    }
    
    if(! SmithProxy::instance().cfg_daemonize) {
        std::thread* log_thread  = create_log_writer(get_logger());
        if(log_thread != nullptr) {
            pthread_setname_np(log_thread->native_handle(),string_format("sxy_lwr_%d",
                    CfgFactory::get().tenant_index).c_str());
        }    
    }
    
    get_logger()->level(WAR);
    CfgFactory::get().log_version(false);  // don't delay, but display warning
    
    if( CfgFactory::get().tenant_name.size() > 0) {
        WAR_("Starting tenant: '%s', index %d",
                CfgFactory::get().tenant_name.c_str(),
                CfgFactory::get().tenant_index);

        this_daemon.set_tenant("smithproxy", CfgFactory::get().tenant_name);
        CfgFactory::get().tenant_name  = CfgFactory::get().tenant_name;
    } 
    else if (CfgFactory::get().tenant_name.size() > 0){
        
        FATS_("You have to specify both options: --tenant-name AND --tenant-index");
        exit(-20);
    }
    else {
        WARS_("Starting tenant: 0 (default)");
        this_daemon.set_tenant("smithproxy", "0");
    }
    
    
    // if logging set in cmd line, use it 
    if(CfgFactory::get().args_debug_flag > NON) {
        get_logger()->level(CfgFactory::get().args_debug_flag);
    }
        
        
    if(! custom_config_file and CfgFactory::get().tenant_index > 0) {
        // look for tenant config (no override set)
        
        std::string tenant_cfg = string_format(config_file_tenant.c_str(), CfgFactory::get().tenant_name.c_str());
        
        struct stat s;
        if (stat(tenant_cfg.c_str(),&s) == 0) {
            WAR_("Tenant config: %s",tenant_cfg.c_str());
            CfgFactory::get().config_file = tenant_cfg;
        } else {
            WAR_("Tenant config %s not found. Using default.",tenant_cfg.c_str());
        }
    }
    
    WARS_(" ");
    // set level to what's in the config
    if (! SmithProxy::instance().load_config(CfgFactory::get().config_file)) {
        if(CfgFactory::get().config_file_check_only) {
            FATS_("Config check: error loading config file.");
            exit(1);
        }
        else {
            FATS_("Error loading config file on startup.");
            exit(1);
        }
    }
    
    if(!CfgFactory::get().apply_tenant_config()) {
        FATS_("Failed to apply tenant specific configuration!");
        exit(2);
    }
    
    if(CfgFactory::get().config_file_check_only) {
        DIAS_("Exiting, asked to check config file only.");
        exit(0);
    }

    if(cfg_mtrace_enable) {
#ifdef MEM_DEBUG
        putenv("MALLOC_TRACE=/var/log/smithproxy_mtrace.log");
        mtrace();
#endif
    }

    
    // if there is loglevel specified in config file and is bigger than we currently have set, use it
    if(cfgapi_table.logging.level > get_logger()->level()) {
        get_logger()->level(cfgapi_table.logging.level);
    }
    
    if(this_daemon.exists_pidfile()) {
        FATS_("There is PID file already in the system.");
        FAT_("Please make sure smithproxy is not running, remove %s and try again.", this_daemon.PID_FILE.c_str());
        exit(-5);
    }
    
    // detect kernel version, and adapt UDP socket family
    if(!version_check(get_kernel_version(),"4.3")) {    
        WARS_("Kernel can't use IPv6 for transparenting UDP. Kernel upgrade is highly recommended.");
        WARS_("IPv6/UDP smithproxy forwarding will not work.");
        WARS_("Set SMITH_IPV6_UDP_BYPASS=1 variable in smithproxy.startup.cfg");
        UDPCom::default_sock_family = AF_INET;
    }
    
    if(SmithProxy::instance().cfg_daemonize) {
        if(get_logger()->targets().size() <= 0) {
            FATS_("Cannot daemonize without logging to file.");
            exit(-5);
        }
        
        get_logger()->dup2_cout(false);
        INFS_("entering daemon mode");
        this_daemon.daemonize();


        SmithProxy::instance().tenant_index(CfgFactory::get().tenant_index);

        // create utility threads
        SmithProxy::instance().create_logger();
        SmithProxy::instance().create_dns_thread();
        SmithProxy::instance().create_identity_thread();

        // launch listeners
        SmithProxy::instance().create_listeners();

    }
    // write out PID file
    this_daemon.write_pidfile();

    
    //     atexit(__libc_freeres);   

    if(SmithProxy::instance().cfg_openssl_mem_dbg) {
#ifndef USE_OPENSSL11
        CRYPTO_malloc_debug_init();
        CRYPTO_dbg_set_options(V_CRYPTO_MDEBUG_ALL);
#endif
        CRYPTO_mem_ctrl(CRYPTO_MEM_CHECK_ON);
        CRYPTO_mem_ctrl(CRYPTO_MEM_CHECK_DISABLE);
    }
    

    if(!html()->load_files(CfgFactory::get().dir_msg_templates)) {
        ERR_("Cannot load messages from '%s', replacements will not work correctly !!!", CfgFactory::get().dir_msg_templates.c_str());
    } else {
        std::string test = "test";
        DIA_("Message testing string: %s", html()->render_noargs(test).c_str());
    }
    
    


    SmithProxy::instance().run();

    CRI_("Smithproxy %s (socle %s) started",SMITH_VERSION,SOCLE_VERSION);

    

    DIAS_("Debug SSL statistics: ");
    DIA_("SSL_accept: %d",SSLCom::counter_ssl_accept);
    DIA_("SSL_connect: %d",SSLCom::counter_ssl_connect);

    CfgFactory::get().cfgapi_cleanup();

    SSLCom::certstore()->destroy();
    
    if(SmithProxy::instance().cfg_daemonize) {
        this_daemon.unlink_pidfile();
    }
    
    CRYPTO_cleanup_all_ex_data();
    ERR_free_strings();
#ifndef USE_OPENSSL11
    ERR_remove_state(0);
#endif
    EVP_cleanup();
    
}

