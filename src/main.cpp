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


#include <cstdlib>
#include <sys/stat.h>
#include <sys/resource.h>

#include <ostream>

#include <getopt.h>

#include <openssl/crypto.h>

#include <socle.hpp>

#include <log/logger.hpp>
#include <hostcx.hpp>
#include <sslcom.hpp>
#include <udpcom.hpp>
#include <display.hpp>

#include <main.hpp>

#include <libconfig.h++>

#include <cfgapi.hpp>
#include <service/daemon.hpp>
#include <staticcontent.hpp>
#include <smithlog.hpp>

#include <service/core/smithproxy.hpp>


void prepare_queue_logger(loglevel const& lev) {

    // set final logger now
    LogOutput::set(std::make_shared<QueueLogger>());

    // create logging thread
    std::thread* log_thread  = create_log_writer();
    if(log_thread != nullptr) {
        pthread_setname_np(log_thread->native_handle(),string_format("sxy_lwr_%d",
                                                                     CfgFactory::get().tenant_index).c_str());
    }

    LogOutput::get()->level(lev);
    CfgFactory::get().log_version(false);  // don't delay, but display warning
}


void prepare_html_renderer() {

    auto& log = DaemonFactory::instance().log;

    if(!html()->load_files(CfgFactory::get().dir_msg_templates)) {
        _err("Cannot load messages from '%s', replacements will not work correctly !!!", CfgFactory::get().dir_msg_templates.c_str());
    } else {
        std::string test = "test";
        _dia("Message testing string: %s", html()->render_noargs(test).c_str());
    }
}

void prepare_mem_debugs() {
    if(CfgFactory::get().cfg_openssl_mem_dbg) {


#ifndef BUILD_RELEASE
        auto& log = DaemonFactory::instance().log;

        _war("openssl memory debug enabled");

        #ifndef USE_OPENSSL11
            CRYPTO_malloc_debug_init();
            CRYPTO_dbg_set_options(V_CRYPTO_MDEBUG_ALL);
        #endif

        CRYPTO_mem_ctrl(CRYPTO_MEM_CHECK_ON);
        CRYPTO_mem_ctrl(CRYPTO_MEM_CHECK_DISABLE);
#endif
    }

}

void print_stats() {
    auto& log = DaemonFactory::instance().log;

    _dia("Debug SSL statistics: ");
    _dia("SSL_accept: %d", SSLCom::counter_ssl_accept.load());
    _dia("SSL_connect: %d", SSLCom::counter_ssl_connect.load());
}

void do_cleanup() {

    // this proven to be better idea than cleanup after exit() call
    CfgFactory::get().cleanup();

    CRYPTO_cleanup_all_ex_data();
    ERR_free_strings();
#ifndef USE_OPENSSL11
    ERR_remove_state(0);
#endif
    EVP_cleanup();
}

void prepare_tenanting(bool is_custom_file) {

    auto& log = DaemonFactory::instance().log;

    std::string config_file_tenant = "/etc/smithproxy/smithproxy.%s.cfg";
    if(is_custom_file) {
        // if user supplied config file, we will obey instructions (it's already set in factory)
        config_file_tenant = CfgFactory::get().config_file;
    }

    auto& this_daemon = DaemonFactory::instance();

    if( (! CfgFactory::get().tenant_name.empty())) {

        if(CfgFactory::get().tenant_index < 0) {
            _war("... tenant name set, but no index given (assuming idx=0)");
            CfgFactory::get().tenant_index = 0;
        }

        _war("Tenant: '%s', index %d",
             CfgFactory::get().tenant_name.c_str(),
             CfgFactory::get().tenant_index);


        std::string tenant_cfg = string_format(config_file_tenant.c_str(), CfgFactory::get().tenant_name.c_str());

        struct stat s{};
        if (stat(tenant_cfg.c_str(),&s) == 0) {
            _war("Tenant config: %s",tenant_cfg.c_str());
            CfgFactory::get().config_file = tenant_cfg;
        } else {
            _war("Tenant config: using default",tenant_cfg.c_str());
        }

        this_daemon.set_tenant("smithproxy", CfgFactory::get().tenant_name);
    }
    else {
        _war("Starting non-tenant configuration");
        CfgFactory::get().tenant_index = 0;
        this_daemon.set_tenant("smithproxy", "default");
    }

    SmithProxy::instance().tenant_index(CfgFactory::get().tenant_index);
}

bool raise_limits() {

    bool ret = false;

    rlimit r{0};
    std::stringstream ss;

    getrlimit(RLIMIT_NOFILE, &r);

    // ss << " files: cur:" << r.rlim_cur << " max: " << r.rlim_max;
    //_cons(ss); ss.clear();


    rlimit fno {
            .rlim_cur = r.rlim_max,
            .rlim_max = r.rlim_max
    };

    if (0 == setrlimit(RLIMIT_NOFILE, &fno)) {
        ret = true;
    }
    return ret;
};


void print_help() {

    std::cerr << std::endl;
    std::cerr << "Smithproxy " << SMITH_VERSION << " - copyleft astib@mag0.net" << std::endl;
    std::cerr << std::endl;
    std::cerr << "  Tenant settings (optional):" << std::endl;
    std::cerr << std::endl;
    std::cerr << "    --tenant-name :  name of the tenant" << std::endl;
    std::cerr << "    --tenant-idx  :  tenant index" << std::endl;
    std::cerr << std::endl;
    std::cerr << "  Startup debugs (optional):" << std::endl;
    std::cerr << std::endl;
    std::cerr << "    --daemonize :  start and fork to background" << std::endl;
    std::cerr << "    --debug     :  debug level startup logs" << std::endl;
    std::cerr << "    --diagnose  :  diag level startup logs" << std::endl;
    std::cerr << std::endl;
    std::cerr << "  Utility options (optional):" << std::endl;
    std::cerr << std::endl;
    std::cerr << "    --version, -c                :  print version and exit with 0" << std::endl;
    std::cerr << "    --config-file, -c <filename> :  specify/override configuration file" << std::endl;
    std::cerr << "    --config-check-only, -o      :  perform configuration file check" << std::endl;
    std::cerr << std::endl;
    std::cerr << "  Notes:" << std::endl;
    std::cerr << std::endl;
    std::cerr << "    Without arguments, smithproxy starts with defaults in the foreground." << std::endl;
    std::cerr << "    Tenants are completely optional and are not needed at all." << std::endl;
    std::cerr << std::endl;
    std::cerr << std::endl;
}

int main(int argc, char *argv[]) {

    memPool::pool();

#ifdef MEMPOOL_ALL
    if( CRYPTO_set_mem_functions(mempool_alloc, mempool_realloc, mempool_free) == 0) {
        std::cerr << "WARNING: openssl allocators not registered, defaulting" << std::endl;
    }
#endif

    if(! raise_limits()) {
        std::cerr << "cannot max file descriptors"  << std::endl;
        exit(-1);
    }


    static struct option long_options[] =
            {
                    /* These options set a flag. */
                    {"debug",   no_argument,        (int*) &CfgFactory::get().args_debug_flag.level_ref(), iDEB},
                    {"diagnose",   no_argument,     (int*) &CfgFactory::get().args_debug_flag.level_ref(), iDIA},
                    {"dump",   no_argument,         (int*) &CfgFactory::get().args_debug_flag.level_ref(), iDUM},
                    {"extreme",   no_argument,      (int*) &CfgFactory::get().args_debug_flag.level_ref(), iEXT},

                    {"config-file", required_argument, nullptr, 'c'},
                    {"config-check-only", no_argument, nullptr, 'o'},
                    {"daemonize", no_argument, nullptr, 'D'},
                    {"version", no_argument, nullptr, 'v'},

                    // multi-tenancy support: listening ports will be shifted by number 'i', while 't' controls logging, pidfile, etc.
                    // both, or none of them have to be set
                    {"tenant-index", required_argument, nullptr, 'i'},
                    {"tenant-name", required_argument, nullptr, 't'},
                    {"help", no_argument,nullptr, 'h'},
                    {nullptr, 0, nullptr, 0}
            };


    DaemonFactory& this_daemon = DaemonFactory::instance();
    auto& log = this_daemon.log;

    CfgFactory::get().config_file = "/etc/smithproxy/smithproxy.cfg";
    bool is_custom_config_file = false;

    while(true) {
    /* getopt_long stores the option index here. */
        int option_index = 0;
    
        int c = getopt_long (argc, argv, "hvocitD",
                        long_options, &option_index);
        if (c < 0) break;

        switch(c) {
            case 0:
                break;
                
            case 'c':
                CfgFactory::get().config_file = std::string(optarg);
                is_custom_config_file = true;
                break;      
                
            case 'o':
                CfgFactory::get().config_file_check_only = true;
                LogOutput::get()->dup2_cout(true);
                break;
                
            case 'D':
                SmithProxy::instance().cfg_daemonize = true;
                break;
                
            case 'i':
                CfgFactory::get().tenant_index = std::stoi(std::string(optarg));
                break;
                
            case 't':
                CfgFactory::get().tenant_name = std::string(optarg);
                break;

            case 'h':
                print_help();
                exit(1);
                
            case 'v':
                std::cout << SMITH_VERSION << "+" << SOCLE_VERSION << std::endl;
                exit(0);
                
                
            default:
                std::cerr << "unknown option: " << c  << std::endl;
                exit(1);                 
        }
    }

    // set synchronous logger for the beginning
    LogOutput::set(LogOutput::default_logger());
    LogOutput::get()->level(WAR);


    // be ready for tenants, or for standalone execution
    prepare_tenanting(is_custom_config_file);


    // be more verbose if check only requested
    if(CfgFactory::get().config_file_check_only) {
        LogOutput::get()->level(DIA);
    }
    bool CONFIG_LOADED = SmithProxy::instance().load_config(CfgFactory::get().config_file);

    // exit if that's only about config check - we should not proceed
    if(CfgFactory::get().config_file_check_only) {

        if (! CONFIG_LOADED) {
            std::cerr <<  "Failed to load config file!" << std::endl;
        } else {
            std::cerr <<  "Config file check OK" << std::endl;
        }

        CfgFactory::get().cleanup();

        if(! CONFIG_LOADED) {
            exit(-1);
        }
        exit(0);
    }




    // if logging set in cmd line, use it 
    if(CfgFactory::get().args_debug_flag > NON) {
        LogOutput::get()->level(CfgFactory::get().args_debug_flag);
    }
    
    // set level to what's in the config
    if (! CONFIG_LOADED ) {
        _fat("Config check: error loading config file.");
        std::cerr << "Config check: error loading config file."  << std::endl;

        CfgFactory::get().cleanup();
        exit(1);
    }
    
    if(!CfgFactory::get().apply_tenant_config()) {
        _fat("Failed to apply tenant specific configuration!");
        std::cerr << "Failed to apply tenant specific configuration!"  << std::endl;

        CfgFactory::get().cleanup();
        exit(2);
    }

    if(CfgFactory::get().cfg_mtrace_enable) {
#ifdef MEM_DEBUG
        putenv("MALLOC_TRACE=/var/log/smithproxy_mtrace.log");
        mtrace();
#endif
    }

    
    // if there is loglevel specified in config file and is bigger than we currently have set, use it
    if(CfgFactory::get().internal_init_level > LogOutput::get()->level()) {
        LogOutput::get()->level(CfgFactory::get().internal_init_level);
    }
    
    if(this_daemon.exists_pidfile()) {
        _fat("There is PID file already in the system.");
        _fat("Please make sure smithproxy is not running, remove %s and try again.", this_daemon.pid_file.c_str());

        std::cerr << "There is PID file already in the system." << std::endl;
        std::cerr << "Please make sure smithproxy is not running, remove " << this_daemon.pid_file << " and try again."  << std::endl;

        CfgFactory::get().cleanup();
        exit(-5);
    }
    
    // detect kernel version, and adapt UDP socket family
    if(!version_check(get_kernel_version(),"4.3")) {    
        _war("Kernel can't use IPv6 for UDP transparency. Kernel upgrade is highly recommended.");
        _war("IPv6/UDP smithproxy forwarding will not work.");
        _war("Set SMITH_IPV6_UDP_BYPASS=1 variable in smithproxy.startup.cfg");

        std::cerr << "your kernel is outdated. More info in log."  << std::endl;
        UDPCom::default_sock_family = AF_INET;
    }
    
    if(SmithProxy::instance().cfg_daemonize) {
        if (LogOutput::get()->targets().empty()) {
            _fat("Cannot daemonize without logging to file.");
            std::cerr << "Cannot daemonize without logging to file."  << std::endl;

            CfgFactory::get().cleanup();
            exit(-5);
        }

        LogOutput::get()->dup2_cout(false);
        _inf("Entering daemon mode.");

        int dem = this_daemon.daemonize();
        if(dem == 0) {
            // master - to exit
            CfgFactory::get().cleanup();
            exit(0);
        }
        else if(dem < 0) {
            // slave, but failed
            CfgFactory::get().cleanup();
            exit(-1);
        }

    }
    // openssl mem debugs
    prepare_mem_debugs();

    // prepare templating system
    prepare_html_renderer();

    // create utility threads
    SmithProxy::instance().create_log_writer_thread();
    SmithProxy::init_syslog();

    SmithProxy::instance().create_dns_thread();
    SmithProxy::instance().create_identity_thread();

    // launch listeners

    if(SmithProxy::instance().create_listeners()) {

        _cri("Smithproxy %s (socle %s) starting...", SMITH_VERSION, SOCLE_VERSION);
        SmithProxy::instance().run();
        print_stats();
    } else {
        // something went wrong, terminate - but join all threads before doing so to prevent ABORT
        SmithProxy::instance().terminate_flag = true;
        SmithProxy::instance().join_all();
    }

    do_cleanup();
    return 0;
}


#ifdef MEMPOOL_ALL

#include <exception>
#include <new>

void * operator new(std::size_t n)
{
    if (memPool::is_ready()) {
        return mempool_alloc(n);
    } else {
        return ::malloc(n);
    }

}
void operator delete(void * p) noexcept
{
    if (memPool::is_ready()) {
        return mempool_free(p);
    } else {
        return ::free(p);
    }
}

#endif