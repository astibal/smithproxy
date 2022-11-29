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

#include <sslcom.hpp>
#include <udpcom.hpp>
#include <display.hpp>

#include <main.hpp>

#include <libconfig.h++>

#include <service/cfgapi/cfgapi.hpp>
#include <utils/tenants.hpp>
#include <service/daemon.hpp>
#include <staticcontent.hpp>
#include <smithlog.hpp>

#include <service/core/smithproxy.hpp>
#include <service/httpd/httpd.hpp>

void prepare_queue_logger(loglevel const& lev) {

    // set final logger now
    Log::set(std::make_shared<QueueLogger>());

    // create logging thread
    std::thread* log_thread  = create_log_writer();
    if(log_thread != nullptr) {
        pthread_setname_np(log_thread->native_handle(),string_format("sxy_lwr_%d",
                                                                     CfgFactory::get()->tenant_index).c_str());
    }

    Log::get()->level(lev);
    CfgFactory::get()->log_version(false);  // don't delay, but display warning
}


void prepare_html_renderer() {

    auto const& log = DaemonFactory::instance()->get_log();

    if(!html()->load_files(CfgFactory::get()->dir_msg_templates)) {
        _err("Cannot load messages from '%s', replacements will not work correctly !!!", CfgFactory::get()->dir_msg_templates.c_str());
    } else {
        std::string test = "test";
        _dia("Message testing string: %s", html()->render_noargs(test).c_str());
    }
}

void prepare_mem_debugs() {
    if(CfgFactory::get()->cfg_openssl_mem_dbg) {


#ifndef BUILD_RELEASE
        auto const& log = DaemonFactory::instance()->get_log();

        _war("openssl memory debug enabled");

        #ifndef USE_OPENSSL11
            CRYPTO_malloc_debug_init();
            CRYPTO_dbg_set_options(V_CRYPTO_MDEBUG_ALL);
        #endif

        #ifndef USE_OPENSSL300
        CRYPTO_mem_ctrl(CRYPTO_MEM_CHECK_ON);
        CRYPTO_mem_ctrl(CRYPTO_MEM_CHECK_DISABLE);
        #endif
#endif
    }

}

void print_stats() {
    auto const& log = DaemonFactory::instance()->get_log();

    const time_t uptime = time(nullptr) - SmithProxy::instance().ts_sys_started;
    const unsigned long t = MitmProxy::total_mtr_up().total() + MitmProxy::total_mtr_down().total();

    auto stat = string_format("Smithproxy was running: %s, served %lu sessions and transferred %sB of data.\n",
            uptime_string(uptime).c_str(),
            static_cast<unsigned long>(MitmProxy::total_sessions().load()),
            number_suffixed(t).c_str());

    if(SmithProxy::instance().cfg_daemonize) {
        _inf("%s", stat.c_str());
    }
    else {
        std::cerr << stat;
    }

    _dia("Debug SSL statistics: ");
    _dia("SSL_accept: %d", SSLCom::counter_ssl_accept.load());
    _dia("SSL_connect: %d", SSLCom::counter_ssl_connect.load());
}

void do_cleanup() {

    // this proven to be better idea than cleanup after exit() call
    CfgFactory::get()->cleanup();

    CRYPTO_cleanup_all_ex_data();
    ERR_free_strings();
#ifndef USE_OPENSSL11
    ERR_remove_state(0);
#endif
    EVP_cleanup();
}

std::optional<sx::cfg::vec_tenants> load_tenant_config() {
    std::string line;
    std::ifstream cfg;

    auto const& log = DaemonFactory::instance()->get_log();

    cfg.open("/etc/smithproxy/smithproxy.tenants.cfg");

    if(not cfg.is_open()) {
        _war("cannot load tenant config");
        return std::nullopt;
    }

    std::vector<sx::cfg::TenantConfig> to_ret;

    while(getline(cfg, line)) {
        sx::cfg::process_tenant_config_line(line, to_ret);
    }

    return to_ret;
}

bool prepare_tenanting(bool is_custom_file) {

    auto const& log = DaemonFactory::instance()->get_log();

    std::string config_file_tenant = "/etc/smithproxy/smithproxy.%s.cfg";
    if(is_custom_file) {
        // if user supplied config file, we will obey instructions (it's already set in factory)
        config_file_tenant = CfgFactory::get()->config_file;
    }

    auto revert = [] {
        CfgFactory::get()->tenant_name = "default";
        CfgFactory::get()->tenant_index = 0;
    };

    auto this_daemon = DaemonFactory::instance();

    if(not CfgFactory::get()->tenant_name.empty()) {

        // let's resolve non-defaults

        if(CfgFactory::get()->tenant_name != "default") {
            auto ten_cfg = load_tenant_config();
            if(not ten_cfg) {
                _war("... tenant name not default, but cannot load tenant config - bailing");
                std::cerr << "... tenant name not default, but cannot load tenant config - bailing" << std::endl;
                revert();
                return false;
            }
            else {
                auto index = sx::cfg::find_tenant(ten_cfg.value(), CfgFactory::get()->tenant_name);
                if(not index) {
                    _war("... tenant name not default, but cannot find index tenant config - bailing");
                    std::cerr << "... tenant name not default, but cannot find index tenant config - bailing" << std::endl;
                    revert();
                    return false;
                }
                else {
                    CfgFactory::get()->tenant_index = index.value();
                }
            }
        }
        else {
            _war("... default tenant name, index forced to 0");
            CfgFactory::get()->tenant_index = 0;
        }

        _war("Tenant: '%s', index %d",
             CfgFactory::get()->tenant_name.c_str(),
             CfgFactory::get()->tenant_index);


        std::string tenant_cfg = string_format(config_file_tenant.c_str(), CfgFactory::get()->tenant_name.c_str());

        struct stat s{};
        if (stat(tenant_cfg.c_str(),&s) == 0) {
            _war("Tenant config: %s",tenant_cfg.c_str());
            CfgFactory::get()->config_file = tenant_cfg;
        } else {
            _war("Tenant config: using default",tenant_cfg.c_str());
        }

        this_daemon->set_tenant("smithproxy", CfgFactory::get()->tenant_name);
    }
    else {
        _war("Starting non-tenant configuration");
        CfgFactory::get()->tenant_index = 0;
        this_daemon->set_tenant("smithproxy", "default");
    }

    SmithProxy::instance().tenant_index(CfgFactory::get()->tenant_index);

    return true;
}

bool raise_limits() {

    bool ret = false;

    rlimit r{};
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
}


void print_help() {

    std::cerr << std::endl;
    std::cerr << "Smithproxy " << SMITH_VERSION << " - copyleft astib@mag0.net" << std::endl;
    std::cerr << std::endl;
    std::cerr << "  Tenant settings (optional):" << std::endl;
    std::cerr << std::endl;
    std::cerr << "    --tenant-name :  name of the tenant" << std::endl;
    std::cerr << std::endl;
    std::cerr << "  Startup debugs (optional):" << std::endl;
    std::cerr << std::endl;
    std::cerr << "    --daemonize :  start and fork to background" << std::endl;
    std::cerr << "    --debug     :  debug level startup logs" << std::endl;
    std::cerr << "    --diagnose  :  diag level startup logs" << std::endl;
    std::cerr << std::endl;
    std::cerr << "  Utility options (optional):" << std::endl;
    std::cerr << std::endl;
    std::cerr << "    --version, -v                :  print version and exit with 0" << std::endl;
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

    {
        auto log = logan::get();
        log->inf("service", "");
    }

    CfgFactory::init();

#ifdef MEMPOOL_ALL
    if( CRYPTO_set_mem_functions(mempool_alloc, mempool_realloc, mempool_free) == 0) {
        std::cerr << "WARNING: openssl allocators not registered, defaulting" << std::endl;
    }
#endif

    if(! raise_limits()) {
        std::cerr << "cannot max file descriptors"  << std::endl;
        return EXIT_FAILURE;
    }


    static struct option long_options[] =
            {
                    /* These options set a flag. */
                    {"debug",   no_argument,        (int*) &CfgFactory::get()->args_debug_flag.level_ref(), iDEB},
                    {"diagnose",   no_argument,     (int*) &CfgFactory::get()->args_debug_flag.level_ref(), iDIA},
                    {"dump",   no_argument,         (int*) &CfgFactory::get()->args_debug_flag.level_ref(), iDUM},
                    {"extreme",   no_argument,      (int*) &CfgFactory::get()->args_debug_flag.level_ref(), iEXT},

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


    auto this_daemon = DaemonFactory::instance();
    auto const& log = this_daemon->get_log();

    CfgFactory::get()->config_file = "/etc/smithproxy/smithproxy.cfg";
    bool is_custom_config_file = false;
    bool is_dup2cout = false;

    while(true) {
    /* getopt_long stores the option index here. */
        int option_index = 0;
    
        int c = getopt_long (argc, argv, "hvoc:t:D",
                        long_options, &option_index);
        if (c < 0) break;


        switch(c) {
            case 0:
                break;
                
            case 'c':
                CfgFactory::get()->config_file = std::string(optarg);
                is_custom_config_file = true;
                break;      
                
            case 'o':
                CfgFactory::get()->config_file_check_only = true;
                is_dup2cout = true;
                break;
                
            case 'D':
                SmithProxy::instance().cfg_daemonize = true;
                break;

            case 't':
                CfgFactory::get()->tenant_name = std::string(optarg);
                break;

            case 'h':
                print_help();
                return EXIT_SUCCESS;
                
            case 'v':
                std::cout << SMITH_VERSION << "+" << SOCLE_VERSION << std::endl;
                return EXIT_SUCCESS;
                
                
            default:
                std::cerr << "unknown option: '" << (char)c << "'"<< std::endl;
                return EXIT_FAILURE;
        }
    }

    // set synchronous logger for the beginning
    Log::init();
    Log::set(Log::default_logger());
    Log::get()->level(WAR);

    if(is_dup2cout) {
        Log::get()->dup2_cout(true);
    }

    // be ready for tenants, or for standalone execution
    if (not prepare_tenanting(is_custom_config_file)) {
        return EXIT_FAILURE;
    }


    // be more verbose if check only requested
    if(CfgFactory::get()->config_file_check_only) {
        Log::get()->level(DIA);
    }
    bool CONFIG_LOADED = SmithProxy::instance().load_config(CfgFactory::get()->config_file);

    if(CONFIG_LOADED) {
        bool upgraded_status = false;

        if(not CfgFactory::get()->config_file_check_only) {
            upgraded_status = CfgFactory::get()->upgrade_and_save();
            if(upgraded_status) {
                _not("config file has been upgraded");
                log.event(NOT, "Configuration updated and saved");
            }
        }

        if(upgraded_status) {
            CONFIG_LOADED = SmithProxy::instance().load_config(CfgFactory::get()->config_file);
            if(CONFIG_LOADED) {
                _not("upgraded config file has been reloaded");
            }
            else {
                _cri("upgraded config file FAILED to load");
            }
        }
    }

    // exit if that's only about config check - we should not proceed
    if(CfgFactory::get()->config_file_check_only) {

        if (! CONFIG_LOADED) {
            std::cerr <<  "Failed to load config file!" << std::endl;
        } else {
            std::cerr <<  "Config file check OK" << std::endl;
        }

        CfgFactory::get()->cleanup();

        if(! CONFIG_LOADED) {
            return EXIT_FAILURE;
        }

        return EXIT_SUCCESS;
    }




    // if logging set in cmd line, use it 
    if(CfgFactory::get()->args_debug_flag > NON) {
        Log::get()->level(CfgFactory::get()->args_debug_flag);
    }
    
    // set level to what's in the config
    if (! CONFIG_LOADED ) {
        _fat("Config check: error loading config file.");
        std::cerr << "Config check: error loading config file."  << std::endl;

        CfgFactory::get()->cleanup();
        return EXIT_FAILURE;
    }
    
    if(!CfgFactory::get()->apply_tenant_config()) {
        _fat("Failed to apply tenant specific configuration!");
        std::cerr << "Failed to apply tenant specific configuration!"  << std::endl;

        CfgFactory::get()->cleanup();
        return EXIT_FAILURE;
    }

    if(CfgFactory::get()->cfg_mtrace_enable) {
#ifdef MEM_DEBUG
        putenv("MALLOC_TRACE=/var/log/smithproxy/mtrace.log");
        mtrace();
#endif
    }

    
    // if there is loglevel specified in config file and is bigger than we currently have set, use it
    if(CfgFactory::get()->internal_init_level > Log::get()->level()) {
        Log::get()->level(CfgFactory::get()->internal_init_level);
    }
    
    if(this_daemon->exists_pidfile()) {
        _fat("There is PID file already in the system.");
        _fat("Please make sure smithproxy is not running, remove %s and try again.", this_daemon->pid_file.c_str());

        std::cerr << "There is PID file already in the system." << std::endl;
        std::cerr << "Please make sure smithproxy is not running, remove " << this_daemon->pid_file << " and try again."  << std::endl;

        CfgFactory::get()->cleanup();
        return EXIT_FAILURE;
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
        if (Log::get()->targets().empty()) {
            _fat("Cannot daemonize without logging to file.");
            std::cerr << "Cannot daemonize without logging to file."  << std::endl;

            CfgFactory::get()->cleanup();
            return EXIT_FAILURE;
        }

        Log::get()->dup2_cout(false);
        _inf("Entering daemon mode.");

        int dem = this_daemon->daemonize();
        if(dem == 0) {
            // master - to exit
            CfgFactory::get()->cleanup();
            return EXIT_SUCCESS;
        }
        else if(dem < 0) {
            // slave, but failed
            CfgFactory::get()->cleanup();
            return EXIT_FAILURE;
        }

    } else {
        // this is necessary for systemd which doesn't favor forked daemons
        // also - there is no harm to write PIDfile even for foreground programs
        this_daemon->write_pidfile();
    }
    // openssl mem debugs
    prepare_mem_debugs();

    // prepare templating system
    prepare_html_renderer();

    // create utility threads
    SmithProxy::instance().create_log_writer_thread();

    Log::get()->events().insert(INF, "Smithproxy %s%s starting", SMITH_VERSION, SMITH_DEVEL > 0 ? "-dev" : "");

    SmithProxy::instance().create_dns_thread();
    SmithProxy::instance().create_identity_thread();

    auto start_api = [&]() {
        if (CfgFactory::get()->accept_api) {

            if (not sx::webserver::HttpSessions::api_keys.empty()) {
                SmithProxy::instance().create_api_thread();
            } else {
                Log::get()->events().insert(ERR, "cannot start API server: key not set");
            }
        }
    };

    // launch listeners

    if(SmithProxy::instance().create_listeners()) {

        // init to get certificates and info
        SSLFactory::factory().init();
        start_api();

        _dia("Smithproxy %s (socle %s) starting...", SMITH_VERSION, SOCLE_VERSION);
        SmithProxy::instance().run();
        print_stats();
    } else {
        _cri("cannot create listeners, exiting...");
        // something went wrong, terminate - but join all threads before doing so to prevent ABORT
        SmithProxy::instance().terminate_flag = true;
        SmithProxy::instance().join_all();
    }

    do_cleanup();
    return EXIT_SUCCESS;
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