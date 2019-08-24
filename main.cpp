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


volatile static int cnt_terminate = 0;
static bool cfg_daemonize = false;

#ifndef MEM_DEBUG
bool cfg_openssl_mem_dbg = false;
bool cfg_mtrace_enable = false;
#else
bool cfg_openssl_mem_dbg = true;
static bool cfg_mtrace_enable = true;
#endif




void my_terminate (int param) {

    if (!cfg_daemonize)
        printf("Terminating ...\n");

    SmithProxy::instance().stop();

    cnt_terminate++;
    if(cnt_terminate == 3) {
        if (!cfg_daemonize)
            printf("Failed to terminate gracefully. Next attempt will be enforced.\n");
    }
    if(cnt_terminate > 3) {
        if (!cfg_daemonize)
            printf("Enforced exit.\n");
        abort();
    }
}


void my_usr1 (int param) {
    DIAS_("USR1 signal handler started");
    NOTS_("reloading policies and its objects !!");
    load_config(CfgFactory::get().config_file,true);
    DIAS_("USR1 signal handler finished");
}




int load_signatures(libconfig::Config& cfg, const char* name, std::vector<duplexFlowMatch*>& target) {
    using namespace libconfig;
    
    const Setting& root = cfg.getRoot();
    const Setting& cfg_signatures = root[name];
    int sigs_len = cfg_signatures.getLength();

    
    DIA_("Loading %s: %d",name,sigs_len);
    for ( int i = 0 ; i < sigs_len; i++) {
        MyDuplexFlowMatch* newsig = new MyDuplexFlowMatch();
        
        
        const Setting& signature = cfg_signatures[i];
        signature.lookupValue("name", newsig->name());
        signature.lookupValue("side", newsig->sig_side);
        signature.lookupValue("cat", newsig->category);                

        const Setting& signature_flow = cfg_signatures[i]["flow"];
        int flow_count = signature_flow.getLength();
        
        DIA_("Loading signature '%s' with %d flow matches",newsig->name().c_str(),flow_count);

        
        for ( int j = 0; j < flow_count; j++ ) {

            std::string side;
            std::string type;
            std::string sigtext;
            int bytes_start;
            int bytes_max;
            
            if(!(signature_flow[j].lookupValue("side", side)
                && signature_flow[j].lookupValue("type", type)
                && signature_flow[j].lookupValue("signature", sigtext)
                && signature_flow[j].lookupValue("bytes_start", bytes_start)
                && signature_flow[j].lookupValue("bytes_max", bytes_max))) {
                
                WAR_("Starttls signature %s failed to load: index %d",i);
                continue;
            }
            
            if( type == "regex") {
                DEB_(" [%d]: new regex flow match",j);
                newsig->add(side[0],new regexMatch(sigtext,bytes_start,bytes_max));
            } else
            if ( type == "simple") {
                DEB_(" [%d]: new simple flow match",j);
                newsig->add(side[0],new simpleMatch(sigtext,bytes_start,bytes_max));
            }
        }
        
        target.push_back(newsig);
    }    
    
    return sigs_len;
}

bool init_syslog() {


    // create UDP socket
    int syslog_socket = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP); 

    struct sockaddr_storage syslog_in;
    memset(&syslog_in, 0, sizeof(struct sockaddr_storage));
    
    if(CfgFactory::get().syslog_family != 6) {
        CfgFactory::get().syslog_family = 4;
        syslog_in.ss_family                = AF_INET;
        ((sockaddr_in*)&syslog_in)->sin_addr.s_addr = inet_addr(CfgFactory::get().syslog_server.c_str());
        if(((sockaddr_in*)&syslog_in)->sin_addr.s_addr == INADDR_NONE) {
            ERR_("Error initializing syslog server: %s", CfgFactory::get().syslog_server.c_str());
            return false;
        }
        
        ((sockaddr_in*)&syslog_in)->sin_port = htons(CfgFactory::get().syslog_port);
    } else {
        CfgFactory::get().syslog_family = 6;
        syslog_in.ss_family                = AF_INET6;
        int ret = inet_pton(AF_INET6, CfgFactory::get().syslog_server.c_str(),(unsigned char*)&((sockaddr_in6*)&syslog_in)->sin6_addr.s6_addr);
        if(ret <= 0) {
            ERR_("Error initializing syslog server: %s", CfgFactory::get().syslog_server.c_str());
            return false;
        }
        ((sockaddr_in6*)&syslog_in)->sin6_port = htons(CfgFactory::get().syslog_port);
    }
    
    
    ::connect(syslog_socket,(sockaddr*)&syslog_in,sizeof(sockaddr_storage));
    
    get_logger()->remote_targets(string_format("syslog-udp%d-%d", CfgFactory::get().syslog_family, syslog_socket),syslog_socket);

    logger_profile* lp = new logger_profile();
    
    lp->logger_type = logger_profile::REMOTE_SYSLOG;
    lp->level_ = CfgFactory::get().syslog_level;
    
    // raising internal logging level
    if(lp->level_ > get_logger()->level()) {
        NOT_("Internal logging raised from %d to %d due to syslog server loglevel.",get_logger()->level(), lp->level_);
        get_logger()->level(lp->level_);
    }
    
    lp->syslog_settings.severity = lp->level_.level_;
    lp->syslog_settings.facility = CfgFactory::get().syslog_facility;
    
    get_logger()->target_profiles()[(uint64_t)syslog_socket] = lp;
    
    return true;
}

bool load_config(std::string& config_f, bool reload) {
    bool ret = true;
    
    using namespace libconfig;
    if(! CfgFactory::get().cfgapi_init(config_f.c_str()) ) {
        FATS_("Unable to load config.");
        ret = false;
    }

    CfgFactory::get().config_file = config_f;
    
    // Add another level of lock. File is already loaded. We need to apply its content.
    // lock is needed here to not try to match against potentially empty/partial policy list
    std::lock_guard<std::recursive_mutex> l_(CfgFactory::lock());
    try {
        
        if(reload) {
            CfgFactory::get().cfgapi_cleanup();
        }

        CfgFactory::get().load_db_address();
        CfgFactory::get().load_db_port();
        CfgFactory::get().load_db_proto();
        CfgFactory::get().load_db_prof_detection();
        CfgFactory::get().load_db_prof_content();
        CfgFactory::get().load_db_prof_tls();
        CfgFactory::get().load_db_prof_alg_dns();
        CfgFactory::get().load_db_prof_auth();

        CfgFactory::get().load_db_policy();
        
        
        if(!reload)  {
            load_signatures(CfgFactory::cfg_obj(),"detection_signatures",sigs_detection);
            load_signatures(CfgFactory::cfg_obj(),"starttls_signatures",sigs_starttls);
        }

        CfgFactory::get().load_settings();

        CfgFactory::cfg_root()["debug"].lookupValue("log_data_crc",baseCom::debug_log_data_crc);
        CfgFactory::cfg_root()["debug"].lookupValue("log_sockets",baseHostCX::socket_in_name);
        CfgFactory::cfg_root()["debug"].lookupValue("log_online_cx_name",baseHostCX::online_name);
        CfgFactory::cfg_root()["debug"].lookupValue("log_srclines",get_logger()->print_srcline());
        CfgFactory::cfg_root()["debug"].lookupValue("log_srclines_always",get_logger()->print_srcline_always());

        CfgFactory::cfg_root()["debug"]["log"].lookupValue("sslcom",SSLCom::log_level_ref().level_);
        CfgFactory::cfg_root()["debug"]["log"].lookupValue("sslmitmcom",baseSSLMitmCom<SSLCom>::log_level_ref().level_);
        CfgFactory::cfg_root()["debug"]["log"].lookupValue("sslmitmcom",baseSSLMitmCom<DTLSCom>::log_level_ref().level_);
        CfgFactory::cfg_root()["debug"]["log"].lookupValue("sslcertstore",SSLFactory::log_level_ref().level_);
        CfgFactory::cfg_root()["debug"]["log"].lookupValue("proxy",baseProxy::log_level_ref().level_);
        CfgFactory::cfg_root()["debug"]["log"].lookupValue("proxy",epoll::log_level.level_);
        CfgFactory::cfg_root()["debug"]["log"].lookupValue("mtrace",cfg_mtrace_enable);
        CfgFactory::cfg_root()["debug"]["log"].lookupValue("openssl_mem_dbg",cfg_openssl_mem_dbg);

        /*DNS ALG EXPLICIT LOG*/
        CfgFactory::cfg_root()["debug"]["log"].lookupValue("alg_dns",DNS_Inspector::log_level_ref().level_);
        CfgFactory::cfg_root()["debug"]["log"].lookupValue("alg_dns",DNS_Packet::log_level_ref().level_);


        CfgFactory::cfg_root()["settings"].lookupValue("write_payload_dir",CfgFactory::get().traflog_dir);
        CfgFactory::cfg_root()["settings"].lookupValue("write_payload_file_prefix",CfgFactory::get().traflog_file_prefix);
        CfgFactory::cfg_root()["settings"].lookupValue("write_payload_file_suffix",CfgFactory::get().traflog_file_suffix);




        // don't mess with logging if just reloading
        if(! reload) {

            
            //init crashlog file with dafe default
            set_crashlog("/tmp/smithproxy_crash.log");

            if(CfgFactory::cfg_root()["settings"].lookupValue("log_file",CfgFactory::get().log_file_base)) {

                CfgFactory::get().log_file = CfgFactory::get().log_file_base;


                if(CfgFactory::get().log_file.size() > 0) {

                    CfgFactory::get().log_file = string_format(CfgFactory::get().log_file.c_str(), CfgFactory::get().tenant_name.c_str());
                    // prepare custom crashlog file
                    std::string crlog = CfgFactory::get().log_file + ".crashlog.log";
                    set_crashlog(crlog.c_str());
                    
                    std::ofstream * o = new std::ofstream(CfgFactory::get().log_file.c_str(),std::ios::app);
                    get_logger()->targets(CfgFactory::get().log_file, o);
                    get_logger()->dup2_cout(false);
                    get_logger()->level(cfgapi_table.logging.level);
                    
                    logger_profile* lp = new logger_profile();
                    lp->print_srcline_ = get_logger()->print_srcline();
                    lp->print_srcline_always_ = get_logger()->print_srcline_always();
                    lp->level_ = cfgapi_table.logging.level;
                    get_logger()->target_profiles()[(uint64_t)o] = lp;
                    
                }
            }
            //
            if(CfgFactory::cfg_root()["settings"].lookupValue("sslkeylog_file", CfgFactory::get().sslkeylog_file_base)) {

                CfgFactory::get().sslkeylog_file = CfgFactory::get().sslkeylog_file_base;

                if(CfgFactory::get().sslkeylog_file.size() > 0) {

                    CfgFactory::get().sslkeylog_file = string_format(CfgFactory::get().sslkeylog_file.c_str(),
                                                                           CfgFactory::get().tenant_name.c_str());

                    std::ofstream * o = new std::ofstream(CfgFactory::get().sslkeylog_file.c_str(),std::ios::app);
                    get_logger()->targets(CfgFactory::get().sslkeylog_file,o);
                    get_logger()->dup2_cout(false);
                    get_logger()->level(cfgapi_table.logging.level);
                    
                    logger_profile* lp = new logger_profile();
                    lp->print_srcline_ = get_logger()->print_srcline();
                    lp->print_srcline_always_ = get_logger()->print_srcline_always();
                    lp->level_ = loglevel(iINF,flag_add(iNOT,CRT|KEYS));
                    get_logger()->target_profiles()[(uint64_t)o] = lp;
                    
                }
            }
            
            
            if( ! CfgFactory::get().syslog_server.empty() ) {
                bool have_syslog = init_syslog();
                if(! have_syslog) {
                    ERRS_("syslog logging not set.");
                }
            }
            
            if(CfgFactory::cfg_root()["settings"].lookupValue("cfg_log_console", CfgFactory::get().log_console)) {
                get_logger()->dup2_cout(CfgFactory::get().log_console);
            }
            
/*            
 *          init_syslog();
*/            
        }
    }
    catch(const SettingNotFoundException &nfex) {
    
        FAT_("Setting not found: %s",nfex.getPath());
        ret = false;
    }
    
    return ret;
}




int main(int argc, char *argv[]) {

    static struct option long_options[] =
            {
                    /* These options set a flag. */
                    {"debug",   no_argument,        (int*) &CfgFactory::get().args_debug_flag.level_, iDEB},
                    {"diagnose",   no_argument,     (int*) &CfgFactory::get().args_debug_flag.level_, iDIA},
                    {"dump",   no_argument,         (int*) &CfgFactory::get().args_debug_flag.level_, iDUM},
                    {"extreme",   no_argument,      (int*) &CfgFactory::get().args_debug_flag.level_, iEXT},

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
                cfg_daemonize = true;
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
    
    if(!cfg_daemonize) {
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

        daemon_set_tenant("smithproxy", CfgFactory::get().tenant_name);
        CfgFactory::get().tenant_name  = CfgFactory::get().tenant_name;
    } 
    else if (CfgFactory::get().tenant_name.size() > 0){
        
        FATS_("You have to specify both options: --tenant-name AND --tenant-index");
        exit(-20);
    }
    else {
        WARS_("Starting tenant: 0 (default)");
        daemon_set_tenant("smithproxy","0"); 
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
    if (!load_config(CfgFactory::get().config_file)) {
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
    
    if(daemon_exists_pidfile()) {
        FATS_("There is PID file already in the system.");
        FAT_("Please make sure smithproxy is not running, remove %s and try again.",PID_FILE.c_str());
        exit(-5);
    }
    
    // detect kernel version, and adapt UDP socket family
    if(!version_check(get_kernel_version(),"4.3")) {    
        WARS_("Kernel can't use IPv6 for transparenting UDP. Kernel upgrade is highly recommended.");
        WARS_("IPv6/UDP smithproxy forwarding will not work.");
        WARS_("Set SMITH_IPV6_UDP_BYPASS=1 variable in smithproxy.startup.cfg");
        UDPCom::default_sock_family = AF_INET;
    }
    
    if(cfg_daemonize) {
        if(get_logger()->targets().size() <= 0) {
            FATS_("Cannot daemonize without logging to file.");
            exit(-5);
        }
        
        get_logger()->dup2_cout(false);
        INFS_("entering daemon mode");
        daemonize();


        SmithProxy::instance().tenant_index(CfgFactory::get().tenant_index);

        // create utility threads
        SmithProxy::instance().create_logger();
        SmithProxy::instance().create_dns_thread();
        SmithProxy::instance().create_identity_thread();

        // launch listeners
        SmithProxy::instance().create_listeners();

    }
    // write out PID file
    daemon_write_pidfile();

    
    //     atexit(__libc_freeres);   

    if(cfg_openssl_mem_dbg) {
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
    
    

    set_daemon_signals(my_terminate,my_usr1);

    SmithProxy::instance().run();

    CRI_("Smithproxy %s (socle %s) started",SMITH_VERSION,SOCLE_VERSION);

    

    DIAS_("Debug SSL statistics: ");
    DIA_("SSL_accept: %d",SSLCom::counter_ssl_accept);
    DIA_("SSL_connect: %d",SSLCom::counter_ssl_connect);

    CfgFactory::get().cfgapi_cleanup();

    SSLCom::certstore()->destroy();
    
    if(cfg_daemonize) {    
        daemon_unlink_pidfile();
    }
    
    CRYPTO_cleanup_all_ex_data();
    ERR_free_strings();
#ifndef USE_OPENSSL11
    ERR_remove_state(0);
#endif
    EVP_cleanup();
    
}

