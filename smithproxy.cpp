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

#include <vector>

#include <csignal>
#include <ctime>
#include <cstdlib>
#include <sys/stat.h>
#include <sys/types.h>

#include <ostream>
#include <ios>

#include <getopt.h>
#include <execinfo.h>

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

#include <smithproxy.hpp>
#include <traflog.hpp>
#include <display.hpp>

#include <libconfig.h++>

#include <mitmhost.hpp>
#include <mitmproxy.hpp>
#include <socksproxy.hpp>

#include <cfgapi.hpp>
#include <daemon.hpp>
#include <cmdserver.hpp>

#define MEM_DEBUG 1
#ifdef MEM_DEBUG
    #include <mcheck.h>
#endif


extern "C" void __libc_freeres(void);

typedef ThreadedAcceptor<MitmMasterProxy,MitmProxy> theAcceptor;
typedef ThreadedReceiver<MitmUdpProxy,MitmProxy> theReceiver;
typedef ThreadedAcceptor<MitmSocksProxy,SocksProxy> socksAcceptor;

class MyPlainAcceptor : public theAcceptor {
};


// Now let's do the Ctrl-C magic
static theAcceptor* plain_proxy = nullptr;
static theAcceptor* ssl_proxy = nullptr;
static theReceiver* udp_proxy = nullptr;
static socksAcceptor* socks_proxy = nullptr;


std::thread* plain_thread = nullptr;
std::thread* ssl_thread = nullptr;
std::thread* udp_thread = nullptr;
std::thread* socks_thread = nullptr;
std::thread* cli_thread = nullptr;

volatile static int cnt_terminate = 0;
static bool cfg_daemonize = false;
static bool cfg_mtrace_enable = false;

static int  args_debug_flag = NON;
// static int   ssl_flag = 0;
static std::string cfg_listen_port = "50080";
static std::string cfg_ssl_listen_port = "50443";
static std::string cfg_udp_port = "50080";
static std::string cfg_socks_port = "1080";

static std::string config_file;
bool config_file_check_only = false;

#define LOG_FILENAME_SZ 512
volatile char crashlog_file[LOG_FILENAME_SZ];
//static unsigned int cfg_log_level = INF;


static int cfg_tcp_workers = 0;
static int cfg_ssl_workers = 0;
static int cfg_udp_workers = 0;
static int cfg_socks_workers = 0;

static std::string cfg_tenant_index;
static std::string cfg_tenant_name;


/*
static unsigned int mystrlen(const char* str, int max) {
    for(int i = 0; i < max; i++ ) {
        if(str[i] == 0) {
            return i;
        }
    }
    return max;
}
static void btrace_handler(int sig) {

    int CRLOG = open((const char*)crashlog_file,O_CREAT | O_WRONLY | O_TRUNC,S_IRUSR|S_IWUSR);
    TEMP_FAILURE_RETRY(write(STDERR_FILENO," ======== Smithproxy exception handler =========\n",50));
    TEMP_FAILURE_RETRY(write(CRLOG," ======== Smithproxy exception handler =========\n",50));
    //FAT_("  [%d] ========= Smithproxy exception handler  =========",sig );

    void *trace[64];
    size_t size, i;
    char **strings;

    size    = backtrace( trace, 64 );
    strings = backtrace_symbols( trace, size );

    if (strings == NULL) {
        //FATS_("failure: backtrace_symbols");
        TEMP_FAILURE_RETRY(write(STDERR_FILENO,"failure: backtrace_symbols\n",28));
        TEMP_FAILURE_RETRY(write(CRLOG,"failure: backtrace_symbols\n",28));
        close(CRLOG);
        exit(EXIT_FAILURE);
    }
    
    
    //FAT_("  [%d] Traceback:",sig );
    TEMP_FAILURE_RETRY(write(STDERR_FILENO,"Traceback:\n",11));
    TEMP_FAILURE_RETRY(write(CRLOG,"Traceback:\n",11));

     for( i = 0; i < size; i++ ) {
//         //FAT_("  [%d] %s", sig, strings[i] );
         TEMP_FAILURE_RETRY(write(STDERR_FILENO,"    ",4));
         TEMP_FAILURE_RETRY(write(CRLOG,"    ",4));
         TEMP_FAILURE_RETRY(write(STDERR_FILENO,strings[i],mystrlen(strings[i],256)));
         TEMP_FAILURE_RETRY(write(CRLOG,strings[i],mystrlen(strings[i],256)));
         TEMP_FAILURE_RETRY(write(STDERR_FILENO,"\n",1));
         TEMP_FAILURE_RETRY(write(CRLOG,"\n",1));
     }
    //backtrace_symbols_fd((void* const*)strings,64,STDERR_FILENO);
    
    //FAT_("  [%d] =================================================", sig );
    TEMP_FAILURE_RETRY(write(STDERR_FILENO," ===============================================\n",50));
    TEMP_FAILURE_RETRY(write(CRLOG," ===============================================\n",50));
    close(CRLOG);
    
    daemon_unlink_pidfile();
    
    free(strings);
    exit(-1);
}
*/


#define UNW_LOCAL_ONLY
#include <libunwind.h>
#include <stdio.h>

static void uw_btrace_handler(int sig) {
    unw_cursor_t cursor; unw_context_t uc;
    unw_word_t ip, sp;

    unw_getcontext(&uc);
    unw_init_local(&cursor, &uc);
    
    int CRLOG = open((const char*)crashlog_file,O_CREAT | O_WRONLY | O_TRUNC,S_IRUSR|S_IWUSR);
    TEMP_FAILURE_RETRY(write(STDERR_FILENO," ======== Smithproxy exception handler =========\n",50));
    TEMP_FAILURE_RETRY(write(CRLOG," ======== Smithproxy exception handler =========\n",50));
    //FAT_("  [%d] ========= Smithproxy exception handler  =========",sig );

    void *trace[64];
    size_t size, i;
    char **strings;

    size    = backtrace( trace, 64 );
    strings = backtrace_symbols( trace, size );

    if (strings == NULL) {
        //FATS_("failure: backtrace_symbols");
        TEMP_FAILURE_RETRY(write(STDERR_FILENO,"failure: backtrace_symbols\n",28));
        TEMP_FAILURE_RETRY(write(CRLOG,"failure: backtrace_symbols\n",28));
        close(CRLOG);
        exit(EXIT_FAILURE);
    }
    
    
    //FAT_("  [%d] Traceback:",sig );
    TEMP_FAILURE_RETRY(write(STDERR_FILENO,"Traceback:\n",11));
    TEMP_FAILURE_RETRY(write(CRLOG,"Traceback:\n",11));

    while (unw_step(&cursor) > 0) {
        char buf_line[256];
        memset(buf_line,0,256);
        char buf_fun[256];
        memset(buf_fun,0,256);

        unw_word_t  offset;
        unw_get_proc_name(&cursor, buf_fun, sizeof(buf_fun), &offset);
        unw_get_reg(&cursor, UNW_REG_IP, &ip);
        unw_get_reg(&cursor, UNW_REG_SP, &sp);
        
        snprintf (buf_line, 255, "ip = %lx, sp = %lx: (%s+0x%x) [%p]\n", (long) ip, (unsigned long) sp, buf_fun, (unsigned int) offset, (void*)ip);
        int n = strnlen(buf_line,255);
         TEMP_FAILURE_RETRY(write(CRLOG,buf_line,n));
         TEMP_FAILURE_RETRY(write(STDERR_FILENO,buf_line,n));
    }
    
    TEMP_FAILURE_RETRY(write(STDERR_FILENO," ===============================================\n",50));
    TEMP_FAILURE_RETRY(write(CRLOG," ===============================================\n",50));
    close(CRLOG);
    
    daemon_unlink_pidfile();
    
    free(strings);
    exit(-1);
}

void my_terminate (int param) {
    
    if (!cfg_daemonize)
    printf("Terminating ...\n");
    if (plain_proxy != nullptr) {
        plain_proxy->dead(true);
    }
    if(ssl_proxy != nullptr) {
        ssl_proxy->dead(true);
    }
    if(udp_proxy != nullptr) {
        udp_proxy->dead(true);
    }
    if(socks_proxy != nullptr) {
        socks_proxy->dead(true);
    }

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

bool load_config(std::string& config_f, bool reload = false);
void my_usr1 (int param) {
    DIAS_("USR1 signal handler started");
    NOTS_("reloading policies and its objects !!");
    load_config(config_file,true);
    DIAS_("USR1 signal handler finished");
}

static struct option long_options[] =
    {
    /* These options set a flag. */
    {"debug",   no_argument,       &args_debug_flag, DEB},
    {"diagnose",   no_argument,       &args_debug_flag, DIA},
    {"dump",   no_argument,       &args_debug_flag, DUM},
    {"extreme",   no_argument,       &args_debug_flag, EXT},
    
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


template <class Listener, class Com>
Listener* prepare_listener(std::string& str_port,const char* friendly_name,int def_port,int sub_workers) {
    
    if(sub_workers < 0) {
        return nullptr;
    }
    
    int port = def_port;
    
    if(str_port.size()) {
        try {
         port = std::stoi(str_port);
        }
        catch(std::invalid_argument e) {
            ERR_("Invalid port specified: %s",str_port.c_str());
            return NULL;
        }
    }
    
    NOT_("Entering %s mode on port %d",friendly_name,port);
    auto s_p = new Listener(new Com());
    s_p->com()->nonlocal_dst(true);
    s_p->worker_count_preference(sub_workers);

    // bind with master proxy (.. and create child proxies for new connections)
    int s = s_p->bind(port,'L');
    if (s < 0) {
        FAT_("Error binding %s port (%d), exiting",friendly_name,s);
        delete s_p;
        return NULL;
    };
    
    return s_p;
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

bool load_config(std::string& config_f, bool reload) {
    bool ret = true;
    
    using namespace libconfig;
    if(! cfgapi_init(config_f.c_str()) ) {
        FATS_("Unable to load config.");
        ret = false;
    }
    
    
    // Add another level of lock. File is already loaded. We need to apply its content.
    // lock is needed here to not try to match against potentially empty/partial policy list
    std::lock_guard<std::recursive_mutex> l(cfgapi_write_lock);
    try {
        
        if(reload) {
            cfgapi_cleanup();
        }
        
        cfgapi_load_obj_address();
        cfgapi_load_obj_port();
        cfgapi_load_obj_proto();
        cfgapi_load_obj_profile_detection();
        cfgapi_load_obj_profile_content();
        cfgapi_load_obj_profile_tls();
        cfgapi_load_obj_profile_auth();
        cfgapi_load_obj_profile_alg_dns();
        
        cfgapi_load_obj_policy();
        
        
        if(!reload)  {
            load_signatures(cfgapi,"detection_signatures",sigs_detection);
            load_signatures(cfgapi,"starttls_signatures",sigs_starttls);
        }
        
        cfgapi.getRoot()["settings"].lookupValue("certs_path",SSLCertStore::certs_path);
        cfgapi.getRoot()["settings"].lookupValue("certs_ca_key_password",SSLCertStore::password);
        cfgapi.getRoot()["settings"].lookupValue("certs_ca_path",SSLCertStore::def_cl_capath);
        
        cfgapi.getRoot()["settings"].lookupValue("plaintext_port",cfg_listen_port);
        cfgapi.getRoot()["settings"].lookupValue("plaintext_workers",cfg_tcp_workers);
        cfgapi.getRoot()["settings"].lookupValue("ssl_port",cfg_ssl_listen_port);
        cfgapi.getRoot()["settings"].lookupValue("ssl_workers",cfg_ssl_workers);
        cfgapi.getRoot()["settings"].lookupValue("ssl_autodetect",MitmMasterProxy::ssl_autodetect);
        cfgapi.getRoot()["settings"].lookupValue("ssl_autodetect_harder",MitmMasterProxy::ssl_autodetect_harder);
        
        cfgapi.getRoot()["settings"].lookupValue("udp_port",cfg_udp_port);
        cfgapi.getRoot()["settings"].lookupValue("udp_workers",cfg_udp_workers);

        cfgapi.getRoot()["settings"].lookupValue("socks_port",cfg_socks_port);
        cfgapi.getRoot()["settings"].lookupValue("socks_workers",cfg_socks_workers);
        
        cfgapi.getRoot()["settings"].lookupValue("log_level",cfgapi_table.logging.level);
        
        cfgapi.getRoot()["debug"].lookupValue("log_data_crc",baseCom::debug_log_data_crc);
        cfgapi.getRoot()["debug"].lookupValue("log_sockets",baseHostCX::socket_in_name);
        cfgapi.getRoot()["debug"].lookupValue("log_online_cx_name",baseHostCX::online_name);
        cfgapi.getRoot()["debug"].lookupValue("log_srclines",lout.print_srcline());
        cfgapi.getRoot()["debug"].lookupValue("log_srclines_always",lout.print_srcline_always());
        
        if(cfgapi.getRoot().exists("settings")) {
            cfgapi.getRoot()["settings"]["auth_portal"].lookupValue("magic_ip",cfgapi_tenant_magic_ip);
        }
        
        cfgapi.getRoot()["debug"]["log"].lookupValue("sslcom",SSLCom::log_level_ref());
        cfgapi.getRoot()["debug"]["log"].lookupValue("sslmitmcom",SSLMitmCom::log_level_ref());
        cfgapi.getRoot()["debug"]["log"].lookupValue("sslcertstore",SSLCertStore::log_level_ref());
        cfgapi.getRoot()["debug"]["log"].lookupValue("proxy",baseProxy::log_level_ref());
        cfgapi.getRoot()["debug"]["log"].lookupValue("mtrace",cfg_mtrace_enable);
        /*DNS ALG EXPLICIT LOG*/
        cfgapi.getRoot()["debug"]["log"].lookupValue("alg_dns",DNS_Inspector::log_level_ref());
        cfgapi.getRoot()["debug"]["log"].lookupValue("alg_dns",DNS_Packet::log_level_ref());
        
        cfgapi.getRoot()["settings"]["cli"].lookupValue("port",cli_port);
        cfgapi.getRoot()["settings"]["cli"].lookupValue("enable_password",cli_enable_password);
        
        // don't mess with logging if just reloading
        if(! reload) {
            std::string log_target;
            bool log_console;
            
            //init crashlog file with dafe default
            strcpy((char*)crashlog_file,"/tmp/smithproxy_crash.log");
            
            if(cfgapi.getRoot()["settings"].lookupValue("log_file",log_target)) {
                
                
                log_target = string_format(log_target,cfgapi_tenant_name.c_str());
                // prepare custom crashlog file
                std::string crlog = log_target + ".crashlog.log";
                memset((void*)crashlog_file,0,LOG_FILENAME_SZ);
                strncpy((char*)crashlog_file,crlog.c_str(),LOG_FILENAME_SZ-1);
                
                std::ofstream * o = new std::ofstream(log_target.c_str(),std::ios::app);
                lout.targets(log_target,o);
                lout.dup2_cout(false);
                lout.level(cfgapi_table.logging.level);
                
                logger_profile* lp = new logger_profile();
                lp->print_srcline_ = lout.print_srcline();
                lp->print_srcline_always_ = lout.print_srcline_always();
                lp->level_ = cfgapi_table.logging.level;
                lout.target_profiles()[(uint64_t)o] = lp;
                
                if(cfgapi.getRoot()["settings"].lookupValue("log_console",log_console)) {
                    lout.dup2_cout(log_console);
                }
            }
        }
    }
    catch(const SettingNotFoundException &nfex) {
    
        FAT_("Setting not found: %s",nfex.getPath());
        ret = false;
    }
    
    return ret;
}

void ignore_sigpipe() {
    struct sigaction act_segv;
    sigemptyset(&act_segv.sa_mask);
    act_segv.sa_flags = 0;
    act_segv.sa_handler = uw_btrace_handler;
    sigaction( SIGSEGV, &act_segv, NULL);
}

int apply_index(std::string& what , const std::string& idx) {
    DEB_("apply_index: what=%s idx=%s",what.c_str(),idx.c_str());
    int port = std::stoi(what);
    int index = std::stoi(idx);
    what = std::to_string(port + index);
    
    return 0;
}

bool apply_tenant_config() {
    int ret = 0;
    
    if(cfg_tenant_index.size() > 0 && cfg_tenant_name.size() > 0) {
        ret += apply_index(cfg_listen_port,cfg_tenant_index);
        ret += apply_index(cfg_ssl_listen_port,cfg_tenant_index);
        ret += apply_index(cfg_udp_port,cfg_tenant_index);
        ret += apply_index(cfg_socks_port,cfg_tenant_index);
        ret += apply_index(cfgapi_identity_portal_port_http,cfg_tenant_index);
        ret += apply_index(cfgapi_identity_portal_port_https,cfg_tenant_index);
        
        cli_port += std::stoi(cfg_tenant_index);
    }
    
    return (ret == 0);
}

int main(int argc, char *argv[]) {

    config_file = "/etc/smithproxy/smithproxy.cfg";
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
                config_file = std::string(optarg);    
                custom_config_file = true;
                break;      
                
            case 'o':
                config_file_check_only = true;
                
            case 'D':
                cfg_daemonize = true;
                break;
                
            case 'i':
                cfg_tenant_index = std::string(optarg);
                break;
                
            case 't':
                cfg_tenant_name = std::string(optarg);
                break;

                
            case 'v':
                std::cout << SMITH_VERSION << "+" << SOCLE_VERSION << std::endl;
                exit(0);
                
                
            default:
                ERR_("unknown option: '%c'",c);
                exit(1);                 
        }
    }
    
    lout.level(WAR);
    cfgapi_log_version(false);  // don't delay, but display warning
    
    if(cfg_tenant_index.size() > 0 && cfg_tenant_name.size() > 0) {
        WAR_("Starting tenant: '%s', index %s",cfg_tenant_name.c_str(),cfg_tenant_index.c_str());

        daemon_set_tenant(cfg_tenant_name);
        cfgapi_tenant_index = std::stoi(cfg_tenant_index);
        cfgapi_tenant_name  = cfg_tenant_name;
    } 
    else if (cfg_tenant_index.size() > 0 || cfg_tenant_name.size() > 0){
        
        FATS_("You have to specify both options: --tenant-name AND --tenant-index");
        exit(-20);
    }
    else {
        WARS_("Starting tenant: 0 (default)");
        daemon_set_tenant("0"); 
    }
    
    
    // if logging set in cmd line, use it 
    if(args_debug_flag > NON) {
        lout.level(args_debug_flag);
    }
        
        
    if(! custom_config_file and cfgapi_tenant_index > 0) {
        // look for tenant config (no override set)
        
        std::string tenant_cfg = string_format(config_file_tenant.c_str(),cfgapi_tenant_name.c_str());
        
        struct stat s;
        if (stat(tenant_cfg.c_str(),&s) == 0) {
            WAR_("Tenant config: %s",tenant_cfg.c_str());
            config_file = tenant_cfg;
        } else {
            WAR_("Tenant config %s not found. Using default.",tenant_cfg.c_str());
        }
    }
    
    WARS_(" ");
    // set level to what's in the config
    if (!load_config(config_file)) {
        if(config_file_check_only) {
            FATS_("Config check: error loading config file.");
            exit(1);
        }
        else {
            FATS_("Error loading config file on startup.");
            exit(1);
        }
    }
    
    if(!apply_tenant_config()) {
        FATS_("Failed to apply tenant specific configuration!");
        exit(2);
    }
    
    if(config_file_check_only) {
        DIAS_("Exiting, asked to check config file only.");
        exit(0);
    }

    if(cfg_mtrace_enable) {
        putenv("MALLOC_TRACE=/var/log/smithproxy_mtrace.log");
        mtrace();
    }

    
    // if there is loglevel specified in config file and is bigger than we currently have set, use it
    if(cfgapi_table.logging.level > lout.level()) {
        lout.level(cfgapi_table.logging.level);
    }
    
    if(daemon_exists_pidfile()) {
        FATS_("There is PID file already in the system.");
        FAT_("Please make sure smithproxy is not running, remove %s and try again.",PID_FILE.c_str());
        exit(-5);
    }
    
    if(cfg_daemonize) {
        if(lout.targets().size() <= 0) {
            FATS_("Cannot daemonize without logging to file.");
            exit(-5);
        }
        
        lout.dup2_cout(false);
        INFS_("entering daemon mode");
        daemonize();
    }
    // write out PID file
    daemon_write_pidfile();

    
    //     atexit(__libc_freeres);    
    //     CRYPTO_malloc_debug_init();
    //     CRYPTO_dbg_set_options(V_CRYPTO_MDEBUG_ALL);
    CRYPTO_mem_ctrl(CRYPTO_MEM_CHECK_ON);

    std::string friendly_thread_name_tcp = string_format("sxy_tcp_%d",cfgapi_tenant_index);
    std::string friendly_thread_name_udp = string_format("sxy_udp_%d",cfgapi_tenant_index);
    std::string friendly_thread_name_tls = string_format("sxy_tls_%d",cfgapi_tenant_index);
    std::string friendly_thread_name_skx = string_format("sxy_skx_%d",cfgapi_tenant_index);
    std::string friendly_thread_name_cli = string_format("sxy_cli_%d",cfgapi_tenant_index);
    std::string friendly_thread_name_own = string_format("sxy_own_%d",cfgapi_tenant_index);

    plain_proxy = prepare_listener<theAcceptor,TCPCom>(cfg_listen_port,"plain-text",50080,cfg_tcp_workers);
    ssl_proxy = prepare_listener<theAcceptor,MySSLMitmCom>(cfg_ssl_listen_port,"SSL",50443,cfg_ssl_workers);
    udp_proxy = prepare_listener<theReceiver,UDPCom>(cfg_udp_port,"plain-udp",50080,cfg_udp_workers);
    socks_proxy = prepare_listener<socksAcceptor,socksTCPCom>(cfg_socks_port,"socks",1080,cfg_socks_workers);
    
    if( (plain_proxy == nullptr && cfg_tcp_workers >= 0) || 
        (ssl_proxy == nullptr && cfg_ssl_workers >= 0)   || 
        (udp_proxy == nullptr && cfg_udp_workers >= 0 )  || 
        (socks_proxy == nullptr && cfg_socks_workers >= 0)    ) {
        
        FATS_("Failed to setup proxies. Bailing!");
        exit(-1);
    }
    
    // install signal handler, we do want to release the memory properly
        // signal handler installation
    void (*prev_fn)(int);
    prev_fn = signal (SIGTERM,my_terminate);
    if (prev_fn==SIG_IGN) signal (SIGTERM,SIG_IGN);

    prev_fn = signal (SIGINT,my_terminate);
    if (prev_fn==SIG_IGN) signal (SIGINT,SIG_IGN);

    prev_fn = signal(SIGABRT, uw_btrace_handler);
    if (prev_fn==SIG_IGN) signal (SIGABRT,SIG_IGN);
    
    prev_fn = signal(SIGUSR1, my_usr1);
    if (prev_fn==SIG_IGN) signal (SIGUSR1,SIG_IGN);


    ignore_sigpipe();
    
//     struct sigaction act_pipe;
//     sigemptyset(&act_pipe.sa_mask);    
//     sigaction( SIGPIPE, &act_pipe, NULL);
//     

    if(plain_proxy) {
        INFS_("Starting TCP listener");
        plain_thread = new std::thread([]() { 
            ignore_sigpipe();
            DIA_("smithproxy_tcp: max file descriptors: %d",daemon_get_limit_fd());
            
            plain_proxy->run(); 
            DIAS_("plaintext workers torn down."); 
            plain_proxy->shutdown(); 
        } );
        pthread_setname_np(plain_thread->native_handle(),friendly_thread_name_tcp.c_str());
    }
    
    if(ssl_proxy) {
        INFS_("Starting TLS listener");        
        ssl_thread = new std::thread([] () { 
            ignore_sigpipe();
            daemon_set_limit_fd(0);
            DIA_("smithproxy_tls: max file descriptors: %d",daemon_get_limit_fd());
            
            ssl_proxy->run(); 
            DIAS_("ssl workers torn down."); 
            ssl_proxy->shutdown();  
        } );    
        pthread_setname_np(ssl_thread->native_handle(),friendly_thread_name_tls.c_str());
    }

    if(udp_proxy) {
        INFS_("Starting UDP listener");        
        udp_thread = new std::thread([] () {
            ignore_sigpipe();
            daemon_set_limit_fd(0);
            DIA_("smithproxy_udp: max file descriptors: %d",daemon_get_limit_fd());
            
            udp_proxy->run(); 
            DIAS_("udp workers torn down."); 
            udp_proxy->shutdown();  
        } );       
        pthread_setname_np(udp_thread->native_handle(),friendly_thread_name_udp.c_str());
    }
    
    if(socks_proxy) {
        INFS_("Starting SOCKS5 listener");
        socks_thread = new std::thread([] () { 
            ignore_sigpipe();
            daemon_set_limit_fd(0);
            DIA_("smithproxy_skx: max file descriptors: %d",daemon_get_limit_fd());
            
            socks_proxy->run(); 
            DIAS_("socks workers torn down."); 
            socks_proxy->shutdown();  
        } );   
        pthread_setname_np(socks_thread->native_handle(),friendly_thread_name_skx.c_str());
    }

    cli_thread = new std::thread([] () { 
        INFS_("Starting CLI");
        ignore_sigpipe();
        DIA_("smithproxy_cli: max file descriptors: %d",daemon_get_limit_fd());
        
        cli_loop(cli_port);
        DIAS_("cli workers torn down."); 
    } );      
    pthread_setname_np(cli_thread->native_handle(),friendly_thread_name_cli.c_str());
    
    CRI_("Smithproxy %s (socle %s) started",SMITH_VERSION,SOCLE_VERSION);
    
    pthread_setname_np(pthread_self(),friendly_thread_name_own.c_str());
    
    if(plain_thread) {
        plain_thread->join();
    }
    if(ssl_thread) {
        ssl_thread->join();
    }
    if(udp_thread) {
        udp_thread->join();
    }    
    if(socks_thread) {
        socks_thread->join();
    }        

    if(plain_thread)
        delete plain_thread;
    if(ssl_thread)
        delete ssl_thread;
    if(udp_thread)
        delete udp_thread;
    if(socks_thread)
        delete socks_thread;
    
    DIAS_("Debug SSL statistics: ");
    DIA_("SSL_accept: %d",SSLCom::counter_ssl_accept);
    DIA_("SSL_connect: %d",SSLCom::counter_ssl_connect);

    cfgapi_cleanup();

    SSLCom::certstore()->destroy();
    
    if(cfg_daemonize) {    
        daemon_unlink_pidfile();
    }
    
    CRYPTO_cleanup_all_ex_data();
    ERR_free_strings();
    ERR_remove_state(0);
    EVP_cleanup();     
}

