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

#include <daemon.hpp>
#include <cmdserver.hpp>
#include <srvutils.hpp>


#define MEM_DEBUG 1
#ifdef MEM_DEBUG
    #include <mcheck.h>
#endif


extern "C" void __libc_freeres(void);

class UxAcceptor : public ThreadedAcceptorProxy<baseProxy> {
public:
    UxAcceptor(baseCom* c, int worker_id) : ThreadedAcceptorProxy< baseProxy>(c,worker_id) {};    
};

typedef ThreadedAcceptor<UxAcceptor,baseProxy> UxProxy;

// running threads and their proxies

static UxProxy* webr_proxy = nullptr;
std::thread* webr_thread = nullptr;


// Configuration variables

static std::string config_file;
std::recursive_mutex merged_cfg_write_lock;
static bool cfg_daemonize = false;
static bool cfg_mtrace_enable = false;
static std::string cfg_log_file;
static int cfg_log_level = INF;
static int cfg_log_console = false;
static int cfg_webr_workers = 0;
static std::string cfg_webr_listen_port = "/var/run/sxy_webr";

// Various

volatile static int cnt_terminate = 0;
static int  args_debug_flag = NON;
bool config_file_check_only = false;

#define LOG_FILENAME_SZ 512
volatile char crashlog_file[LOG_FILENAME_SZ];


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
    if (webr_proxy != nullptr) {
        webr_proxy->dead(true);
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
    
    {0, 0, 0, 0}
};  


bool load_config(std::string& config_f, bool reload) {
    bool ret = true;
    std::lock_guard<std::recursive_mutex> l(merged_cfg_write_lock);
    
    using namespace libconfig;
    Config cfgapi;

    DIAS_("Reading config file");
    
    // Read the file. If there is an error, report it and exit.
    try {
        cfgapi.readFile(config_f.c_str());
        
        if (cfgapi.getRoot()["settings"].lookupValue("log_file",cfg_log_file)) {
            
            std::string& log_target = cfg_log_file;
            // prepare custom crashlog file
            std::string crlog = log_target + ".crashlog.log";
            memset((void*)crashlog_file,0,LOG_FILENAME_SZ);
            strncpy((char*)crashlog_file,crlog.c_str(),LOG_FILENAME_SZ-1);
            
            std::ofstream * o = new std::ofstream(log_target.c_str(),std::ios::app);
            get_logger()->targets(log_target,o);
            get_logger()->dup2_cout(false);
            get_logger()->level(cfg_log_level);
            
            logger_profile* lp = new logger_profile();
            lp->print_srcline_ = get_logger()->print_srcline();
            lp->print_srcline_always_ = get_logger()->print_srcline_always();
            lp->level_ = cfg_log_level;
            get_logger()->target_profiles()[(uint64_t)o] = lp;
            
            if(cfgapi.getRoot()["settings"].lookupValue("log_console",cfg_log_console)) {
                get_logger()->dup2_cout(cfg_log_console);
            }        
        }

        cfgapi.getRoot()["settings"].lookupValue("log_level",cfg_log_level);
    }
    catch(const FileIOException &fioex)
    {
        ERR_("I/O error while reading config file: %s",config_f.c_str());
        ret = false;   
    }
    catch(const ParseException &pex)
    {
        ERR_("Parse error in %s at %s:%d - %s", config_f.c_str(), pex.getFile(), pex.getLine(), pex.getError());
        ret = false;
    }

    
    if(! ret ) {
        FATS_("Unable to load config.");
        return ret;
    }
    
    try {
        cfgapi.getRoot()["settings"].lookupValue("log_level",cfg_log_level);
        if(reload) {
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

int main(int argc, char *argv[]) {
    
    PID_FILE="/var/run/smithmerged.pid";

    config_file = "/etc/smithproxy/merged.cfg";
    bool custom_config_file = false;
    
    while(1) {
    /* getopt_long stores the option index here. */
        int option_index = 0;
    
        char c = getopt_long (argc, argv, "p:voDc",
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
                
            case 'v':
                std::cout << SMITH_VERSION << "+" << SOCLE_VERSION << std::endl;
                exit(0);
                
                
            default:
                ERR_("unknown option: '%c'",c);
                exit(1);                 
        }
    }
    
    get_logger()->level(WAR);
    
    // if logging set in cmd line, use it 
    if(args_debug_flag > NON) {
        get_logger()->level(args_debug_flag);
    }
        
    WARS_(" ");
    // set level to what's in the config
    if (!load_config(config_file)) {
        if(custom_config_file); // make compiler happy
        
        if(config_file_check_only) {
            FATS_("Config check: error loading config file.");
            exit(1);
        }
        else {
            FATS_("Error loading config file on startup.");
            exit(1);
        }
    }
    
    if(config_file_check_only) {
        DIAS_("Exiting, asked to check config file only.");
        exit(0);
    }

    if(cfg_mtrace_enable) {
        putenv("MALLOC_TRACE=/var/log/smithproxy_mtrace.log");
        mtrace();
    }
  
    if(daemon_exists_pidfile()) {
        FATS_("There is PID file already in the system.");
        FAT_("Please make sure smithproxy is not running, remove %s and try again.",PID_FILE.c_str());
        exit(-5);
    }
    
    if(cfg_daemonize) {
        if(get_logger()->targets().size() <= 0) {
            FATS_("Cannot daemonize without logging to file.");
            exit(-5);
        }
        
        get_logger()->dup2_cout(false);
        INFS_("entering daemon mode");
        daemonize();
    }
    // write out PID file
    daemon_write_pidfile();

    //     atexit(__libc_freeres);    
    //     CRYPTO_malloc_debug_init();
    //     CRYPTO_dbg_set_options(V_CRYPTO_MDEBUG_ALL);
    CRYPTO_mem_ctrl(CRYPTO_MEM_CHECK_ON);

    std::string friendly_thread_name_webr = "sxy_mer_webr";

    webr_proxy = prepare_listener<UxProxy,UxCom>(cfg_webr_listen_port,"plain-text","/var/run/sxy_webr",cfg_webr_workers);
    
    if(webr_proxy == nullptr && cfg_webr_workers >= 0) {
        
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
    
    if(webr_proxy) {
        INFS_("Starting webr listener");
        webr_thread = new std::thread([]() { 
            ignore_sigpipe();
            DIA_("smithproxy_webr: max file descriptors: %d",daemon_get_limit_fd());
            
            webr_proxy->run(); 
            DIAS_("webr workers torn down."); 
            webr_proxy->shutdown(); 
        } );
        pthread_setname_np(webr_thread->native_handle(),friendly_thread_name_webr.c_str());
    }
    
    
    CRI_("Smithproxy %s merged threads (socle %s)  started",SMITH_VERSION,SOCLE_VERSION);
    
    pthread_setname_np(pthread_self(),"sxy_merged");
    
    if(webr_thread) {
        webr_thread->join();
    }

    if(webr_thread)
        delete webr_thread;
    
    DIAS_("Debug SSL statistics: ");
    DIA_("SSL_accept: %d",SSLCom::counter_ssl_accept);
    DIA_("SSL_connect: %d",SSLCom::counter_ssl_connect);

    SSLCom::certstore()->destroy();
    
    if(cfg_daemonize) {    
        daemon_unlink_pidfile();
    }
    
    CRYPTO_cleanup_all_ex_data();
    ERR_free_strings();
    ERR_remove_state(0);
    EVP_cleanup();     
}

