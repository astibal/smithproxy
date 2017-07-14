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
#include <ostream>
#include <ios>

#include <getopt.h>

#include <socle.hpp>

#include <logger.hpp>
#include <hostcx.hpp>
#include <baseproxy.hpp>
#include <masterproxy.hpp>
#include <threadedacceptor.hpp>
#include <display.hpp>

#include <smithproxy.hpp>
#include <display.hpp>

#include <libconfig.h++>

#include <daemon.hpp>
#include <srvutils.hpp>
#include <smithlog.hpp>

#include <smithdcx.hpp>

#define MEM_DEBUG 1
#ifdef MEM_DEBUG
    #include <mcheck.h>
#endif


class SmithServerCX : public SmithProtoCX {
public:
    SmithServerCX(baseCom* c, unsigned int s) : SmithProtoCX(c,s) {};
    SmithServerCX(baseCom* c, const char* h, const char* p) : SmithProtoCX(c,h,p) {};
    virtual ~SmithServerCX() {};
    
    virtual void process_package(LTVEntry* e) {
        DEB_("Package dump: \n%s",e->hr().c_str());
        
        
        LTVEntry* m = e->search({CL_REQTYPE});
        if(m && m->data_int() == RQT_RATEURL) {
        
            LTVEntry* rating_rq = e->search({CL_PAYLOAD,RQT_RATEURL});
            if(rating_rq) {
                INF_("found rating URI: %s",rating_rq->data_str().c_str());
                
                LTVEntry* resp = pkg_rating_response(111);
                resp->pack();
                
                send(resp);
                
                delete resp;
                
            } else {
                ERRS_("No payload or rating URL entry.");
                LTVEntry* resp = pkg_error_response("nothing to rate");
                resp->pack();
                send(resp);
                
                delete resp;
            }
            
        } else if (m && false) {
            /*another ID*/
        } else {
            if(m) {
                ERR_("Unsupported request type %d", m->id());
            } else {
                ERRS_("Request type unspecified, ignoring message.");
            }
            
            LTVEntry* resp = pkg_error_response("unknown request");
            resp->pack();
            send(resp);
            
            delete resp;
        }
    };
    
    
    LTVEntry* pkg_error_response(const char* text = nullptr) {
        LTVEntry* e = new LTVEntry();
        e->container(CL_INIT);
 
        LTVEntry* err = new LTVEntry();
        err->set_num(255,LTVEntry::num,255);
        e->add(err);
        
        if(text != nullptr) {
            LTVEntry* err2 = new LTVEntry();
            err2->set_str(254,LTVEntry::str,text);
            e->add(err2);
        }
        
        return e;
    }
    
    LTVEntry* pkg_rating_response(int category) {
        LTVEntry* e = new LTVEntry();
        e->container(CL_INIT);
        
        LTVEntry* r = new LTVEntry();
        r->container(RQT_RATEURL);
        
        LTVEntry* x = new LTVEntry();
        x->set_num(RATEURL_CAT,LTVEntry::num,category);
        r->add(x);
        
        e->add(r);
        
        return e;
    }
};


class SmithdProxy : public baseProxy {
public:
    SmithdProxy(baseCom* c) : baseProxy(c) {};
    virtual ~SmithdProxy() {};

    virtual void on_left_error(baseHostCX*) {  dead(true); };
    virtual void on_right_error(baseHostCX*) { dead(true); };    
    
    virtual void on_left_bytes(baseHostCX* cx) {
        INF_("Left %d bytes arrived to 0x%x",cx->readbuf()->size(), cx);
    }
};
    

class UxAcceptor : public ThreadedAcceptorProxy<SmithdProxy> {
public:
    UxAcceptor(baseCom* c, int worker_id) : ThreadedAcceptorProxy<SmithdProxy>(c,worker_id) {};
    
    virtual baseHostCX* new_cx(const char* h, const char* p) { return new SmithServerCX(com()->slave(),h,p); };
    virtual baseHostCX* new_cx(int s) { return new SmithServerCX(com()->slave(), s); };
    virtual void on_left_new(baseHostCX* cx) {
        SmithdProxy* p = new SmithdProxy(com()->slave());
        p->ladd(cx);
        this->proxies().push_back(p);
    }
};

typedef ThreadedAcceptor<UxAcceptor,SmithdProxy> UxProxy;

// running threads and their proxies

static UxProxy* backend_proxy = nullptr;
std::thread* backend_thread = nullptr;


// Configuration variables

static std::string config_file;
std::recursive_mutex merged_cfg_write_lock;
static bool cfg_daemonize = false;
static bool cfg_mtrace_enable = false;
static std::string cfg_log_file;
static int cfg_log_level = INF;
static int cfg_log_console = false;
static int cfg_smithd_workers = 0;
static std::string cfg_smithd_listen_port = "/var/run/smithd.sock";

// Various

volatile static int cnt_terminate = 0;
static int  args_debug_flag = NON;
bool config_file_check_only = false;


void my_terminate (int param) {
    
    if (!cfg_daemonize)
    printf("Terminating ...\n");
    if (backend_proxy != nullptr) {
        backend_proxy->dead(true);
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
            set_crashlog(crlog.c_str());
            
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

int main(int argc, char *argv[]) {
    
    PID_FILE="/var/run/smithd.pid";

    config_file = "/etc/smithproxy/smithd.cfg";
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
    
    set_logger(new QueueLogger());
    
    if(!cfg_daemonize) {
        std::thread* log_thread  = create_log_writer(get_logger());
        if(log_thread != nullptr) {
            pthread_setname_np(log_thread->native_handle(),"sxd_lwr");
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
        putenv("MALLOC_TRACE=/var/log/smithd_mtrace.log");
        mtrace();
    }
  
    if(daemon_exists_pidfile()) {
        FATS_("There is PID file already in the system.");
        FAT_("Please make sure smithd is not running, remove %s and try again.",PID_FILE.c_str());
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

    std::string friendly_thread_name_smithd = "sxy_smithd";

    backend_proxy = prepare_listener<UxProxy,UxCom>(cfg_smithd_listen_port,"plain-text","/var/run/smithd.sock",cfg_smithd_workers);
    
    if(backend_proxy == nullptr && cfg_smithd_workers >= 0) {
        
        FATS_("Failed to setup proxies. Bailing!");
        exit(-1);
    }

    set_daemon_signals(my_terminate,my_usr1);
    
    if(backend_proxy) {
        INFS_("Starting smithd listener");
        backend_thread = new std::thread([]() { 
            set_daemon_signals(my_terminate,my_usr1);
            DIA_("smithd: max file descriptors: %d",daemon_get_limit_fd());
            
            backend_proxy->run(); 
            DIAS_("smithd workers torn down."); 
            backend_proxy->shutdown(); 
        } );
        pthread_setname_np(backend_thread->native_handle(),friendly_thread_name_smithd.c_str());
    }
    
    
    CRI_("Smithd backend (smithproxy %s, socle %s)  started",SMITH_VERSION,SOCLE_VERSION);
    
    pthread_setname_np(pthread_self(),"smithd");
    
    if(backend_thread) {
        backend_thread->join();
    }

    if(backend_thread)
        delete backend_thread;
    
    // cleanup
    daemon_unlink_pidfile();
    unlink(cfg_smithd_listen_port.c_str());
}

 