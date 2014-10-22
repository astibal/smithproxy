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
#include <getopt.h>

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
#include <cfgapi.hpp>

extern "C" void __libc_freeres(void);

typedef ThreadedAcceptor<MitmMasterProxy,MyProxy> theAcceptor;
typedef ThreadedReceiver<MitmUdpProxy,MyProxy> theReceiver;

class MyPlainAcceptor : public theAcceptor {
};


// Now let's do the Ctrl-C magic
static theAcceptor* plain_proxy = NULL;
static theAcceptor* ssl_proxy = NULL;
static theReceiver* udp_proxy = NULL;

std::thread* plain_thread = NULL;
std::thread* ssl_thread = NULL;
std::thread* udp_thread = NULL;

void my_terminate (int param)
{
  FATS_("Terminating ...");
  if (plain_proxy != NULL) {
    plain_proxy->dead(true);
  }
  if(ssl_proxy != NULL) {
    ssl_proxy->dead(true);
  }
  if(udp_proxy != NULL) {
    udp_proxy->dead(true);
  }  
}


static int  args_debug_flag = NON;
// static int   ssl_flag = 0;
static std::string cfg_listen_port;
static std::string cfg_ssl_listen_port;
static std::string cfg_udp_port;

static std::string config_file;
static int cfg_log_level = INF;

static struct option long_options[] =
    {
    /* These options set a flag. */
    {"debug",   no_argument,       &args_debug_flag, DEB},
    {"diagnose",   no_argument,       &args_debug_flag, DIA},
    {"dump",   no_argument,       &args_debug_flag, DUM},
    {"extreme",   no_argument,       &args_debug_flag, EXT},
    
    {"config-file", required_argument, 0, 'c'},
    {0, 0, 0, 0}
};  


template <class Listener, class Com>
Listener* prepare_listener(std::string& str_port,const char* friendly_name,int def_port) {
    
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
    s_p->com()->nonlocal(true);

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
    const Setting& cfg_startrls_signatures = root[name];
    int sigs_starttls_len = cfg_startrls_signatures.getLength();

    
    DIA_("Loading %s: %d",name,sigs_starttls_len);
    for ( int i = 0 ; i < sigs_starttls_len; i++) {
        MyDuplexFlowMatch* newsig = new MyDuplexFlowMatch();
        
        
        const Setting& signature = cfg_startrls_signatures[i];
        signature.lookupValue("name", newsig->name());
        signature.lookupValue("side", newsig->sig_side);
        signature.lookupValue("cat", newsig->category);                

        const Setting& signature_flow = cfg_startrls_signatures[i]["flow"];
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
    
    return sigs_starttls_len;
}

void load_config(std::string& config_f) {
    using namespace libconfig;
    
    DIAS_("Reading config file");
    
    // Read the file. If there is an error, report it and exit.
    try {
        cfgapi.readFile(config_f.c_str());
    }
    catch(const FileIOException &fioex)
    {
        ERR_("I/O error while reading config file: %s",config_f.c_str());
        exit(-1);   
    }
    catch(const ParseException &pex)
    {
        ERR_("Parse error in %s at %s:%d - %s", config_f.c_str(), pex.getFile(), pex.getLine(), pex.getError());
        exit(-2);
    }
    
    
    try {
        load_signatures(cfgapi,"starttls_signatures",sigs_starttls);
        load_signatures(cfgapi,"detection_signatures",sigs_detection);
        
        cfgapi.getRoot()["settings"].lookupValue("certs_path",SSLCertStore::certs_path);
        cfgapi.getRoot()["settings"].lookupValue("certs_ca_key_password",SSLCertStore::password);
        cfgapi.getRoot()["settings"].lookupValue("plaintext_port",cfg_listen_port);
        cfgapi.getRoot()["settings"].lookupValue("ssl_port",cfg_ssl_listen_port);
        cfgapi.getRoot()["settings"].lookupValue("udp_port",cfg_udp_port);
        cfgapi.getRoot()["settings"].lookupValue("log_level",cfg_log_level);
        cfgapi.getRoot()["debug"].lookupValue("log_data_crc",baseCom::debug_log_data_crc);
        cfgapi.getRoot()["debug"].lookupValue("log_sockets",baseHostCX::socket_in_name);
    }
    catch(const SettingNotFoundException &nfex) {
    
        FATS_("Setting not found: %s",nfex.getPath());
        exit(-66);
    }
}

int main(int argc, char *argv[]) {
    
    atexit(__libc_freeres);
    config_file = "/etc/smithproxy/smithproxy.cfg";
    
//     CRYPTO_malloc_debug_init();
//     CRYPTO_dbg_set_options(V_CRYPTO_MDEBUG_ALL);
    
    CRYPTO_mem_ctrl(CRYPTO_MEM_CHECK_ON);
    
	// setting logging facility level to show banner :)
	lout.level(INF);
    
	CRI_("Starting Smithproxy %s (socle %s)",SMITH_VERSION,SOCLE_VERSION);
	
    while(1) {
    /* getopt_long stores the option index here. */
        int option_index = 0;
    
        char c = getopt_long (argc, argv, "p:",
                        long_options, &option_index);
        if (c < 0) break;

        switch(c) {
            case 0:
                break;
                
            case 'c':
                config_file = std::string(optarg);        
                break;                
                
            default:
               abort();                 
        }
    }

    // set level to what's in the config
    load_config(config_file);	
    
    // override config setting if CLI option is used
	lout.level(args_debug_flag > NON ? args_debug_flag : cfg_log_level );

    plain_proxy = prepare_listener<theAcceptor,TCPCom>(cfg_listen_port,"plain-text",50080);
    ssl_proxy = prepare_listener<theAcceptor,MySSLMitmCom>(cfg_ssl_listen_port,"SSL",50443);
    udp_proxy = prepare_listener<theReceiver,UDPCom>(cfg_udp_port,"plain-udp",50081);
    
    
	// install signal handler, we do want to release the memory properly
		// signal handler installation
	void (*prev_fn)(int);
	prev_fn = signal (SIGTERM,my_terminate);
	if (prev_fn==SIG_IGN) signal (SIGTERM,SIG_IGN);

	prev_fn = signal (SIGINT,my_terminate);
	if (prev_fn==SIG_IGN) signal (SIGINT,SIG_IGN);
	
    
    
    plain_thread = new std::thread([]() { 
        plain_proxy->run(); 
        DIAS_("plaintext workers torn down."); 
        plain_proxy->shutdown(); 
    } );
    
    ssl_thread = new std::thread([] () { 
        ssl_proxy->run(); 
        DIAS_("ssl workers torn down."); 
        ssl_proxy->shutdown();  
    } );    

    udp_thread = new std::thread([] () { 
        udp_proxy->run(); 
        DIAS_("udp workers torn down."); 
        udp_proxy->shutdown();  
    } );       
    
    if(plain_thread) {
        plain_thread->join();
    }
    if(ssl_thread) {
        ssl_thread->join();
    }
    if(udp_thread) {
        udp_thread->join();
    }    
    
    CRYPTO_cleanup_all_ex_data();
    ERR_free_strings();
    ERR_remove_state(0);
    EVP_cleanup();    
    
    auto s = new SSLCom();
    s->certstore()->destroy();
    delete s;
    
    delete plain_thread;
    delete ssl_thread;
    delete udp_thread;
    
    DIAS_("Debug SSL statistics: ");
    DIA_("SSL_accept: %d",SSLCom::counter_ssl_accept);
    DIA_("SSL_connect: %d",SSLCom::counter_ssl_connect);
    
    __libc_freeres();
}

