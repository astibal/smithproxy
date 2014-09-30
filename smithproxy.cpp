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

std::vector<duplexFlowMatch*> sigs_starttls;
std::vector<duplexFlowMatch*> sigs_detection;




class MySSLMitmCom : public SSLMitmCom {
public:
    virtual ~MySSLMitmCom() {};
    
    
    
       virtual baseCom* replicate() { return new SSLMitmCom(); };    
       virtual bool spoof_cert(X509* x) {
           log().append("\n ==== Server certificate:\n" + SSLCertStore::print_cert(x) + "\n ====\n");
           bool r = SSLMitmCom::spoof_cert(x);
           
           
           return r;
       }
};


class MyDuplexFlowMatch : public duplexFlowMatch {
    
public:    
    std::string sig_side;
    std::string category;
};

class MitmHostCX : public AppHostCX {
public:
	
    
    virtual ~MitmHostCX() {};
    
	// surprise, constructor filling hostname and port
	MitmHostCX(baseCom* c, const char* h, const char* p ) : AppHostCX::AppHostCX(c,h,p) {
		DEB_("MitmHostCX: constructor %s:%s",h,p);
        load_signatures();
	};
	MitmHostCX( baseCom* c, int s ) : AppHostCX::AppHostCX(c,s) {
		DEB_("MitmHostCX: constructor %d",s);
        load_signatures();
	};
	
    virtual int process() {
		
		// incoming data are in the readbuf
		unsigned char *ptr = baseHostCX::readbuf()->data();
		unsigned int len = baseHostCX::readbuf()->size();
		
		// our only processing: hex dup the payload to the log
		DEBS_("Incoming data(" + this->name() + "):\n" +hex_dump(ptr,len));
		
		//  read buffer will be truncated by 'len' bytes. Note: truncated bytes are LOST.
		return len;
	};
    
    virtual void load_signatures() {
        
        DEBS_("MitmHostCX::load_signatures: start");
        
        zip_signatures(starttls_sensor(),sigs_starttls);
        zip_signatures(sensor(),sigs_detection);
        
        DEBS_("MitmHostCX::load_signatures: stop");
    };

    virtual void on_detect(duplexFlowMatch* x_sig, flowMatchState& s, vector_range& r) {
        
        MyDuplexFlowMatch* sig_sig = (MyDuplexFlowMatch*)x_sig;

        WAR_("Connection from %s matching signature: cat='%s', name='%s'",this->full_name('L').c_str(), sig_sig->category.c_str(), sig_sig->name().c_str());
        DEB_("Connection from %s matching signature: cat='%s', name='%s' at %s",this->full_name('L').c_str(), sig_sig->category.c_str(), sig_sig->name().c_str(), vrangetos(r).c_str());
        
        this->log().append( string_format("\nDetected application: cat='%s', name='%s'\n",sig_sig->category.c_str(), sig_sig->name().c_str()));
    }
    
    
    virtual void on_starttls() {
        DIAS_("we should now handover myself to SSL worker");
        
        // we know this side is client
//         delete com();
//         delete peercom();

        com_ = new MySSLMitmCom();
        com()->init();
        
        peer()->com_ = new SSLMitmCom();
        peer(peer()); // this will re-init
        peer()->peer(this);
        
        DIAS_("peers set");
        
        // set flag to wait for the peer to finish spoofing

        paused(true);
        ((SSLCom*)peercom())->upgrade_client_socket(peer()->socket());
        ((SSLCom*)com())->upgrade_server_socket(socket());        
        
        log().append("\n STARTTLS: plain connection upgraded to SSL/TLS, continuing with inspection.\n\n");
        
        DIAS_("on_starttls finished");
    }
};


/*
 now let's override baseProxy, and use on_left/right_bytes method!
 this proxy is working with *already accepted* sockets

 basically Proxy class recognizes LEFT and RIGHT side. You can organize those contexts on both sides.
 it's up to you what will do with them, it doesn't have any particular technical meaning; it just 
 follows the principle that you are usually proxying 2 sides (most commonly clients with servers, but 
 left-right is more generic and follows common sense.
*/


class MyProxy : public baseProxy {
    
protected:
    trafLog tlog_;
    
    bool write_payload_ = false;
    
public:	
    bool write_payload(void) { return write_payload_; } 
    void write_payload(bool b) { write_payload_ = b; }
    
    trafLog& tlog() { return tlog_; }
    
	explicit MyProxy(baseCom* c) : baseProxy(c),
	tlog_(this) {
	};
    
	virtual ~MyProxy() {
		if(write_payload()) {
			DEBS_("MyProxy::destructor: syncing writer");

            for(typename std::vector<baseHostCX*>::iterator j = this->left_sockets.begin(); j != this->left_sockets.end(); ++j) {
                auto cx = (*j);
                if(cx->log().size()) {
                    tlog().write('L', cx->log());
                    cx->log() = "";
                }
            }               
            
            for(typename std::vector<baseHostCX*>::iterator j = this->right_sockets.begin(); j != this->right_sockets.end(); ++j) {
                auto cx = (*j);
                if(cx->log().size()) {
                    tlog().write('R', cx->log());
                    cx->log() = "";
                }
            }         
            
			tlog().left_write("Connection stop\n");
		}
	}
	
	// this virtual method is called whenever there are new bytes in any LEFT host context!
	virtual void on_left_bytes(baseHostCX* cx) {
		
        if(write_payload()) {
            if(cx->log().size()) {
                tlog().write('L', cx->log());
                cx->log() = "";
            }
            
            tlog().left_write(cx->to_read());
        }
        
		// because we have left bytes, let's copy them into all right side sockets!
		for(typename std::vector<baseHostCX*>::iterator j = this->right_sockets.begin(); j != this->right_sockets.end(); j++) {

			// to_read: returns readbuf's buffer "view" of previously processed bytes 
			// to_write: this is appending to caller's write buffer

			// next line therefore calls processing context to return new processed bytes (to_read is like to offer: I have new processed data, read it if you want)
			// those processed data will be wiped by next read() call, so let's now write them all to right socket!
			(*j)->to_write(cx->to_read());
		}
	};
	
	// let's make this one short
    virtual void on_right_bytes(baseHostCX* cx) {
        
        if(write_payload()) {
            if(cx->log().size()) {
                tlog().write('R',cx->log());
                cx->log() = "";
            }
            
            tlog().right_write(cx->to_read());
        }
        
		for(typename std::vector<baseHostCX*>::iterator j = this->left_sockets.begin(); j != this->left_sockets.end(); j++) {
			(*j)->to_write(cx->to_read());
		}
	}
	
	// ... and also when there is error on L/R side, claim the proxy DEAD. When marked dead, it will be safely 
	// closed by it's master proxy next cycle.
    virtual void on_left_error(baseHostCX* cx) { 
		DEB_("on_left_error[%s]: proxy marked dead",(this->error_on_read ? "read" : "write"));
		DUMS_(this->hr());
        
        if(write_payload()) {
            tlog().left_write("Client side connection closed: " + cx->name() + "\n");
        }
        

        INF_("Connection from %s closed, sent=%d/%dB received=%d/%dB, flags=%c",
                            cx->full_name('L').c_str(),
                                            cx->meter_read_count,cx->meter_read_bytes,
                                                                cx->meter_write_count, cx->meter_write_bytes,
                                                                            'L');
                                                                       
//         INF_("Proxy 0x%08x closed by client: sent=%d/%dB received=%d/%dB",this,cx->meter_read_count,cx->meter_read_bytes,
//              cx->meter_write_count, cx->meter_write_bytes);
		
		this->dead(true); 
	};
	
	virtual void on_right_error(baseHostCX* cx) { 
		DEB_("on_right_error[%s]: proxy marked dead",(this->error_on_read ? "read" : "write"));
        
        if(write_payload()) {
            tlog().right_write("Server side connection closed: " + cx->name() + "\n");
        }
        
//         INF_("Created new proxy 0x%08x from %s:%s to %s:%d",new_proxy,f,f_p, t,t_p );
        
		INF_("Connection from %s closed, sent=%d/%dB received=%d/%dB, flags=%c",
                              cx->full_name('R').c_str(), 
                                              cx->meter_write_count, cx->meter_write_bytes,
                                                              cx->meter_read_count,cx->meter_read_bytes,
                                                                      'R');
//         INF_("Proxy 0x%08x closed by server: sent=%d/%dB received=%d/%dB",this,cx->meter_write_count, cx->meter_write_bytes,
//                         cx->meter_read_count,cx->meter_read_bytes);
        
		this->dead(true); 
	};	
};


class MitmMasterProxy : public ThreadedAcceptorProxy<MyProxy> {

public:
    
    MitmMasterProxy(baseCom* c) : ThreadedAcceptorProxy< MyProxy >(c) {};
	
	virtual baseHostCX* new_cx(int s) { 
        auto r = new MitmHostCX(com()->replicate(),s);
        DEB_("Pausing new connection %s",r->c_name());
        r->paused(true);
		return r; 
	};	
	
    virtual void on_left_new(baseHostCX* just_accepted_cx) {
		// ok, we just accepted socket, created context for it (using new_cx) and we probably need ... 
		// to create child proxy and attach this cx to it.
		
		// NEW: whole method is reorganized 

		if(! just_accepted_cx->com()->nonlocal_resolved()) {
			ERRS_("Was not possible to resolve original destination!");
			just_accepted_cx->close();
			delete just_accepted_cx;
		} 
		else {
			MyProxy* new_proxy = new MyProxy(com()->replicate());
			
			// let's add this just_accepted_cx into new_proxy
            if(just_accepted_cx->paused()) {
                DEBS_("MitmMasterProxy::on_left_new: ldaadd the new paused cx");
                new_proxy->ldaadd(just_accepted_cx);
            } else{
                DEBS_("MitmMasterProxy::on_left_new: ladd the new cx (unpaused)");
                new_proxy->ladd(just_accepted_cx);
            }
			MitmHostCX *target_cx = new MitmHostCX(com()->replicate(), just_accepted_cx->com()->nonlocal_host().c_str(), 
											   string_format("%d",just_accepted_cx->com()->nonlocal_port()).c_str()
											  );
			// connect it! - btw ... we don't want to block of course...
            
            std::string h;
            std::string p;
            just_accepted_cx->name();
            just_accepted_cx->com()->resolve_socket_src(just_accepted_cx->socket(),&h,&p);
            
//          // Keep it here: would be good if we can do something like this in the future
//            
//          DIA_("About to name socket after: %s:%s",h.c_str(),p.c_str());
//          int bind_status = target_cx->com()->namesocket(target_cx->socket(),h,(unsigned short) std::stoi(p));
// 			if (bind_status != 0) {
//                 
//                 char abc[256];
//                 
//                 strerror_r(bind_status,abc,255);
//                 DIA_("cannot bind this port: %s",abc);
//             }
            target_cx->connect(false);

            just_accepted_cx->peer(target_cx);
            target_cx->peer(just_accepted_cx);

            ((AppHostCX*)just_accepted_cx)->mode(AppHostCX::MODE_PRE);
            target_cx->mode(AppHostCX::MODE_NONE);
                        
			//NEW: end of new
			
			// almost done, just add this target_cx to right side of new proxy
			new_proxy->radd(target_cx);

            
            if(new_proxy->write_payload()) {
                new_proxy->tlog().left_write("Connection start\n");
            }
            
			// FINAL point: adding new child proxy to the list
			this->proxies().push_back(new_proxy);
            
            INF_("Connection from %s established", just_accepted_cx->full_name('L').c_str());
		}
		
		DEBS_("MitmMasterProxy::on_left_new: finished");
	}

	virtual int handle_sockets_once(baseCom* c) {
        //T_DIAS_("slist",5,this->hr()+"\n===============\n");
		
		return ThreadedAcceptorProxy<MyProxy>::handle_sockets_once(c);
	}

};

typedef ThreadedAcceptor<MitmMasterProxy,MyProxy> theAcceptor;
typedef ThreadedReceiver<ThreadedReceiverProxy<MyProxy>,MyProxy> theReceiver;

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
    Config cfg;
    
    DIAS_("Reading config file");
    
    // Read the file. If there is an error, report it and exit.
    try {
        cfg.readFile(config_f.c_str());
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
        load_signatures(cfg,"starttls_signatures",sigs_starttls);
        load_signatures(cfg,"detection_signatures",sigs_detection);
        
        cfg.getRoot()["settings"].lookupValue("certs_path",SSLCertStore::certs_path);
        cfg.getRoot()["settings"].lookupValue("certs_ca_key_password",SSLCertStore::password);
        cfg.getRoot()["settings"].lookupValue("plaintext_port",cfg_listen_port);
        cfg.getRoot()["settings"].lookupValue("ssl_port",cfg_ssl_listen_port);
        cfg.getRoot()["settings"].lookupValue("udp_port",cfg_udp_port);
        cfg.getRoot()["settings"].lookupValue("log_level",cfg_log_level);
        cfg.getRoot()["debug"].lookupValue("log_data_crc",baseCom::debug_log_data_crc);
    }
    catch(const SettingNotFoundException &nfex) {
    
        FATS_("Setting not found: %s",nfex.getPath());
        exit(-66);
    }
}

int main(int argc, char *argv[]) {
    
    config_file = "etc/smithproxy.cfg";
    
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
        DIAS_("ssl workers torn down."); 
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
}

