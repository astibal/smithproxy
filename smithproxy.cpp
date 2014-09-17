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

#include <csignal>
#include <ctime>
#include <getopt.h>

#include <proxylib.hpp>

#include <logger.hpp>
#include <hostcx.hpp>
#include <apphostcx.hpp>
#include <baseproxy.hpp>
#include <masterproxy.hpp>
#include <threadedproxy.hpp>
#include <sslcom.hpp>
#include <sslmitmcom.hpp>
#include <display.hpp>

#include <smithproxy.hpp>
#include <traflog.hpp>
#include <display.hpp>


duplexFlowMatch* sig_http_get;
duplexFlowMatch* sig_starttls_smtp;
duplexFlowMatch* sig_starttls_imap;
duplexFlowMatch* sig_starttls_pop3;
duplexFlowMatch* sig_starttls_ftp; //openssl s_client -host secureftp-test.com -port 21 -starttls ftp
duplexFlowMatch* sig_starttls_xmpp; //openssl s_client -connect isj3cmx.webexconnect.com:5222 -starttls xmpp

duplexFlowMatch* sig_virus_eicar;

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
        
        duplexStateSignature sig_test_http;
        
        sig_test_http.category = "www";
        sig_test_http.name = "http/get|post";

        // FIXME: following is just for the test only, signature will point to some VERY central storage
        //   !!! I am keeping this deliberately LEAKING, until central signature database is implemented
        sig_test_http.signature = sig_http_get;
        this->sensor().push_back(std::pair<duplexStateSignature,bool>(sig_test_http,false));
        
        duplexStateSignature sig_test_starttls_smtp;
        sig_test_starttls_smtp.category = "mail";
        sig_test_starttls_smtp.name = "smtp/starttls";    
        sig_test_starttls_smtp.signature = sig_starttls_smtp;
        this->starttls_sensor().push_back(std::pair<duplexStateSignature,bool>(sig_test_starttls_smtp,false));

        duplexStateSignature sig_test_starttls_imap;
        sig_test_starttls_imap.category = "mail";
        sig_test_starttls_imap.name = "imap/starttls";    
        sig_test_starttls_imap.signature = sig_starttls_imap;
        this->starttls_sensor().push_back(std::pair<duplexStateSignature,bool>(sig_test_starttls_imap,false));

        duplexStateSignature sig_test_starttls_pop3;
        sig_test_starttls_pop3.category = "mail";
        sig_test_starttls_pop3.name = "pop3/starttls";    
        sig_test_starttls_pop3.signature = sig_starttls_pop3;
        this->starttls_sensor().push_back(std::pair<duplexStateSignature,bool>(sig_test_starttls_pop3,false));

        duplexStateSignature sig_test_starttls_ftp;
        sig_test_starttls_ftp.category = "files";
        sig_test_starttls_ftp.name = "ftp/starttls";    
        sig_test_starttls_ftp.signature = sig_starttls_ftp;
        this->starttls_sensor().push_back(std::pair<duplexStateSignature,bool>(sig_test_starttls_ftp,false));

        duplexStateSignature sig_test_starttls_xmpp;
        sig_test_starttls_xmpp.category = "im";
        sig_test_starttls_xmpp.name = "xmpp/starttls";    
        sig_test_starttls_xmpp.signature = sig_starttls_xmpp;
        this->starttls_sensor().push_back(std::pair<duplexStateSignature,bool>(sig_test_starttls_xmpp,false));        
        
        
        duplexStateSignature sig_test_virus_eicar;
        sig_test_virus_eicar.category = "av";
        sig_test_virus_eicar.name = "virus/eicar";    
        sig_test_virus_eicar.signature = sig_virus_eicar;
        this->sensor().push_back(std::pair<duplexStateSignature,bool>(sig_test_virus_eicar,false));
        
        DEBS_("MitmHostCX::load_signatures: stop");
    };

    virtual void on_detect(duplexSignature& sig_sig, vector_range& r) {
        WAR_("Connection from %s matching signature: cat='%s', name='%s' at %s",this->full_name('L').c_str(), sig_sig.category.c_str(), sig_sig.name.c_str(), vrangetos(r).c_str());
        this->log().append( string_format("\nDetected application: cat='%s', name='%s'\n",sig_sig.category.c_str(), sig_sig.name.c_str()));
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
        

        INF_("Connection from %s closed, sent=%d/%dB received=%d/%dB",cx->full_name('L').c_str(),cx->meter_read_count,cx->meter_read_bytes,
             cx->meter_write_count, cx->meter_write_bytes);
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
        
		INF_("Connection from %s closed, sent=%d/%dB received=%d/%dB",cx->full_name('R').c_str(), cx->meter_write_count, cx->meter_write_bytes,
                        cx->meter_read_count,cx->meter_read_bytes);
//         INF_("Proxy 0x%08x closed by server: sent=%d/%dB received=%d/%dB",this,cx->meter_write_count, cx->meter_write_bytes,
//                         cx->meter_read_count,cx->meter_read_bytes);
        
		this->dead(true); 
	};	
};


class MitmMasterProxy : public ThreadedWorkerProxy<MyProxy> {

public:
    
    MitmMasterProxy(baseCom* c) : ThreadedWorkerProxy< MyProxy >(c) {};
	
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

	virtual int run_once() {
        //T_DIAS_("slist",5,this->hr()+"\n===============\n");
		
		return ThreadedWorkerProxy<MyProxy>::run_once();
	}

};

typedef ThreadedAcceptor<MitmMasterProxy,MyProxy> theAcceptor;
typedef ThreadedAcceptor<MitmMasterProxy,MyProxy> theSSLAcceptor;


class MyPlainAcceptor : public theAcceptor {
};


// Now let's do the Ctrl-C magic
static theAcceptor* plain_proxy = NULL;
static theSSLAcceptor* ssl_proxy = NULL;

std::thread* plain_thread = NULL;
std::thread* ssl_thread = NULL;

void my_terminate (int param)
{
  FATS_("Terminating ...");
  if (plain_proxy != NULL) {
    plain_proxy->dead(true);
  }
  if(ssl_proxy != NULL) {
    ssl_proxy->dead(true);
  }
}


static int  debug_flag = INF;
// static int   ssl_flag = 0;
static std::string listen_port;
static std::string ssl_listen_port;

static struct option long_options[] =
    {
    /* These options set a flag. */
    {"debug",   no_argument,       &debug_flag, DEB},
    {"diagnose",   no_argument,       &debug_flag, DIA},
    {"dump",   no_argument,       &debug_flag, DUM},

    {"ssl-port",  required_argument, 0, 's'},
    {"port",    required_argument, 0, 'p'},
    {0, 0, 0, 0}
};  


template <class Com>
theAcceptor* prepare_acceptor(std::string& str_port,const char* friendly_name,int def_port) {
    
    int port = def_port;
    
    if(str_port.size()) {
        try {
         port = std::stoi(str_port);
        }
        catch(std::invalid_argument e) {
            ERR_("Invalid port specified: %s",listen_port.c_str());
            return NULL;
        }
    }
    
    INF_("Entering %s mode on port %d",friendly_name,port);
    auto s_p = new theAcceptor(new Com());
    s_p->com()->nonlocal(true);

    // bind with master proxy (.. and create child proxies for new connections)
    if (s_p->bind(port,'L') < 0) {
        FATS_("Error binding port, exiting");
        delete s_p;
        return NULL;
    };
    
    return s_p;
}

int main(int argc, char *argv[]) {
//     CRYPTO_malloc_debug_init();
//     CRYPTO_dbg_set_options(V_CRYPTO_MDEBUG_ALL);
    CRYPTO_mem_ctrl(CRYPTO_MEM_CHECK_ON);
    
    sig_http_get= new duplexFlowMatch();                // this is basically container with (possibly) more 'match' types, aware of direction
                                                                    // direction is based on unsigned char value r - read buff, w - write buff
    sig_http_get->add('r',new regexMatch("^(GET|POST) +([^ ]+)",0,16));
    sig_http_get->add('w',new regexMatch("HTTP/1.[01] +([1-5][0-9][0-9]) ",0,16));        
            
    
    sig_starttls_smtp = new duplexFlowMatch();
    sig_starttls_smtp->add('r',new regexMatch("^STARTTLS",0,16));
    sig_starttls_smtp->add('w',new regexMatch("^2[0-5]0 ",0,16));        
    

    sig_starttls_imap = new duplexFlowMatch();
    sig_starttls_imap->add('r',new regexMatch(". STARTTLS\r\n",0,16));
    sig_starttls_imap->add('w',new regexMatch(". OK",0,64));        
    

    sig_starttls_pop3 = new duplexFlowMatch();
    sig_starttls_pop3->add('r',new regexMatch("^STLS\r\n",0,10));
    sig_starttls_pop3->add('w',new regexMatch("^[+]OK",0,5));        

    sig_starttls_ftp = new duplexFlowMatch();
    sig_starttls_ftp->add('r',new regexMatch("^AUTH TLS\r\n",0,10));
    sig_starttls_ftp->add('w',new regexMatch("^[2][0-9][0-9] AUTH",0,10));        
    
    //<starttls xmlns='urn:ietf:params:xml:ns:xmpp-tls'/>
    //<proceed xmlns='urn:ietf:params:xml:ns:xmpp-tls'/>
    sig_starttls_xmpp = new duplexFlowMatch();
    sig_starttls_xmpp->add('r',new regexMatch("^<starttls [^>/]+xmpp-tls[^>/]/>",0,64));
    sig_starttls_xmpp->add('w',new regexMatch("^<proceed [^>/]+xmpp-tls[^>/]/>",0,64));        
        

    sig_virus_eicar = new duplexFlowMatch();
    sig_virus_eicar->add('w',new simpleMatch("X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"));        
    //X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*
    
	// setting logging facility level
	lout.level(INF);
	
	INF_("Starting Smithproxy %s (proxylib %s)",SMITH_VERSION,PROXYLIB_VERSION);
	
    while(1) {
    /* getopt_long stores the option index here. */
        int option_index = 0;
    
        char c = getopt_long (argc, argv, "p:",
                        long_options, &option_index);
        if (c < 0) break;

        switch(c) {
            case 0:
                break;
            
            case 'p':
                listen_port = std::string(optarg);        
                break;

            case 's':
                ssl_listen_port = std::string(optarg);        
                break;
                
            default:
               abort();                 
        }
    }
	
	
	lout.level(debug_flag);
    
   

    plain_proxy = prepare_acceptor<TCPCom>(listen_port,"plain-text",50080);
    ssl_proxy = prepare_acceptor<MySSLMitmCom>(ssl_listen_port,"SSL",50443);
    
    
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
    
    
    if(plain_thread) {
        plain_thread->join();
    }
    if(ssl_thread) {
        ssl_thread->join();
    }
    
    CRYPTO_cleanup_all_ex_data();
    ERR_free_strings();
    ERR_remove_state(0);
    EVP_cleanup();    
    
    auto s = new SSLCom();
    s->certstore()->destroy();
    delete s;

}
