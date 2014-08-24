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
#include <baseproxy.hpp>
#include <masterproxy.hpp>
#include <threadedproxy.hpp>
#include <sslcom.hpp>
#include <sslmitmcom.hpp>
#include <display.hpp>

#include <smithproxy.hpp>
#include <traflog.hpp>


class MySSLMitmCom : public SSLMitmCom {
public:
       virtual bool spoof_cert(X509* x) {
           log().append(SSLCertStore::print_cert(x));
           bool r = SSLMitmCom::spoof_cert(x);
           
           
           return r;
       }
};

template <class Com>
class MitmHostCX : public baseHostCX<Com> {
public:
	
	// surprise, constructor filling hostname and port
	MitmHostCX( const char* h, const char* p ) : baseHostCX<Com>::baseHostCX(h,p) {
		DEB_("MitmHostCX: constructor %s:%s",h,p);
	};
	MitmHostCX( int s ) : baseHostCX<Com>::baseHostCX(s) {
		DEB_("MitmHostCX: constructor %d",s);
	};
	
	// first useful code: overriding process() method: do something with read buffer when bytes arrived into the socket
    virtual int process() {
		
		// IMPORTANT: where are those incoming data? In the readbuf() !!!
		unsigned char *ptr = baseHostCX<Com>::readbuf()->data();
		unsigned int len = baseHostCX<Com>::readbuf()->size();
		
		// our only processing: hex dup the payload to the log
		DEBS_("Incoming data(" + this->name() + "):\n" +hex_dump(ptr,len));
		
		// IMPORTANT: with returning len, read buffer will be truncated by 'len' bytes. Note: truncated bytes are LOST.
		return len;
	};
    
};


/*
 now let's override baseProxy, and use on_left/right_bytes method!
 this proxy is working with *already accepted* sockets

 basically Proxy class recognizes LEFT and RIGHT side. You can organize those contexts on both sides.
 it's up to you what will do with them, it doesn't have any particular technical meaning; it just 
 follows the principle that you are usually proxying 2 sides (most commonly clients with servers, but 
 left-right is more generic and follows common sense.
*/

// NEW: Just for the case you are wondering if here is anything new: no, it's not! :)
// 		L<->R copy mechanism stays the same.

template <class Com>
class MyProxy : public baseProxy<Com> {
public:	
	explicit MyProxy() : baseProxy<Com>(),
	tlog(this) {
	};
    
	virtual ~MyProxy() {
		if(tlog.active()) {
			DEBS_("MyProxy::destructor: syncing writer");
			tlog.left_write("Connection stop\n");
		}
	}
	
	// this virtual method is called whenever there are new bytes in any LEFT host context!
	virtual void on_left_bytes(baseHostCX<Com>* cx) {
		
        if(cx->log().size()) {
            tlog.write('R'," ==== Server certificate:\n"+cx->log()+"\n ====\n");
            cx->log() = "";
        }
        
		tlog.left_write(cx->to_read());
		
		// because we have left bytes, let's copy them into all right side sockets!
		for(typename std::vector<baseHostCX<Com>*>::iterator j = this->right_sockets.begin(); j != this->right_sockets.end(); j++) {

			// to_read: returns readbuf's buffer "view" of previously processed bytes 
			// to_write: this is appending to caller's write buffer

			// next line therefore calls processing context to return new processed bytes (to_read is like to offer: I have new processed data, read it if you want)
			// those processed data will be wiped by next read() call, so let's now write them all to right socket!
			(*j)->to_write(cx->to_read());
		}
	};
	
	// let's make this one short
    virtual void on_right_bytes(baseHostCX<Com>* cx) {
        
        if(cx->log().size()) {
            tlog.write('R'," ==== Server certificate:\n"+cx->log()+"\n====\n");
            cx->log() = "";
        }
        
		tlog.right_write(cx->to_read());
		for(typename std::vector<baseHostCX<Com>*>::iterator j = this->left_sockets.begin(); j != this->left_sockets.end(); j++) {
			(*j)->to_write(cx->to_read());
		}
	}
	
	// ... and also when there is error on L/R side, claim the proxy DEAD. When marked dead, it will be safely 
	// closed by it's master proxy next cycle.
    virtual void on_left_error(baseHostCX<Com >* cx) { 
		DEB_("on_left_error[%s]: proxy marked dead",(this->error_on_read ? "read" : "write"));
		DUMS_(this->hr());
		tlog.left_write("Client side connection closed: " + cx->name() + "\n");
        INF_("Proxy 0x%08x closed by client: sent=%d/%dB received=%d/%dB",this,cx->meter_read_count,cx->meter_read_bytes,
             cx->meter_write_count, cx->meter_write_bytes);
		
		this->dead(true); 
	};
	
	virtual void on_right_error(baseHostCX<Com >* cx) { 
		DEB_("on_right_error[%s]: proxy marked dead",(this->error_on_read ? "read" : "write"));
		tlog.right_write("Server side connection closed: " + cx->name() + "\n");
		INF_("Proxy 0x%08x closed by server: sent=%d/%dB received=%d/%dB",this,cx->meter_write_count, cx->meter_write_bytes,
                        cx->meter_read_count,cx->meter_read_bytes);
		this->dead(true); 
	};	

      trafLog<Com> tlog;

};


template<class Com>
class MitmMasterProxy : public ThreadedWorkerProxy<Com,MyProxy<Com>> {
	
	virtual baseHostCX<Com>* new_cx(int s) { 
        auto r = new MitmHostCX<Com>(s);
        DEB_("Pausing new connection %s",r->c_name());
        r->paused(true);
		return r; 
	};	
	
    virtual void on_left_new(baseHostCX<Com >* just_accepted_cx) {
		// ok, we just accepted socket, created context for it (using new_cx) and we probably need ... 
		// to create child proxy and attach this cx to it.
		
		// NEW: whole method is reorganized 

		if(! just_accepted_cx->nonlocal_resolved()) {
			ERRS_("Was not possible to resolve original destination!");
			just_accepted_cx->close();
			delete just_accepted_cx;
		} 
		else {
			MyProxy<Com> *new_proxy = new MyProxy<Com>();
			
			// let's add this just_accepted_cx into new_proxy
            if(just_accepted_cx->paused()) {
                DEBS_("MitmMasterProxy::on_left_new: ldaadd the new paused cx");
                new_proxy->ldaadd(just_accepted_cx);
            } else{
                DEBS_("MitmMasterProxy::on_left_new: ladd the new cx (unpaused)");
                new_proxy->ladd(just_accepted_cx);
            }
			MitmHostCX<Com> *target_cx = new MitmHostCX<Com>(just_accepted_cx->nonlocal_host().c_str(), 
											   string_format("%d",just_accepted_cx->nonlocal_port()).c_str()
											  );
			// connect it! - btw ... we don't want to block of course...
            
            std::string h;
            std::string p;
            just_accepted_cx->resolve_socket_src(just_accepted_cx->socket(),&h,&p);
            DIA_("About to name socket after: %s:%s",h.c_str(),p.c_str());
            
            int bind_status = target_cx->namesocket(target_cx->socket(),h,(unsigned short) std::stoi(p));
			if (bind_status != 0) {
                
                char abc[256];
                
                strerror_r(bind_status,abc,255);
                DIA_("cannot bind this port: %s",abc);
            }
            target_cx->connect(false);

            just_accepted_cx->peer(target_cx);
            target_cx->peer(just_accepted_cx);
                        
			//NEW: end of new
			
			// almost done, just add this target_cx to right side of new proxy
			new_proxy->radd(target_cx);

            
			// write start message
			new_proxy->tlog.left_write("Connection start\n");
			// FINAL point: adding new child proxy to the list
			this->proxies().push_back(new_proxy);
            
            const char* f = just_accepted_cx->host().c_str();
            const char* f_p = just_accepted_cx->port().c_str();
            const char* t =  just_accepted_cx->nonlocal_host().c_str();
            unsigned int t_p = just_accepted_cx->nonlocal_port();
            INF_("Created new proxy 0x%08x from %s:%s to %s:%d",new_proxy,f,f_p, t,t_p );
		}
		
		DEBS_("MitmMasterProxy::on_left_new: finished");
	}

	virtual int run_once() {
        //T_DIAS_("slist",5,this->hr()+"\n===============\n");
		
		return ThreadedWorkerProxy<Com,MyProxy<Com>>::run_once();
	}

};

typedef ThreadedAcceptor<TCPCom,MitmMasterProxy<TCPCom>,MyProxy<TCPCom>> theAcceptor;
typedef ThreadedAcceptor<MySSLMitmCom,MitmMasterProxy<MySSLMitmCom>,MyProxy<MySSLMitmCom>> theSSLAcceptor;


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


template <class Acceptor>
Acceptor* prepare_acceptor(std::string& str_port,const char* friendly_name,int def_port) {
    
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
    auto s_p = new Acceptor();
    s_p->nonlocal(true);

    // bind with master proxy (.. and create child proxies for new connections)
    if (s_p->bind(port,'L') < 0) {
        FATS_("Error binding port, exiting");
        delete s_p;
        return NULL;
    };
    
    return s_p;
}

int main(int argc, char *argv[]) {
	
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
    
   

    plain_proxy = prepare_acceptor<theAcceptor>(listen_port,"plain-text",50080);
    ssl_proxy = prepare_acceptor<theSSLAcceptor>(ssl_listen_port,"SSL",50443);
    
    
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
}
