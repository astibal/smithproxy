#include <csignal>
#include <ctime>

#include <logger.hpp>
#include <hostcx.hpp>
#include <baseproxy.hpp>
#include <masterproxy.hpp>
#include <threadedproxy.hpp>
#include <sslcom.hpp>
#include <sslmitmcom.hpp>
#include <display.hpp>

#include <tmitm.hpp>
#include <traflog.hpp>


std::string target_appl;


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
		
		this->dead(true); 
	};
	
	virtual void on_right_error(baseHostCX<Com >* cx) { 
		DEB_("on_right_error[%s]: proxy marked dead",(this->error_on_read ? "read" : "write"));
		tlog.right_write("Server side connection closed: " + cx->name() + "\n");
		
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

// Now let's do the Ctrl-C magic
static Proxy* main_proxy;

void my_terminate (int param)
{
  FATS_("Terminating ...");
  main_proxy->shutdown();
  exit(1);
}

int main(int argc, char *argv[]) {
	
	// setting logging facility level
	lout.level(DIA);
	
	INF_("Starting tmitm %s",TMITM_VERSION);
	
	// some idiot-proof help
	if (argc != 3) {
		ERR_("Usage: %s <listen_port> <443 = SSL, any value cleartext>",argv[0]);
		return -1;
	}
	
	target_appl = argv[2] ;

	int mode = std::stol(target_appl);

	if( mode == 443) {
		INF_("Entering SSL mode: %d",mode);
		auto p = new theSSLAcceptor();
		p->nonlocal(true);

		// bind with master proxy (.. and create child proxies for new connections)
		if (p->bind(std::stoul(argv[1]),'L') < 0) {
			FATS_("Error binding port, exiting");
			return -1;
		};

		p->run();
		
		main_proxy = (Proxy*)p;
	} else {
		INF_("Entering plaintext mode: %d",mode);
		auto p = new theAcceptor();
		p->nonlocal(true);
		// bind with master proxy (.. and create child proxies for new connections)
		if (p->bind(std::stoul(argv[1]),'L') < 0) {
			FATS_("Error binding port, exiting");
			return -1;
		};

		p->run();
		
		main_proxy = (Proxy*)p;
	}
	
	
	
	// install signal handler, we do want to release the memory properly
		// signal handler installation
	void (*prev_fn)(int);
	prev_fn = signal (SIGTERM,my_terminate);
	if (prev_fn==SIG_IGN) signal (SIGTERM,SIG_IGN);

	prev_fn = signal (SIGINT,my_terminate);
	if (prev_fn==SIG_IGN) signal (SIGINT,SIG_IGN);
	
// 	main_proxy->run();

	delete main_proxy;
}
