#include <sslcom.hpp>
#include <tcpcom.hpp>

#include <sockshostcx.hpp>
#include <socksproxy.hpp>
#include <mitmhost.hpp>
#include <cfgapi.hpp>


SocksProxy::SocksProxy(baseCom* c): MitmProxy(c) {}
SocksProxy::~SocksProxy() {}

void SocksProxy::on_left_message(baseHostCX* basecx) {

    socksServerCX* cx = static_cast<socksServerCX*>(basecx);
    if(cx != nullptr) {
        if(cx->state_ == WAIT_POLICY) {
            DIAS_("SocksProxy::on_left_message: policy check: accepted");
            std::vector<baseHostCX*> l;
            std::vector<baseHostCX*> r;
            l.push_back(cx);
            r.push_back(cx->right);
            
            int policy_num = cfgapi_obj_policy_match(l,r);
            bool verdict = cfgapi_obj_policy_action(policy_num);
            DIA_("socksProxy::on_left_message: policy check result: %s", verdict ? "accept" : "reject" );
            
            socks5_policy s5_verdict = verdict ? ACCEPT : REJECT;
            cx->verdict(s5_verdict);
        }
        else if(cx->state_ == HANDOFF) {
            DIAS_("SocksProxy::on_left_message: socksHostCX handoff msg received");
            cx->state(ZOMBIE);
            
            socks5_handoff(cx);
        } else {

            WARS_("SocksProxy::on_left_message: unknown message");
        }
    }
}

void SocksProxy::socks5_handoff(socksServerCX* cx) {

    DEBS_("SocksProxy::socks5_handoff: start");
    
    int s = cx->socket();
    bool ssl = false;
    
    baseCom* new_com = nullptr;
    switch(cx->com()->nonlocal_dst_port()) {
        case 443:
        case 465:
        case 636:
        case 993:
        case 995:
            new_com = new socksSSLMitmCom();
            ssl = true;
            break;
        default:
            new_com = new socksTCPCom();
    }
    
    MitmHostCX* n_cx = new MitmHostCX(new_com, s);
    n_cx->paused(true);
    n_cx->com()->name();
    n_cx->name();
    n_cx->com()->nonlocal_dst(true);
    n_cx->com()->nonlocal_dst_host() = cx->com()->nonlocal_dst_host();
    n_cx->com()->nonlocal_dst_port() = cx->com()->nonlocal_dst_port();
    n_cx->com()->nonlocal_dst_resolved(true);
//     n_cx->writebuf()->append(cx->writebuf()->data(),cx->writebuf()->size());
    
    // get rid of it
    //cx->socket(0);
    cx->remove_socket();
    delete cx;
    
    left_sockets.clear();
    ldaadd(n_cx);
    n_cx->on_delay_socket(s);
    
    MitmHostCX *target_cx = new MitmHostCX(n_cx->com()->replicate(), n_cx->com()->nonlocal_dst_host().c_str(), 
                                        string_format("%d",n_cx->com()->nonlocal_dst_port()).c_str()
                                        );
    std::string h;
    std::string p;
    n_cx->name();
    n_cx->com()->resolve_socket_src(n_cx->socket(),&h,&p);
    
    
    n_cx->peer(target_cx);
    target_cx->peer(n_cx);

    target_cx->com()->nonlocal_src(true); //FIXME
    target_cx->com()->nonlocal_src_host() = h;
    target_cx->com()->nonlocal_src_port() = std::stoi(p);
    
    target_cx->connect(false);       
    
    if(ssl) {
        ((SSLCom*)n_cx->com())->upgrade_server_socket(n_cx->socket());
        DEBS_("SocksProxy::socks5_handoff: mark1");        
        
        ((SSLCom*)target_cx->com())->upgrade_client_socket(target_cx->socket());
    }
    
    radd(target_cx);
    
    cfgapi_obj_policy_apply(n_cx,this);
        
    DIAS_("SocksProxy::socks5_handoff: finished");
}







baseHostCX* MitmSocksProxy::new_cx(int s) {
    auto r = new socksServerCX(com()->replicate(),s);
    return r; 
}

void MitmSocksProxy::on_left_new(baseHostCX* just_accepted_cx) {

    SocksProxy* new_proxy = new SocksProxy(com()->replicate());
    
    // let's add this just_accepted_cx into new_proxy
    std::string h;
    std::string p;
    just_accepted_cx->name();
    just_accepted_cx->com()->resolve_socket_src(just_accepted_cx->socket(),&h,&p);
    
    new_proxy->ladd(just_accepted_cx);    
    
    this->proxies().push_back(new_proxy);
    
    DEBS_("MitmMasterProxy::on_left_new: finished");
}
