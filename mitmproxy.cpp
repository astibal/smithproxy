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

#include <cstdlib>
#include <ctime>

#include <mitmproxy.hpp>
#include <mitmhost.hpp>
#include <logger.hpp>
#include <cfgapi.hpp>
#include <sockshostcx.hpp>


MitmProxy::MitmProxy(baseCom* c): baseProxy(c) {

    std::string data_dir = "mitm";
    std::string file_pref = "";
    std::string file_suff = "smcap";
    
    cfgapi.getRoot()["settings"].lookupValue("write_payload_dir",data_dir);
    cfgapi.getRoot()["settings"].lookupValue("write_payload_file_prefix",file_pref);
    cfgapi.getRoot()["settings"].lookupValue("write_payload_file_suffix",file_suff);
    
    tlog_ = new trafLog(this,data_dir.c_str(),file_pref.c_str(),file_suff.c_str());
}


MitmProxy::~MitmProxy() {
    
    if(write_payload()) {
        DEBS_("MitmProxy::destructor: syncing writer");

        for(typename std::vector<baseHostCX*>::iterator j = this->left_sockets.begin(); j != this->left_sockets.end(); ++j) {
            auto cx = (*j);
            if(cx->log().size()) {
                tlog()->write('L', cx->log());
                cx->log() = "";
            }
        }               
        
        for(typename std::vector<baseHostCX*>::iterator j = this->right_sockets.begin(); j != this->right_sockets.end(); ++j) {
            auto cx = (*j);
            if(cx->log().size()) {
                tlog()->write('R', cx->log());
                cx->log() = "";
            }
        }         
        
        tlog()->left_write("Connection stop\n");
    }
    
    delete tlog_;
}

void MitmProxy::on_left_bytes(baseHostCX* cx) {
        
    if(write_payload()) {
        if(cx->log().size()) {
            tlog()->write('L', cx->log());
            cx->log() = "";
        }
        
        tlog()->left_write(cx->to_read());
    }
    
    bool redirected = false;
    
    MitmHostCX* mh = dynamic_cast<MitmHostCX*>(cx);
    if(mh != nullptr) {
	if(mh->replacement() > MitmHostCX::REPLACE_NONE) {
	    redirected = true;
	    handle_replacement(mh);
	}
    }
    
    
    // because we have left bytes, let's copy them into all right side sockets!
    for(typename std::vector<baseHostCX*>::iterator j = this->right_sockets.begin(); j != this->right_sockets.end(); j++) {
	if(!redirected) {
	    (*j)->to_write(cx->to_read());
	} else {
	  
	  // rest of connections should be closed when sending replacement to a client
	  (*j)->shutdown();
	}
    }    
}

void MitmProxy::on_right_bytes(baseHostCX* cx) {
        
    if(write_payload()) {
        if(cx->log().size()) {
            tlog()->write('R',cx->log());
            cx->log() = "";
        }
        
        tlog()->right_write(cx->to_read());
    }
    
    for(typename std::vector<baseHostCX*>::iterator j = this->left_sockets.begin(); j != this->left_sockets.end(); j++) {
        (*j)->to_write(cx->to_read());
    }
}

void MitmProxy::on_left_error(baseHostCX* cx) {

    if(this->dead()) return;  // don't process errors twice
    
    DEB_("on_left_error[%s]: proxy marked dead",(this->error_on_read ? "read" : "write"));
    DUMS_(this->hr());
    
    if(write_payload()) {
        tlog()->left_write("Client side connection closed: " + cx->name() + "\n");
    }
    

    INF_("Connection from %s closed, sent=%d/%dB received=%d/%dB, flags=%c",
                        cx->full_name('L').c_str(),
                                        cx->meter_read_count,cx->meter_read_bytes,
                                                            cx->meter_write_count, cx->meter_write_bytes,
                                                                        'L');
    this->dead(true); 
}

void MitmProxy::on_right_error(baseHostCX* cx)
{
    if(this->dead()) return;  // don't process errors twice
    
    DEB_("on_right_error[%s]: proxy marked dead",(this->error_on_read ? "read" : "write"));
    
    if(write_payload()) {
        tlog()->right_write("Server side connection closed: " + cx->name() + "\n");
    }
    
//         INF_("Created new proxy 0x%08x from %s:%s to %s:%d",new_proxy,f,f_p, t,t_p );
    
    INF_("Connection from %s closed, sent=%d/%dB received=%d/%dB, flags=%c",
                            cx->full_name('R').c_str(), 
                                            cx->meter_write_count, cx->meter_write_bytes,
                                                            cx->meter_read_count,cx->meter_read_bytes,
                                                                    'R');
    this->dead(true); 
}



void MitmProxy::handle_replacement(MitmHostCX* cx) {
  
    //std::string redir("<script>window.location=\"http://www.mojebanka.cz/\";</script>");
    std::string redir_pre("<script>window.location=\"");
    std::string redir_suf("\";</script>");  
    std::string repl;
    int 	redir_hint = 0;
    
    std::string block("<!DOCTYPE html><html><body><h1>Page has been blocked</h1><p>Access has been blocked by smithproxy. Get over it.</p></body></html>");
    
    switch(cx->replacement()) {
	case MitmHostCX::REPLACE_REDIRECT:
	  
	  srand(time(nullptr) % ((unsigned long)cx));
	  redir_hint = rand();
	  
	  repl = redir_pre + "http://127.0.0.1:65444/smithredir?hint=" + std::to_string(redir_hint) + redir_suf;
	  cx->to_write((unsigned char*)repl.c_str(),repl.size());
	  cx->close_after_write(true);
	  break;

	case MitmHostCX::REPLACE_BLOCK:
	  repl = block;
	  cx->to_write((unsigned char*)repl.c_str(),repl.size());
	  cx->close_after_write(true);
	  
	  break;
	case MitmHostCX::REPLACE_NONE:
	    DIAS_("void MitmProxy::handle_replacement: asked to handle NONE. No-op.");
    } 
}



baseHostCX* MitmMasterProxy::new_cx(int s) {
    auto r = new MitmHostCX(com()->replicate(),s);
    DEB_("Pausing new connection %s",r->c_name());
    r->paused(true);
    return r; 
}
void MitmMasterProxy::on_left_new(baseHostCX* just_accepted_cx) {
    // ok, we just accepted socket, created context for it (using new_cx) and we probably need ... 
    // to create child proxy and attach this cx to it.

    if(! just_accepted_cx->com()->nonlocal_dst_resolved()) {
        ERRS_("Was not possible to resolve original destination!");
        just_accepted_cx->shutdown();
        delete just_accepted_cx;
    } 
    else {
        MitmProxy* new_proxy = new MitmProxy(com()->replicate());
        
        // let's add this just_accepted_cx into new_proxy
        if(just_accepted_cx->paused_read()) {
            DEBS_("MitmMasterProxy::on_left_new: ldaadd the new paused cx");
            new_proxy->ldaadd(just_accepted_cx);
        } else{
            DEBS_("MitmMasterProxy::on_left_new: ladd the new cx (unpaused)");
            new_proxy->ladd(just_accepted_cx);
        }
        MitmHostCX *target_cx = new MitmHostCX(com()->replicate(), just_accepted_cx->com()->nonlocal_dst_host().c_str(), 
                                            string_format("%d",just_accepted_cx->com()->nonlocal_dst_port()).c_str()
                                            );
        // connect it! - btw ... we don't want to block of course...
        
        std::string h;
        std::string p;
        just_accepted_cx->name();
        just_accepted_cx->com()->resolve_socket_src(just_accepted_cx->socket(),&h,&p);
        
	just_accepted_cx->peer(target_cx);
        target_cx->peer(just_accepted_cx);          


        // almost done, just add this target_cx to right side of new proxy
        new_proxy->radd(target_cx);
        
        // apply policy and get result
        int policy_num = cfgapi_obj_policy_apply(just_accepted_cx,new_proxy);
        if(policy_num >= 0) {
            
            MitmHostCX* src;
            src = dynamic_cast<MitmHostCX*>(just_accepted_cx);
            if (src != nullptr) {
                src->matched_policy(policy_num);
            } else {
                DIA_("MitmMasterProxy::on_left_new: %s cannot be converted to MitmHostCx",just_accepted_cx->c_name());
            }
            target_cx->matched_policy(policy_num);
            
            this->proxies().push_back(new_proxy);
            
            if(cfgapi_obj_policy.at(policy_num)->nat == POLICY_NAT_NONE) {
                target_cx->com()->nonlocal_src(true);
                target_cx->com()->nonlocal_src_host() = h;
                target_cx->com()->nonlocal_src_port() = std::stoi(p);               
            }
            
/*            just_accepted_cx->peer(target_cx);
            target_cx->peer(just_accepted_cx);  */          
            
            target_cx->connect(false);        
        } else {
            delete new_proxy;
        }
    }
    
    DEBS_("MitmMasterProxy::on_left_new: finished");
}

int MitmMasterProxy::handle_sockets_once(baseCom* c) {
    //T_DIAS_("slist",5,this->hr()+"\n===============\n");
    return ThreadedAcceptorProxy<MitmProxy>::handle_sockets_once(c);
}


void MitmUdpProxy::on_left_new(baseHostCX* just_accepted_cx)
{
    MitmProxy* new_proxy = new MitmProxy(com()->replicate());
    // let's add this just_accepted_cx into new_proxy
    if(just_accepted_cx->paused_read()) {
        DEBS_("MitmMasterProxy::on_left_new: ldaadd the new paused cx");
        new_proxy->ldaadd(just_accepted_cx);
    } else{
        DEBS_("MitmMasterProxy::on_left_new: ladd the new cx (unpaused)");
        new_proxy->ladd(just_accepted_cx);
    }
    
    MitmHostCX *target_cx = new MitmHostCX(com()->replicate(), just_accepted_cx->com()->nonlocal_dst_host().c_str(), 
                                    string_format("%d",just_accepted_cx->com()->nonlocal_dst_port()).c_str()
                                    );
    

    std::string h;
    std::string p;
    just_accepted_cx->name();
    just_accepted_cx->com()->resolve_socket_src(just_accepted_cx->socket(),&h,&p);
    
    just_accepted_cx->peer(target_cx);
    target_cx->peer(just_accepted_cx);


    
    ((AppHostCX*)just_accepted_cx)->mode(AppHostCX::MODE_NONE);
    target_cx->mode(AppHostCX::MODE_NONE);
    
    new_proxy->radd(target_cx);

    // apply policy and get result
    int policy_num = cfgapi_obj_policy_apply(just_accepted_cx,new_proxy);
    if(policy_num >= 0) {
        this->proxies().push_back(new_proxy);
        
        if(cfgapi_obj_policy.at(policy_num)->nat == POLICY_NAT_NONE) {
            target_cx->com()->nonlocal_src(true);
            target_cx->com()->nonlocal_src_host() = h;
            target_cx->com()->nonlocal_src_port() = std::stoi(p);               
        }
        target_cx->connect(false);        
    }
        
    DEBS_("MitmUDPProxy::on_left_new: finished");    
}
