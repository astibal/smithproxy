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

#include <mitmproxy.hpp>
#include <mitmhost.hpp>
#include <logger.hpp>
#include <cfgapi.hpp>

MyProxy::~MyProxy() {
    
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

void MyProxy::on_left_bytes(baseHostCX* cx) {
        
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
}

void MyProxy::on_right_bytes(baseHostCX* cx) {
        
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

void MyProxy::on_left_error(baseHostCX* cx) {
    
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
    this->dead(true); 
}

void MyProxy::on_right_error(baseHostCX* cx)
{
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
    this->dead(true); 
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
//          if (bind_status != 0) {
//                 
//                 char abc[256];
//                 
//                 strerror_r(bind_status,abc,255);
//                 DIA_("cannot bind this port: %s",abc);
//         }
        target_cx->connect(false);

        just_accepted_cx->peer(target_cx);
        target_cx->peer(just_accepted_cx);
                    
        //NEW: end of new
        
        // almost done, just add this target_cx to right side of new proxy
        new_proxy->radd(target_cx);
        
        int policy_num = cfgapi_obj_policy_match(new_proxy);
        int verdict = cfgapi_obj_policy_action(policy_num);
        if(verdict == POLICY_ACTION_PASS) {
            bool cfg_wrt;
            
            ProfileContent* pc  = cfgapi_obj_policy_profile_content(policy_num);
            ProfileDetection* pd = cfgapi_obj_policy_profile_detection(policy_num);
            const char* pc_name = "none";
            const char* pc_global_write = "global_yes";
            const char* pd_name = "none";
            
            /* Processing content profile */
            
            if(pc != nullptr) {
                DIA_("MitmMasterProxy::on_left_new: policy content profile: write payload: %d", pc->write_payload);
                new_proxy->write_payload(pc->write_payload);
                pc_name = pc->name.c_str();
            }
            else if(cfgapi.getRoot()["settings"].lookupValue("default_write_payload",cfg_wrt)) {
                DIA_("MitmMasterProxy::on_left_new: global content profile: %d", cfg_wrt);
                new_proxy->write_payload(cfg_wrt);
                pc_name = pc_global_write;
            }
            
            if(new_proxy->write_payload()) {
                new_proxy->tlog().left_write("Connection start\n");
            }
            
            
            /* Processing detection profile */
            
            // we scan connection on client's side
            target_cx->mode(AppHostCX::MODE_NONE);
            ((AppHostCX*)just_accepted_cx)->mode(AppHostCX::MODE_NONE);
            if(pd != nullptr)  {
                DIA_("MitmMasterProxy::on_left_new: policy detection profile: mode: %d", pd->mode);
                ((AppHostCX*)just_accepted_cx)->mode(pd->mode);
                pd_name = pd->name.c_str();
            }
            
            
            // FINAL point: adding new child proxy to the list
            this->proxies().push_back(new_proxy);

            INF_("Connection %s accepted by policy #%d, prof_c=%s, prof_d=%s",just_accepted_cx->full_name('L').c_str(),policy_num,pc_name,pd_name);
            
        } else {
            INF_("Connection %s denied by policy #%d.",just_accepted_cx->full_name('L').c_str(),policy_num);
            delete new_proxy;
        }
    }
    
    DEBS_("MitmMasterProxy::on_left_new: finished");
}

int MitmMasterProxy::handle_sockets_once(baseCom* c) {
    //T_DIAS_("slist",5,this->hr()+"\n===============\n");
    return ThreadedAcceptorProxy<MyProxy>::handle_sockets_once(c);
}


void MitmUdpProxy::on_left_new(baseHostCX* just_accepted_cx)
{
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
    
    just_accepted_cx->name();
    target_cx->connect(false);
    
    just_accepted_cx->peer(target_cx);
    target_cx->peer(just_accepted_cx);

    ((AppHostCX*)just_accepted_cx)->mode(AppHostCX::MODE_NONE);
    target_cx->mode(AppHostCX::MODE_NONE);
    
    new_proxy->radd(target_cx);

    // FINAL point: adding new child proxy to the list
    this->proxies().push_back(new_proxy);
    
    INF_("Connection from %s established", just_accepted_cx->full_name('L').c_str());        

    if(new_proxy->write_payload()) {
        new_proxy->tlog().left_write("Connection start\n");
    }    
}
