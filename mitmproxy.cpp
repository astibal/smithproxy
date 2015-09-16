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
#include <time.h>

#include <mitmproxy.hpp>
#include <mitmhost.hpp>
#include <logger.hpp>
#include <cfgapi.hpp>
#include <cfgapi_auth.hpp>
#include <sockshostcx.hpp>

DEFINE_LOGGING(MitmProxy);

unsigned long MitmProxy::meter_left_bytes_second;
unsigned long MitmProxy::meter_right_bytes_second;
time_t MitmProxy::cnt_left_bytes_second;
time_t MitmProxy::cnt_right_bytes_second;

MitmProxy::MitmProxy(baseCom* c): baseProxy(c), sobject() {

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

std::string MitmProxy::to_string(int verbosity) { 
    std::string r =  "MitmProxy:" + baseProxy::to_string(verbosity); 
    if(verbosity >= DEB) {
        r += string_format("\n    identity: %d",identity_resolved());
    }
    
    return r;
}


bool MitmProxy::resolve_identity(baseHostCX* cx,bool insert_guest=false) {
    
    if(identity_resolved()) {
        if(update_identity(cx)) {
            return true;
        } else {
            identity_resolved(false);
        }
    }
    
    bool ret = false;
    
    DIA_("identity check: source IP: %s",cx->host().c_str());
    
    cfgapi_auth_shm_ip_table_refresh();
    DEB_("identity check: table size: %d", auth_ip_map.size());
    
    cfgapi_identity_ip_lock.lock();
    auto ip = auth_ip_map.find(cx->host());

    if (ip != auth_ip_map.end()) {
        logon_info& li = (*ip).second.last_logon_info;
        DIA_("identity found for IP %s: user: %s groups: %s",cx->host().c_str(),li.username, li.groups);

        // if update_identity fails, identity is no longer valid!
        ret = update_identity(cx);
        identity_resolved(ret);
        if(ret) { 
            identity(li); 
        }

    } else {
        if (insert_guest == true) {
            logon_info li = logon_info(cx->host().c_str(),"guest","");
            
            ret = update_identity(cx);
            identity_resolved(ret);
            if(ret) { 
                identity(li); 
            }
        }
    }
    
    
    cfgapi_identity_ip_lock.unlock();
    DEB_("identity check: return %d",ret);
    return ret;
}


bool MitmProxy::update_identity(baseHostCX* cx) {

    bool ret = false;
    
    cfgapi_identity_ip_lock.lock();    
    auto ip = auth_ip_map.find(cx->host());

    DEB_("update_identity: start for %s",cx->host().c_str());
    
    if (ip != auth_ip_map.end()) {
        IdentityInfo& id = (*ip).second;
        DIA_("updating identity: user %s from %s (groups: %s)",id.last_logon_info.username, cx->host().c_str(), id.last_logon_info.groups);

        if (!id.i_timeout()) {
            id.touch();
            ret = true;
        } else {
            INF_("identity timeout: user %s from %s (groups: %s)",id.last_logon_info.username, cx->host().c_str(), id.last_logon_info.groups);
            
            // erase internal ip map entry

            auth_ip_map.erase(ip);
            
            // erase shared ip map entry
            
            auth_shm_ip_map.acquire();
            auto sh_it = auth_shm_ip_map.map_entries().find(cx->host());
            
            for(auto& x_it: auth_shm_ip_map.map_entries()) {
                INF_("::%s::",x_it.first.c_str());
            }
            
            if(sh_it != auth_shm_ip_map.map_entries().end()) {
                DIAS_("Identity timeout: entry found in shared table: deleted. Saving.");
                auth_shm_ip_map.map_entries().erase(sh_it);
                
                if(LEV_(DEB)) {
                    DEBS_("Identity timeout: After:");
                    for(auto& x_it: auth_shm_ip_map.map_entries()) {
                        DEB_("::%s::",x_it.first.c_str());
                    }                
                }
                auth_shm_ip_map.save(true);
            }
            auth_shm_ip_map.release();
            
        }
    }

    cfgapi_identity_ip_lock.unlock();
    return ret;
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

        
        if(opt_auth_authenticate || opt_auth_resolve) {
        
            resolve_identity(cx);
            
            if(!identity_resolved()) {        
                DEBS_("identity check: unknown");
                
                if(opt_auth_authenticate) {
                    if(mh->replace_type == MitmHostCX::REPLACETYPE_HTTP) {
                
                        mh->replacement(MitmHostCX::REPLACE_REDIRECT);
                        redirected = true;
                        handle_replacement(mh);
                    } 
                    else {
                        // wait, if header won't come in some time, kill the proxy
                        if(cx->meter_read_bytes > 200) {
                            // we cannot use replacements and identity is not resolved... what we can do. Shutdown.
                            EXTS_("not enough data received to ensure right replacement-aware protocol.");
                            dead(true);
                        }
                    }
                }
            }
        }
    }
    
    
    // because we have left bytes, let's copy them into all right side sockets!
    for(typename std::vector<baseHostCX*>::iterator j = this->right_sockets.begin(); j != this->right_sockets.end(); j++) {
        if(!redirected) {
            (*j)->to_write(cx->to_read());
            DIA_("mitmproxy::on_left_bytes: %d copied",cx->to_read().size())
        } else {
        
        // rest of connections should be closed when sending replacement to a client
        (*j)->shutdown();
        }
    }    
    for(typename std::vector<baseHostCX*>::iterator j = this->right_delayed_accepts.begin(); j != this->right_delayed_accepts.end(); j++) {
        if(!redirected) {
            (*j)->to_write(cx->to_read());
            DIA_("mitmproxy::on_left_bytes: %d copied to delayed",cx->to_read().size())
        } else {
        
        // rest of connections should be closed when sending replacement to a client
        (*j)->shutdown();
        }
    }    
 
    socle::time_update_counter_sec(&cnt_left_bytes_second,&meter_left_bytes_second,1,cx->to_read().size());
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
        DIA_("mitmproxy::on_right_bytes: %d copied",cx->to_read().size())
    }
    for(typename std::vector<baseHostCX*>::iterator j = this->left_delayed_accepts.begin(); j != this->left_delayed_accepts.end(); j++) {
        (*j)->to_write(cx->to_read());
        DIA_("mitmproxy::on_right_bytes: %d copied to delayed",cx->to_read().size())
    }

    socle::time_update_counter_sec(&cnt_right_bytes_second,&meter_right_bytes_second,1,cx->to_read().size());
}

void MitmProxy::on_left_error(baseHostCX* cx) {

    if(this->dead()) return;  // don't process errors twice
    
    DEB_("on_left_error[%s]: proxy marked dead",(this->error_on_read ? "read" : "write"));
    DUMS_(to_string().c_str());
    
    if(write_payload()) {
        tlog()->left_write("Client side connection closed: " + cx->name() + "\n");
    }
    
    if(opt_auth_resolve)
        resolve_identity(cx);

    INF_("Connection from %s closed: user=%s up=%d/%dB dw=%d/%dB flags=%c",
                        cx->full_name('L').c_str(),
                                     (identity_resolved() ? identity().username : ""),
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


    INF_("Connection from %s closed: user=%s up=%d/%dB dw=%d/%dB flags=%c",
                            cx->full_name('R').c_str(), 
                                     (identity_resolved() ? identity().username : ""),         
                                            cx->meter_write_count, cx->meter_write_bytes,
                                                            cx->meter_read_count,cx->meter_read_bytes,
                                                                    'R');
    this->dead(true); 
}



void MitmProxy::handle_replacement(MitmHostCX* cx) {
  
    std::string redir_pre("<!DOCTYPE html><html><head><script>window.location=\"");
    std::string redir_suf("\";</script></head><body></body></html>");  
  
//     std::string redir_pre("HTTP/1.0 301 Moved Permanently\r\nLocation: ");
//     std::string redir_suf("\r\n\r\n");  
  
    
    std::string repl;
    std::string repl_port = cfgapi_identity_portal_port_http;
    std::string repl_proto = "http";
    int 	redir_hint = 0;
    
    if(cx->application_data->is_ssl) {
	repl_proto = "https";
	repl_port = cfgapi_identity_portal_port_https;
    }    
    
    std::string block("HTTP/1.0 OK\r\n<!DOCTYPE html><html><body><h1>Page has been blocked</h1><p>Access has been blocked by smithproxy. Get over it.</p></body></html>");
    
    //cx->host().c_str()
    
    if (cx->replacement() == MitmHostCX::REPLACE_REDIRECT) {
	  //srand(time(nullptr) % ((unsigned long)cx));
	  //redir_hint = rand();

	  cfgapi_identity_token_lock.lock();
	  auto id_token = cfgapi_identity_token_cache.find(cx->host());
	  
	  if(id_token != cfgapi_identity_token_cache.end()) {
	      INF_("found a cached token for %s",cx->host().c_str());
	      std::pair<unsigned int,std::string>& cache_entry = (*id_token).second;
	      
	      unsigned int now      = time(nullptr);
	      unsigned int token_ts = cache_entry.first;
	      std::string& token_tk = cache_entry.second;
	      
	      if(now - token_ts < cfgapi_identity_token_timeout) {
		  INF_("MitmProxy::handle_replacement: cached token %s for request: %s",token_tk.c_str(),cx->application_data->hr().c_str());
		  
		  repl = redir_pre + repl_proto + "://"+cfgapi_identity_portal_address+":"+repl_port+"/cgi-bin/auth.py?token=" + token_tk + redir_suf;
		  cx->to_write((unsigned char*)repl.c_str(),repl.size());
		  cx->close_after_write(true);
	      } else {
		  INF_("MitmProxy::handle_replacement: expired token %s for request: %s",token_tk.c_str(),cx->application_data->hr().c_str());
		  goto new_token;
	      }
	  } else {
	  
	      new_token:
	    
          std::string token_text = cx->application_data->original_request() + " |" + cfgapi_obj_policy_profile_auth( cx->matched_policy())->identities;
          logon_token tok = logon_token(token_text.c_str());
	      
	      INF_("MitmProxy::handle_replacement: new auth token %s for request: %s",tok.token,cx->application_data->hr().c_str());
	      repl = redir_pre + repl_proto + "://"+cfgapi_identity_portal_address+":"+repl_port+"/cgi-bin/auth.py?token=" + tok.token + redir_suf;
	      
		  cx->to_write((unsigned char*)repl.c_str(),repl.size());
		  cx->close_after_write(true);
	      
	      cfgapi_auth_shm_token_table_refresh();
	      
	      auth_shm_token_map.entries().push_back(tok);
	      auth_shm_token_map.acquire();
	      auth_shm_token_map.save(true);
	      auth_shm_token_map.release();
	      
	      INFS_("MitmProxy::handle_replacement: token table updated");
	      cfgapi_identity_token_cache[cx->host()] = std::pair<unsigned int,std::string>(time(nullptr),tok.token);
	  }
	  
	  cfgapi_identity_token_lock.unlock();
    } else
    if (cx->replacement() == MitmHostCX::REPLACE_BLOCK) {

	  repl = block;
	  cx->to_write((unsigned char*)repl.c_str(),repl.size());
	  cx->close_after_write(true);
	  
    } else
    if (cx->replacement() == MitmHostCX::REPLACE_NONE) {
	    DIAS_("void MitmProxy::handle_replacement: asked to handle NONE. No-op.");
    } 
}


bool MitmMasterProxy::ssl_autodetect = false;
bool MitmMasterProxy::ssl_autodetect_harder = true;

#define NEW_CX_PEEK_BUFFER_SZ  10
bool MitmMasterProxy::detect_ssl_on_plain_socket(int s) {
    
    int ret = false;

    int time_increment = 2500; // 2.5ms
    int time_max = time_increment*5;
    int time_taken = 0;
    
    if (s > 0) {
        again:
        
        char peek_buffer[NEW_CX_PEEK_BUFFER_SZ];
        int b = ::recv(s,peek_buffer,NEW_CX_PEEK_BUFFER_SZ,MSG_PEEK|MSG_DONTWAIT);
        
        if(b > 6) {
            if (peek_buffer[0] == 0x16 && peek_buffer[1] == 0x03 && ( peek_buffer[5] == 0x00 || peek_buffer[5] == 0x01 || peek_buffer[5] == 0x02 )) {
                INF_("detect_ssl_on_plain_socket: SSL detected on socket %d",s);
                ret = true;
            }
        } else {
            if(ssl_autodetect_harder && time_taken < time_max) {
                struct timespec t;
                t.tv_sec = 0;
                t.tv_nsec = time_increment;
                
                ::nanosleep(&t,nullptr);
                time_taken += time_increment;
                DIA_("detect_ssl_on_plain_socket: SSL strict detection on socket %d: dalayed by %dnsec",s,time_increment);
                goto again;
            }
        }
    }
    
    return ret;
}

baseHostCX* MitmMasterProxy::new_cx(int s) {
    
    DEBS_("MitmMasterProxy::new_cx: new_cx start");
    
    bool is_ssl = false;
    bool is_ssl_port = false;
    
    SSLCom* my_sslcom = dynamic_cast<SSLCom*>(com());
    baseCom* c = nullptr;
    
    if(my_sslcom != nullptr) {
        is_ssl_port = true;
    }
    else
    if(ssl_autodetect) {
        // my com is NOT ssl-based, trigger auto-detect

        is_ssl = detect_ssl_on_plain_socket(s);
        if(! is_ssl) {
            c = com()->slave();
        } else {
            c = new SSLMitmCom();
            c->master(com());
        } 
    }
    
    if(c == nullptr) {
        c = com()->slave();
    }
    
    auto r = new MitmHostCX(c,s);
    if (is_ssl) {
        INF_("Connection %s: SSL detected on unusual port.",r->c_name());
        r->is_ssl = true;
        r->is_ssl_port = is_ssl_port;
    }
    if(is_ssl_port) {
        r->is_ssl = true;
    }
    
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
        MitmProxy* new_proxy = new MitmProxy(just_accepted_cx->com()->slave());
        
        // let's add this just_accepted_cx into new_proxy
        if(just_accepted_cx->paused_read()) {
            DEBS_("MitmMasterProxy::on_left_new: ldaadd the new paused cx");
            new_proxy->ldaadd(just_accepted_cx);
        } else{
            DEBS_("MitmMasterProxy::on_left_new: ladd the new cx (unpaused)");
            new_proxy->ladd(just_accepted_cx);
        }
        MitmHostCX *target_cx = new MitmHostCX(just_accepted_cx->com()->slave(), just_accepted_cx->com()->nonlocal_dst_host().c_str(), 
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

            //traffic is allowed
            
            MitmHostCX* src_cx;
            src_cx = dynamic_cast<MitmHostCX*>(just_accepted_cx);
            if (src_cx != nullptr) {
                
                // we know proxy can be properly configured now, both peers are MitmHostCX types
                
                // let know CX what policy it matched (it is handly CX will know under some circumstances like upgrade to SSL)
                src_cx->matched_policy(policy_num);
                target_cx->matched_policy(policy_num);

                // resolve source information - is there un identity info for that IP?
                if(new_proxy->opt_auth_authenticate && new_proxy->opt_auth_resolve) {
                    new_proxy->resolve_identity(src_cx);
                }
                
                // setup NAT
                if(cfgapi_obj_policy.at(policy_num)->nat == POLICY_NAT_NONE) {
                    target_cx->com()->nonlocal_src(true);
                    target_cx->com()->nonlocal_src_host() = h;
                    target_cx->com()->nonlocal_src_port() = std::stoi(p);               
                }
                
                // finalize connection acceptance by adding new proxy to proxies and connect
                this->proxies().push_back(new_proxy);
                
                //FIXME: this is really ugly!! :) It's here since radd has been called before socket for target_cx was created.
                int real_socket = target_cx->connect(false);
                com()->set_monitor(real_socket);
                com()->set_poll_handler(real_socket,new_proxy);
                
            } else {
                delete new_proxy;
                NOT_("MitmMasterProxy::on_left_new: %s cannot be converted to MitmHostCx",just_accepted_cx->c_name());
            }
  
        } else {
            
            // hmm. traffic is denied.
            delete new_proxy;
        }
        
        new_proxy->name(new_proxy->to_string(INF));
    }
    
    DEBS_("MitmMasterProxy::on_left_new: finished");
}

int MitmMasterProxy::handle_sockets_once(baseCom* c) {
    //T_DIAS_("slist",5,this->hr()+"\n===============\n");
    return ThreadedAcceptorProxy<MitmProxy>::handle_sockets_once(c);
}


void MitmUdpProxy::on_left_new(baseHostCX* just_accepted_cx)
{
    MitmProxy* new_proxy = new MitmProxy(com()->slave());
    // let's add this just_accepted_cx into new_proxy
    if(just_accepted_cx->paused_read()) {
        DEBS_("MitmMasterProxy::on_left_new: ldaadd the new paused cx");
        new_proxy->ldaadd(just_accepted_cx);
    } else{
        DEBS_("MitmMasterProxy::on_left_new: ladd the new cx (unpaused)");
        new_proxy->ladd(just_accepted_cx);
    }
    
    MitmHostCX *target_cx = new MitmHostCX(com()->slave(), just_accepted_cx->com()->nonlocal_dst_host().c_str(), 
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

        int real_socket = target_cx->connect(false);
        target_cx->rename();
        com()->set_monitor(real_socket);
        com()->set_poll_handler(real_socket,new_proxy);
    }
    
    new_proxy->name(new_proxy->to_string());
    DEBS_("MitmUDPProxy::on_left_new: finished");    
}

baseHostCX* MitmUdpProxy::MitmUdpProxy::new_cx(int s) {
    return new MitmHostCX(com()->slave(),s);
}
