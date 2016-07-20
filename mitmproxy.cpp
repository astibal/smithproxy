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

#include <regex>
#include <cstdlib>
#include <ctime>
#include <time.h>

#include <mitmproxy.hpp>
#include <mitmhost.hpp>
#include <logger.hpp>
#include <cfgapi.hpp>
#include <cfgapi_auth.hpp>
#include <sockshostcx.hpp>
#include <uxcom.hpp>

#include <algorithm>
#include <ctime>

DEFINE_LOGGING(leafProxy);
DEFINE_LOGGING(MitmProxy);

unsigned long MitmProxy::meter_left_bytes_second;
unsigned long MitmProxy::meter_right_bytes_second;
time_t MitmProxy::cnt_left_bytes_second;
time_t MitmProxy::cnt_right_bytes_second;
ptr_cache<std::string,whitelist_verify_entry_t> MitmProxy::whitelist_verify("whitelist - verify",500,true,whitelist_verify_entry_t::is_expired);

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
    
    if(content_rule_ != nullptr) {
      delete content_rule_;
    }
    
    if(av_proxy != nullptr) {
        delete av_proxy;
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


void MitmProxy::identity_resolved(bool b) {
    identity_resolved_ = b;
}
bool MitmProxy::identity_resolved() {
    return identity_resolved_;
}


bool MitmProxy::apply_id_policies(baseHostCX* cx) {
    
    cfgapi_identity_ip_lock.lock();

    
    
    IdentityInfo* idi = cfgapi_ip_auth_get(cx->host());
    ProfileSubAuth* final_profile = nullptr;
    
    if( idi != nullptr) {
        DIA_("apply_id_policies: matched policy: %d",matched_policy());        
        PolicyRule* policy = cfgapi_obj_policy.at(matched_policy());
        
        ProfileAuth* auth_policy = policy->profile_auth;

        
        if(auth_policy != nullptr) {
            for(auto sub: auth_policy->sub_policies) {
                ProfileSubAuth* sub_prof = sub;
                std::string sub_name = sub->name;
                
                DIA_("apply_id_policies: checking identity policy for: %s", sub_name.c_str());
                
                for(auto my_id: idi->groups_vec) {
                    DIA_("apply_id_policies: identity in policy: %s, match-test real user group '%s'",sub_prof->name.c_str(), my_id.c_str());
                    if(sub_prof->name == my_id) {
                        DIAS_("apply_id_policies: .. matched.");
                        final_profile = sub_prof;
                        break;
                    }
                }
                
                if(final_profile != nullptr) {
                    break;
                }
            }
        }
        
        if(final_profile != nullptr) {
            
            const char* pc_name = "none";
            const char* pd_name = "none";
            const char* pt_name = "none";
            std::string algs = "";
            
            DIA_("apply_id_policies: assigning sub-profile %s",final_profile->name.c_str());
            if(final_profile->profile_content != nullptr) {
                if (cfgapi_obj_profile_content_apply(cx,this,final_profile->profile_content)) {
                    pc_name = final_profile->profile_content->name.c_str();
                    DIA_("apply_id_policies: assigning content sub-profile %s",final_profile->profile_content->name.c_str());
                }
            }
            if(final_profile->profile_detection != nullptr) {
                if (cfgapi_obj_profile_detect_apply(cx,this,final_profile->profile_detection)) {
                    pd_name = final_profile->profile_detection->name.c_str();
                    DIA_("apply_id_policies: assigning detection sub-profile %s",final_profile->profile_detection->name.c_str());
                }
            }
            if(final_profile->profile_tls != nullptr) {
                if(cfgapi_obj_profile_tls_apply(cx,this,final_profile->profile_tls)) {
                    pt_name = final_profile->profile_tls->name.c_str();
                    DIA_("apply_id_policies: assigning tls sub-profile %s",final_profile->profile_tls->name.c_str());
                }
            }
            if(final_profile->profile_alg_dns != nullptr) {
                if(cfgapi_obj_alg_dns_apply(cx,this,final_profile->profile_alg_dns)) {
                    algs += final_profile->profile_alg_dns->name + " ";
                    DIA_("apply_id_policies: assigning tls sub-profile %s",final_profile->profile_tls->name.c_str());
                }
            }
            
            // end of custom sub-profiles
            INF_("Connection %s: identity-based sub-profile: name=%s cont=%s det=%s tls=%s algs=%s",cx->full_name('L').c_str(),final_profile->name.c_str(),
                            pc_name, pd_name, pt_name, algs.c_str()
                            );
        }
        
        cfgapi_identity_ip_lock.unlock();
        return (final_profile != nullptr);
    } 
    
    cfgapi_identity_ip_lock.unlock();
    return false;
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
        shm_logon_info& li = (*ip).second.last_logon_info;
        DIA_("identity found for IP %s: user: %s groups: %s",cx->host().c_str(),li.username, li.groups);

        // if update_identity fails, identity is no longer valid!
        ret = update_identity(cx);
        identity_resolved(ret);
        if(ret) { 
            identity(li); 
        }
        
        // apply specific identity-based profile. 'li' is still valid, since we still hold the lock
        // get ptr to identity_info

        DIA_("resolve_identity: about to call apply_id_policies, group: %s",li.groups);
        apply_id_policies(cx);

    } else {
        if (insert_guest == true) {
            shm_logon_info li = shm_logon_info(cx->host().c_str(),"guest","");
            
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
            cfgapi_ip_auth_remove(cx->host());
        }
    }

    cfgapi_identity_ip_lock.unlock();
    return ret;
}

int MitmProxy::handle_sockets_once(baseCom* xcom) {
    
    if(av_proxy != nullptr) {
        if(xcom->master()->poller.in_read_set(av_proxy->socket())) {
            handle_internal_data(av_proxy);
        }
    }
    
    return baseProxy::handle_sockets_once(xcom);
}


std::string whitelist_make_key(MitmHostCX* cx)  {
    
    std::string key;
    
    if(cx != nullptr && cx->peer() != nullptr) {
        key = cx->host() + ":" + cx->peer()->host() + ":" + cx->peer()->port();
    } else {
        key = "?";
    }
    
    return key;
}


void MitmProxy::on_left_bytes(baseHostCX* cx) {
    
    if(is_backend_cx(cx)) {
        INF_("on_left_bytes[%s]: left internal connection new data arrived",cx->full_name('L').c_str());
        handle_internal_data(cx);
        return;
    }    
    
    
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
                    if(mh->replacement_type() == MitmHostCX::REPLACETYPE_HTTP) {
                
                        mh->replacement_flag(MitmHostCX::REPLACE_REDIRECT);
                        redirected = true;
                        handle_replacement_auth(mh);
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
            } else {
                if(auth_block_identity) {
                    if(mh->replacement_type() == MitmHostCX::REPLACETYPE_HTTP) {
                        DIAS_("MitmProxy::on_left_bytes: we should block it");
                        mh->replacement_flag(MitmHostCX::REPLACE_BLOCK);
                        redirected = true;
                        handle_replacement_auth(mh);
                    }
                }
            }
        }
     
        // check com responses
        // peer SSLCom
        SSLCom* scom = dynamic_cast<SSLCom*>(cx->peercom());
        if(scom && scom->opt_failed_certcheck_replacement) {
            if(scom->verify_status != SSLCom::VERIFY_OK) {
                
                bool whitelist_found = false;
                
                //look for whitelisted entry
                std::string key = whitelist_make_key(mh);
                if(key.size() > 0 && key != "?") {
                    whitelist_verify.lock();
                    whitelist_verify_entry_t* wh = whitelist_verify.get(key);
                    DIA_("whitelist_verify[%s]: %s",key.c_str(), wh ? "found" : "not found" );
                    whitelist_verify.unlock();
                    
                    // !!! wh might be already invalid here, unlocked !!!
                    if(wh != nullptr) {
                        whitelist_found = true;
                    } 
                }
                
                
                if(!whitelist_found) {
                    DIAS_("relaxed cert-check: peer sslcom verify not OK, not in whitelist");
                    if(mh->replacement_type() == MitmHostCX::REPLACETYPE_HTTP) {
                        mh->replacement_flag(MitmHostCX::REPLACE_BLOCK);
                        redirected = true;
                        handle_replacement_ssl(mh);
                        
                    } else {
                        dead(true);
                    }
                }
            }
        }
     
        if(mh->inspection_verdict() == Inspector::CACHED) {
            DIAS_("cached content: not proxying");
            return;
        }
    }
    
    
    // because we have left bytes, let's copy them into all right side sockets!
    for(typename std::vector<baseHostCX*>::iterator j = this->right_sockets.begin(); j != this->right_sockets.end(); j++) {
        if( is_backend_cx(*j) ) continue;
        
        if(!redirected) {
            if(content_rule() != nullptr) {
                buffer b = content_replace_apply(cx->to_read());
                (*j)->to_write(b);
                DIA___("mitmproxy::on_left_bytes: original %d bytes replaced with %d bytes",cx->to_read().size(),b.size())
            } else {
                (*j)->to_write(cx->to_read());
                DIA_("mitmproxy::on_left_bytes: %d copied",cx->to_read().size())
            }
        } else {
        
        // rest of connections should be closed when sending replacement to a client
        (*j)->shutdown();
        }
    }    
    for(typename std::vector<baseHostCX*>::iterator j = this->right_delayed_accepts.begin(); j != this->right_delayed_accepts.end(); j++) {
        if( is_backend_cx(*j) ) continue;
        
        if(!redirected) {
            if(content_rule() != nullptr) {
                buffer b = content_replace_apply(cx->to_read());
                (*j)->to_write(b);
                DIA___("mitmproxy::on_left_bytes: original %d bytes replaced with %d bytes into delayed",cx->to_read().size(),b.size())
            } else {	  
                (*j)->to_write(cx->to_read());
                DIA_("mitmproxy::on_left_bytes: %d copied to delayed",cx->to_read().size())
            }
        } else {
        
        // rest of connections should be closed when sending replacement to a client
        (*j)->shutdown();
        }
    }    
 
    socle::time_update_counter_sec(&cnt_left_bytes_second,&meter_left_bytes_second,1,cx->to_read().size());
}

void MitmProxy::on_right_bytes(baseHostCX* cx) {

    if(is_backend_cx(cx)) {
        INF_("on_right_bytes[%s]: right internal connection new data arrived",cx->full_name('R').c_str());
        handle_internal_data(cx);
        return;
    }    
    
    if(write_payload()) {
        if(cx->log().size()) {
            tlog()->write('R',cx->log());
            cx->log() = "";
        }
        
        tlog()->right_write(cx->to_read());
    }
    
    
    if(av_backend_status >= AV_STAT_OK && av_proxy != nullptr) {
        
        int32_t data_len = htonl(cx->to_read().size());
        
        av_proxy->to_write((unsigned char*)&data_len,4);
        av_proxy->to_write(cx->to_read());
        
        // test: terminate 
        int32_t zero = 0;
        av_proxy->to_write((unsigned char*)&zero,4);
        
        //INF___("Sent to AV:\n%s",hex_dump(av_proxy->writebuf()).c_str());
        
        av_proxy->write();
    }
    
    
    for(typename std::vector<baseHostCX*>::iterator j = this->left_sockets.begin(); j != this->left_sockets.end(); j++) {
        if( is_backend_cx(*j) ) continue;
        
        if(content_rule() != nullptr) {
            buffer b = content_replace_apply(cx->to_read());
            (*j)->to_write(b);
            DIA___("mitmproxy::on_right_bytes: original %d bytes replaced with %d bytes",cx->to_read().size(),b.size())
        } else {      
            (*j)->to_write(cx->to_read());
            DIA_("mitmproxy::on_right_bytes: %d copied",cx->to_read().size())
        }
    }
    for(typename std::vector<baseHostCX*>::iterator j = this->left_delayed_accepts.begin(); j != this->left_delayed_accepts.end(); j++) {
        if( is_backend_cx(*j) ) continue;
        
        if(content_rule() != nullptr) {
            buffer b = content_replace_apply(cx->to_read());
            (*j)->to_write(b);
            DIA___("mitmproxy::on_right_bytes: original %d bytes replaced with %d bytes into delayed",cx->to_read().size(),b.size())
        } else {      
            (*j)->to_write(cx->to_read()); 
            DIA_("mitmproxy::on_right_bytes: %d copied to delayed",cx->to_read().size())
        }
    }

    socle::time_update_counter_sec(&cnt_right_bytes_second,&meter_right_bytes_second,1,cx->to_read().size());
}


bool MitmProxy::is_backend_cx(baseHostCX* cx) {
    std::vector<baseHostCX*>:: iterator it = std::find(backends_.begin(),backends_.end(),cx);
    return (it != backends_.end());
}

void MitmProxy::on_backend_error(baseHostCX* cx) {

    DIA___("on_backend_error: %s",cx->c_name());
    
    com()->master()->unset_monitor(cx->socket());
    cx->shutdown();

    auto it = std::find(backends_.begin(),backends_.end(),cx);
    if(it != backends_.end()) {
        //backends_.erase(it);
    }
    
    auto itl = std::find(left_sockets.begin(),left_sockets.end(),cx);
    if(itl != left_sockets.end()) {
        left_sockets.erase(itl);
        return;
    }
    auto itr = std::find(right_sockets.begin(),right_sockets.end(),cx);
    if(itr != right_sockets.end()) {
        right_sockets.erase(itr);
        return;
    }
}


void MitmProxy::__debug_zero_connections(baseHostCX* cx) {

    if(cx->meter_write_count == 0 && cx->meter_write_bytes == 0 ) {
        SSLCom* c = dynamic_cast<SSLCom*>(cx->com());
        if(c) {
            c->log_profiling_stats(INF);
            int p = 0; 
            int s = cx->socket();
            if(s == 0) s = cx->closed_socket();
            if(s != 0) {
                buffer b(1024);
                p = cx->com()->peek(s,b.data(),b.capacity(),0);
                INF_("        cx peek size %d",p);
            }
            
        }
        
        if(cx->peer()) {
            SSLCom* c = dynamic_cast<SSLCom*>(cx->peer()->com());
            if(c) {
                c->log_profiling_stats(INF);
                INF_("        peer transferred bytes: up=%d/%dB dw=%d/%dB",cx->peer()->meter_read_count,cx->peer()->meter_read_bytes,
                                                                cx->peer()->meter_write_count, cx->peer()->meter_write_bytes);
                int p = 0; 
                int s = cx->peer()->socket();
                if(s == 0) s = cx->peer()->closed_socket();
                if(s != 0) {
                    buffer b(1024);
                    p = cx->peer()->com()->peek(s,b.data(),b.capacity(),0);
                    INF_("        peer peek size %d",p);
                }                
            }
            
        }
    }
}


void MitmProxy::on_left_error(baseHostCX* cx) {

    if(this->dead()) return;  // don't process errors twice

    
    if(is_backend_cx(cx)) {
        
        on_backend_error(cx);
        if(cx->socket() > 0) {
            // we will ignore backend cx, since they can close/open at will during life of the proxy
            INF_("on_left_error[%s]: left internal connection closed",cx->full_name('L').c_str());
        }
        // don't harm proxy, leave.
        return;
    }
    
    DEB_("on_left_error[%s]: proxy marked dead",(this->error_on_read ? "read" : "write"));
    DUMS_(to_string().c_str());
    
    if(write_payload()) {
        tlog()->left_write("Client side connection closed: " + cx->name() + "\n");
    }
    
    if(opt_auth_resolve)
        resolve_identity(cx);

    std::string flags = "L";
    MitmHostCX* mh = dynamic_cast<MitmHostCX*>(cx);
    if (mh != nullptr && mh->inspection_verdict() == Inspector::CACHED) flags+="C";
    
    INF_("Connection from %s closed: user=%s up=%d/%dB dw=%d/%dB flags=%s+%s",
                        cx->full_name('L').c_str(),
                                     (identity_resolved() ? identity().username : ""),
                                        cx->meter_read_count,cx->meter_read_bytes,
                                                            cx->meter_write_count, cx->meter_write_bytes,
                                                                        flags.c_str(),
                                                                        com()->full_flags_str().c_str()
        );

    if(LEV_(DEB)) __debug_zero_connections(cx);
    
    this->dead(true); 
}

void MitmProxy::on_right_error(baseHostCX* cx)
{
    if(this->dead()) return;  // don't process errors twice

    if(is_backend_cx(cx)) {
        // we will ignore backend cx, since they can close/open at will during life of the proxy
        INF_("on_right_error[%s]: right internal connection closed",cx->full_name('R').c_str());
        on_backend_error(cx);
        
        // don't harm proxy, leave.
        return;
    }    
    
    DEB_("on_right_error[%s]: proxy marked dead",(this->error_on_read ? "read" : "write"));
    
    if(write_payload()) {
        tlog()->right_write("Server side connection closed: " + cx->name() + "\n");
    }
    
//         INF_("Created new proxy 0x%08x from %s:%s to %s:%d",new_proxy,f,f_p, t,t_p );


    std::string flags = "R";
    std::string comflags = "";
    MitmHostCX* mh_peer = dynamic_cast<MitmHostCX*>(cx->peer());
    if (mh_peer != nullptr) {
        if(mh_peer->inspection_verdict() == Inspector::CACHED) flags+="C";
        if(mh_peer->com() != nullptr)
            comflags = mh_peer->com()->full_flags_str();
    }

    INF_("Connection from %s closed: user=%s up=%d/%dB dw=%d/%dB flags=%s+%s",
                            cx->full_name('R').c_str(), 
                                     (identity_resolved() ? identity().username : ""),         
                                            cx->meter_write_count, cx->meter_write_bytes,
                                                            cx->meter_read_count,cx->meter_read_bytes,
                                                                    flags.c_str(),
                                                                    comflags.c_str()
        );

    if(LEV_(DEB)) __debug_zero_connections(cx);
    
    this->dead(true); 
}



void MitmProxy::handle_replacement_auth(MitmHostCX* cx) {
  
    std::string redir_pre("<!DOCTYPE html><html><head><script>top.location.href=\"");
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
    
    std::string block_pre("<!DOCTYPE html><html><head></head><body><h1>Page has been blocked</h1><p>Access has been blocked by smithproxy.</p>\
    <p>To check your user privileges go to status page <a href=");
    std::string block_post(">here</a></p></body></html>");
    
    //cx->host().c_str()
    
    if (cx->replacement_flag() == MitmHostCX::REPLACE_REDIRECT) {
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
                INF_("MitmProxy::handle_replacement_auth: cached token %s for request: %s",token_tk.c_str(),cx->application_data->hr().c_str());
                
                repl = redir_pre + repl_proto + "://"+cfgapi_identity_portal_address+":"+repl_port+"/cgi-bin/auth.py?token=" + token_tk + redir_suf;
                cx->to_write((unsigned char*)repl.c_str(),repl.size());
                cx->close_after_write(true);
            } else {
                INF_("MitmProxy::handle_replacement_auth: expired token %s for request: %s",token_tk.c_str(),cx->application_data->hr().c_str());
                goto new_token;
            }
        } else {
        
            new_token:
            
            std::string token_text = cx->application_data->original_request();
          
            for(auto i: cfgapi_obj_policy_profile_auth( cx->matched_policy())->sub_policies) {
                DIA_("MitmProxy::handle_replacement_auth: token: requesting identity %s",i->name.c_str());
                token_text  += " |" + i->name;
            }
            shm_logon_token tok = shm_logon_token(token_text.c_str());
            
            INF_("MitmProxy::handle_replacement_auth: new auth token %s for request: %s",tok.token,cx->application_data->hr().c_str());
            repl = redir_pre + repl_proto + "://"+cfgapi_identity_portal_address+":"+repl_port+"/cgi-bin/auth.py?token=" + tok.token + redir_suf;
            
            cx->to_write((unsigned char*)repl.c_str(),repl.size());
            cx->close_after_write(true);
            
            cfgapi_auth_shm_token_table_refresh();
            
            auth_shm_token_map.entries().push_back(tok);
            auth_shm_token_map.acquire();
            auth_shm_token_map.save(true);
            auth_shm_token_map.release();
            
            INFS_("MitmProxy::handle_replacement_auth: token table updated");
            cfgapi_identity_token_cache[cx->host()] = std::pair<unsigned int,std::string>(time(nullptr),tok.token);
        }
        
        cfgapi_identity_token_lock.unlock();
    } else
    if (cx->replacement_flag() == MitmHostCX::REPLACE_BLOCK) {

        DIAS_("MitmProxy::handle_replacement_auth: instructed to replace block");
        repl = block_pre + repl_proto + "://"+cfgapi_identity_portal_address+":"+repl_port + "/cgi-bin/auth.py?a=z" + block_post;
        cx->to_write((unsigned char*)repl.c_str(),repl.size());
        cx->close_after_write(true);

    } else
    if (cx->replacement_flag() == MitmHostCX::REPLACE_NONE) {
        DIAS_("MitmProxy::handle_replacement_auth: asked to handle NONE. No-op.");
    } 
}

void MitmProxy::handle_internal_data(baseHostCX* cx) {
    if( cx->read() == 0) {
        DIAS___("backend channel closed on read.");
        cx->shutdown();
        return;
    }        
    
    int len = cx->readbuf()->size();
    INF_("handle_internal_data[%s]: %d bytes arrived",cx->full_name('L').c_str(),len);
    
    if(cx == av_proxy) {
        INF___("handle_internal_data[%s]: AV message: %s",cx->full_name('L').c_str(), hex_dump(cx->readbuf()).c_str());
    }
}


void MitmProxy::handle_replacement_ssl(MitmHostCX* cx) {
    
    std::string repl;
    std::string repl_port = cfgapi_identity_portal_port_http;
    std::string repl_proto = "http";
    int     redir_hint = 0;
    
    if(cx->application_data->is_ssl) {
        repl_proto = "https";
        repl_port = cfgapi_identity_portal_port_https;
    }    
    
    std::string block_pre("<!DOCTYPE html><html><head></head><body><h1>Issue with encrypted page</h1><p>Access has been blocked by smithproxy.</p>");
    std::string block_post("</body></html>");
    std::string block_additinal_info;
    std::string block_override_pre = "<form action=\"/SM/IT/HP/RO/XY";
    
    std::string key = whitelist_make_key(cx);
    if(cx->peer()) {
        block_override_pre += "/override/target=" + key;//cx->peer()->host() + "#" + cx->peer()->port() + "&";
    }
    std::string block_override;
    std::string block_target_info;
    
    
    app_HttpRequest* app_request = dynamic_cast<app_HttpRequest*>(cx->application_data);
    if(app_request != nullptr) {
        
//         INF_(" --- request: %s",app_request->request().c_str());
//         INF_(" ---     uri: %s",app_request->uri.c_str());
//         INF_(" --- origuri: %s",app_request->original_request().c_str());
//         INF_(" --- referer: %s",app_request->referer.c_str());
        
        if(app_request->request().find("/SM/IT/HP/RO/XY/override") != std::string::npos) {
            
            // PHASE IV.
            // perform override action
            
            DIA_("ssl_override: ph4 - asked for verify override for %s", whitelist_make_key(cx).c_str());
            
            std::string orig_url = "about:blank";
            
            //we require orig_url is the last argument!!!
            unsigned int a = app_request->request().find("orig_url");
            if(a != std::string::npos) {
                //len of "orig_url=" is 9
                orig_url = app_request->request().substr(a+9);
            }
            
            
            std::string override_applied = string_format("<!DOCTYPE html><html><head><meta http-equiv=\"Refresh\" content=\"0; url=%s\"></head><body>applied, redirecting back to %s</body></html>",
                                                         orig_url.c_str(),orig_url.c_str());

            whitelist_verify_entry v;

            whitelist_verify.lock();
            whitelist_verify.set(key,new whitelist_verify_entry_t(v,300));
            whitelist_verify.unlock();
            
            cx->to_write((unsigned char*)override_applied.c_str(),override_applied.size());
            cx->close_after_write(true);
            
            WAR_("Connection from %s: SSL override activated for %s",cx->full_name('L').c_str(), app_request->request().c_str());
            
            return;
            
        } else 
        if(app_request->request().find("/SM/IT/HP/RO/XY/warning") != std::string::npos){
            
            // PHASE III.
            // display warning and button which will trigger override
        
            DIA_("ssl_override: ph3 - warning replacement for %s", whitelist_make_key(cx).c_str());
            
            block_target_info = "<p><b>Requested URL:</b></br>" + app_request->request() + "</p>";
            block_override = string_format("orig_url=%s\"><br><input type=\"submit\" value=\"Override\"></form>","/");
            
            
            SSLCom* scom = dynamic_cast<SSLCom*>(cx->peercom());
            if(scom) {
                bool is_set = false;
                if(scom->verify_check(SSLCom::SELF_SIGNED)) {
                        block_additinal_info += "<p><b>Reason:</b></br>Target certificate is self-signed.<p>"; is_set = true;
                        block_additinal_info += block_override_pre + block_override;
                }
                if(scom->verify_check(SSLCom::UNKNOWN_ISSUER)) {
                        block_additinal_info += "<p><b>Reason:</b></br>Target certificate is issued by untrusted certificate identity.<p>"; is_set = true;
                        block_additinal_info += block_override_pre + block_override;
                }
                if(scom->verify_check(SSLCom::CLIENT_CERT_RQ)) {
                        block_additinal_info += "<p><b>Reason:</b></br>Target server asks for client certificate.<p>"; is_set = true;
                        block_additinal_info += block_override_pre + block_override;
                }
                
                if(!is_set) {
                        block_additinal_info += "<p><b>Reason:</b></br>Oops, no detailed problem description:(<p>";
                }
            }
            
            DIAS_("MitmProxy::handle_replacement_ssl: instructed to replace block");
            repl = block_pre + block_target_info + block_additinal_info + block_post;
            cx->to_write((unsigned char*)repl.c_str(),repl.size());
            cx->close_after_write(true);
        } else 
        if(app_request->uri == "/"){
            // PHASE II
            // redir to warning message
            
            DIA_("ssl_override: ph2 - redir to warning replacement for  %s", whitelist_make_key(cx).c_str());
            
            std::string repl = "<!DOCTYPE html><html><head><meta http-equiv=\"Refresh\" content=\"0; url=/SM/IT/HP/RO/XY/warning\"></head><body></body></html>";
            cx->to_write((unsigned char*)repl.c_str(),repl.size());
            cx->close_after_write(true);            
        }   
        else {
            // PHASE I
            // redirecting to / -- for example some subpages would be displayed incorrectly
            
            DIA_("ssl_override: ph1 - redir to / for %s", whitelist_make_key(cx).c_str());
            
            std::string redir_pre("<!DOCTYPE html><html><head><script>top.location.href=\"");
            std::string redir_suf("\";</script></head><body></body></html>");  
            
            //std::string repl = "<!DOCTYPE html><html><head><meta http-equiv=\"Refresh\" content=\"0; url=/\"></head><body></body></html>";            
            std::string repl = redir_pre + "/" + redir_suf;            
            cx->to_write((unsigned char*)repl.c_str(),repl.size());
            cx->close_after_write(true);            
        }
    }
    
}

void MitmProxy::init_content_replace() {
    
    if(content_rule_ != nullptr) {
        DIAS_("MitmProxy::init_content_replace: deleting old replace rules");
        delete content_rule_;
    }
    
    content_rule_ = new std::vector<ProfileContentRule>;
}

buffer MitmProxy::content_replace_apply(buffer b) {
    std::string data = b.to_string();
    std::string result = data;
    
    int stage = 0;
    for(auto i = content_rule()->begin(); i != content_rule()->end(); ++i) {
        ProfileContentRule& profile = (*i);
        
        try {
            std::regex re_match(profile.match.c_str());
            std::string repl = profile.replace;
            
            if(profile.replace_each_nth != 0) {

                // unfortunately std::regex_replace doesn't return if it really replaced something
                // ... which is no problem if we don't care. But in case we want to replace only 
                // .... nth occurence, we have to do extra search to check (requiring one extra regex match).
                std::smatch sm;
                bool is_there = std::regex_search(result,sm,re_match);

                if(is_there) {
                    profile.replace_each_counter_++;
                    if(profile.replace_each_counter_ >= profile.replace_each_nth) {
                        
                        if(profile.fill_length) {
                            result = regex_replace_fill(result, profile.match, repl);
                        } else {
                            result = std::regex_replace(result, re_match, repl);              
                        }
                        profile.replace_each_counter_ = 0;
                        DIA___("Replacing bytes[stage %d]: n-th counter hit",stage);
                    }
                }
                
            } else {
                if(profile.fill_length) {
                    result = regex_replace_fill(result, profile.match, repl);
                } else {
                    result = std::regex_replace(result, re_match, repl);              
                }
            }

            DIA___("Replacing bytes[stage %d]:",stage);
        }
        catch(std::regex_error e) {
        NOT_("MitmProxy::content_replace_apply: failed to replace string: %s",e.what());
        }
        
        ++stage;
    }
    
    
    
    
    
    buffer ret_b;
    ret_b.append(result.c_str(),result.size());
    
    DIA___("content rewritten: original %d bytes with new %d bytes.",b.size(),ret_b.size());
    DUM___("Replacing bytes (%d):\n%s\n# with bytes(%d):\n%s",data.size(),hex_dump(b).c_str(),ret_b.size(),hex_dump(ret_b).c_str());
    return ret_b;
}

int MitmProxy::av_backend_init() {

    if(av_backend_status == AV_STAT_NONE && opt_av_check) {
        UxCom* u = new UxCom();
        u->master(com()->master());
        baseHostCX *backend_cx = new baseHostCX(u,"/var/run/clamav/clamd.ctl","0");

        int real_socket = backend_cx->connect(false); 
        if(real_socket > 0) {
            backends().push_back(backend_cx);
            
            com()->set_monitor(real_socket);
            com()->set_poll_handler(real_socket,this);
            
            std::string init_str = "nINSTREAM\n";
            backend_cx->to_write((unsigned char*)init_str.c_str(),init_str.size());
            backend_cx->write();
            
            av_backend_status = AV_STAT_OK;
            av_proxy = backend_cx;
            
            DIA___("AV backend initialized successfully on socket %d", real_socket);
        } else {
            av_backend_status = AV_STAT_FAILED;
            ERRS___("AV backend initialization failed")
            delete backend_cx;
        }
    }
    
    return av_backend_status;
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
        std::string h;
        std::string p;
        just_accepted_cx->name();
        just_accepted_cx->com()->resolve_socket_src(just_accepted_cx->socket(),&h,&p);

        MitmProxy* new_proxy = new MitmProxy(just_accepted_cx->com()->slave());
        
        // let's add this just_accepted_cx into new_proxy
        if(just_accepted_cx->paused_read()) {
            DEBS_("MitmMasterProxy::on_left_new: ldaadd the new paused cx");
            new_proxy->ldaadd(just_accepted_cx);
        } else{
            DEBS_("MitmMasterProxy::on_left_new: ladd the new cx (unpaused)");
            new_proxy->ladd(just_accepted_cx);
        }
        
        bool matched_vip = false; //did it match virtual IP?
        
        std::string target_host = just_accepted_cx->com()->nonlocal_dst_host();
        std::string orig_target_host;
        short unsigned int target_port = just_accepted_cx->com()->nonlocal_dst_port();
        short unsigned int orig_target_port;

        if( target_host == cfgapi_tenant_magic_ip) {
            
            orig_target_host = target_host;
            orig_target_port = target_port;
            
            if(target_port == 65000 || target_port == 143) {
                // bend broker magic IP
                target_port = 65000 + cfgapi_tenant_index;
            }
            else if(target_port != 443) {
                // auth portal https magic IP
                target_port = std::stoi(cfgapi_identity_portal_port_http);
            } else {
                // auth portal plaintext magic IP
                target_port = std::stoi(cfgapi_identity_portal_port_https);
            }
            target_host = "127.0.0.1";
            
            DIA_("Connection from %s to %s:%d: traffic redirected from magic IP to %s:%d",just_accepted_cx->c_name(), 
                 orig_target_host.c_str(), orig_target_port,
                 target_host.c_str(), target_port);
            matched_vip = true;
        }
        
        MitmHostCX *target_cx = new MitmHostCX(just_accepted_cx->com()->slave(), target_host.c_str(), 
                                            string_format("%d",target_port).c_str()
                                            );
        
        
        // connect it! - btw ... we don't want to block of course...
        
        
        just_accepted_cx->peer(target_cx);
        target_cx->peer(just_accepted_cx);          


        // almost done, just add this target_cx to right side of new proxy
        new_proxy->radd(target_cx);
        bool delete_proxy = false;
        
        // apply policy and get result
        int policy_num = cfgapi_obj_policy_apply(just_accepted_cx,new_proxy);

        // bypass ssl com to VIP
        if(matched_vip) {
            SSLCom* scom = dynamic_cast<SSLCom*>(just_accepted_cx->com());
            if(scom != nullptr) {
                scom->opt_bypass = true;
            }
            
            scom = dynamic_cast<SSLCom*>(target_cx->com());
            if(scom != nullptr) {
                scom->opt_bypass = true;
            }
            
        }
        
        if(policy_num >= 0) {

            //traffic is allowed
            
            MitmHostCX* src_cx;
            src_cx = dynamic_cast<MitmHostCX*>(just_accepted_cx);
            if (src_cx != nullptr) {
                
                // we know proxy can be properly configured now, both peers are MitmHostCX types
                
                // let know CX what policy it matched (it is handly CX will know under some circumstances like upgrade to SSL)
                src_cx->matched_policy(policy_num);
                target_cx->matched_policy(policy_num);
                new_proxy->matched_policy(policy_num);

                // resolve source information - is there un identity info for that IP?
                if(new_proxy->opt_auth_authenticate && new_proxy->opt_auth_resolve) {
                    bool res = new_proxy->resolve_identity(src_cx);

                    // reload table and check timeouts each 5 seconds 
                    time_t now = time(nullptr);
                    if(now > auth_table_refreshed + 5) {
                        cfgapi_auth_shm_ip_table_refresh();
                        auth_table_refreshed = now;
                        
                        //one day this can run in separate thread to not slow down session setup rate
                        cfgapi_ip_auth_timeout_check();
                    }
                    
                    
                    if(!res) {
                        if(target_port != 80 && target_port != 443){
                            delete_proxy = true;
                            INF_("Dropping non-replaceable connection %s due to unknown source IP",just_accepted_cx->c_name());
                            goto end;
                        }
                    } else {
                        bool bad_auth = true;
                        
                        cfgapi_identity_ip_lock.lock();    
                        auto ip = auth_ip_map.find(just_accepted_cx->host());
                        
                        if (ip != auth_ip_map.end()) {
                            IdentityInfo& id = (*ip).second;
                            std::string groups = id.last_logon_info.groups;
                            
                            if(cfgapi_obj_policy_profile_auth(policy_num) != nullptr)
                            for ( auto i: cfgapi_obj_policy_profile_auth(policy_num)->sub_policies) {
                                for(auto x: id.groups_vec) {
                                    DEB_("Connection identities: ip identity '%s' against policy '%s'",x.c_str(),i->name.c_str());
                                    if(x == i->name) {
                                        DIA_("Connection identities: ip identity '%s' matches policy '%s'",x.c_str(),i->name.c_str());
                                        bad_auth = false;
                                    }
                                }
                            }
                            if(bad_auth) {
                                if(target_port != 80 && target_port != 443) {
                                    INF_("Dropping non-replaceable connection %s due to non-matching identity",just_accepted_cx->c_name());
                                }
                                else {
                                    INF_("Connection %s with non-matching identity (to be replaced)",just_accepted_cx->c_name());
                                    // set bad_auth true, because despite authentication failed, it could be replaced (we can let user know 
                                    // he is not allowed to proceed
                                    bad_auth = false;
                                    new_proxy->auth_block_identity = true;
                                }
                            }
                        }
                        cfgapi_identity_ip_lock.unlock();
                        
                        if(bad_auth) {
                            delete_proxy = true;
                            goto end;
                        }
                    }
                }
                
                // setup NAT
                if(cfgapi_obj_policy.at(policy_num)->nat == POLICY_NAT_NONE && ! matched_vip) {
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
                delete_proxy = true;
                NOT_("MitmMasterProxy::on_left_new: %s cannot be converted to MitmHostCx",just_accepted_cx->c_name());
            }
  
        } else {
            
            // hmm. traffic is denied.
            delete_proxy = true;
        }
        
        // if set, initialize AV socket
        if(new_proxy->opt_av_check && ( target_port == 80 || target_port == 443 ) ) {
           new_proxy->av_backend_init();
        }
        
        end:
        
        new_proxy->name(new_proxy->to_string(INF));
        
        
        if(delete_proxy) {
            INF_("Dropping proxy %s",new_proxy->c_name());
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


    
    ((MitmHostCX*)just_accepted_cx)->mode(AppHostCX::MODE_NONE);
    target_cx->mode(AppHostCX::MODE_NONE);
    
    new_proxy->radd(target_cx);

    // apply policy and get result
    int policy_num = cfgapi_obj_policy_apply(just_accepted_cx,new_proxy);
    if(policy_num >= 0) {
        this->proxies().push_back(new_proxy);
        
        ((MitmHostCX*)just_accepted_cx)->matched_policy(policy_num);
        target_cx->matched_policy(policy_num);
        new_proxy->matched_policy(policy_num);
        
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
