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
#include <staticcontent.hpp>
#include <filterproxy.hpp>

#include <algorithm>
#include <ctime>


DEFINE_LOGGING(MitmProxy);



socle::meter MitmProxy::total_mtr_up;
socle::meter MitmProxy::total_mtr_down;

ptr_cache<std::string,whitelist_verify_entry_t> MitmProxy::whitelist_verify("whitelist - verify",500,true,whitelist_verify_entry_t::is_expired);

MitmProxy::MitmProxy(baseCom* c): baseProxy(c), sobject() {

}

void MitmProxy::toggle_tlog() {
    
    // create traffic logger if it doesn't exist
    if(tlog_ == nullptr) {
        std::string data_dir = "mitm";
        std::string file_pref = "";
        std::string file_suff = "smcap";
        
        cfgapi.getRoot()["settings"].lookupValue("write_payload_dir",data_dir);
        cfgapi.getRoot()["settings"].lookupValue("write_payload_file_prefix",file_pref);
        cfgapi.getRoot()["settings"].lookupValue("write_payload_file_suffix",file_suff);
        
        tlog_ = new trafLog(this,data_dir.c_str(),file_pref.c_str(),file_suff.c_str());
    }
    
    // check if we have there status file
    if(tlog_) {
        std::string data_dir = "mitm";
        cfgapi.getRoot()["settings"].lookupValue("write_payload_dir",data_dir);

        data_dir += "/disabled";
        
        struct stat st;
        int result = stat(data_dir.c_str(), &st);
        bool present = (result == 0);
        
        if(present) {
            if(tlog()->status() == true) {
                WARS___("capture disabled by disabled-file");
            }
            tlog()->status(false);
        } else {
            if(tlog()->status() == false) {
                WARS___("capture re-enabled from previous disabled-file state");
            }            
            tlog()->status(true);
        }
    }
}


MitmProxy::~MitmProxy() {
    
    if(write_payload()) {
        DEBS___("MitmProxy::destructor: syncing writer");

        for(typename std::vector<baseHostCX*>::iterator j = this->left_sockets.begin(); j != this->left_sockets.end(); ++j) {
            auto cx = (*j);
            if(cx->log().size()) {
                if(tlog()) tlog()->write('L', cx->log());
                cx->log() = "";
            }
        }               
        
        for(typename std::vector<baseHostCX*>::iterator j = this->right_sockets.begin(); j != this->right_sockets.end(); ++j) {
            auto cx = (*j);
            if(cx->log().size()) {
                if(tlog()) tlog()->write('R', cx->log());
                cx->log() = "";
            }
        }         
        
        if(tlog()) tlog()->left_write("Connection stop\n");
    }
    
    if(content_rule_ != nullptr) {
      delete content_rule_;
    }
        
    delete tlog_;
    
    if(identity_ != nullptr) { delete identity_; }
}

std::string MitmProxy::to_string(int verbosity) { 
    std::stringstream r;
    r <<  "MitmProxy:" + baseProxy::to_string(verbosity);
    
    if(verbosity >= INF) {
        r << string_format(" policy: %d ",matched_policy());
        
        if(identity_resolved()) {
            r << string_format("identity: %s ",identity_->username().c_str());
        }
        
        if(verbosity > INF) r << "\n    ";
        
        r << string_format("up/down: %s/%s",number_suffixed(mtr_up.get()*8).c_str(),number_suffixed(mtr_down.get()*8).c_str());
        
        if(verbosity > INF) { 
                r << string_format("\n    PolicyRule Id: 0x%x",cfgapi_obj_policy.at(matched_policy()));

            if(identity_resolved()) {
                r << string_format("\n    User:   %s",identity_->username().c_str()); 
                r << string_format("\n    Groups: %s",identity_->groups().c_str()); 
            }
        }        
    }
    
    return r.str();
}


void MitmProxy::identity_resolved(bool b) {
    identity_resolved_ = b;
}
bool MitmProxy::identity_resolved() {
    return identity_resolved_;
}


bool MitmProxy::apply_id_policies(baseHostCX* cx) {


    int af = AF_INET;
    if(cx->com()) {
        af = cx->com()->l3_proto();
    }
    std::string str_af = inet_family_str(af); 
    
    if(af == AF_INET || af == 0) cfgapi_identity_ip_lock.lock();
    if(af == AF_INET6) cfgapi_identity_ip6_lock.lock();    

    // use common base pointer, so we can use all IdentityInfo types
    IdentityInfoBase* id_ptr = nullptr;
    
    if(af == AF_INET || af == 0) {
        auto ip = auth_ip_map.find(cx->host());
        if (ip != auth_ip_map.end()) {
            id_ptr = &(*ip).second;
        }
    }
    else if(af == AF_INET6) {
        auto ip = auth_ip6_map.find(cx->host());
        if (ip != auth_ip6_map.end()) {
            id_ptr = &(*ip).second;
        }
    }
    
    ProfileSubAuth* final_profile = nullptr;
    
    if( id_ptr != nullptr) {
        DIA___("apply_id_policies: matched policy: %d",matched_policy());        
        PolicyRule* policy = cfgapi_obj_policy.at(matched_policy());
        
        ProfileAuth* auth_policy = policy->profile_auth;

        
        if(auth_policy != nullptr) {
            for(auto sub: auth_policy->sub_policies) {
                ProfileSubAuth* sub_prof = sub;
                std::string sub_name = sub->name;
                
                DIA___("apply_id_policies: checking identity policy for: %s", sub_name.c_str());
                
                for(auto my_id: id_ptr->groups_vec) {
                    DIA___("apply_id_policies: identity in policy: %s, match-test real user group '%s'",sub_prof->name.c_str(), my_id.c_str());
                    if(sub_prof->name == my_id) {
                        DIAS___("apply_id_policies: .. matched.");
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
            
            DIA___("apply_id_policies: assigning sub-profile %s",final_profile->name.c_str());
            if(final_profile->profile_content != nullptr) {
                if (cfgapi_obj_profile_content_apply(cx,this,final_profile->profile_content)) {
                    pc_name = final_profile->profile_content->prof_name.c_str();
                    DIA___("apply_id_policies: assigning content sub-profile %s",final_profile->profile_content->prof_name.c_str());
                }
            }
            if(final_profile->profile_detection != nullptr) {
                if (cfgapi_obj_profile_detect_apply(cx,this,final_profile->profile_detection)) {
                    pd_name = final_profile->profile_detection->prof_name.c_str();
                    DIA___("apply_id_policies: assigning detection sub-profile %s",final_profile->profile_detection->prof_name.c_str());
                }
            }
            if(final_profile->profile_tls != nullptr) {
                if(cfgapi_obj_profile_tls_apply(cx,this,final_profile->profile_tls)) {
                    pt_name = final_profile->profile_tls->prof_name.c_str();
                    DIA___("apply_id_policies: assigning tls sub-profile %s",final_profile->profile_tls->prof_name.c_str());
                }
            }
            if(final_profile->profile_alg_dns != nullptr) {
                if(cfgapi_obj_alg_dns_apply(cx,this,final_profile->profile_alg_dns)) {
                    algs += final_profile->profile_alg_dns->name + " ";
                    DIA___("apply_id_policies: assigning tls sub-profile %s",final_profile->profile_tls->prof_name.c_str());
                }
            }
            
            // end of custom sub-profiles
            INF___("Connection %s: identity-based sub-profile: name=%s cont=%s det=%s tls=%s algs=%s",cx->full_name('L').c_str(),final_profile->name.c_str(),
                            pc_name, pd_name, pt_name, algs.c_str()
                            );
        }
        
        if(af == AF_INET || af == 0) cfgapi_identity_ip_lock.unlock();
        if(af == AF_INET6) cfgapi_identity_ip6_lock.unlock();  
        return (final_profile != nullptr);
    } 

    if(af == AF_INET || af == 0) cfgapi_identity_ip_lock.unlock();
    if(af == AF_INET6) cfgapi_identity_ip6_lock.unlock();      
    return false;
}

bool MitmProxy::resolve_identity(baseHostCX* cx,bool insert_guest=false) {
    
    int af = AF_INET;
    if(cx->com()) {
        af = cx->com()->l3_proto();
    }
    std::string str_af = inet_family_str(af);
    
    if(identity_resolved()) {
        
        bool update_status = false;
        if(af == AF_INET || af == 0) update_status = update_auth_ipX_map(cx);
        if(af == AF_INET6) update_status = update_auth_ipX_map(cx); 
        
        if(update_status) {
            return true;
        } else {
            identity_resolved(false);
        }
    }
    
    bool valid_ip_auth = false;
    
    DIA___("identity check[%s]: source: %s",str_af.c_str(), cx->host().c_str());
    
    if(af == AF_INET) cfgapi_auth_shm_ip_table_refresh();
    if(af == AF_INET6) cfgapi_auth_shm_ip6_table_refresh();
    
    
    cfgapi_identity_ip_lock.lock();
    shm_logon_info_base* id_ptr = nullptr;
    
    if(af == AF_INET || af == 0) {
        DEB___("identity check[%s]: table size: %d",str_af.c_str(), auth_ip_map.size());
        auto ip = auth_ip_map.find(cx->host());
        if (ip != auth_ip_map.end()) {
            shm_logon_info& li = (*ip).second.last_logon_info;
            id_ptr = &li;
        } else {
            if (insert_guest == true) {
                id_ptr = new shm_logon_info(cx->host().c_str(),"guest","guest+guests+guests_ipv4");
            }
        }
    }
    else if(af == AF_INET6) {
        /* maintain in sync with previous if block */
        DEB___("identity check[%s]: table size: %d",str_af.c_str(), auth_ip6_map.size());
        auto ip = auth_ip6_map.find(cx->host());
        if (ip != auth_ip6_map.end()) {
            shm_logon_info6& li = (*ip).second.last_logon_info;
            id_ptr = &li;
        } else {
            if (insert_guest == true) {
                id_ptr = new shm_logon_info6(cx->host().c_str(),"guest","guest+guests+guests_ipv6");
            }
        }    
    }

    if(id_ptr != nullptr) {
        DIA___("identity found for %s %s: user: %s groups: %s",str_af.c_str(),cx->host().c_str(),id_ptr->username().c_str(), id_ptr->groups().c_str());

        // if update_auth_ip_map fails, identity is no longer valid!
        
        if(af == AF_INET || af == 0) valid_ip_auth = update_auth_ipX_map(cx);
        if(af == AF_INET6) valid_ip_auth = update_auth_ipX_map(cx);
            
        
        identity_resolved(valid_ip_auth);
        if(valid_ip_auth) { 
            identity(id_ptr);
        }
        
        // apply specific identity-based profile. 'li' is still valid, since we still hold the lock
        // get ptr to identity_info

        DIA___("resolve_identity[%s]: about to call apply_id_policies, group: %s",str_af.c_str(), id_ptr->groups().c_str());
        apply_id_policies(cx);
    }
    
    cfgapi_identity_ip_lock.unlock();
    DEB___("identity check[%s]: return %d",str_af.c_str(), valid_ip_auth);
    return valid_ip_auth;
}


bool MitmProxy::update_auth_ipX_map(baseHostCX* cx) {

    bool ret = false;
    
    int af = AF_INET;
    if(cx->com()) {
        af = cx->com()->l3_proto();
    }
    std::string str_af = inet_family_str(af);    
    
    if(af == AF_INET || af == 0) cfgapi_identity_ip_lock.lock();
    if(af == AF_INET6) cfgapi_identity_ip6_lock.lock();

    DEB___("update_auth_ip_map: start for %s %s",str_af.c_str(), cx->host().c_str());
    
    IdentityInfoBase* id_ptr = nullptr;
    
    if(af == AF_INET || af == 0) {
        auto ip = auth_ip_map.find(cx->host());
        if (ip != auth_ip_map.end()) {
            id_ptr = &(*ip).second;
        }
    }
    else if(af == AF_INET6) {
        auto ip = auth_ip6_map.find(cx->host());
        if (ip != auth_ip6_map.end()) {
            id_ptr = &(*ip).second;
        }
    }
    
    if(id_ptr != nullptr) {
        DIA___("update_auth_ip_map: user %s from %s %s (groups: %s)",id_ptr->username.c_str(), str_af.c_str(), cx->host().c_str(), id_ptr->groups.c_str());

        id_ptr->last_seen_policy = matched_policy();
        
        if (!id_ptr->i_timeout()) {
            id_ptr->touch();
            ret = true;
        } else {
            INF___("identity timeout: user %s from %s %s (groups: %s)",id_ptr->username.c_str(), str_af.c_str(), cx->host().c_str(), id_ptr->groups.c_str());
            
            // erase internal ip map entry
            if(af == AF_INET || af == 0) cfgapi_ip_auth_remove(cx->host());
            if(af == AF_INET6) cfgapi_ip6_auth_remove(cx->host());
        }
    }

    if(af == AF_INET || af == 0) cfgapi_identity_ip_lock.unlock();
    if(af == AF_INET6) cfgapi_identity_ip6_lock.unlock();
    
    DEB___("update_auth_ip_map: finished for %s %s, result %d",str_af.c_str(), cx->host().c_str(),ret);
    return ret;
}


void MitmProxy::add_filter(std::string name, FilterProxy* fp) {

    filters_.push_back(std::pair<std::string,FilterProxy*>(name,fp));
    
    for(auto s: fp->ls()) {
        com()->set_monitor(s->socket());
        com()->set_poll_handler(s->socket(),this);
    }
    
    for(auto s: fp->rs()) {
        com()->set_monitor(s->socket());
        com()->set_poll_handler(s->socket(),this);
    }    
}


int MitmProxy::handle_sockets_once(baseCom* xcom) {
    
    for(auto filter_pair: filters_) {
        std::string& filter_name = filter_pair.first;
        baseProxy* filter_proxy = filter_pair.second;
        
        DEB___("MitmProxy::handle_sockets_once: running filter %s", filter_name.c_str());
        filter_proxy->handle_sockets_once(xcom);
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


bool MitmProxy::handle_authentication(MitmHostCX* mh)
{
    bool redirected = false;
    
    if(opt_auth_authenticate || opt_auth_resolve) {
    
        resolve_identity(mh);
        
        if(!identity_resolved()) {        
            DEBS___("identity check: unknown");
            
            if(opt_auth_authenticate) {
                if(mh->replacement_type() == MitmHostCX::REPLACETYPE_HTTP) {
            
                    mh->replacement_flag(MitmHostCX::REPLACE_REDIRECT);
                    redirected = true;
                    handle_replacement_auth(mh);
                } 
                else {
                    // wait, if header won't come in some time, kill the proxy
                    if(mh->meter_read_bytes > 200) {
                        // we cannot use replacements and identity is not resolved... what we can do. Shutdown.
                        EXTS___("not enough data received to ensure right replacement-aware protocol.");
                        dead(true);
                    }
                }
            }
        } else {
            if(auth_block_identity) {
                if(mh->replacement_type() == MitmHostCX::REPLACETYPE_HTTP) {
                    DIAS___("MitmProxy::on_left_bytes: we should block it");
                    mh->replacement_flag(MitmHostCX::REPLACE_BLOCK);
                    redirected = true;
                    handle_replacement_auth(mh);
                }
            }
        }
    }
    return redirected;
}


bool MitmProxy::handle_com_response_ssl(MitmHostCX* mh)
{
    bool redirected = false;
    
    SSLCom* scom = dynamic_cast<SSLCom*>(mh->peercom());
    if(scom && scom->opt_failed_certcheck_replacement) {
        if(scom->verify_status != SSLCom::VERIFY_OK) {
            
            bool whitelist_found = false;
            
            //look for whitelisted entry
            std::string key = whitelist_make_key(mh);
            if(key.size() > 0 && key != "?") {
                whitelist_verify.lock();
                whitelist_verify_entry_t* wh = whitelist_verify.get(key);
                DIA___("whitelist_verify[%s]: %s",key.c_str(), wh ? "found" : "not found" );
                whitelist_verify.unlock();
                
                // !!! wh might be already invalid here, unlocked !!!
                if(wh != nullptr) {
                    whitelist_found = true;
                } 
            }
            
            
            if(!whitelist_found) {
                DIAS___("relaxed cert-check: peer sslcom verify not OK, not in whitelist");
                if(mh->replacement_type() == MitmHostCX::REPLACETYPE_HTTP) {
                    mh->replacement_flag(MitmHostCX::REPLACE_BLOCK);
                    redirected = true;
                    handle_replacement_ssl(mh);
                    
                } 
                else if(scom->verify_check(SSLCom::CLIENT_CERT_RQ) && scom->opt_client_cert_action > 0) {
                    //we should not block
                    if(scom->opt_client_cert_action >= 2) {
                        whitelist_verify.lock();
                        
                        whitelist_verify_entry v;
                        whitelist_verify.set(key,new whitelist_verify_entry_t(v,scom->opt_failed_certcheck_override_timeout));
                        whitelist_verify.unlock();
                    }
                }
                else {
                    dead(true);
                }
            }
        }
    }
    
    return redirected;
}

bool MitmProxy::handle_cached_response(MitmHostCX* mh) {
    
    if(mh->inspection_verdict() == Inspector::CACHED) {
        DIAS___("cached content: not proxying");
        return true;
    }
    
    return false;
}

void MitmProxy::on_left_bytes(baseHostCX* cx) {
    
    if(write_payload()) {
        
        toggle_tlog();
        
        if(cx->log().size()) {
            if(tlog()) tlog()->write('L', cx->log());
            cx->log() = "";
        }
        
        if(tlog()) tlog()->left_write(cx->to_read());
    }
    

    bool redirected = false;
    
    MitmHostCX* mh = dynamic_cast<MitmHostCX*>(cx);

    if(mh != nullptr) {

        // check authentication
        redirected = handle_authentication(mh);
     
        // check com responses
        redirected = handle_com_response_ssl(mh);
        
        
        if(handle_cached_response(mh) == true) { return; }
    }
    
    
    // because we have left bytes, let's copy them into all right side sockets!
    for(auto j: right_sockets) {
        
        if(!redirected) {
            if(content_rule() != nullptr) {
                buffer b = content_replace_apply(cx->to_read());
                j->to_write(b);
                DIA___("mitmproxy::on_left_bytes: original %d bytes replaced with %d bytes",cx->to_read().size(),b.size())
            } else {
                j->to_write(cx->to_read());
                DIA___("mitmproxy::on_left_bytes: %d copied",cx->to_read().size())
            }
        } else {
        
            // rest of connections should be closed when sending replacement to a client
            j->shutdown();
        }
    }    
    for(auto j: right_delayed_accepts) {
        
        if(!redirected) {
            if(content_rule() != nullptr) {
                buffer b = content_replace_apply(cx->to_read());
                j->to_write(b);
                DIA___("mitmproxy::on_left_bytes: original %d bytes replaced with %d bytes into delayed",cx->to_read().size(),b.size())
            } else {	  
                j->to_write(cx->to_read());
                DIA___("mitmproxy::on_left_bytes: %d copied to delayed",cx->to_read().size())
            }
        } else {
        
            // rest of connections should be closed when sending replacement to a client
            j->shutdown();
        }
    }    

    //update meters
    total_mtr_up.update(cx->to_read().size());
    mtr_up.update(cx->to_read().size());
}

void MitmProxy::on_right_bytes(baseHostCX* cx) {
    
    if(write_payload()) {

        toggle_tlog();
        
        if(cx->log().size()) {
            if(tlog()) tlog()->write('R',cx->log());
            cx->log() = "";
        }
        
        if(tlog()) tlog()->right_write(cx->to_read());
    }
    
    
    for(auto j: left_sockets) {
        
        if(content_rule() != nullptr) {
            buffer b = content_replace_apply(cx->to_read());
            j->to_write(b);
            DIA___("mitmproxy::on_right_bytes: original %d bytes replaced with %d bytes",cx->to_read().size(),b.size())
        } else {      
            j->to_write(cx->to_read());
            DIA___("mitmproxy::on_right_bytes: %d copied",cx->to_read().size())
        }
    }
    for(auto j: left_delayed_accepts) {
        
        if(content_rule() != nullptr) {
            buffer b = content_replace_apply(cx->to_read());
            j->to_write(b);
            DIA___("mitmproxy::on_right_bytes: original %d bytes replaced with %d bytes into delayed",cx->to_read().size(),b.size())
        } else {      
            j->to_write(cx->to_read()); 
            DIA___("mitmproxy::on_right_bytes: %d copied to delayed",cx->to_read().size())
        }
    }

    // update meters
    total_mtr_down.update(cx->to_read().size());
    mtr_down.update(cx->to_read().size());
}


void MitmProxy::__debug_zero_connections(baseHostCX* cx) {

    if(cx->meter_write_count == 0 && cx->meter_write_bytes == 0 ) {
        SSLCom* c = dynamic_cast<SSLCom*>(cx->com());
        if(c) {
            c->log_profiling_stats(iINF);
            int p = 0; 
            int s = cx->socket();
            if(s == 0) s = cx->closed_socket();
            if(s != 0) {
                buffer b(1024);
                p = cx->com()->peek(s,b.data(),b.capacity(),0);
                INF___("        cx peek size %d",p);
            }
            
        }
        
        if(cx->peer()) {
            SSLCom* c = dynamic_cast<SSLCom*>(cx->peer()->com());
            if(c) {
                c->log_profiling_stats(iINF);
                INF___("        peer transferred bytes: up=%d/%dB dw=%d/%dB",cx->peer()->meter_read_count,cx->peer()->meter_read_bytes,
                                                                cx->peer()->meter_write_count, cx->peer()->meter_write_bytes);
                int p = 0; 
                int s = cx->peer()->socket();
                if(s == 0) s = cx->peer()->closed_socket();
                if(s != 0) {
                    buffer b(1024);
                    p = cx->peer()->com()->peek(s,b.data(),b.capacity(),0);
                    INF___("        peer peek size %d",p);
                }                
            }
            
        }
    }
}


void MitmProxy::on_left_error(baseHostCX* cx) {

    if(cx == nullptr) return;
    
    if(this->dead()) return;  // don't process errors twice

    
    DEB___("on_left_error[%s]: proxy marked dead",(this->error_on_read ? "read" : "write"));
    DUMS___(to_string().c_str());
    
    if(write_payload()) {
        toggle_tlog();
        if(tlog()) tlog()->left_write("Client side connection closed: " + cx->name() + "\n");
    }
    
    if(opt_auth_resolve)
        resolve_identity(cx);

    std::string flags = "L";
    MitmHostCX* mh = dynamic_cast<MitmHostCX*>(cx);
    if (mh != nullptr && mh->inspection_verdict() == Inspector::CACHED) flags+="C";

    std::string detail = string_format("user=%s up=%d/%dB dw=%d/%dB flags=%s+%s",
                                        (identity_resolved() ? identity()->username().c_str() : ""),
                                            cx->meter_read_count,cx->meter_read_bytes,
                                                                cx->meter_write_count, cx->meter_write_bytes,
                                                                            flags.c_str(),
                                                                            com()->full_flags_str().c_str()
            );
    
    if(cx->peer() && cx->peer()->writebuf()->size() == 0) {
        std::string msg = string_format("Connection from %s closed: %s",cx->full_name('L').c_str(),detail.c_str());
        INFS_(msg.c_str());
        if(LEV_(DEB)) __debug_zero_connections(cx);
        
        this->dead(true); 
    } else {
        
        if(!_half_closed_log) {
            std::string msg = string_format("Connection from %s left half-closed: %s",cx->full_name('L').c_str(),detail.c_str());
            INFS_(msg.c_str());
            
            _half_closed_log = true;
        }
        // cannot set dead now, there are bytes pending
    }
    
    if(cx) {
        cfgapi_ipX_auth_inc_counters(cx);
    }
}

void MitmProxy::on_right_error(baseHostCX* cx)
{
    if(this->dead()) return;  // don't process errors twice
    
    DEB___("on_right_error[%s]: proxy marked dead",(this->error_on_read ? "read" : "write"));
    
    if(write_payload()) {
        toggle_tlog();
        if(tlog()) tlog()->right_write("Server side connection closed: " + cx->name() + "\n");
    }
    
//         INF___("Created new proxy 0x%08x from %s:%s to %s:%d",new_proxy,f,f_p, t,t_p );


    std::string flags = "R";
    std::string comflags = "";
    MitmHostCX* mh_peer = dynamic_cast<MitmHostCX*>(cx->peer());
    if (mh_peer != nullptr) {
        if(mh_peer->inspection_verdict() == Inspector::CACHED) flags+="C";
        if(mh_peer->com() != nullptr)
            comflags = mh_peer->com()->full_flags_str();
    }

    std::string detail = string_format("user=%s up=%d/%dB dw=%d/%dB flags=%s+%s",
                                        (identity_resolved() ? identity()->username().c_str() : ""),
                                            cx->meter_read_count,cx->meter_read_bytes,
                                                                cx->meter_write_count, cx->meter_write_bytes,
                                                                            flags.c_str(),
                                                                            com()->full_flags_str().c_str()
            );
    
    
    if(cx->peer() && cx->peer()->writebuf()->size() == 0) {
        std::string msg = string_format("Connection from %s closed: %s",cx->full_name('R').c_str(),detail.c_str());
        INFS_(msg.c_str());
        if(LEV_(DEB)) __debug_zero_connections(cx);
        
        this->dead(true); 
    } else {
        
        if(!_half_closed_log) {
            std::string msg = string_format("Connection from %s right half-closed: %s",cx->full_name('R').c_str(),detail.c_str());
            INFS_(msg.c_str());
            
            _half_closed_log = true;
        }
        // cannot set dead now, there are bytes pending
    } 
    
    if(cx->peer()) {
        cfgapi_ipX_auth_inc_counters(cx->peer());        
    }
}



void MitmProxy::handle_replacement_auth(MitmHostCX* cx) {
  
    std::string redir_pre("<html><head><script>top.location.href=\"");
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
    
    std::string block_pre("<h2 class=\"fg-red\">Page has been blocked</h2><p>Access has been blocked by smithproxy.</p>\
    <p>To check your user privileges go to status page<p><p> <form action=\"");
    std::string block_post("\"><input type=\"submit\" value=\"User Info\" class=\"btn-red\"></form>");
    
    //cx->host().c_str()
    
    if (cx->replacement_flag() == MitmHostCX::REPLACE_REDIRECT) {
        //srand(time(nullptr) % ((unsigned long)cx));
        //redir_hint = rand();

        cfgapi_identity_token_lock.lock();
        auto id_token = cfgapi_identity_token_cache.find(cx->host());
        
        if(id_token != cfgapi_identity_token_cache.end()) {
            INF___("found a cached token for %s",cx->host().c_str());
            std::pair<unsigned int,std::string>& cache_entry = (*id_token).second;
            
            unsigned int now      = time(nullptr);
            unsigned int token_ts = cache_entry.first;
            std::string& token_tk = cache_entry.second;
            
            if(now - token_ts < cfgapi_identity_token_timeout) {
                INF___("MitmProxy::handle_replacement_auth: cached token %s for request: %s",token_tk.c_str(),cx->application_data->hr().c_str());
                
                if(cx->com()) {
                    if(cx->com()->l3_proto() == AF_INET) {
                        repl = redir_pre + repl_proto + "://"+cfgapi_identity_portal_address+":"+repl_port+"/cgi-bin/auth.py?token=" + token_tk + redir_suf;
                    } else if(cx->com()->l3_proto() == AF_INET6) {
                        repl = redir_pre + repl_proto + "://"+cfgapi_identity_portal_address6+":"+repl_port+"/cgi-bin/auth.py?token=" + token_tk + redir_suf;
                    } 
                } 
                
                if(repl.size() == 0) {
                    // default to IPv4 address
                    repl = redir_pre + repl_proto + "://"+cfgapi_identity_portal_address+":"+repl_port+"/cgi-bin/auth.py?token=" + token_tk + redir_suf;
                }
                
                repl = global_staticconent->render_server_response(repl);
                
                cx->to_write((unsigned char*)repl.c_str(),repl.size());
                cx->close_after_write(true);
            } else {
                INF___("MitmProxy::handle_replacement_auth: expired token %s for request: %s",token_tk.c_str(),cx->application_data->hr().c_str());
                goto new_token;
            }
        } else {
        
            new_token:
            
            std::string token_text = cx->application_data->original_request();
          
            for(auto i: cfgapi_obj_policy_profile_auth( cx->matched_policy())->sub_policies) {
                DIA___("MitmProxy::handle_replacement_auth: token: requesting identity %s",i->name.c_str());
                token_text  += " |" + i->name;
            }
            shm_logon_token tok = shm_logon_token(token_text.c_str());
            
            INF___("MitmProxy::handle_replacement_auth: new auth token %s for request: %s",tok.token().c_str(),cx->application_data->hr().c_str());
            
            if(cx->com()) {
                if(cx->com()->l3_proto() == AF_INET) {
                    repl = redir_pre + repl_proto + "://"+cfgapi_identity_portal_address+":"+repl_port+"/cgi-bin/auth.py?token=" + tok.token() + redir_suf;
                } else if(cx->com()->l3_proto() == AF_INET6) {
                    repl = redir_pre + repl_proto + "://"+cfgapi_identity_portal_address6+":"+repl_port+"/cgi-bin/auth.py?token=" + tok.token() + redir_suf;
                } 
            } 
            
            if(repl.size() == 0) {
                // default to IPv4 address
                INFS___("XXX: fallback to IPv4");
                repl = redir_pre + repl_proto + "://"+cfgapi_identity_portal_address+":"+repl_port+"/cgi-bin/auth.py?token=" + tok.token() + redir_suf;
            }
            
            repl = global_staticconent->render_server_response(repl);
            
            cx->to_write((unsigned char*)repl.c_str(),repl.size());
            cx->close_after_write(true);
            
            cfgapi_auth_shm_token_table_refresh();
            
            auth_shm_token_map.entries().push_back(tok);
            auth_shm_token_map.acquire();
            auth_shm_token_map.save(true);
            auth_shm_token_map.release();
            
            DIAS___("MitmProxy::handle_replacement_auth: token table updated");
            cfgapi_identity_token_cache[cx->host()] = std::pair<unsigned int,std::string>(time(nullptr),tok.token());
        }
        
        cfgapi_identity_token_lock.unlock();
    } else
    if (cx->replacement_flag() == MitmHostCX::REPLACE_BLOCK) {

        DIAS___("MitmProxy::handle_replacement_auth: instructed to replace block");
        repl = block_pre + repl_proto + "://"+cfgapi_identity_portal_address+":"+repl_port + "/cgi-bin/auth.py?a=z" + block_post;
        
        std::string cap  = "Page Blocked";
        std::string meta = "";
        repl = global_staticconent->render_msg_html_page(cap,meta, repl,"500px");
        repl = global_staticconent->render_server_response(repl);
        
        cx->to_write((unsigned char*)repl.c_str(),repl.size());
        cx->close_after_write(true);

    } else
    if (cx->replacement_flag() == MitmHostCX::REPLACE_NONE) {
        DIAS___("MitmProxy::handle_replacement_auth: asked to handle NONE. No-op.");
    } 
}


void MitmProxy::handle_replacement_ssl(MitmHostCX* cx) {
    
    std::string repl;
    
    SSLCom* scom = dynamic_cast<SSLCom*>(cx->peercom());
    if(!scom) {
        std::string error("<html><head></head><body><p>Internal error</p><p>com object is not ssl-type</p></body></html>");
        error = global_staticconent->render_server_response(error);
        
        cx->to_write((unsigned char*)error.c_str(),error.size());
        cx->close_after_write(true);  
        
        ERRS___("cannot handle replacement for TLS, com is not SSLCom");
        
        return;
    }
    
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
        
//         INF___(" --- request: %s",app_request->request().c_str());
//         INF___(" ---     uri: %s",app_request->uri.c_str());
//         INF___(" --- origuri: %s",app_request->original_request().c_str());
//         INF___(" --- referer: %s",app_request->referer.c_str());
        
        
        if(app_request->request().find("/SM/IT/HP/RO/XY/override") != std::string::npos) {
            
            // PHASE IV.
            // perform override action
                
                        
            if(scom->opt_failed_certcheck_override) {
            
                DIA___("ssl_override: ph4 - asked for verify override for %s", whitelist_make_key(cx).c_str());
                
                std::string orig_url = "about:blank";
                
                //we require orig_url is the last argument!!!
                unsigned int a = app_request->request().find("orig_url");
                if(a != std::string::npos) {
                    //len of "orig_url=" is 9
                    orig_url = app_request->request().substr(a+9);
                }
                
                
                std::string override_applied = string_format("<html><head><meta http-equiv=\"Refresh\" content=\"0; url=%s\"></head><body><!-- applied, redirecting back to %s --></body></html>",
                                                            orig_url.c_str(),orig_url.c_str());

                whitelist_verify_entry v;

                whitelist_verify.lock();
                whitelist_verify.set(key,new whitelist_verify_entry_t(v,scom->opt_failed_certcheck_override_timeout));
                whitelist_verify.unlock();
                
                override_applied = global_staticconent->render_server_response(override_applied);
                
                cx->to_write((unsigned char*)override_applied.c_str(),override_applied.size());
                cx->close_after_write(true);
                
                WAR___("Connection from %s: SSL override activated for %s",cx->full_name('L').c_str(), app_request->request().c_str());
                
                return;
                
            } else {
                // override is not enabled, but client somehow reached this (attack?)
                std::string error("<html><head></head><body><p>Failed to override</p><p>Action is denied.</p></body></html>");
                error = global_staticconent->render_server_response(error);
                cx->to_write((unsigned char*)error.c_str(),error.size());
                cx->close_after_write(true);                  
                
                return;
            }
            
        } else 
        if(app_request->request().find("/SM/IT/HP/RO/XY/warning") != std::string::npos){
            
            // PHASE III.
            // display warning and button which will trigger override
        
            DIA___("ssl_override: ph3 - warning replacement for %s", whitelist_make_key(cx).c_str());
            
            block_target_info = "<p><h3 class=\"fg-red\">Requested site:</h3>" + app_request->proto + app_request->host + "</p>";
            block_override = string_format("orig_url=%s\"><input type=\"submit\" value=\"Override\" class=\"btn-red\"></form>","/");

            if(scom->verify_get() > 0) {
                bool is_set = false;
                
                if(scom->verify_check(SSLCom::SELF_SIGNED)) {
                        block_additinal_info += "<p><h3 class=\"fg-red\">Reason:</h3>Target certificate is self-signed.</p>"; is_set = true;
                }
                if(scom->verify_check(SSLCom::SELF_SIGNED_CHAIN)) {
                        block_additinal_info += "<p><h3 class=\"fg-red\">Reason:</h3>Server certificate's chain contains self-signed, untrusted CA certificate.</p>"; is_set = true;
                }
                if(scom->verify_check(SSLCom::UNKNOWN_ISSUER)) {
                        block_additinal_info += "<p><h class=\"fg-red\"3>Reason:</h3>Server certificate is issued by untrusted certificate authority.</p>"; is_set = true;
                }
                if(scom->verify_check(SSLCom::CLIENT_CERT_RQ)) {
                        block_additinal_info += "<p><h3 class=\"fg-red\">Reason:</h3>Server is asking for a client certificate.<p>"; is_set = true;
                }
                if(scom->verify_check(SSLCom::REVOKED)) {
                        block_additinal_info += "<p><h3 class=\"fg-red\">Reason:</h3>Server's certificate is REVOKED. This is a serious issue, it's highly recommended to not continue to this page.</p>"; is_set = true;
                }                
                
                if(!is_set) {
                        block_additinal_info += string_format("<p><h3 class=\"fg-red\">Reason:</h3>Oops, no detailed problem description (code: 0x%04x)</p>",scom->verify_get());
                }
            } else {
                block_additinal_info += string_format("<p><h3 class=\"fg-red\">Reason:</h3>Oops, no detailed problem description (code: 0x%04x)</p>",scom->verify_get());
            }
            
            if(scom->opt_failed_certcheck_override)  block_additinal_info += block_override_pre + block_override;
            
            DIAS___("MitmProxy::handle_replacement_ssl: instructed to replace block");
            
            std::string cap = "TLS security warning";
            std::string meta;
            std::string war_img = global_staticconent->render_noargs("html_img_warning");
            std::string msg = string_format("<h2 class=\"fg-red\">%s TLS security warning</h2>%s",war_img.c_str(),(block_target_info + block_additinal_info).c_str());
            repl = global_staticconent->render_msg_html_page(cap, meta, msg,"500px");
            repl = global_staticconent->render_server_response(repl);
            
            cx->to_write((unsigned char*)repl.c_str(),repl.size());
            cx->close_after_write(true);
        } else 
        if(app_request->uri == "/"){
            // PHASE II
            // redir to warning message
            
            DIA___("ssl_override: ph2 - redir to warning replacement for  %s", whitelist_make_key(cx).c_str());
            
            std::string repl = "<html><head><meta http-equiv=\"Refresh\" content=\"0; url=/SM/IT/HP/RO/XY/warning?q=1\"></head><body></body></html>";
            repl = global_staticconent->render_server_response(repl);
            cx->to_write((unsigned char*)repl.c_str(),repl.size());
            cx->close_after_write(true);            
        }   
        else {
            // PHASE I
            // redirecting to / -- for example some subpages would be displayed incorrectly
            
            DIA___("ssl_override: ph1 - redir to / for %s", whitelist_make_key(cx).c_str());
            
            std::string redir_pre("<html><head><script>top.location.href=\"");
            std::string redir_suf("\";</script></head><body></body></html>");  
            
            //std::string repl = "<html><head><meta http-equiv=\"Refresh\" content=\"0; url=/\"></head><body></body></html>";            
            std::string repl = redir_pre + "/" + redir_suf;   
            repl = global_staticconent->render_server_response(repl);
            
            cx->to_write((unsigned char*)repl.c_str(),repl.size());
            cx->close_after_write(true);            
        }
    }
    
}

void MitmProxy::init_content_replace() {
    
    if(content_rule_ != nullptr) {
        DIAS___("MitmProxy::init_content_replace: deleting old replace rules");
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
        NOT___("MitmProxy::content_replace_apply: failed to replace string: %s",e.what());
        }
        
        ++stage;
    }
    
    
    
    
    
    buffer ret_b;
    ret_b.append(result.c_str(),result.size());
    
    DIA___("content rewritten: original %d bytes with new %d bytes.",b.size(),ret_b.size());
    DUM___("Replacing bytes (%d):\n%s\n# with bytes(%d):\n%s",data.size(),hex_dump(b).c_str(),ret_b.size(),hex_dump(ret_b).c_str());
    return ret_b;
}

void MitmProxy::tap() {

    DIAS___("MitmProxy::tap: start");
    
    for (auto cx: left_sockets) {
        com()->unset_monitor(cx->socket());
        cx->paused(true);
    }
    for (auto cx: right_sockets) {
        com()->unset_monitor(cx->socket());
        cx->paused(true);
    }
}

void MitmProxy::untap() {

    DIAS___("MitmProxy::untap: start");

    for (auto cx: left_sockets) {
        com()->set_monitor(cx->socket());
        cx->paused(false);
    }
    for (auto cx: right_sockets) {
        com()->set_monitor(cx->socket());
        cx->paused(false);
    }
}

MitmHostCX* MitmProxy::first_left() {
    MitmHostCX* ret{};
    
    if(ls().size()) {
        ret = dynamic_cast<MitmHostCX*>(ls().at(0));
    }
    else 
    if(lda().size()) {
        ret = dynamic_cast<MitmHostCX*>(lda().at(0));
    }
        
    return ret;
}

MitmHostCX* MitmProxy::first_right() {
    MitmHostCX* ret{};
    
    if(rs().size()) {
        ret = dynamic_cast<MitmHostCX*>(rs().at(0));
    }
    else 
    if(rda().size()) {
        ret = dynamic_cast<MitmHostCX*>(rda().at(0));
    }
        
    return ret;
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
                INF___("detect_ssl_on_plain_socket: SSL detected on socket %d",s);
                ret = true;
            }
        } else {
            if(ssl_autodetect_harder && time_taken < time_max) {
                struct timespec t;
                t.tv_sec = 0;
                t.tv_nsec = time_increment;
                
                ::nanosleep(&t,nullptr);
                time_taken += time_increment;
                DIA___("detect_ssl_on_plain_socket: SSL strict detection on socket %d: dalayed by %dnsec",s,time_increment);
                goto again;
            }
        }
    }
    
    return ret;
}

baseHostCX* MitmMasterProxy::new_cx(int s) {
    
    DEBS___("MitmMasterProxy::new_cx: new_cx start");
    
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
            c = new baseSSLMitmCom<SSLCom>();
            c->master(com());
        } 
    }
    
    if(c == nullptr) {
        c = com()->slave();
    }
    
    auto r = new MitmHostCX(c,s);
    if (is_ssl) {
        INF___("Connection %s: SSL detected on unusual port.",r->c_name());
        r->is_ssl = true;
        r->is_ssl_port = is_ssl_port;
    }
    if(is_ssl_port) {
        r->is_ssl = true;
    }
    
    DEB___("Pausing new connection %s",r->c_name());
    r->paused(true);
    return r; 
}
void MitmMasterProxy::on_left_new(baseHostCX* just_accepted_cx) {
    // ok, we just accepted socket, created context for it (using new_cx) and we probably need ... 
    // to create child proxy and attach this cx to it.

    if(! just_accepted_cx->com()->nonlocal_dst_resolved()) {
        ERRS___("Was not possible to resolve original destination!");
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
            DEBS___("MitmMasterProxy::on_left_new: ldaadd the new paused cx");
            new_proxy->ldaadd(just_accepted_cx);
        } else{
            DEBS___("MitmMasterProxy::on_left_new: ladd the new cx (unpaused)");
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
            
            DIA___("Connection from %s to %s:%d: traffic redirected from magic IP to %s:%d",just_accepted_cx->c_name(), 
                 orig_target_host.c_str(), orig_target_port,
                 target_host.c_str(), target_port);
            matched_vip = true;
        }
        
        MitmHostCX *target_cx = new MitmHostCX(just_accepted_cx->com()->slave(), target_host.c_str(), 
                                            string_format("%d",target_port).c_str()
                                            );
        
        
        // connect it! - btw ... we don't want to block of course...
        
        target_cx->com()->l3_proto(just_accepted_cx->com()->l3_proto());
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

                // resolve source information - is there an identity info for that IP?
                if(new_proxy->opt_auth_authenticate && new_proxy->opt_auth_resolve) {
                    bool res = new_proxy->resolve_identity(src_cx);

                    // reload table and check timeouts each 5 seconds 
                    time_t now = time(nullptr);
                    if(now > auth_table_refreshed + 5) {
                        cfgapi_auth_shm_ip_table_refresh();
                        cfgapi_auth_shm_ip6_table_refresh();
                        auth_table_refreshed = now;
                        
                        //one day this can run in separate thread to not slow down session setup rate
                        cfgapi_ip_auth_timeout_check();
                        cfgapi_ip6_auth_timeout_check();
                    }
                    
                    
                    if(!res) {
                        if(target_port != 80 && target_port != 443){
                            delete_proxy = true;
                            INF___("Dropping non-replaceable connection %s due to unknown source IP",just_accepted_cx->c_name());
                            goto end;
                        }
                    } else {
                        bool bad_auth = true;

                        // investigate L3 protocol
                        int af = AF_INET;
                        if(just_accepted_cx->com()) {
                            af = just_accepted_cx->com()->l3_proto();
                        }
                        std::string str_af = inet_family_str(af);
                        
                        
                        cfgapi_identity_ip_lock.lock();
                        
                        // use common base pointer, so we can use all IdentityInfo types
                        IdentityInfoBase* id_ptr = nullptr;
                        
                        if(af == AF_INET || af == 0) {
                            auto ip = auth_ip_map.find(just_accepted_cx->host());
                            if (ip != auth_ip_map.end()) {
                                id_ptr = &(*ip).second;
                            }
                        }
                        else if(af == AF_INET6) {
                            auto ip = auth_ip6_map.find(just_accepted_cx->host());
                            if (ip != auth_ip6_map.end()) {
                                id_ptr = &(*ip).second;
                            }
                        }
                        
                        if(id_ptr != nullptr) {
                            //std::string groups = id_ptr->last_logon_info.groups();
                            
                            if(cfgapi_obj_policy_profile_auth(policy_num) != nullptr)
                            for ( auto i: cfgapi_obj_policy_profile_auth(policy_num)->sub_policies) {
                                for(auto x: id_ptr->groups_vec) {
                                    DEB___("Connection identities: ip identity '%s' against policy '%s'",x.c_str(),i->name.c_str());
                                    if(x == i->name) {
                                        DIA___("Connection identities: ip identity '%s' matches policy '%s'",x.c_str(),i->name.c_str());
                                        bad_auth = false;
                                    }
                                }
                            }
                            if(bad_auth) {
                                if(target_port != 80 && target_port != 443) {
                                    INF___("Dropping non-replaceable connection %s due to non-matching identity",just_accepted_cx->c_name());
                                }
                                else {
                                    INF___("Connection %s with non-matching identity (to be replaced)",just_accepted_cx->c_name());
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
                NOT___("MitmMasterProxy::on_left_new: %s cannot be converted to MitmHostCx",just_accepted_cx->c_name());
            }
  
        } else {
            
            // hmm. traffic is denied.
            delete_proxy = true;
        }
        
        end:
        
        new_proxy->name(new_proxy->to_string(iINF));
        
        
        if(delete_proxy) {
            INF___("Dropping proxy %s",new_proxy->c_name());
            delete new_proxy;
        }        
    }
    
    DEBS___("MitmMasterProxy::on_left_new: finished");
}

int MitmMasterProxy::handle_sockets_once(baseCom* c) {
    //T_DIAS___("slist",5,this->hr()+"\n===============\n");
    return ThreadedAcceptorProxy<MitmProxy>::handle_sockets_once(c);
}


void MitmUdpProxy::on_left_new(baseHostCX* just_accepted_cx)
{
    MitmProxy* new_proxy = new MitmProxy(com()->slave());
    // let's add this just_accepted_cx into new_proxy
    if(just_accepted_cx->paused_read()) {
        DEBS___("MitmMasterProxy::on_left_new: ldaadd the new paused cx");
        new_proxy->ldaadd(just_accepted_cx);
    } else{
        DEBS___("MitmMasterProxy::on_left_new: ladd the new cx (unpaused)");
        new_proxy->ladd(just_accepted_cx);
    }
    
    MitmHostCX *target_cx = new MitmHostCX(com()->slave(), just_accepted_cx->com()->nonlocal_dst_host().c_str(), 
                                    string_format("%d",just_accepted_cx->com()->nonlocal_dst_port()).c_str()
                                    );
    

    std::string h;
    std::string p;
    just_accepted_cx->name();
    just_accepted_cx->com()->resolve_socket_src(just_accepted_cx->socket(),&h,&p);
    target_cx->com()->l3_proto(just_accepted_cx->com()->l3_proto());
    
    //DEB___("UDP proxy: src l3 = %s dst l3 = %s",inet_family_str(just_accepted_cx->com()->l3_proto()).c_str(), inet_family_str(target_cx->com()->l3_proto()).c_str());
    
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
    DEBS___("MitmUDPProxy::on_left_new: finished");    
}

baseHostCX* MitmUdpProxy::MitmUdpProxy::new_cx(int s) {
    return new MitmHostCX(com()->slave(),s);
}

