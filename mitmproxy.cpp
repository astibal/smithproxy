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

    Linking Smithproxy statically or dynamically with other modules is
    making a combined work based on Smithproxy. Thus, the terms and
    conditions of the GNU General Public License cover the whole combination.

    In addition, as a special exception, the copyright holders of Smithproxy
    give you permission to combine Smithproxy with free software programs
    or libraries that are released under the GNU LGPL and with code
    included in the standard release of OpenSSL under the OpenSSL's license
    (or modified versions of such code, with unchanged license).
    You may copy and distribute such a system following the terms
    of the GNU GPL for Smithproxy and the licenses of the other code
    concerned, provided that you include the source code of that other code
    when and as the GNU GPL requires distribution of source code.

    Note that people who make modified versions of Smithproxy are not
    obligated to grant this special exception for their modified versions;
    it is their choice whether to do so. The GNU General Public License
    gives permission to release a modified version without this exception;
    this exception also makes it possible to release a modified version
    which carries forward this exception.
*/    

#include <regex>
#include <cstdlib>
#include <ctime>

#include <mitmproxy.hpp>
#include <mitmhost.hpp>
#include <log/logger.hpp>
#include <cfgapi.hpp>
#include <sockshostcx.hpp>
#include <uxcom.hpp>
#include <staticcontent.hpp>
#include <filterproxy.hpp>
#include <authfactory.hpp>

#include <algorithm>
#include <ctime>


DEFINE_LOGGING(MitmProxy);


MitmProxy::MitmProxy(baseCom* c): baseProxy(c), sobject() {

    // FIXME: testing filter - get back to it later!
    //add_filter("test",new TestFilter(this,5));

    log = logan::attach(this, "proxy");
}

void MitmProxy::toggle_tlog() {
    
    // create traffic logger if it doesn't exist
    if(tlog_ == nullptr) {

        tlog_ = new socle::trafLog( this,
                                    CfgFactory::get().traflog_dir.c_str(),
                                    CfgFactory::get().traflog_file_prefix.c_str(),
                                    CfgFactory::get().traflog_file_suffix.c_str());
    }
    
    // check if we have there status file
    if(tlog_) {
        std::string data_dir = CfgFactory::get().traflog_dir;

        data_dir += "/disabled";
        
        struct stat st{0};
        int result = stat(data_dir.c_str(), &st);
        bool present = (result == 0);
        
        if(present) {
            if(tlog()->status()) {
                _war("capture disabled by disabled-file");
            }
            tlog()->status(false);
        } else {
            if(! tlog()->status()) {
                _war("capture re-enabled from previous disabled-file state");
            }            
            tlog()->status(true);
        }
    }
}


MitmProxy::~MitmProxy() {
    
    if(write_payload()) {
        _deb("MitmProxy::destructor: syncing writer");

        for(auto* cx: ls()) {
            if(! cx->comlog().empty()) {
                if(tlog()) tlog()->write('L', cx->comlog());
                cx->comlog().clear();
            }
        }               
        
        for(auto* cx: rs()) {
            if(! cx->comlog().empty()) {
                if(tlog()) tlog()->write('R', cx->comlog());
                cx->comlog().clear();
            }
        }         
        
        if(tlog()) tlog()->left_write("Connection stop\n");
    }
    
    delete content_rule_;
    delete tlog_;
    delete identity_;
    
    // delete all filters
    for (auto const& p: filters_) {
        delete p.second;
    }
}

std::string MitmProxy::to_string(int verbosity) const {
    std::stringstream r;
    r <<  "MitmProxy:" + baseProxy::to_string(verbosity);
    
    if(verbosity >= INF) {
        r << string_format(" policy: %d ", matched_policy());
        
        if(identity_resolved()) {
            r << string_format("identity: %s ",identity_->username().c_str());
        }
        
        if(verbosity > INF) r << "\n    ";
        
        r << string_format("up/down: %s/%s",number_suffixed(mtr_up.get()*8).c_str(),number_suffixed(mtr_down.get()*8).c_str());
        
        if(verbosity > INF) { 
            r << string_format("\n    Policy  index: %d",matched_policy());

            PolicyRule* p = nullptr;
            
            if(matched_policy() >= 0) {
                p = CfgFactory::get().db_policy.at(matched_policy());
            }
            
            r << string_format("\n    PolicyRule Id: 0x%x",p);

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
bool MitmProxy::identity_resolved() const {
    return identity_resolved_;
}


bool MitmProxy::apply_id_policies(baseHostCX* cx) {


    int af = AF_INET;
    if(cx->com()) {
        af = cx->com()->l3_proto();
    }
    std::string str_af = inet_family_str(af);
    IdentityInfoBase* id_ptr = nullptr;

    bool found = false;
    std::vector<std::string> group_vec;

    if(af == AF_INET || af == 0) {
        std::scoped_lock<std::recursive_mutex> l_(AuthFactory::get_ip4_lock());

        // use common base pointer, so we can use all IdentityInfo types

        auto ip = AuthFactory::get_ip4_map().find(cx->host());
        if (ip != AuthFactory::get_ip4_map().end()) {
            id_ptr = &(*ip).second;

            if(id_ptr) {
                found = true;
                for (auto const &my_id: id_ptr->groups_vec) {
                    group_vec.push_back(my_id);
                }
            }
        }
    }
    else if(af == AF_INET6) {
        std::scoped_lock<std::recursive_mutex> l_(AuthFactory::get_ip6_lock());
        // use common base pointer, so we can use all IdentityInfo types

        auto ip = AuthFactory::get_ip6_map().find(cx->host());
        if (ip != AuthFactory::get_ip6_map().end()) {
            id_ptr = &(*ip).second;

            if(id_ptr) {
                found = true;
                for(auto const& my_id: id_ptr->groups_vec) {
                    group_vec.push_back(my_id);
                }
            }
        }
    }


    ProfileSubAuth* final_profile = nullptr;
    
    if( found ) {
        _dia("apply_id_policies: matched policy: %d",matched_policy());        
        PolicyRule* policy = CfgFactory::get().db_policy.at(matched_policy());
        
        ProfileAuth* auth_policy = policy->profile_auth;

        
        if(auth_policy != nullptr) {
            for(auto sub: auth_policy->sub_policies) {
                ProfileSubAuth* sub_prof = sub;
                std::string sub_name = sub->name;
                
                _dia("apply_id_policies: checking identity policy for: %s", sub_name.c_str());
                
                for(auto const& my_id: group_vec) {
                    _dia("apply_id_policies: identity in policy: %s, match-test real user group '%s'",sub_prof->name.c_str(), my_id.c_str());
                    if(sub_prof->name == my_id) {
                        _dia("apply_id_policies: .. matched.");
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
            std::string algs;
            
            _dia("apply_id_policies: assigning sub-profile %s",final_profile->name.c_str());
            if(final_profile->profile_content != nullptr) {
                if (CfgFactory::get().prof_content_apply(cx, this, final_profile->profile_content)) {
                    pc_name = final_profile->profile_content->prof_name.c_str();
                    _dia("apply_id_policies: assigning content sub-profile %s",final_profile->profile_content->prof_name.c_str());
                }
            }
            if(final_profile->profile_detection != nullptr) {
                if (CfgFactory::get().prof_detect_apply(cx, this, final_profile->profile_detection)) {
                    pd_name = final_profile->profile_detection->prof_name.c_str();
                    _dia("apply_id_policies: assigning detection sub-profile %s",final_profile->profile_detection->prof_name.c_str());
                }
            }
            if(final_profile->profile_tls != nullptr) {
                if(CfgFactory::get().prof_tls_apply(cx, this, final_profile->profile_tls)) {
                    pt_name = final_profile->profile_tls->prof_name.c_str();
                    _dia("apply_id_policies: assigning tls sub-profile %s",final_profile->profile_tls->prof_name.c_str());
                }
            }
            if(final_profile->profile_alg_dns != nullptr) {
                if(CfgFactory::get().prof_alg_dns_apply(cx, this, final_profile->profile_alg_dns)) {
                    algs += final_profile->profile_alg_dns->prof_name + " ";
                    _dia("apply_id_policies: assigning tls sub-profile %s",final_profile->profile_tls->prof_name.c_str());
                }
            }
            
            // end of custom sub-profiles
            _inf("Connection %s: identity-based sub-profile: name=%s cont=%s det=%s tls=%s algs=%s",cx->full_name('L').c_str(),final_profile->name.c_str(),
                            pc_name, pd_name, pt_name, algs.c_str()
                            );
        }

        return (final_profile != nullptr);
    } 

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
    
    _dia("identity check[%s]: source: %s",str_af.c_str(), cx->host().c_str());

    shm_logon_info_base* id_ptr = nullptr;
    
    if(af == AF_INET || af == 0) {

        std::scoped_lock<std::recursive_mutex> l_(AuthFactory::get_ip4_lock());
        AuthFactory::get().shm_ip4_table_refresh();

        _deb("identity check[%s]: table size: %d",str_af.c_str(), AuthFactory::get_ip4_map().size());
        auto ip = AuthFactory::get_ip4_map().find(cx->host());
        if (ip != AuthFactory::get_ip4_map().end()) {
            shm_logon_info& li = (*ip).second.last_logon_info;
            id_ptr = li.clone();
        } else {
            if (insert_guest) {
                id_ptr = new shm_logon_info(cx->host().c_str(),"guest","guest+guests+guests_ipv4");
            }
        }
    }
    else if(af == AF_INET6) {
        /* maintain in sync with previous if block */

        std::scoped_lock<std::recursive_mutex> l_(AuthFactory::get_ip6_lock());
        AuthFactory::get().shm_ip6_table_refresh();

        _deb("identity check[%s]: table size: %d",str_af.c_str(), AuthFactory::get_ip6_map().size());
        auto ip = AuthFactory::get_ip6_map().find(cx->host());
        if (ip != AuthFactory::get_ip6_map().end()) {
            shm_logon_info6& li = (*ip).second.last_logon_info;
            id_ptr = li.clone();
        } else {
            if (insert_guest) {
                id_ptr = new shm_logon_info6(cx->host().c_str(),"guest","guest+guests+guests_ipv6");
            }
        }    
    }

    if(id_ptr != nullptr) {
        _dia("identity found for %s %s: user: %s groups: %s",str_af.c_str(),cx->host().c_str(),id_ptr->username().c_str(), id_ptr->groups().c_str());

        // if update_auth_ip_map fails, identity is no longer valid!
        
        if(af == AF_INET || af == 0) valid_ip_auth = update_auth_ipX_map(cx);
        if(af == AF_INET6) valid_ip_auth = update_auth_ipX_map(cx);
            
        
        identity_resolved(valid_ip_auth);
        if(valid_ip_auth) { 
            identity(id_ptr);
        }
        
        // apply specific identity-based profile. 'li' is still valid, since we still hold the lock
        // get ptr to identity_info

        _dia("resolve_identity[%s]: about to call apply_id_policies, group: %s",str_af.c_str(), id_ptr->groups().c_str());
        apply_id_policies(cx);


        // id_ptr is either a clone, or new guest id
        delete id_ptr;
    }


    _deb("identity check[%s]: return %d",str_af.c_str(), valid_ip_auth);
    return valid_ip_auth;
}


bool MitmProxy::update_auth_ipX_map(baseHostCX* cx) {

    bool ret = false;
    
    int af = AF_INET;
    if(cx->com()) {
        af = cx->com()->l3_proto();
    }
    std::string str_af = inet_family_str(af);    
    

    _deb("update_auth_ip_map: start for %s %s",str_af.c_str(), cx->host().c_str());
    
    IdentityInfoBase* id_ptr = nullptr;
    
    if(af == AF_INET || af == 0) {
        std::scoped_lock<std::recursive_mutex> l_(AuthFactory::get_ip4_lock());

        auto ip = AuthFactory::get_ip4_map().find(cx->host());
        if (ip != AuthFactory::get_ip4_map().end()) {
            id_ptr = &(*ip).second;
        }
    }
    else if(af == AF_INET6) {
        std::scoped_lock<std::recursive_mutex> l_(AuthFactory::get_ip6_lock());

        auto ip = AuthFactory::get_ip6_map().find(cx->host());
        if (ip != AuthFactory::get_ip6_map().end()) {
            id_ptr = &(*ip).second;
        }
    }
    
    if(id_ptr != nullptr) {
        _dia("update_auth_ip_map: user %s from %s %s (groups: %s)",id_ptr->username.c_str(), str_af.c_str(), cx->host().c_str(), id_ptr->groups.c_str());

        id_ptr->last_seen_policy = matched_policy();
        
        if (!id_ptr->i_timeout()) {
            id_ptr->touch();
            ret = true;
        } else {
            _inf("identity timeout: user %s from %s %s (groups: %s)",id_ptr->username.c_str(), str_af.c_str(), cx->host().c_str(), id_ptr->groups.c_str());
            
            // erase internal ip map entry
            if(af == AF_INET || af == 0) {
                std::scoped_lock<std::recursive_mutex> l_(AuthFactory::get_ip4_lock());
                AuthFactory::get().ip4_remove(cx->host());
            }
            else if(af == AF_INET6) {
                std::scoped_lock<std::recursive_mutex> l_(AuthFactory::get_ip6_lock());
                AuthFactory::get().ip6_remove(cx->host());
            }
        }
    }
    
    _deb("update_auth_ip_map: finished for %s %s, result %d",str_af.c_str(), cx->host().c_str(),ret);
    return ret;
}


void MitmProxy::add_filter(std::string const& name, FilterProxy* fp) {

    filters_.emplace_back(std::pair<std::string,FilterProxy*>(name,fp));
    
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
    
    for(auto const& filter_pair: filters_) {
        std::string const& filter_name = filter_pair.first;
        baseProxy* filter_proxy = filter_pair.second;
        
        _deb("MitmProxy::handle_sockets_once: running filter %s", filter_name.c_str());
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
            _deb("identity check: unknown");
            
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
                        _ext("not enough data received to ensure right replacement-aware protocol.");
                        state().dead(true);
                    }
                }
            }
        } else {
            if(auth_block_identity) {
                if(mh->replacement_type() == MitmHostCX::REPLACETYPE_HTTP) {
                    _dia("MitmProxy::on_left_bytes: we should block it");
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
    
    auto* scom = dynamic_cast<SSLCom*>(mh->peercom());
    if(scom && scom->opt_failed_certcheck_replacement) {
        if(!(
            scom->verify_get() == SSLCom::VERIFY_OK
             ||
            scom->verify_get() == ( SSLCom::VERIFY_OK | SSLCom::CLIENT_CERT_RQ )
            )) {
            
            bool whitelist_found = false;
            
            //look for whitelisted entry
            std::string key = whitelist_make_key(mh);
            if( ( !key.empty() ) && key != "?") {
                std::lock_guard<std::recursive_mutex> l_(whitelist_verify().getlock());

                whitelist_verify_entry_t* wh = whitelist_verify().get(key);
                _dia("whitelist_verify[%s]: %s",key.c_str(), wh ? "found" : "not found" );

                // !!! wh might be already invalid here, unlocked !!!
                if(wh != nullptr) {
                    whitelist_found = true;
                    if (scom->opt_failed_certcheck_override_timeout_type == 1) {
                        wh->expired_at() = ::time(nullptr) + scom->opt_failed_certcheck_override_timeout;
                        _dia("whitelist_verify[%s]: timeout reset to %d",key.c_str(), scom->opt_failed_certcheck_override_timeout );
                    }
                }
            }
            
            
            if(!whitelist_found) {
                _dia("relaxed cert-check: peer sslcom verify not OK, not in whitelist");

                if(mh->replacement_type() == MitmHostCX::REPLACETYPE_NONE) {

                    // _dia(" -> replacement: none - letting go");
                    // ok - it might happen signature is not yet triggered (and replacement message should happened).
                    // there are 2 options:
                    // a) block the connection
                    // b) reset the connection

                    // certainly there is NO F***ING WAY to letting it go.

                    bool nice_redirect = false;

                    if(first_right()) {
                        if ("443" == first_right()->port()) {
                            nice_redirect = true;
                        }
                    }

                    if(! nice_redirect) {
                        _war("certificate not OK on unknown protocol and port - dropping proxy");
                        state().dead(true);
                    }
                    else {
                        _war("certificate not OK on known port - assuming http");
                        mh->replacement_type(MitmHostCX::REPLACETYPE_HTTP);
                        mh->replacement_flag(MitmHostCX::REPLACE_BLOCK);
                        redirected = true;
                        handle_replacement_ssl(mh);
                    }
                }
                else if(mh->replacement_type() == MitmHostCX::REPLACETYPE_HTTP) {
                    _dia(" -> replacement: HTTP - redirecting");
                    mh->replacement_flag(MitmHostCX::REPLACE_BLOCK);
                    redirected = true;
                    handle_replacement_ssl(mh);
                    
                } 
                else if(scom->verify_check(SSLCom::CLIENT_CERT_RQ) && scom->opt_client_cert_action > 0) {

                    _dia(" -> client-cert request:  opt_client_cert_action=%d", scom->opt_client_cert_action);

                    if(scom->opt_client_cert_action >= 2) {
                        //we should not block
                        _dia(" -> client-cert request: auto-whitelist");

                        std::lock_guard<std::recursive_mutex> l_(whitelist_verify().getlock());
                        
                        whitelist_verify_entry v;
                        whitelist_verify().set(key,new whitelist_verify_entry_t(v,scom->opt_failed_certcheck_override_timeout));
                    } else {
                        _dia(" -> client-cert request: none");
                    }

                }
                else {
                    _dia(" -> replacement unknown: killing proxy");
                    state().dead(true);
                }
            }
        }
    }
    
    return redirected;
}

bool MitmProxy::handle_cached_response(MitmHostCX* mh) {
    
    if(mh->inspection_verdict() == Inspector::CACHED) {
        _dia("cached content: not proxying");
        return true;
    }
    
    return false;
}

void MitmProxy::on_left_bytes(baseHostCX* cx) {
    
    if(write_payload()) {
        
        toggle_tlog();
        
        if(! cx->comlog().empty()) {
            if(tlog()) tlog()->write('L', cx->comlog());
            cx->comlog().clear();
        }
        
        if(tlog()) tlog()->left_write(cx->to_read());
    }
    

    bool redirected = false;
    
    auto* mh = dynamic_cast<MitmHostCX*>(cx);

    if(mh != nullptr) {

        // check authentication
        redirected = handle_authentication(mh);
     
        // check com responses
        redirected = handle_com_response_ssl(mh);
        
        
        if(handle_cached_response(mh)) {
            return;
        }
    }
    
    
    // because we have left bytes, let's copy them into all right side sockets!
    for(auto j: right_sockets) {
        
        if(!redirected) {
            if(content_rule() != nullptr) {
                buffer b = content_replace_apply(cx->to_read());
                j->to_write(b);
                _dia("mitmproxy::on_left_bytes: original %d bytes replaced with %d bytes",cx->to_read().size(),b.size());
            } else {
                j->to_write(cx->to_read());
                _dia("mitmproxy::on_left_bytes: %d copied",cx->to_read().size());
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
                _dia("mitmproxy::on_left_bytes: original %d bytes replaced with %d bytes into delayed",cx->to_read().size(),b.size());
            } else {	  
                j->to_write(cx->to_read());
                _dia("mitmproxy::on_left_bytes: %d copied to delayed",cx->to_read().size());
            }
        } else {
        
            // rest of connections should be closed when sending replacement to a client
            j->shutdown();
        }
    }    

    //update meters
    total_mtr_up().update(cx->to_read().size());
    mtr_up.update(cx->to_read().size());
}

void MitmProxy::on_right_bytes(baseHostCX* cx) {
    
    if(write_payload()) {

        toggle_tlog();
        
        if(! cx->comlog().empty()) {
            if(tlog()) tlog()->write('R',cx->comlog());
            cx->comlog().clear();
        }
        
        if(tlog()) tlog()->right_write(cx->to_read());
    }
    
    
    for(auto j: left_sockets) {
        
        if(content_rule() != nullptr) {
            buffer b = content_replace_apply(cx->to_read());
            j->to_write(b);
            _dia("mitmproxy::on_right_bytes: original %d bytes replaced with %d bytes",cx->to_read().size(),b.size());
        } else {      
            j->to_write(cx->to_read());
            _dia("mitmproxy::on_right_bytes: %d copied",cx->to_read().size());
        }
    }
    for(auto j: left_delayed_accepts) {
        
        if(content_rule() != nullptr) {
            buffer b = content_replace_apply(cx->to_read());
            j->to_write(b);
            _dia("mitmproxy::on_right_bytes: original %d bytes replaced with %d bytes into delayed",cx->to_read().size(),b.size());
        } else {      
            j->to_write(cx->to_read()); 
            _dia("mitmproxy::on_right_bytes: %d copied to delayed",cx->to_read().size());
        }
    }

    // update meters
    total_mtr_down().update(cx->to_read().size());
    mtr_down.update(cx->to_read().size());
}


void MitmProxy::__debug_zero_connections(baseHostCX* cx) {

    if(cx->meter_write_count == 0 && cx->meter_write_bytes == 0 ) {
        auto* xcom = dynamic_cast<SSLCom*>(cx->com());
        if(xcom) {
            xcom->log_profiling_stats(iINF);
            int p = 0; 
            int s = cx->socket();
            if(s == 0) s = cx->closed_socket();
            if(s != 0) {
                buffer b(1024);
                p = cx->com()->peek(s,b.data(),b.capacity(),0);
                _inf("        cx peek size %d",p);
            }
            
        }
        
        if(cx->peer()) {
            auto* xcom_peer = dynamic_cast<SSLCom*>(cx->peer()->com());
            if(xcom_peer) {
                xcom_peer->log_profiling_stats(iINF);
                _inf("        peer transferred bytes: up=%d/%dB dw=%d/%dB",cx->peer()->meter_read_count,cx->peer()->meter_read_bytes,
                                                                cx->peer()->meter_write_count, cx->peer()->meter_write_bytes);
                int p = 0; 
                int s = cx->peer()->socket();
                if(s == 0) s = cx->peer()->closed_socket();
                if(s != 0) {
                    buffer b(1024);
                    p = cx->peer()->com()->peek(s,b.data(),b.capacity(),0);
                    _inf("        peer peek size %d",p);
                }                
            }
            
        }
    }
}


void MitmProxy::on_half_close(baseHostCX* cx) {
    if(cx->peer() && cx->peercom() && cx->peercom()) {
        // we have existing peer with non-zero write queue - set hold timer 
        if(half_holdtimer > 0) {
            
            // we count timer already!
            long expiry = half_holdtimer + half_timeout() - ::time(nullptr);
            
            if(expiry > 0) {
                _ext("half-closed: live peer with pending data: keeping up for %ls",expiry);
            } else {
                _dia("half-closed: timer's up (%l). closing prematurely.",expiry);
                state().dead(true);
            }
            
            
        } else {
            _dia("half-closed: live peer with pending data: keeping up for %ds",half_timeout);
            half_holdtimer = ::time(nullptr);
        }
        
    } else {
        // if peer doesn't exist or peercom doesn't exit, mark proxy dead -- noone to speak to
        _dia("half-closed: peer with pending write-data is dead.");
        state().dead(true);
    }
}

void MitmProxy::on_left_error(baseHostCX* cx) {

    if(cx == nullptr) return;
    
    if(state().dead()) return;  // don't process errors twice

    
    _deb("on_left_error[%s]: proxy marked dead",(state().error_on_read ? "read" : "write"));
    _dum(to_string().c_str());
    
    if(write_payload()) {
        toggle_tlog();
        if(tlog()) {
            tlog()->left_write("Client side connection closed: " + cx->name() + "\n");
            if(! replacement_msg.empty()) {
                tlog()->left_write(cx->name() + "   dropped by proxy:" + replacement_msg + "\n");
            }
        }
    }
    
    if(opt_auth_resolve)
        resolve_identity(cx);

    std::string flags = "L";
    auto* mh = dynamic_cast<MitmHostCX*>(cx);
    if (mh != nullptr && mh->inspection_verdict() == Inspector::CACHED) flags+="C";

    std::stringstream detail;
    
    if(cx->peercom()) {
        auto* sc = dynamic_cast<SSLMitmCom*>(cx->peercom());
        if(sc) {
            detail << string_format("sni=%s ",sc->get_peer_sni().c_str());
        }
    }
    if(mh && mh->application_data) {
        
        auto* http = dynamic_cast<app_HttpRequest*>(mh->application_data);
        if(http) {
            detail << "app=" << http->proto << http->host << " ";
        }
        else {
            detail << "app=" << mh->application_data->hr() << " ";
        }
    }
    
    detail << string_format("user=%s up=%d/%dB dw=%d/%dB flags=%s+%s",
                                        (identity_resolved() ? identity()->username().c_str() : ""),
                                            cx->meter_read_count,cx->meter_read_bytes,
                                                                cx->meter_write_count, cx->meter_write_bytes,
                                                                            flags.c_str(),
                                                                            com()->full_flags_str().c_str()
            );

    if(cx->peer() && cx->peer()->writebuf()->empty()) {
        std::stringstream msg;
        msg << "Connection from " << cx->full_name('L') << " closed: " << detail.str();
        if(! replacement_msg.empty() ) {
            msg << ", dropped: " << replacement_msg;
            _inf("%s", msg.str().c_str()); // log to generic logger
        }
        _inf("%s", msg.str().c_str());
        if(*log.level() > DEB) __debug_zero_connections(cx);
        
        state().dead(true);
    } else {
        on_half_close(cx);
        if(state().dead()) {
            // status dead is new, since we check dead status at the begining
            std::stringstream msg;
            msg << "Connection from " << cx->full_name('L') << " left half-closed: " << detail.str();
            _inf("%s", msg.str().c_str());
        }
    }
    
    if(cx) {
        AuthFactory::get().ipX_inc_counters(cx);
    }
}

void MitmProxy::on_right_error(baseHostCX* cx)
{
    if(state().dead()) return;  // don't process errors twice
    
    _deb("on_right_error[%s]: proxy marked dead",(state().error_on_read ? "read" : "write"));
    
    if(write_payload()) {
        toggle_tlog();
        if(tlog()) {
            tlog()->right_write("Server side connection closed: " + cx->name() + "\n");
            if(! replacement_msg.empty()) {
                tlog()->right_write(cx->name() + "   dropped by proxy:" + replacement_msg + "\n");
            }
        }
    }
    
//         _inf("Created new proxy 0x%08x from %s:%s to %s:%d",new_proxy,f,f_p, t,t_p );


    std::string flags = "R";
    std::string comflags;
    auto* mh_peer = dynamic_cast<MitmHostCX*>(cx->peer());
    if (mh_peer != nullptr) {
        if(mh_peer->inspection_verdict() == Inspector::CACHED) flags+="C";
        if(mh_peer->com() != nullptr)
            comflags = mh_peer->com()->full_flags_str();
    }

    
    std::stringstream detail;
    auto* sc = dynamic_cast<SSLMitmCom*>(cx->com());
    if(sc) {
        detail << "sni= " << sc->get_peer_sni();
    }
    if(mh_peer && mh_peer->application_data) {
        auto* http = dynamic_cast<app_HttpRequest*>(mh_peer->application_data);
        if(http) {
            detail << "app=" << http->proto << http->host << " ";
        }
        else {
            detail << "app=" << mh_peer->application_data->hr() << " ";
        }
    }
    detail << string_format("user=%s up=%d/%dB dw=%d/%dB flags=%s+%s",
                                        (identity_resolved() ? identity()->username().c_str() : ""),
                                            cx->meter_read_count,cx->meter_read_bytes,
                                                                cx->meter_write_count, cx->meter_write_bytes,
                                                                            flags.c_str(),
                                                                            com()->full_flags_str().c_str()
            );
    
    
    if( cx->peer() && cx->peer()->writebuf()->empty() ) {
        std::stringstream msg;
        msg << "Connection from " << cx->full_name('R') << " closed: " << detail.str().c_str();
        if(! replacement_msg.empty() ) {
            msg << ", dropped: " << replacement_msg;
            _inf("%s", msg.str().c_str()); // log to generic logger
        }
        _inf("%s", msg.str().c_str());

        if(*log.level() > DEB) __debug_zero_connections(cx);
        
        state().dead(true);
    } else {

        on_half_close(cx);
        if(state().dead()) {
            // status dead is new, since we check dead status at the begining
            std::stringstream msg;
            msg << "Connection from " << cx->full_name('R') << " right half-closed: " << detail.str().c_str();
            _inf("%s", msg.str().c_str());
        }
    } 
    
    if(cx->peer()) {
        AuthFactory::get().ipX_inc_counters(cx->peer());
    }
}



void MitmProxy::handle_replacement_auth(MitmHostCX* cx) {
  
    std::string redir_pre("<html><head><script>top.location.href=\"");
    std::string redir_suf("\";</script></head><body></body></html>");  
  
//     std::string redir_pre("HTTP/1.0 301 Moved Permanently\r\nLocation: ");
//     std::string redir_suf("\r\n\r\n");  
  
    
    std::string repl;
    std::string repl_port = AuthFactory::get().portal_port_http;
    std::string repl_proto = "http";

    if(cx->application_data->is_ssl) {
        repl_proto = "https";
        repl_port =AuthFactory::get().portal_port_https;
    }    
    
    std::string block_pre("<h2 class=\"fg-red\">Page has been blocked</h2><p>Access has been blocked by smithproxy.</p>"
                          "<p>To check your user privileges go to status page<p><p> <form action=\"");

    std::string block_post("\"><input type=\"submit\" value=\"User Info\" class=\"btn-red\"></form>");
    
    if (cx->replacement_flag() == MitmHostCX::REPLACE_REDIRECT) {

        std::scoped_lock<std::recursive_mutex> l_(AuthFactory::get_token_lock());
        auto id_token = AuthFactory::get_token_map().find(cx->host());
        
        if(id_token != AuthFactory::get_token_map().end()) {
            _inf("found a cached token for %s",cx->host().c_str());
            std::pair<unsigned int,std::string>& cache_entry = (*id_token).second;
            
            unsigned int now      = time(nullptr);
            unsigned int token_ts = cache_entry.first;
            std::string& token_tk = cache_entry.second;
            
            if(now - token_ts < AuthFactory::get().token_timeout) {
                _inf("MitmProxy::handle_replacement_auth: cached token %s for request: %s",token_tk.c_str(),cx->application_data->hr().c_str());
                
                if(cx->com()) {
                    if(cx->com()->l3_proto() == AF_INET) {
                        repl = redir_pre + repl_proto + "://"+AuthFactory::get().portal_address+":"+repl_port+"/cgi-bin/auth.py?token=" + token_tk + redir_suf;
                    } else if(cx->com()->l3_proto() == AF_INET6) {
                        repl = redir_pre + repl_proto + "://"+AuthFactory::get().portal_address6+":"+repl_port+"/cgi-bin/auth.py?token=" + token_tk + redir_suf;
                    } 
                } 
                
                if(repl.empty()) {
                    // default to IPv4 address
                    repl = redir_pre + repl_proto + "://"+AuthFactory::get().portal_address+":"+repl_port+"/cgi-bin/auth.py?token=" + token_tk + redir_suf;
                }
                
                repl = html()->render_server_response(repl);
                
                cx->to_write((unsigned char*)repl.c_str(),repl.size());
                cx->close_after_write(true);

                replacement_msg += "(auth: known token)";
            } else {
                _inf("MitmProxy::handle_replacement_auth: expired token %s for request: %s",token_tk.c_str(),cx->application_data->hr().c_str());
                goto new_token;
            }
        } else {
        
            new_token:
            
            std::string token_text = cx->application_data->original_request();
          
            for(auto i: CfgFactory::get().policy_prof_auth(cx->matched_policy())->sub_policies) {
                _dia("MitmProxy::handle_replacement_auth: token: requesting identity %s",i->name.c_str());
                token_text  += " |" + i->name;
            }
            shm_logon_token tok = shm_logon_token(token_text.c_str());
            
            _inf("MitmProxy::handle_replacement_auth: new auth token %s for request: %s",tok.token().c_str(),cx->application_data->hr().c_str());
            
            if(cx->com()) {
                if(cx->com()->l3_proto() == AF_INET) {
                    repl = redir_pre + repl_proto + "://"+AuthFactory::get().portal_address+":"+repl_port+"/cgi-bin/auth.py?token=" + tok.token() + redir_suf;
                } else if(cx->com()->l3_proto() == AF_INET6) {
                    repl = redir_pre + repl_proto + "://"+AuthFactory::get().portal_address6+":"+repl_port+"/cgi-bin/auth.py?token=" + tok.token() + redir_suf;
                } 
            } 
            
            if(repl.empty()) {
                // default to IPv4 address
                _inf("XXX: fallback to IPv4");
                repl = redir_pre + repl_proto + "://"+AuthFactory::get().portal_address+":"+repl_port+"/cgi-bin/auth.py?token=" + tok.token() + redir_suf;
            }
            
            repl = html()->render_server_response(repl);
            
            cx->to_write((unsigned char*)repl.c_str(),repl.size());
            cx->close_after_write(true);
            replacement_msg += "(auth: new token)";

            AuthFactory::get().shm_token_table_refresh();

            AuthFactory::get().shm_token_map_.entries().push_back(tok);
            AuthFactory::get().shm_token_map_.acquire();
            AuthFactory::get().shm_token_map_.save(true);
            AuthFactory::get().shm_token_map_.release();
            
            _dia("MitmProxy::handle_replacement_auth: token table updated");
            AuthFactory::get_token_map()[cx->host()] = std::pair<unsigned int,std::string>(time(nullptr),tok.token());
        }
    } else
    if (cx->replacement_flag() == MitmHostCX::REPLACE_BLOCK) {

        _dia("MitmProxy::handle_replacement_auth: instructed to replace block");
        repl = block_pre + repl_proto + "://"+AuthFactory::get().portal_address+":"+repl_port + "/cgi-bin/auth.py?a=z" + block_post;
        
        std::string cap  = "Page Blocked";
        std::string meta;
        repl = html()->render_msg_html_page(cap,meta, repl,"700px");
        repl = html()->render_server_response(repl);
        
        cx->to_write((unsigned char*)repl.c_str(),repl.size());
        cx->close_after_write(true);

        replacement_msg += "(auth: blocked)";

    } else
    if (cx->replacement_flag() == MitmHostCX::REPLACE_NONE) {
        _dia("MitmProxy::handle_replacement_auth: asked to handle NONE. No-op.");
    } 
}

std::string verify_flag_string(int code) {
    switch(code) {
        case SSLCom::VERIFY_OK:
            return "Certificate verification successful";
        case SSLCom::SELF_SIGNED:
            return "Target certificate is self-signed";
        case SSLCom::SELF_SIGNED_CHAIN:
            return "Server certificate's chain contains self-signed, untrusted CA certificate";
        case SSLCom::UNKNOWN_ISSUER:
            return "Server certificate is issued by untrusted certificate authority";
        case SSLCom::CLIENT_CERT_RQ:
            return "Server is asking client for a certificate";
        case SSLCom::REVOKED:
            return "Server's certificate is REVOKED";
        case SSLCom::HOSTNAME_FAILED:
            return "Client application asked for SNI server is not offering";
        default:
            return "";
    }
}

void MitmProxy::set_replacement_msg_ssl(SSLCom* scom) {
    if(scom && scom->verify_get() != SSLCom::VERIFY_OK) {

        if(scom->verify_check(SSLCom::SELF_SIGNED)) {
            replacement_msg += "(ssl:" + verify_flag_string(SSLCom::SELF_SIGNED) + ")";
        }
        if(scom->verify_check(SSLCom::SELF_SIGNED_CHAIN)) {
            replacement_msg += "(ssl:" + verify_flag_string(SSLCom::SELF_SIGNED_CHAIN) + ")";
        }
        if(scom->verify_check(SSLCom::UNKNOWN_ISSUER)) {
            replacement_msg += "(ssl:" + verify_flag_string(SSLCom::UNKNOWN_ISSUER) + ")";
        }
        if(scom->verify_check(SSLCom::CLIENT_CERT_RQ)) {
            replacement_msg += "(ssl:" + verify_flag_string(SSLCom::CLIENT_CERT_RQ) + ")";
        }
        if(scom->verify_check(SSLCom::REVOKED)) {
            replacement_msg += "(ssl:" + verify_flag_string(SSLCom::REVOKED) + ")";
        }
        if(scom->verify_check(SSLCom::HOSTNAME_FAILED)) {
            replacement_msg += "(ssl:" + verify_flag_string(SSLCom::HOSTNAME_FAILED) + ")";
        }
    }
}

std::string MitmProxy::replacement_ssl_verify_detail(SSLCom* scom) {

    std::stringstream ss;
    if(scom && scom->verify_get() != SSLCom::VERIFY_OK) {
        bool is_set = false;

        if(scom->verify_check(SSLCom::SELF_SIGNED)) {
            ss << "<p><h3 class=\"fg-red\">Reason:</h3> " << verify_flag_string(SSLCom::SELF_SIGNED) << ".</p>";
            is_set = true;
        }
        if(scom->verify_check(SSLCom::SELF_SIGNED_CHAIN)) {
            ss << "<p><h3 class=\"fg-red\">Reason:</h3> " <<  verify_flag_string(SSLCom::SELF_SIGNED_CHAIN) << ".</p>";
            is_set = true;
        }
        if(scom->verify_check(SSLCom::UNKNOWN_ISSUER)) {
            ss << "<p><h class=\"fg-red\"3>Reason:</h3>"<< verify_flag_string(SSLCom::UNKNOWN_ISSUER) <<".</p>";
            is_set = true;
        }
        if(scom->verify_check(SSLCom::CLIENT_CERT_RQ)) {
            ss << "<p><h3 class=\"fg-red\">Reason:</h3>" << verify_flag_string(SSLCom::CLIENT_CERT_RQ) <<".<p>";
            is_set = true;
        }
        if(scom->verify_check(SSLCom::REVOKED)) {
            ss <<  "<p><h3 class=\"fg-red\">Reason:</h3>" << verify_flag_string(SSLCom::REVOKED) << ". "
                                    "This is a serious issue, it's highly recommended to not continue "
                                    "to this page.</p>";
            is_set = true;
        }
        if(scom->verify_check(SSLCom::HOSTNAME_FAILED)) {
            ss << "<p><h3 class=\"fg-red\">Reason:</h3>" << verify_flag_string(SSLCom::HOSTNAME_FAILED) << ".</p>";
            is_set = true;
        }


        if(!is_set) {
            ss << string_format("<p><h3 class=\"fg-red\">Reason:</h3>Oops, no detailed problem description (code: 0x%04x)</p>",scom->verify_get());
        }
    } else {
        ss << string_format("<p><h3 class=\"fg-red\">Reason:</h3>Oops, no detailed problem description (code: 0x%04x)</p>",scom->verify_get());
    }

    return ss.str();
}


std::string MitmProxy::replacement_ssl_page(SSLCom* scom, app_HttpRequest* app_request, std::string const& more_info) {
    std::string repl;

    std::string block_target_info = "<p><h3 class=\"fg-red\">Requested site:</h3>" + app_request->proto + app_request->host + "</p>";

    std::string block_additinal_info = replacement_ssl_verify_detail(scom) + more_info;

    std::string cap = "TLS security warning";
    std::string meta;
    std::string war_img = html()->render_noargs("html_img_warning");
    std::string msg = string_format("<h2 class=\"fg-red\">%s TLS security warning</h2>%s",war_img.c_str(),(block_target_info + block_additinal_info).c_str());
    repl = html()->render_msg_html_page(cap, meta, msg,"700px");
    repl = html()->render_server_response(repl);

    return repl;
}

void MitmProxy::handle_replacement_ssl(MitmHostCX* cx) {
    
    std::string repl;
    
    auto* scom = dynamic_cast<SSLCom*>(cx->peercom());
    if(!scom) {
        std::string error("<html><head></head><body><p>Internal error</p><p>com object is not ssl-type</p></body></html>");
        error = html()->render_server_response(error);
        
        cx->to_write((unsigned char*)error.c_str(),error.size());
        cx->close_after_write(true);
        set_replacement_msg_ssl(scom);

        _err("cannot handle replacement for TLS, com is not SSLCom");
        
        return;
    }
    
    std::string block_additinal_info;
    std::string block_override;

    if(scom->opt_failed_certcheck_override)   {
        std::string block_override_pre = "<form action=\"/SM/IT/HP/RO/XY";

        std::string key = whitelist_make_key(cx);
        if(cx->peer()) {
            block_override_pre += "/override/target=" + key;//cx->peer()->host() + "#" + cx->peer()->port() + "&";
        }
        std::string block_target_info;
        block_override = block_override_pre + R"(orig_url=/"><input type="submit" value="Override" class="btn-red"></form>)";
    }
    
    auto* app_request = dynamic_cast<app_HttpRequest*>(cx->application_data);
    if(app_request != nullptr) {
        
//         _inf(" --- request: %s",app_request->request().c_str());
//         _inf(" ---     uri: %s",app_request->uri.c_str());
//         _inf(" --- origuri: %s",app_request->original_request().c_str());
//         _inf(" --- referer: %s",app_request->referer.c_str());
        
        
        if(app_request->request().find("/SM/IT/HP/RO/XY/override") != std::string::npos) {
            
            // PHASE IV.
            // perform override action
                
                        
            if(scom->opt_failed_certcheck_override) {
            
                _dia("ssl_override: ph4 - asked for verify override for %s", whitelist_make_key(cx).c_str());
                
                std::string orig_url = "about:blank";
                
                //we require orig_url is the last argument!!!
                auto a = app_request->request().find("orig_url");
                if(a != std::string::npos) {
                    //len of "orig_url=" is 9
                    orig_url = app_request->request().substr(a+9);
                }
                
                
                std::string override_applied = string_format(
                        "<html><head><meta http-equiv=\"Refresh\" content=\"0; url=%s\"></head><body><!-- applied, redirecting back to %s --></body></html>",
                                                            orig_url.c_str(),orig_url.c_str());

                whitelist_verify_entry v;

                {
                    std::lock_guard<std::recursive_mutex> l_(whitelist_verify().getlock());
                    whitelist_verify().set(whitelist_make_key(cx),
                                         new whitelist_verify_entry_t(v, scom->opt_failed_certcheck_override_timeout));
                }
                
                override_applied = html()->render_server_response(override_applied);
                
                cx->to_write((unsigned char*)override_applied.c_str(),override_applied.size());
                cx->close_after_write(true);
                set_replacement_msg_ssl(scom);
                replacement_msg += "(ssl: override)";
                
                _war("Connection from %s: SSL override activated for %s",cx->full_name('L').c_str(), app_request->request().c_str());
                
                return;
                
            } else {
                // override is not enabled, but client somehow reached this (attack?)
                std::string error("<html><head></head><body><p>Failed to override</p><p>Action is denied.</p></body></html>");
                error = html()->render_server_response(error);
                cx->to_write((unsigned char*)error.c_str(),error.size());
                cx->close_after_write(true);
                set_replacement_msg_ssl(scom);
                replacement_msg += "(ssl: override disabled)";
                
                return;
            }
            
        } else 
        if(app_request->request().find("/SM/IT/HP/RO/XY/warning") != std::string::npos){
            
            // PHASE III.
            // display warning and button which will trigger override
        
            _dia("ssl_override: ph3 - warning replacement for %s", whitelist_make_key(cx).c_str());
            
            repl = replacement_ssl_page(scom, app_request, block_override);

            cx->to_write((unsigned char*)repl.c_str(),repl.size());
            set_replacement_msg_ssl(scom);
            cx->close_after_write(true);
        } else 
        if(app_request->uri == "/"){
            // PHASE II
            // redir to warning message
            
            _dia("ssl_override: ph2 - redir to warning replacement for  %s", whitelist_make_key(cx).c_str());
            
            std::string repl = "<html><head><meta http-equiv=\"Refresh\" content=\"0; url=/SM/IT/HP/RO/XY/warning?q=1\"></head><body></body></html>";
            repl = html()->render_server_response(repl);
            cx->to_write(repl);
            cx->close_after_write(true);
            set_replacement_msg_ssl(scom);
        }   
        else {
            // PHASE I
            // redirecting to / -- for example some subpages would be displayed incorrectly
            
            _dia("ssl_override: ph1 - redir to / for %s", whitelist_make_key(cx).c_str());
            
            std::string redir_pre("<html><head><script>top.location.href=\"");
            std::string redir_suf("\";</script></head><body></body></html>");  
            
            //std::string repl = "<html><head><meta http-equiv=\"Refresh\" content=\"0; url=/\"></head><body></body></html>";            
            std::string repl = redir_pre + "/" + redir_suf;   
            repl = html()->render_server_response(repl);
            
            cx->to_write((unsigned char*)repl.c_str(),repl.size());
            cx->close_after_write(true);
            set_replacement_msg_ssl(scom);
        }
    }

    else {
        _dia("ssl_override: enforced ph1 - redir to / for %s", whitelist_make_key(cx).c_str());
        _inf("readbuf: \n%s", hex_dump(cx->readbuf(), 4).c_str());

        std::string redir_pre("<html><head><script>top.location.href=\"");
        std::string redir_suf("\";</script></head><body></body></html>");

        //std::string repl = "<html><head><meta http-equiv=\"Refresh\" content=\"0; url=/\"></head><body></body></html>";
        std::string repl = redir_pre + "/" + redir_suf;
        repl = html()->render_server_response(repl);

        cx->to_write((unsigned char*)repl.c_str(),repl.size());
        cx->close_after_write(true);
        set_replacement_msg_ssl(scom);
        replacement_msg += "(ssl: enforced)";
    }
}

void MitmProxy::init_content_replace() {
    
    if(content_rule_ != nullptr) {
        _dia("MitmProxy::init_content_replace: deleting old replace rules");
        delete content_rule_;
    }
    
    content_rule_ = new std::vector<ProfileContentRule>;
}

buffer MitmProxy::content_replace_apply(buffer b) {
    std::string data = b.to_string();
    std::string result = data;
    
    int stage = 0;
    for(auto& profile: *content_rule()) {
        
        try {
            std::regex re_match(profile.match.c_str());
            std::string repl = profile.replace;
            
            if(profile.replace_each_nth != 0) {

                // unfortunately std::regex_replace doesn't return if it really replaced something
                // ... which is no problem if we don't care. But in case we want to replace only 
                // .... nth occurrence, we have to do extra search to check (requiring one extra regex match).
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
                        _dia("Replacing bytes[stage %d]: n-th counter hit",stage);
                    }
                }
                
            } else {
                if(profile.fill_length) {
                    result = regex_replace_fill(result, profile.match, repl);
                } else {
                    result = std::regex_replace(result, re_match, repl);              
                }
            }

            _dia("Replacing bytes[stage %d]:",stage);
        }
        catch(std::regex_error const& e) {
        _not("MitmProxy::content_replace_apply: failed to replace string: %s",e.what());
        }
        
        ++stage;
    }
    
    
    
    
    
    buffer ret_b;
    ret_b.append(result.c_str(),result.size());
    
    _dia("content rewritten: original %d bytes with new %d bytes.",b.size(),ret_b.size());
    _dum("Replacing bytes (%d):\n%s\n# with bytes(%d):\n%s",data.size(),hex_dump(b).c_str(),ret_b.size(),hex_dump(ret_b).c_str());
    return ret_b;
}

void MitmProxy::tap() {

    _dia("MitmProxy::tap: start");
    
    for (auto cx: left_sockets) {
        com()->unset_monitor(cx->socket());
        cx->waiting_for_peercom(true);
    }
    for (auto cx: right_sockets) {
        com()->unset_monitor(cx->socket());
        cx->waiting_for_peercom(true);
    }
}

void MitmProxy::untap() {

    _dia("MitmProxy::untap: start");

    for (auto cx: left_sockets) {
        com()->set_monitor(cx->socket());
        cx->waiting_for_peercom(false);
    }
    for (auto cx: right_sockets) {
        com()->set_monitor(cx->socket());
        cx->waiting_for_peercom(false);
    }
}

MitmHostCX* MitmProxy::first_left() {
    MitmHostCX* ret{};
    
    if(! ls().empty()) {
        ret = dynamic_cast<MitmHostCX*>(ls().at(0));
    }
    else if(! lda().empty()) {
        ret = dynamic_cast<MitmHostCX*>(lda().at(0));
    }
        
    return ret;
}

MitmHostCX* MitmProxy::first_right() {
    MitmHostCX* ret = nullptr;
    
    if(! rs().empty()) {
        ret = dynamic_cast<MitmHostCX*>(rs().at(0));
    }
    else if(! rda().empty()) {
            ret = dynamic_cast<MitmHostCX*>(rda().at(0));
    }

    return ret;
}



bool MitmMasterProxy::ssl_autodetect = false;
bool MitmMasterProxy::ssl_autodetect_harder = true;

bool MitmMasterProxy::detect_ssl_on_plain_socket(int s) {
    
    int ret = false;
    constexpr unsigned int NEW_CX_PEEK_BUFFER_SZ = 10;
    constexpr int time_increment = 2500; // 2.5ms
    constexpr int time_max = time_increment*5;

    int time_taken = 0;
    
    if (s > 0) {
        again:
        char peek_buffer[NEW_CX_PEEK_BUFFER_SZ];

        int b = ::recv(s,peek_buffer,NEW_CX_PEEK_BUFFER_SZ,MSG_PEEK|MSG_DONTWAIT);
        
        if(b > 6) {
            if (peek_buffer[0] == 0x16 && peek_buffer[1] == 0x03 && ( peek_buffer[5] == 0x00 || peek_buffer[5] == 0x01 || peek_buffer[5] == 0x02 )) {
                _inf("detect_ssl_on_plain_socket: SSL detected on socket %d",s);
                ret = true;
            }
        } else {
            if(ssl_autodetect_harder && time_taken < time_max) {
                struct timespec t{0};
                t.tv_sec = 0;
                t.tv_nsec = time_increment;
                
                ::nanosleep(&t,nullptr);
                time_taken += time_increment;
                _dia("detect_ssl_on_plain_socket: SSL strict detection on socket %d: dalayed by %dnsec",s,time_increment);
                goto again;
            }
        }
    }
    
    return ret;
}

baseHostCX* MitmMasterProxy::new_cx(int s) {
    
    _deb("MitmMasterProxy::new_cx: new_cx start");
    
    bool is_ssl = false;
    bool is_ssl_port = false;
    
    auto* my_sslcom = dynamic_cast<SSLCom*>(com());
    baseCom* c = nullptr;
    
    if(my_sslcom != nullptr) {
        is_ssl_port = true;
    }
    else if(ssl_autodetect) {
        // my com is NOT ssl-based, trigger auto-detect

        is_ssl = detect_ssl_on_plain_socket(s);
        if(! is_ssl) {
            c = com()->slave();
        } else {
            c = new baseSSLMitmCom<SSLCom>();
            c->master(com());
        } 
    }
    
    if(! c) {
        c = com()->slave();
    }
    
    auto r = new MitmHostCX(c,s);
    if (is_ssl) {
        _inf("Connection %s: SSL detected on unusual port.",r->c_name());
        r->is_ssl = true;
        r->is_ssl_port = is_ssl_port;
    }
    if(is_ssl_port) {
        r->is_ssl = true;
    }
    
    _deb("Pausing new connection %s",r->c_name());
    r->waiting_for_peercom(true);
    return r; 
}
void MitmMasterProxy::on_left_new(baseHostCX* just_accepted_cx) {
    // ok, we just accepted socket, created context for it (using new_cx) and we probably need ... 
    // to create child proxy and attach this cx to it.

    if(! just_accepted_cx->com()->nonlocal_dst_resolved()) {
        _err("Was not possible to resolve original destination!");
        just_accepted_cx->shutdown();
        delete just_accepted_cx;
    } 
    else {
        std::string h;
        std::string p;
        just_accepted_cx->name();
        just_accepted_cx->com()->resolve_socket_src(just_accepted_cx->socket(),&h,&p);

        auto* new_proxy = new MitmProxy(just_accepted_cx->com()->slave());
        
        // let's add this just_accepted_cx into new_proxy
        if(just_accepted_cx->read_waiting_for_peercom()) {
            _deb("MitmMasterProxy::on_left_new: ldaadd the new waiting_for_peercom cx");
            new_proxy->ldaadd(just_accepted_cx);
        } else{
            _deb("MitmMasterProxy::on_left_new: ladd the new cx (unpaused)");
            new_proxy->ladd(just_accepted_cx);
        }
        
        bool matched_vip = false; //did it match virtual IP?
        
        std::string target_host = just_accepted_cx->com()->nonlocal_dst_host();
        std::string orig_target_host;
        short unsigned int target_port = just_accepted_cx->com()->nonlocal_dst_port();
        short unsigned int orig_target_port;

        if( target_host == CfgFactory::get().tenant_magic_ip) {
            
            orig_target_host = target_host;
            orig_target_port = target_port;
            
            if(target_port == 65000 || target_port == 143) {
                // bend broker magic IP
                target_port = 65000 + CfgFactory::get().tenant_index;
            }
            else if(target_port != 443) {
                // auth portal https magic IP
                target_port = std::stoi(AuthFactory::get().portal_port_http);
            } else {
                // auth portal plaintext magic IP
                target_port = std::stoi(AuthFactory::get().portal_port_https);
            }
            target_host = "127.0.0.1";
            
            _dia("Connection from %s to %s:%d: traffic redirected from magic IP to %s:%d",just_accepted_cx->c_name(), 
                 orig_target_host.c_str(), orig_target_port,
                 target_host.c_str(), target_port);
            matched_vip = true;
        }
        
        auto *target_cx = new MitmHostCX(just_accepted_cx->com()->slave(), target_host.c_str(),
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
        int policy_num = CfgFactory::get().policy_apply(just_accepted_cx, new_proxy);

        // bypass ssl com to VIP
        if(matched_vip) {
            auto* scom = dynamic_cast<SSLCom*>(just_accepted_cx->com());
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
                        AuthFactory::get().shm_ip4_table_refresh();
                        AuthFactory::get().shm_ip6_table_refresh();
                        auth_table_refreshed = now;
                        
                        //one day this can run in separate thread to not slow down session setup rate
                        AuthFactory::get().ip4_timeout_check();
                        AuthFactory::get().ip6_timeout_check();
                    }
                    
                    
                    if(!res) {
                        if(target_port != 80 && target_port != 443){
                            delete_proxy = true;
                            _inf("Dropping non-replaceable connection %s due to unknown source IP",just_accepted_cx->c_name());
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
                        
                        
                        // use common base pointer, so we can use all IdentityInfo types

                        IdentityInfoBase* id_ptr = nullptr;
                        bool found = false;
                        std::vector<std::string> group_vec;
                        
                        if(af == AF_INET || af == 0) {

                            std::scoped_lock<std::recursive_mutex> l_(AuthFactory::get_ip4_lock());

                            auto ip = AuthFactory::get_ip4_map().find(just_accepted_cx->host());
                            if (ip != AuthFactory::get_ip4_map().end()) {
                                id_ptr = &(*ip).second;
                                found = true;
                                if(id_ptr)
                                    group_vec = id_ptr->groups_vec;
                            }
                        }
                        else if(af == AF_INET6) {

                            std::scoped_lock<std::recursive_mutex> l_(AuthFactory::get_ip6_lock());

                            auto ip = AuthFactory::get_ip6_map().find(just_accepted_cx->host());
                            if (ip != AuthFactory::get_ip6_map().end()) {
                                id_ptr = &(*ip).second;
                                found = true;
                                if(id_ptr)
                                    group_vec = id_ptr->groups_vec;
                            }
                        }
                        
                        if( found ) {
                            //std::string groups = id_ptr->last_logon_info.groups();
                            
                            if(CfgFactory::get().policy_prof_auth(policy_num) != nullptr) {
                                for ( auto i: CfgFactory::get().policy_prof_auth(policy_num)->sub_policies) {
                                    for(auto const& x: group_vec) {
                                        _deb("Connection identities: ip identity '%s' against policy '%s'",x.c_str(),i->name.c_str());
                                        if(x == i->name) {
                                            _dia("Connection identities: ip identity '%s' matches policy '%s'",x.c_str(),i->name.c_str());
                                            bad_auth = false;
                                        }
                                    }
                                }
                            }

                            if(bad_auth) {
                                if(target_port != 80 && target_port != 443) {
                                    _inf("Dropping non-replaceable connection %s due to non-matching identity",just_accepted_cx->c_name());
                                }
                                else {
                                    _inf("Connection %s with non-matching identity (to be replaced)",just_accepted_cx->c_name());
                                    // set bad_auth true, because despite authentication failed, it could be replaced (we can let user know 
                                    // he is not allowed to proceed
                                    bad_auth = false;
                                    new_proxy->auth_block_identity = true;
                                }
                            }
                        }
                        
                        if(bad_auth) {
                            delete_proxy = true;
                            goto end;
                        }
                    }
                }
                
                // setup NAT
                if(CfgFactory::get().db_policy.at(policy_num)->nat == POLICY_NAT_NONE && ! matched_vip) {
                    target_cx->com()->nonlocal_src(true);
                    target_cx->com()->nonlocal_src_host() = h;
                    target_cx->com()->nonlocal_src_port() = std::stoi(p);               
                }
                
                // finalize connection acceptance by adding new proxy to proxies and connect
                this->proxies().insert(new_proxy);
                
                //FIXME: this is really ugly!! :) It's here since radd has been called before socket for target_cx was created.
                int real_socket = target_cx->connect();
                com()->set_monitor(real_socket);
                com()->set_poll_handler(real_socket,new_proxy);
                
            } else {
                delete_proxy = true;
                _not("MitmMasterProxy::on_left_new: %s cannot be converted to MitmHostCx",just_accepted_cx->c_name());
            }
  
        } else {
            
            // hmm. traffic is denied.
            delete_proxy = true;
        }
        
        end:
        
        new_proxy->name(new_proxy->to_string(iINF));
        
        
        if(delete_proxy) {
            _inf("Dropping proxy %s",new_proxy->c_name());
            delete new_proxy;
        }        
    }
    
    _deb("MitmMasterProxy::on_left_new: finished");
}

int MitmMasterProxy::handle_sockets_once(baseCom* c) {
    //T__dia("slist",5,this->hr()+"\n===============\n");
    return ThreadedAcceptorProxy<MitmProxy>::handle_sockets_once(c);
}


void MitmUdpProxy::on_left_new(baseHostCX* just_accepted_cx)
{
    auto* new_proxy = new MitmProxy(com()->slave());
    // let's add this just_accepted_cx into new_proxy
    if(just_accepted_cx->read_waiting_for_peercom()) {
        _deb("MitmMasterProxy::on_left_new: ldaadd the new waiting_for_peercom cx");
        new_proxy->ldaadd(just_accepted_cx);
    } else{
        _deb("MitmMasterProxy::on_left_new: ladd the new cx (unpaused)");
        new_proxy->ladd(just_accepted_cx);
    }
    
    auto *target_cx = new MitmHostCX(com()->slave(), just_accepted_cx->com()->nonlocal_dst_host().c_str(),
                                    string_format("%d",just_accepted_cx->com()->nonlocal_dst_port()).c_str()
                                    );
    

    std::string h;
    std::string p;
    just_accepted_cx->name();
    just_accepted_cx->com()->resolve_socket_src(just_accepted_cx->socket(),&h,&p);
    target_cx->com()->l3_proto(just_accepted_cx->com()->l3_proto());
    
    //_deb("UDP proxy: src l3 = %s dst l3 = %s",inet_family_str(just_accepted_cx->com()->l3_proto()).c_str(), inet_family_str(target_cx->com()->l3_proto()).c_str());
    
    just_accepted_cx->peer(target_cx);
    target_cx->peer(just_accepted_cx);


    
    ((MitmHostCX*)just_accepted_cx)->mode(AppHostCX::MODE_NONE);
    target_cx->mode(AppHostCX::MODE_NONE);
    
    new_proxy->radd(target_cx);

    // apply policy and get result
    int policy_num = CfgFactory::get().policy_apply(just_accepted_cx, new_proxy);
    if(policy_num >= 0) {
        this->proxies().insert(new_proxy);
        
        ((MitmHostCX*)just_accepted_cx)->matched_policy(policy_num);
        target_cx->matched_policy(policy_num);
        new_proxy->matched_policy(policy_num);
        
        if(CfgFactory::get().db_policy.at(policy_num)->nat == POLICY_NAT_NONE) {
            target_cx->com()->nonlocal_src(true);
            target_cx->com()->nonlocal_src_host() = h;
            target_cx->com()->nonlocal_src_port() = std::stoi(p);               
        }

        int real_socket = target_cx->connect();
        target_cx->rename();
        com()->set_monitor(real_socket);
        com()->set_poll_handler(real_socket,new_proxy);
    }
    
    new_proxy->name(new_proxy->to_string());
    _deb("MitmUDPProxy::on_left_new: finished");    
}

baseHostCX* MitmUdpProxy::MitmUdpProxy::new_cx(int s) {
    return new MitmHostCX(com()->slave(),s);
}

