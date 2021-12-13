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
#include <ctime>

#include <proxy/mitmproxy.hpp>
#include <proxy/mitmhost.hpp>
#include <proxy/filterproxy.hpp>
#include <proxy/proxymaker.hpp>

#include <log/logger.hpp>
#include <cfgapi.hpp>

#include <uxcom.hpp>
#include <staticcontent.hpp>
#include <policy/authfactory.hpp>

#include <traflog/fsoutput.hpp>

#include <algorithm>

using namespace socle;

MitmProxy::MitmProxy(baseCom* c): baseProxy(c), sobject() {

    // NOTE: testing filter - get back to it later!
    // add_filter("test",new TestFilter(this,5));

    log = logan::attach(this, "com.proxy");

    total_sessions()++;
}

void MitmProxy::toggle_tlog () {
    
    // create traffic logger if it doesn't exist
    if(not tlog_) {

        switch (writer_opts()->format.value) {
            case ContentCaptureFormat::type_t::SMCAP: {
                tlog_ = std::make_unique<socle::traflog::SmcapLog>(this,
                                                                   CfgFactory::get()->capture_local.dir.c_str(),
                                                                   CfgFactory::get()->capture_local.file_prefix.c_str(),
                                                                   CfgFactory::get()->capture_local.file_suffix.c_str());

                }
                break;

            case ContentCaptureFormat::type_t::PCAP: {
                auto pcaplog = std::make_unique<socle::traflog::PcapLog>(this,
                                                             CfgFactory::get()->capture_local.dir.c_str(),
                                                             CfgFactory::get()->capture_local.file_prefix.c_str(),
                                                             CfgFactory::get()->capture_local.file_suffix.c_str(),

                                                             true);
                pcaplog->details.ttl = 32;
                tlog_ = std::move(pcaplog);

                }
                break;

            case ContentCaptureFormat::type_t::PCAP_SINGLE: {

                static std::once_flag once;
                std::call_once(once, [] {
                    auto &single = socle::traflog::PcapLog::single_instance();

                    single.FS = socle::traflog::FsOutput(nullptr, CfgFactory::get()->capture_local.dir.c_str(),
                                                         CfgFactory::get()->capture_local.file_prefix.c_str(),
                                                         CfgFactory::get()->capture_local.file_suffix.c_str(), false);

                    single.FS.generate_filename_single("smithproxy", true);
                });

                auto n = std::make_unique<socle::traflog::PcapLog>(this, CfgFactory::get()->capture_local.dir.c_str(),
                                                                   CfgFactory::get()->capture_local.file_prefix.c_str(),
                                                                   CfgFactory::get()->capture_local.file_suffix.c_str(),
                                                                   false);
                n->single_only = true;
                n->details.ttl = 32;

                tlog_ = std::move(n);

                }
                break;
        }
    }
    
    // check if we have there status file
    if(tlog_) {
        std::string data_dir = CfgFactory::get()->capture_local.dir;

        data_dir += "/disabled";
        
        struct stat st{};
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
    
    if(writer_opts()->write_payload) {
        _deb("MitmProxy::destructor: syncing writer");

        for(auto* cx: ls()) {
            if(! cx->comlog().empty()) {
                if(tlog()) tlog()->write(side_t::LEFT, cx->comlog());
                cx->comlog().clear();
            }
        }               
        
        for(auto* cx: rs()) {
            if(! cx->comlog().empty()) {
                if(tlog()) tlog()->write_right(cx->comlog());
                cx->comlog().clear();
            }
        }         
        
        if(tlog()) tlog()->write_left("Connection stop\n");
    }
    
    delete content_rule_;
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
        
        r << string_format("up/down: %s/%s",number_suffixed(stats_.mtr_up.get()*8).c_str(),number_suffixed(stats_.mtr_down.get()*8).c_str());
        
        if(verbosity > INF) { 
            r << string_format("\n    Policy  index: %d", matched_policy());


            if(matched_policy() >= 0) {
                auto p = CfgFactory::get()->db_policy_list.at(matched_policy());
                r << string_format("\n    PolicyRule oid: 0x%x", p->oid());
            }


            if(identity_resolved()) {
                r << string_format("\n    User:   %s", identity_->username().c_str());
                r << string_format("\n    Groups: %s", identity_->groups().c_str());
            }
        }        
    }
    
    return r.str();
}


void MitmProxy::identity_resolved(bool b) {
    identity_resolved_ = b;
}

bool MitmProxy::apply_id_policies(baseHostCX* cx) {


    int af = AF_INET;
    if(cx->com()) {
        af = cx->com()->l3_proto();
    }
    std::string str_af = SocketInfo::inet_family_str(af);
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


    std::shared_ptr<ProfileSubAuth> final_profile;
    
    if( found ) {
        _dia("apply_id_policies: matched policy: %d",matched_policy());        
        auto policy = CfgFactory::get()->db_policy_list.at(matched_policy());
        
        auto auth_policy = policy->profile_auth;

        
        if(auth_policy) {
            for(auto const& sub_prof: auth_policy->sub_policies) {
                
                _dia("apply_id_policies: checking identity policy for: %s", sub_prof->element_name().c_str());
                
                for(auto const& my_id: group_vec) {
                    _dia("apply_id_policies: identity in policy: %s, match-test real user group '%s'",
                         sub_prof->element_name().c_str(), my_id.c_str());
                    if(sub_prof->element_name() == my_id) {
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
            
            _dia("apply_id_policies: assigning sub-profile %s", final_profile->element_name().c_str());
            if(final_profile->profile_content != nullptr) {
                if (CfgFactory::get()->prof_content_apply(cx, this, final_profile->profile_content)) {
                    pc_name = final_profile->profile_content->element_name().c_str();
                    _dia("apply_id_policies: assigning content sub-profile %s",
                         final_profile->profile_content->element_name().c_str());
                }
            }
            if(final_profile->profile_detection != nullptr) {
                if (CfgFactory::get()->prof_detect_apply(cx, this, final_profile->profile_detection)) {
                    pd_name = final_profile->profile_detection->element_name().c_str();
                    _dia("apply_id_policies: assigning detection sub-profile %s",
                         final_profile->profile_detection->element_name().c_str());
                }
            }
            if(final_profile->profile_tls != nullptr) {
                if(CfgFactory::get()->prof_tls_apply(cx, this, final_profile->profile_tls)) {
                    pt_name = final_profile->profile_tls->element_name().c_str();
                    _dia("apply_id_policies: assigning tls sub-profile %s", final_profile->profile_tls->element_name().c_str());
                }
            }
            if(final_profile->profile_alg_dns != nullptr) {
                if(CfgFactory::get()->prof_alg_dns_apply(cx, this, final_profile->profile_alg_dns)) {
                    algs += final_profile->profile_alg_dns->element_name() + " ";
                    _dia("apply_id_policies: assigning tls sub-profile %s", final_profile->profile_tls->element_name().c_str());
                }
            }
            
            // end of custom sub-profiles
            _inf("Connection %s: identity-based sub-profile: name=%s cont=%s det=%s tls=%s algs=%s",cx->full_name('L').c_str(),
                 final_profile->element_name().c_str(),
                            pc_name, pd_name, pt_name, algs.c_str()
                            );
        }

        return (final_profile != nullptr);
    } 

    return false;
}

bool MitmProxy::resolve_identity(baseHostCX* cx, bool insert_guest = false) {

    if(not cx) return false;
    
    int af = AF_INET;
    if(cx->com()) {
        af = cx->com()->l3_proto();
    }
    std::string str_af = SocketInfo::inet_family_str(af);

    bool new_identity = false;

    if(identity_resolved()) {
        
        bool update_status = false;
        if(af == AF_INET || af == 0) update_status = update_auth_ipX_map(cx);
        if(af == AF_INET6) update_status = update_auth_ipX_map(cx); 
        
        if(update_status) {
            return true;
        } else {
            identity_resolved(false);
        }

        _deb("resolved identity check[%s]: source: %s", str_af.c_str(), cx->host().c_str());
    } else {

        new_identity = true;
        _dia("unresolved identity check[%s]: source: %s", str_af.c_str(), cx->host().c_str());
    }


    bool valid_ip_auth = false;
    shm_logon_info_base* id_ptr = nullptr;
    
    if(af == AF_INET || af == 0) {

        std::scoped_lock<std::recursive_mutex> l_(AuthFactory::get_ip4_lock());
        AuthFactory::get().shm_ip4_table_refresh();

        _deb("identity check[%s]: table size: %d", str_af.c_str(), AuthFactory::get_ip4_map().size());
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

        _deb("identity check[%s]: table size: %d", str_af.c_str(), AuthFactory::get_ip6_map().size());
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

        if(new_identity) {
            _inf("unresolved identity found for %s %s: user: %s groups: %s", str_af.c_str(), cx->host().c_str(),
                 id_ptr->username().c_str(), id_ptr->groups().c_str());
        } else {
            _deb("resolved identity found for %s %s: user: %s groups: %s", str_af.c_str(), cx->host().c_str(),
                 id_ptr->username().c_str(), id_ptr->groups().c_str());

        }

        // if update_auth_ip_map fails, identity is no longer valid!
        
        if(af == AF_INET || af == 0) valid_ip_auth = update_auth_ipX_map(cx);
        if(af == AF_INET6) valid_ip_auth = update_auth_ipX_map(cx);
            
        
        identity_resolved(valid_ip_auth);
        if(valid_ip_auth) { 
            identity(id_ptr);
        }
        
        // apply specific identity-based profile. 'li' is still valid, since we still hold the lock
        // get ptr to identity_info

        if(new_identity) {
            _dia("resolve_identity[%s]: about to call apply_id_policies on new identity, group: %s", str_af.c_str(),
                 id_ptr->groups().c_str());
        } else {
            _deb("resolve_identity[%s]: about to call apply_id_policies on known identity, group: %s", str_af.c_str(),
                 id_ptr->groups().c_str());
        }

        apply_id_policies(cx);


        // id_ptr is either a clone, or new guest id
        delete id_ptr;
    }


    _dum("identity check[%s]: return %d", str_af.c_str(), valid_ip_auth);
    return valid_ip_auth;
}


bool MitmProxy::update_auth_ipX_map(baseHostCX* cx) {

    bool ret = false;
    
    int af = AF_INET;
    if(cx->com()) {
        af = cx->com()->l3_proto();
    }
    std::string str_af = SocketInfo::inet_family_str(af);
    

    _dum("update_auth_ip_map: start for %s %s", str_af.c_str(), cx->host().c_str());
    
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
        _deb("update_auth_ip_map: user %s from %s %s (groups: %s)",id_ptr->username.c_str(), str_af.c_str(), cx->host().c_str(), id_ptr->groups.c_str());

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
    
    _dum("update_auth_ip_map: finished for %s %s, result %d",str_af.c_str(), cx->host().c_str(),ret);
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
            _deb("handle_authentication: identity check: unknown");
            
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
                    _dia("MitmProxy::handle_authentication: we should block it");
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
    if(ssl_handled) {
        return false;
    }

    bool redirected = false;

    auto* scom = dynamic_cast<SSLCom*>(mh->peercom());


    if(scom && scom->is_verify_status_opt_allowed()) {

        // exceptions are satisfied and we can continue with proxying, regardless of other options

        ssl_handled = true;
        return false;
    }

    if(scom && scom->opt_failed_certcheck_replacement) {

//        if(! ocsp_caller_tried) {
//            ocsp_caller_tried = true;
//            ocsp_caller = AsyncOcspInvoker::invoke(*this);
//
//            _err("left: ocsp check invoked");
//        }

        if(!(
            scom->verify_get() == SSLCom::VRF_OK
             ||
            scom->verify_get() == ( SSLCom::VRF_OK | SSLCom::VRF_CLIENT_CERT_RQ )
            )) {

            if(tlog()) tlog()->write_left("original TLS peer verification failed");

            bool whitelist_found = false;
            
            //look for whitelisted entry
            std::string key = whitelist_make_key(mh);
            if( ( !key.empty() ) && key != "?") {
                std::lock_guard<std::recursive_mutex> l_(whitelist_verify().getlock());

                auto wh_entry = whitelist_verify().get(key);
                _dia("whitelist_verify[%s]: %s", key.c_str(), wh_entry ? "found" : "not found" );

                // !!! wh might be already invalid here, unlocked !!!
                if(wh_entry != nullptr) {
                    whitelist_found = true;
                    if (scom->opt_failed_certcheck_override_timeout_type == 1) {
                        wh_entry->expired_at() = ::time(nullptr) + scom->opt_failed_certcheck_override_timeout;
                        _dia("whitelist_verify[%s]: timeout reset to %d", key.c_str(), scom->opt_failed_certcheck_override_timeout );
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
                else if(scom->verify_bitcheck(SSLCom::VRF_CLIENT_CERT_RQ) && scom->opt_client_cert_action > 0) {

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

    ssl_handled = true;

    return redirected;
}

bool MitmProxy::handle_cached_response(MitmHostCX* mh) {
    
    if(mh->inspection_verdict() == Inspector::CACHED) {

        if(tlog()) {
            tlog()->write_right("content has been served from cache\n");
            if(mh->inspection_verdict_response()) tlog()->write(side_t::RIGHT, *mh->inspection_verdict_response());
        }

        _dia("cached content: not proxying");
        return true;
    }
    
    return false;
}


void MitmProxy::proxy(baseHostCX* from, baseHostCX* to, side_t side, bool redirected) {

    if (!redirected) {
        if (content_rule() != nullptr) {
            buffer b = content_replace_apply(from->to_read());
            to->to_write(b);
            _dia("mitmproxy::proxy-%c: original %d bytes replaced with %d bytes", from_side(side), from->to_read().size(),
                 b.size());
        } else {
            to->to_write(from->to_read());
            _dia("mitmproxy::proxy-%c: %d copied", from_side(side), from->to_read().size());
        }
    } else {

        // rest of connections should be closed when sending replacement to a client
        to->shutdown();
    }
};

void MitmProxy::on_left_bytes(baseHostCX* cx) {

    if(writer_opts()->write_payload) {

        toggle_tlog();
        
        if(! cx->comlog().empty()) {
            if(tlog()) tlog()->write_left(cx->comlog());
            cx->comlog().clear();
        }
        
        if(tlog()) tlog()->write_left(cx->to_read());
    }
    

    bool redirected = false;
    
    auto* mh = dynamic_cast<MitmHostCX*>(cx);

    if(mh != nullptr) {

        // check authentication
        redirected = handle_authentication(mh);
     
        // check com responses
        redirected = handle_com_response_ssl(mh);
        

        // don't copy data if we have cached response, or we are are dropped and marked dead()
        if(handle_cached_response(mh) || state().dead()) {
            return;
        }
    }

    // because we have left bytes, let's copy them into all right side sockets!
    std::for_each(
            right_sockets.begin(),
            right_sockets.end(),
            [&](auto* to) {proxy(cx, to, side_t::LEFT, redirected); });

    // because we have left bytes, let's copy them into all right side sockets!
    std::for_each(
            right_delayed_accepts.begin(),
            right_delayed_accepts.end(),
            [&](auto* to) {proxy(cx, to, side_t::LEFT, redirected); });


    //update meters
    total_mtr_up().update(cx->to_read().size());
}

void MitmProxy::on_right_bytes(baseHostCX* cx) {
    if(writer_opts()->write_payload) {

        toggle_tlog();
        
        if(! cx->comlog().empty()) {
            if(tlog()) tlog()->write_right(cx->comlog());
            cx->comlog().clear();
        }
        
        if(tlog()) tlog()->write_right(cx->to_read());
    }


//    // enters only if left bytes are not received a therefore not SSL additional tasks
//    // performed
//    if(! ssl_handled) {
//        if(auto* scom = dynamic_cast<SSLCom*>(cx->com()) ; scom) {
//            if (!ocsp_caller_tried) {
//                ocsp_caller_tried = true;
//                ocsp_caller = AsyncOcspInvoker::invoke(*this);
//                _err("right: ocsp check invoked");
//            }
//        } else {
//
//            // if com is not SSL, no further ssl attempts are neded (spare dynamic casts)
//            ssl_handled = true;
//        }
//    }


    bool redirected = false;

    auto* mh = dynamic_cast<MitmHostCX*>(cx->peer());

    if(mh != nullptr) {

        // check authentication
        redirected = handle_authentication(mh);

        // check com responses
        redirected = handle_com_response_ssl(mh);

    }

    std::for_each(
            left_sockets.begin(),
            left_sockets.end(),
            [&](auto* to) {proxy(cx, to, side_t::RIGHT, redirected); });

    // because we have left bytes, let's copy them into all right side sockets!
    std::for_each(
            left_delayed_accepts.begin(),
            left_delayed_accepts.end(),
            [&](auto* to) {proxy(cx, to, side_t::RIGHT, redirected); });


    // update total meters
    total_mtr_down().update(cx->to_read().size());
}


void MitmProxy::_debug_zero_connections(baseHostCX* cx) {

    if(cx->meter_write_count == 0 && cx->meter_write_bytes == 0 ) {
        auto* xcom = dynamic_cast<SSLCom*>(cx->com());
        if(xcom) {
            xcom->log_profiling_stats(iINF);

            int s = cx->socket();
            if(s == 0) s = cx->closed_socket();
            if(s != 0) {
                buffer b(1024);
                auto p = cx->com()->peek(s,b.data(),b.capacity(),0);
                _inf("        cx peek size %d", p);
            }
            
        }
        
        if(cx->peer()) {
            auto* xcom_peer = dynamic_cast<SSLCom*>(cx->peer()->com());
            if(xcom_peer) {
                xcom_peer->log_profiling_stats(iINF);
                _inf("        peer transferred bytes: up=%d/%dB dw=%d/%dB", cx->peer()->meter_read_count, cx->peer()->meter_read_bytes,
                                                                cx->peer()->meter_write_count, cx->peer()->meter_write_bytes);
                int s = cx->peer()->socket();
                if(s == 0) s = cx->peer()->closed_socket();
                if(s != 0) {
                    buffer b(1024);
                    auto p = cx->peer()->com()->peek(s,b.data(),b.capacity(),0);
                    _inf("        peer peek size %d", p);
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
                _ext("on_half_close: live peer with pending data: keeping up for %ds", expiry);
            } else {
                _dia("on_half_close: timer's up (%ds) - closing.", expiry);
                state().dead(true);
            }
            
            
        } else {
            _dia("on_half_close: live peer with pending data: keeping up for %ds", half_timeout);
            half_holdtimer = ::time(nullptr);
        }
        
    } else {
        // if peer doesn't exist or peercom doesn't exit, mark proxy dead -- no one to speak to
        _dia("on_half_close: peer with pending write-data is dead.");
        state().dead(true);
    }
}


std::string get_connection_details_str(MitmProxy* px, baseHostCX* cx, char side) {

    if(!cx) {
        return "";
    }

    std::string flags;
    flags += side;

    auto* mh = dynamic_cast<MitmHostCX*>(cx);

    if(side == 'R' && cx->peer())
        mh = dynamic_cast<MitmHostCX*>(cx->peer());

    if (mh != nullptr && mh->inspection_verdict() == Inspector::CACHED) flags+="C";

    std::stringstream detail;

    if(cx->peercom()) {
        auto* sc = dynamic_cast<SSLMitmCom*>(cx->peercom());
        if(sc) {
            detail << string_format("sni=%s ",sc->get_peer_sni().c_str());
        }
    }
    if(mh && mh->engine_ctx.application_data) {

        auto* http = dynamic_cast<sx::engine::http::app_HttpRequest*>(mh->engine_ctx.application_data.get());
        if(http) {
            detail << "app=" << http->proto << http->host << " ";
        }
        else {
            detail << "app=" << mh->engine_ctx.application_data->str() << " ";
        }
    }

    std::string identity;
    std::string px_flags;

    if(px) {
        if(px->identity_resolved()) {
            identity = px->identity()->username();
        }
        if(px->com()) {
            px_flags = px->com()->full_flags_str();
        }
    }

    detail << string_format("user=%s up=%d/%dB dw=%d/%dB flags=%s+%s",
                            identity.c_str(),
                            cx->meter_read_count, cx->meter_read_bytes,
                            cx->meter_write_count, cx->meter_write_bytes,
                            flags.c_str(),
                            px_flags.c_str()
    );

    return detail.str();
}


void MitmProxy::on_error(baseHostCX* cx, char side, const char* side_label) {
    if(cx == nullptr) {
        std::stringstream msg;

        msg << "Connection closed (null cx) on ";

        if(state().error_on_left_read) msg << "Lr";
        if(state().error_on_left_write) msg << "Lw";
        if(state().error_on_right_read) msg << "Rr";
        if(state().error_on_right_write) msg << "Rw";

        msg << ": "
            << get_connection_details_str(this, cx, side);
        _err("%s", msg.str().c_str());

        state().dead(true);
        return;
    }

    // if not dead (yet), do some cleanup/logging chores
    if( !state().dead()) {

        // don't waste time on low-effort delivery stuff, just get rid of it now.
        if(com()->l4_proto() == SOCK_DGRAM) {
            state().dead(true);
            return;
        }

        if(cx->peer()) {
            if(! cx->peer()->writebuf()->empty()) {

                // do half-closed actions, and mark proxy dead if needed
                on_half_close(cx);

                if (state().dead()) {
                    // status dead is new, since we check dead status at the beginning
                    std::stringstream msg;
                    msg << "Connection " << side_label << " half-closed on ";

                    if(state().error_on_left_read) msg << "Lr";
                    if(state().error_on_left_write) msg << "Lw";
                    if(state().error_on_right_read) msg << "Rr";
                    if(state().error_on_right_write) msg << "Rw";

                    msg << ": "
                        << get_connection_details_str(this, cx, side);
                    _inf("%s", msg.str().c_str());

                } else {
                    // on_half_close did not marked it dead, yet
                    std::stringstream msg;

                    msg << "Connection " << side_label << " half-closing on ";
                    if(state().error_on_left_read) msg << "Lr";
                    if(state().error_on_left_write) msg << "Lw";
                    if(state().error_on_right_read) msg << "Rr";
                    if(state().error_on_right_write) msg << "Rw";

                    msg << ": "
                        << get_connection_details_str(this, cx, side);
                    _dia("%s", msg.str().c_str());

                    // provoke write to the peer's socket (could be superfluous)
                    com()->set_write_monitor(cx->peer()->socket());
                }
            } else {

                // duplicate code to DEAD before calling us

                std::stringstream msg;
                msg << "Connection from " << cx->full_name(side) << " closed: " << get_connection_details_str(this, cx, side);
                if(! replacement_msg.empty() ) {
                    msg << ", dropped: " << replacement_msg;
                    _inf("%s", msg.str().c_str()); // log to generic logger
                }
                _inf("%s", msg.str().c_str());

                state().dead(true);
            }
        } else {
            std::stringstream msg;
            msg << "Connection from " << side_label << " half-closing (peer dead) on ";

            if(state().error_on_left_read) msg << "Lr";
            if(state().error_on_left_write) msg << "Lw";
            if(state().error_on_right_read) msg << "Rr";
            if(state().error_on_right_write) msg << "Rw";

            msg << ": "
                << get_connection_details_str(this, cx, side);
            _dia("%s", msg.str().c_str());

            state().dead(true);
        }
    } else {
        // DEAD before calling us!

        if(opt_auth_resolve)
            resolve_identity(cx);

        if(cx->peer() && cx->peer()->writebuf()->empty()) {
            std::stringstream msg;
            msg << "Connection from " << cx->full_name(side) << " closed: " << get_connection_details_str(this, cx, side);
            if(! replacement_msg.empty() ) {
                msg << ", replaced: " << replacement_msg;
            }
            _inf("%s", msg.str().c_str());
            if(*log.level() > DEB) _debug_zero_connections(cx);

            state().dead(true);
        }
    }


    // state could change. Log if we are dead now
    if(state().dead()){
        if (writer_opts()->write_payload) {
            toggle_tlog();
            if (tlog()) {

                std::stringstream ss;
                ss << std::string(side_label) << "side connection closed: " << cx->name() << "\n";
                auto msg = ss.str();

                tlog()->write(to_side(side), msg);
                if (!replacement_msg.empty()) {
                    tlog()->write(to_side(side), cx->name() + "   dropped by proxy:" + replacement_msg + "\n");
                }
            }
        }
    }
}

void MitmProxy::on_left_error(baseHostCX* cx) {
    on_error(cx, 'L', "client");

    if(state().dead())
        AuthFactory::get().ipX_inc_counters(cx);
}

void MitmProxy::on_right_error(baseHostCX* cx) {
    on_error(cx, 'R', "server");

    if(state().dead() && cx->peer())
        AuthFactory::get().ipX_inc_counters(cx->peer());

}



void MitmProxy::handle_replacement_auth(MitmHostCX* cx) {
  
    std::string redir_pre("<html><head><script>top.location.href=\"");
    std::string redir_suf("\";</script></head><body></body></html>");  
  
//     std::string redir_pre("HTTP/1.0 301 Moved Permanently\r\nLocation: ");
//     std::string redir_suf("\r\n\r\n");  
  
    
    std::string repl;
    std::string repl_port = AuthFactory::get().portal_port_http;
    std::string repl_proto = "http";

    if(cx->engine_ctx.application_data->is_ssl) {
        repl_proto = "https";
        repl_port =AuthFactory::get().portal_port_https;
    }    
    
    std::string block_pre("<h2 class=\"fg-red\">Page has been blocked</h2><p>Access has been blocked by smithproxy.</p>"
                          "<p>To check your user privileges go to status page<p><p> <form action=\"");

    std::string block_post(R"("><input type="submit" value="User Info" class="btn-red"></form>)");
    
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
                _inf("MitmProxy::handle_replacement_auth: cached token %s for request: %s",
                                token_tk.c_str(), cx->engine_ctx.application_data->str().c_str());
                
                if(cx->com()) {
                    if(cx->com()->l3_proto() == AF_INET) {
                        repl = redir_pre + repl_proto
                                + "://"+AuthFactory::get().portal_address+":"+repl_port+"/cgi-bin/auth.py?token="
                                + token_tk + redir_suf;

                    } else if(cx->com()->l3_proto() == AF_INET6) {
                        repl = redir_pre + repl_proto
                                + "://"+AuthFactory::get().portal_address6+":"+repl_port+"/cgi-bin/auth.py?token="
                                + token_tk + redir_suf;
                    } 
                } 
                
                if(repl.empty()) {
                    // default to IPv4 address
                    repl = redir_pre + repl_proto
                            + "://"+AuthFactory::get().portal_address+":"+repl_port+"/cgi-bin/auth.py?token="
                            + token_tk + redir_suf;
                }
                
                repl = html()->render_server_response(repl);
                
                cx->to_write((unsigned char*)repl.c_str(),repl.size());
                cx->close_after_write(true);

                replacement_msg += "(auth: known token)";
            } else {
                _inf("MitmProxy::handle_replacement_auth: expired token %s for request: %s",
                                token_tk.c_str(), cx->engine_ctx.application_data->str().c_str());
                goto new_token;
            }
        } else {
        
            new_token:
            
            std::string token_text = cx->engine_ctx.application_data->original_request();
          
            for(auto const& i: CfgFactory::get()->policy_prof_auth(cx->matched_policy())->sub_policies) {
                _dia("MitmProxy::handle_replacement_auth: token: requesting identity %s", i->element_name().c_str());
                token_text  += " |" + i->element_name();
            }
            shm_logon_token tok = shm_logon_token(token_text.c_str());
            
            _inf("MitmProxy::handle_replacement_auth: new auth token %s for request: %s",
                                tok.token().c_str(), cx->engine_ctx.application_data->str().c_str());
            
            if(cx->com()) {
                if(cx->com()->l3_proto() == AF_INET) {
                    repl = redir_pre + repl_proto
                            + "://"+AuthFactory::get().portal_address+":"+repl_port+"/cgi-bin/auth.py?token="
                            + tok.token() + redir_suf;

                } else if(cx->com()->l3_proto() == AF_INET6) {
                    repl = redir_pre + repl_proto
                            + "://"+AuthFactory::get().portal_address6+":"+repl_port+"/cgi-bin/auth.py?token="
                            + tok.token() + redir_suf;
                } 
            } 
            
            if(repl.empty()) {
                // default to IPv4 address
                _dia("reply fallback to IPv4");
                repl = redir_pre + repl_proto
                        + "://"+AuthFactory::get().portal_address+":"+repl_port+"/cgi-bin/auth.py?token="
                        + tok.token() + redir_suf;
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

std::string MitmProxy::verify_flag_string(int code) {
    switch(code) {
        case SSLCom::VRF_OK:
            return "Certificate verification successful";
        case SSLCom::VRF_SELF_SIGNED:
            return "Target certificate is self-signed";
        case SSLCom::VRF_SELF_SIGNED_CHAIN:
            return "Server certificate's chain contains self-signed, untrusted CA certificate";
        case SSLCom::VRF_UNKNOWN_ISSUER:
            return "Server certificate is issued by untrusted certificate authority";
        case SSLCom::VRF_CLIENT_CERT_RQ:
            return "Server is asking client for a certificate";
        case SSLCom::VRF_REVOKED:
            return "Server's certificate is REVOKED";
        case SSLCom::VRF_HOSTNAME_FAILED:
            return "Client application asked for SNI server is not offering";
        case SSLCom::VRF_INVALID:
            return "Certificate is not valid";
        case SSLCom::VRF_ALLFAILED:
            return "It was not possible to obtain certificate status";
        case SSLCom::VRF_CT_MISSING:
            return "Certificate Transparency info is missing";
        default:
            return string_format("code 0x04%x", code);
    }
}

std::string MitmProxy::verify_flag_string_extended(int code) {
    switch(code) {
        case SSLCom::VRF_OTHER_SHA1_SIGNATURE:
            return "Issuer certificate is signed using SHA1 (considered insecure).";
        case SSLCom::VRF_OTHER_CT_INVALID:
            return "Certificate Transparency tag is INVALID.";
        case SSLCom::VRF_OTHER_CT_FAILED:
            return "Unable to verify Certificate Transparency tag.";
        default:
            return string_format("extended code 0x04%x", code);
    }
}

void MitmProxy::set_replacement_msg_ssl(SSLCom* scom) {
    if(scom && scom->verify_get() != SSLCom::VRF_OK) {

        std::stringstream  ss;

        if(scom->verify_bitcheck(SSLCom::VRF_SELF_SIGNED)) {
            ss << "(ssl:" << verify_flag_string(SSLCom::VRF_SELF_SIGNED) << ")";
        }
        if(scom->verify_bitcheck(SSLCom::VRF_SELF_SIGNED_CHAIN)) {
            ss << "(ssl:" << verify_flag_string(SSLCom::VRF_SELF_SIGNED_CHAIN) << ")";
        }
        if(scom->verify_bitcheck(SSLCom::VRF_UNKNOWN_ISSUER)) {
            ss << "(ssl:" << verify_flag_string(SSLCom::VRF_UNKNOWN_ISSUER) << ")";
        }
        if(scom->verify_bitcheck(SSLCom::VRF_CLIENT_CERT_RQ)) {
            ss << "(ssl:" << verify_flag_string(SSLCom::VRF_CLIENT_CERT_RQ) << ")";
        }
        if(scom->verify_bitcheck(SSLCom::VRF_REVOKED)) {
            ss << "(ssl:" << verify_flag_string(SSLCom::VRF_REVOKED) << ")";
        }
        if(scom->verify_bitcheck(SSLCom::VRF_HOSTNAME_FAILED)) {
            ss << "(ssl:" << verify_flag_string(SSLCom::VRF_HOSTNAME_FAILED) << ")";
        }
        if(scom->verify_bitcheck(SSLCom::VRF_EXTENDED_INFO)) {

            for(auto const& ei: scom->verify_extended_info()) {
                ss << "(ssl: " << verify_flag_string(ei) << ")";
            }
        }
        replacement_msg += ss.str();
    }
}

std::string MitmProxy::replacement_ssl_verify_detail(SSLCom* scom) {

    std::stringstream ss;
    if(scom) {
        if (scom->verify_get() != SSLCom::VRF_OK) {
            bool is_set = false;
            int reason_count = 0;

            if (scom->verify_bitcheck(SSLCom::VRF_SELF_SIGNED)) {
                ss << "<p><h3 class=\"fg-red\">Reason " << ++reason_count << ":</h3> " << verify_flag_string(SSLCom::VRF_SELF_SIGNED) << ".</p>";
                is_set = true;
            }
            if (scom->verify_bitcheck(SSLCom::VRF_SELF_SIGNED_CHAIN)) {
                ss << "<p><h3 class=\"fg-red\">Reason " << ++reason_count << ":</h3> " << verify_flag_string(SSLCom::VRF_SELF_SIGNED_CHAIN)
                   << ".</p>";
                is_set = true;
            }
            if (scom->verify_bitcheck(SSLCom::VRF_UNKNOWN_ISSUER)) {
                ss << "<p><h class=\"fg-red\">Reason " << ++reason_count << ":</h3>" << verify_flag_string(SSLCom::VRF_UNKNOWN_ISSUER) << ".</p>";
                is_set = true;
            }
            if (scom->verify_bitcheck(SSLCom::VRF_CLIENT_CERT_RQ)) {
                ss << "<p><h3 class=\"fg-red\">Reason " << ++reason_count << ":</h3>" << verify_flag_string(SSLCom::VRF_CLIENT_CERT_RQ) << ".<p>";
                is_set = true;
            }
            if (scom->verify_bitcheck(SSLCom::VRF_REVOKED)) {
                ss << "<p><h3 class=\"fg-red\">Reason " << ++reason_count << ":</h3>" << verify_flag_string(SSLCom::VRF_REVOKED) <<
                       ". "
                       "This is a serious issue, it's highly recommended to not continue "
                       "to this page.</p>";
                is_set = true;
            }
            if (scom->verify_bitcheck(SSLCom::VRF_CT_MISSING)) {
                ss << "<p><h3 class=\"fg-red\">Reason " << ++reason_count << ":</h3>" << verify_flag_string(SSLCom::VRF_CT_MISSING) <<
                   ". "
                   "This is a serious issue if your target is a public internet service. In such a case it's highly recommended to not continue."
                   "</p>";
                is_set = true;
            }
            if (scom->verify_bitcheck(SSLCom::VRF_CT_FAILED)) {
                ss << "<p><h3 class=\"fg-red\">Reason " << ++reason_count << ":</h3>" << verify_flag_string(SSLCom::VRF_CT_MISSING) <<
                   ". "
                   "This is a serious issue if your target is a public internet service. Don't continue unless you really know what you are doing. "
                   "</p>";
                is_set = true;
            }

            if (scom->verify_bitcheck(SSLCom::VRF_INVALID)) {
                ss << "<p><h3 class=\"fg-red\">Reason " << ++reason_count << ":</h3>" << verify_flag_string(SSLCom::VRF_INVALID) << ".</p>";
                is_set = true;
            }
            if (scom->verify_bitcheck(SSLCom::VRF_HOSTNAME_FAILED)) {
                ss << "<p><h3 class=\"fg-red\">Reason " << ++reason_count << ":</h3>" << verify_flag_string(SSLCom::VRF_HOSTNAME_FAILED) << ".</p>";
                is_set = true;
            }
            if (scom->verify_bitcheck(SSLCom::VRF_ALLFAILED)) {
                ss << "<p><h3 class=\"fg-red\">Reason " << ++reason_count << ":</h3>" << verify_flag_string(SSLCom::VRF_ALLFAILED) << ".</p>";
                is_set = true;
            }
            if(scom->verify_bitcheck(SSLCom::VRF_EXTENDED_INFO)) {
                for (auto const &ei: scom->verify_extended_info()) {
                    ss << "<p><h3 class=\"fg-red\">Reason " << ++reason_count << ":</h3>" << verify_flag_string_extended(ei) << ".</p>";
                    is_set = true;
                }
            }

            if (!is_set) {
                ss << string_format(
                        "<p><h3 class=\"fg-red\">Reason:</h3>Oops, no detailed problem description (code: 0x%x)</p>",
                        scom->verify_get());
            }
        } else {
            ss << string_format(
                    "<p><h3 class=\"fg-red\">Reason:</h3>Oops, no detailed problem description (code: 0x%x)</p>",
                    scom->verify_get());
        }
    }

    return ss.str();
}


std::string MitmProxy::replacement_ssl_page(SSLCom* scom, sx::engine::http::app_HttpRequest* app_request, std::string const& more_info) {
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

    if(tlog()) tlog()->write_left("TLS content replacement\n");

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
    

    auto* app_request = dynamic_cast<sx::engine::http::app_HttpRequest*>(cx->engine_ctx.application_data.get());
    if(app_request != nullptr) {
        
//         _inf(" --- request: %s",app_request->request().c_str());
//         _inf(" ---     uri: %s",app_request->uri.c_str());
//         _inf(" --- origuri: %s",app_request->original_request().c_str());
//         _inf(" --- referer: %s",app_request->referer.c_str());

        auto find_orig_uri = [&]() -> std::optional<std::string> {
            auto request = app_request->request();
            auto a = request.find("orig_url");
            if(a != std::string::npos) {
                //len of "orig_url=" is 9
                return request.substr(a+9, std::string::npos);
            }

            return std::nullopt;
        };


        auto generate_block_override = [&]() -> std::string {
            std::string block_override;

            if (scom->opt_failed_certcheck_override) {
                std::string block_override_pre = R"(<form action="/SM/IT/HP/RO/XY)";

                std::string key = whitelist_make_key(cx);
                if (cx->peer()) {
                    block_override_pre += "/override/target=" + key;
                    if (not app_request->uri.empty()) {
                        block_override_pre += "&orig_url=" + find_orig_uri().value_or("/");
                    }
                }
                std::string block_target_info;
                block_override =
                        block_override_pre + R"("><input type="submit" value="Override" class="btn-red"></form>)";
            }

            return block_override;
        };

        if(app_request->request().find("/SM/IT/HP/RO/XY/override") != std::string::npos) {
            
            // PHASE IV.
            // perform override action
                
                        
            if(scom->opt_failed_certcheck_override) {
            
                _dia("ssl_override: ph4 - asked for verify override for %s", whitelist_make_key(cx).c_str());
                
                std::string orig_url = find_orig_uri().value_or("/");

                std::string override_applied = string_format(
                        R"(<html><head><meta http-equiv="Refresh" content="0; url=%s"></head><body><!-- applied, redirecting back to %s --></body></html>)",
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
                
                _war("Connection from %s: SSL override activated for %s", cx->full_name('L').c_str(), app_request->request().c_str());
                
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
            
            std::string repl = replacement_ssl_page(scom, app_request, generate_block_override());

            cx->to_write((unsigned char*)repl.c_str(),repl.size());
            set_replacement_msg_ssl(scom);
            cx->close_after_write(true);
        } else 
        if(app_request->uri == "/"){
            // PHASE II
            // redir to warning message
            
            _dia("ssl_override: ph2 - redir to warning replacement for  %s", whitelist_make_key(cx).c_str());
            
            std::string repl = R"(<html><head><meta http-equiv="Refresh" content="0; url=/SM/IT/HP/RO/XY/warning?q=1"></head><body></body></html>)";
            repl = html()->render_server_response(repl);
            cx->to_write(repl);
            cx->close_after_write(true);
            set_replacement_msg_ssl(scom);
        }   
        else {
            // PHASE I
            // redirecting to / -- for example some subpages would be displayed incorrectly
            
            _dia("ssl_override: ph1 - redir to / for %s", whitelist_make_key(cx).c_str());
            
            std::string redir_pre(R"(<html><head><script>top.location.href=")");
            std::string redir_suf(R"(";</script></head><body></body></html>)");

            std::string repl = redir_pre + "/SM/IT/HP/RO/XY/warning?q=1&orig_url=" +app_request->uri + redir_suf;
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
    std::string data = b.str();
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
                        _dia("Replacing bytes[stage %d]: n-th counter hit", stage);
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
        _not("MitmProxy::content_replace_apply: failed to replace string: %s", e.what());
        }
        
        ++stage;
    }
    
    
    
    
    
    buffer ret_b;
    ret_b.append(result.c_str(),result.size());
    
    _dia("content rewritten: original %d bytes with new %d bytes.",b.size(), ret_b.size());
    _dum("Replacing bytes (%d):\n%s\n# with bytes(%d):\n%s", data.size(), hex_dump(b).c_str(),
                                                            ret_b.size(),hex_dump(ret_b).c_str());
    return ret_b;
}


void MitmProxy::tap_left() {
    _dia("MitmProxy::tap left: start");

    auto lefties = { left_sockets, left_delayed_accepts, left_pc_cx, left_bind_sockets };

    for ( auto const& vec: lefties ) {
        for (auto* cx: vec) {
            com()->unset_monitor(cx->socket());
            cx->waiting_for_peercom(true);
            cx->io_disabled(true);
        }
    }
}

void MitmProxy::tap_right() {
    _dia("MitmProxy::tap right: start");

    auto righties = { right_sockets, right_delayed_accepts, right_pc_cx, right_bind_sockets };

    for ( auto const& vec: righties ) {
        for (auto cx: vec) {
            com()->unset_monitor(cx->socket());
            cx->waiting_for_peercom(true);
            cx->io_disabled(true);
        }
    }
}

void MitmProxy::tap() {
    tap_left();
    tap_right();
}

void MitmProxy::untap_left() {
    _dia("MitmProxy::untap left: start");

    auto lefties = { left_sockets, left_delayed_accepts, left_pc_cx, left_bind_sockets };

    for ( auto const& vec: lefties ) {
        for (auto *cx: vec) {

            com()->set_poll_handler(cx->socket(), this);
            com()->set_write_monitor(cx->socket());

            cx->waiting_for_peercom(false);
            cx->io_disabled(false);
        }
    }
}

void MitmProxy::untap_right() {

    _dia("MitmProxy::untap: start");

    auto righties = { right_sockets, right_delayed_accepts, right_pc_cx, right_bind_sockets };

    for ( auto const& vec: righties ) {
        for (auto cx: vec) {

            com()->set_poll_handler(cx->socket(), this);
            com()->set_write_monitor(cx->socket());

            cx->waiting_for_peercom(false);
            cx->io_disabled(false);
        }
    }
}


void MitmProxy::untap() {
    untap_left();
    untap_right();
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

bool MitmMasterProxy::detect_ssl_on_plain_socket(int sock) {
    
    int ret = false;
    constexpr unsigned int NEW_CX_PEEK_BUFFER_SZ = 10;
    constexpr int time_increment = 2500; // 2.5ms
    constexpr int time_max = time_increment*5;

    int time_taken = 0;
    
    if (sock > 0) {

        again:
        char peek_buffer[NEW_CX_PEEK_BUFFER_SZ];

        auto b = ::recv(sock, peek_buffer, NEW_CX_PEEK_BUFFER_SZ, MSG_PEEK | MSG_DONTWAIT);
        
        if(b > 6) {
            if (peek_buffer[0] == 0x16 && peek_buffer[1] == 0x03 && ( peek_buffer[5] == 0x00 || peek_buffer[5] == 0x01 || peek_buffer[5] == 0x02 )) {
                _inf("detect_ssl_on_plain_socket: SSL detected on socket %d", sock);
                ret = true;
            }
        } else {
            if(ssl_autodetect_harder && time_taken < time_max) {
                struct timespec t{};
                t.tv_sec = 0;
                t.tv_nsec = time_increment;
                
                ::nanosleep(&t,nullptr);
                time_taken += time_increment;
                _dia("detect_ssl_on_plain_socket: SSL strict detection on socket %d: delayed by %dnsec", sock, time_increment);

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
        _inf("Connection %s: SSL detected on unusual port.", r->c_type());
        r->is_ssl = true;
        r->is_ssl_port = is_ssl_port;
    }
    if(is_ssl_port) {
        r->is_ssl = true;
    }
    
    _deb("Pausing new connection %s", r->c_type());
    r->waiting_for_peercom(true);
    return r; 
}

void MitmMasterProxy::on_left_new(baseHostCX* just_accepted_cx) {
    // ok, we just accepted socket, created context for it (using new_cx) and we probably need ... 
    // to create child proxy and attach this cx to it.

    if(! just_accepted_cx->com()->nonlocal_dst_resolved()) {
        _err("on_left_new: cannot resolve socket destination");
        just_accepted_cx->shutdown();
        delete just_accepted_cx;
        return;
    }

    std::string source_host;
    std::string source_port;

    if(not just_accepted_cx->com()->resolve_socket_src(just_accepted_cx->socket(), &source_host, &source_port)) {
        _err("on_left_new: cannot resolve socket source");

        just_accepted_cx->shutdown();
        delete just_accepted_cx;
        return;
    }


    std::string target_host = just_accepted_cx->com()->nonlocal_dst_host();
    unsigned short target_port = just_accepted_cx->com()->nonlocal_dst_port();


    bool redirected_magic = false;
    if(target_host == CfgFactory::get()->tenant_magic_ip) {
        redirected_magic = true;
        auto redir = sx::proxymaker::to_magic(target_host, target_port);
        target_host = redir.first;
        target_port = redir.second;

        _dia("Connection from %s redirected from magic IP to %s:%d",
             just_accepted_cx->name().c_str(),
             target_host.c_str(), target_port);
    };


    auto *target_cx = new MitmHostCX(just_accepted_cx->com()->slave(),
                             target_host.c_str(),
                             string_format("%d",target_port).c_str());

    auto* new_proxy = sx::proxymaker::make(just_accepted_cx, target_cx);

    if(not sx::proxymaker::policy(new_proxy, redirected_magic)) {
        delete new_proxy;
        return;
    }

    if(not sx::proxymaker::authorize(new_proxy)) {
        if(not sx::proxymaker::is_replaceable(target_port)) {
            delete new_proxy;
            return;
        }
    }

    if(not sx::proxymaker::setup_snat(new_proxy, source_host, source_port)) {
        delete new_proxy;
        return;
    }

    if(not sx::proxymaker::connect(this, new_proxy)) {
        delete new_proxy;
        return;
    }

    _deb("MitmMasterProxy::on_left_new: finished");
}

int MitmMasterProxy::handle_sockets_once(baseCom* c) {
    //T__dia("slist",5,this->hr()+"\n===============\n");
    return ThreadedAcceptorProxy<MitmProxy>::handle_sockets_once(c);
}


void MitmUdpProxy::on_left_new(baseHostCX* just_accepted_cx)
{
    std::string target_host = just_accepted_cx->com()->nonlocal_dst_host();
    unsigned short target_port = just_accepted_cx->com()->nonlocal_dst_port();

    auto *target_cx = new MitmHostCX(just_accepted_cx->com()->slave(),
                                     target_host.c_str(),
                                     string_format("%d",target_port).c_str());

    auto* new_proxy = sx::proxymaker::make(just_accepted_cx, target_cx);


    if(not sx::proxymaker::policy(new_proxy, false)) {
        delete new_proxy;
        return;
    }

    if(not sx::proxymaker::authorize(new_proxy)) {
        if(not sx::proxymaker::is_replaceable(target_port)) {
            delete new_proxy;
            return;
        }
    }

    std::string source_host;
    std::string source_port;

    if(not just_accepted_cx->com()->resolve_socket_src(just_accepted_cx->socket(), &source_host, &source_port)) {
        _err("on_left_new: cannot resolve socket source");

        just_accepted_cx->shutdown();
        delete just_accepted_cx;
        return;
    }

    if(not sx::proxymaker::setup_snat(new_proxy, source_host, source_port)) {
        delete new_proxy;
        return;
    }

    if(not sx::proxymaker::connect(this, new_proxy)) {
        delete new_proxy;
        return;
    }

    _deb("MitmUDPProxy::on_left_new: finished");
}

baseHostCX* MitmUdpProxy::MitmUdpProxy::new_cx(int s) {
    return new MitmHostCX(com()->slave(),s);
}

