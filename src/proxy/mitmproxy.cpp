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
#include <proxy/filters/filterproxy.hpp>
#include <proxy/filters/sinkhole.hpp>

#include <proxy/proxymaker.hpp>
#include <proxy/nbrhood.hpp>

#include <log/logger.hpp>
#include <service/cfgapi/cfgapi.hpp>
#include <service/http/webhooks.hpp>

#include <uxcom.hpp>
#include <staticcontent.hpp>
#include <policy/authfactory.hpp>

#include <traflog/fsoutput.hpp>
#include <service/tpool.hpp>

#include <algorithm>

#include <socle/common/base64.hpp>

using namespace socle;

MitmProxy::MitmProxy(baseCom* c): baseProxy(c), sobject() {

    current_sessions()++;
    total_sessions()++;
}

void MitmProxy::toggle_tlog () {

    if(not writer_opts()->write_payload) return;

    auto const& cfg = CfgFactory::get();

    // let pass further local.disabled and remote.enabled => writes only GRE packets using PCAP features
    if(not cfg->capture_local.enabled and not cfg->capture_remote.enabled) return;





    // create traffic logger if it doesn't exist
    if(not tlog_) {

        auto fmt = cfg->capture_local.format;

        switch (fmt.value) {
            case ContentCaptureFormat::type_t::SMCAP: {

                auto suf = fmt.to_ext(CfgFactory::get()->capture_local.file_suffix);

                tlog_ = std::make_unique<socle::traflog::SmcapLog>(this,
                                                                   CfgFactory::get()->capture_local.dir.c_str(),
                                                                   CfgFactory::get()->capture_local.file_prefix.c_str(),
                                                                   suf.c_str());

                }
                break;

            case ContentCaptureFormat::type_t::PCAP: {
                auto suf = fmt.to_ext(CfgFactory::get()->capture_local.file_suffix);

                auto pcaplog = std::make_unique<socle::traflog::PcapLog>(this,
                                                             CfgFactory::get()->capture_local.dir.c_str(),
                                                             CfgFactory::get()->capture_local.file_prefix.c_str(),
                                                             suf.c_str(),
                                                             true);
                pcaplog->details.ttl = 32;
                CfgFactory::gre_export_apply(pcaplog.get());
                tlog_ = std::move(pcaplog);

                }
                break;

            case ContentCaptureFormat::type_t::PCAP_SINGLE: {

                static std::once_flag once;
                std::call_once(once, [&fmt, &cfg] {
                    auto &single = socle::traflog::PcapLog::single_instance();
                    auto suf = fmt.to_ext(CfgFactory::get()->capture_local.file_suffix);

                    single.FS = socle::traflog::FsOutput(nullptr, cfg->capture_local.dir.c_str(),
                                                         cfg->capture_local.file_prefix.c_str(),
                                                         suf.c_str(), false);

                    single.FS.generate_filename_single("smithproxy", true);

                    CfgFactory::gre_export_apply(&single);
                });

                auto suf = fmt.to_ext(CfgFactory::get()->capture_local.file_suffix);
                auto n = std::make_unique<socle::traflog::PcapLog>(this, CfgFactory::get()->capture_local.dir.c_str(),
                                                                   CfgFactory::get()->capture_local.file_prefix.c_str(),
                                                                   suf.c_str(),
                                                                   false);
                n->single_only = true;
                n->details.ttl = 32;

                CfgFactory::gre_export_apply(n.get());

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
        const int result = stat(data_dir.c_str(), &st);
        const bool present = (result == 0);
        
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

        for(auto const* cx: ls()) {
            if(! cx->comlog().empty()) {
                if(tlog()) tlog()->write(side_t::LEFT, cx->comlog());
                cx->comlog().clear();
            }
        }               
        
        for(auto const* cx: rs()) {
            if(! cx->comlog().empty()) {
                if(tlog()) tlog()->write_right(cx->comlog());
                cx->comlog().clear();
            }
        }         
        
        if(tlog()) tlog()->write_left("Connection stop\n");
    }


    if(not filters_.empty() and sx::http::webhooks::is_enabled()) {
        auto event = nlohmann::json();
        bool got_something = false;

        for (auto &[name, filter]: filters_) {
            if(filter->update_states()) {
                event[name] = filter->to_json(iINF);
                got_something = true;
            }
            else {
                _dia("filter %s did not profile any useful data for webhook", name.c_str());
            }
        }

        if(got_something) {
            sx::http::webhooks::send_action("connection-info", to_connection_ID(), event);
            _dia("webhook sent");
        } else {
            _dia("nothing to sent to webhook");
        }
    }

    current_sessions()--;
}

std::string MitmProxy::to_connection_label(bool force_resolve) const {
    auto const* left = first_left();
    auto const* right = first_right();

    std::stringstream ss;
    left ? ss << left->name(iINF, force_resolve) : ss << "0:0";
    ss << "+";
    right ? ss << right->name(iINF, force_resolve) : ss << "0:0";

    return ss.str();
}


std::string MitmProxy::to_connection_ID() const {
    return string_format("Proxy-%lX-OID-%lX", StaticContent::boot_random, oid());
}

void MitmProxy::webhook_session_start() const {
    if(not sx::http::webhooks::is_enabled() or wh_start) return;

    nlohmann::json j;
    auto cl = to_connection_label();
    j["info"] = { {"session", cl } };
    sx::http::webhooks::send_action("connection-start", to_connection_ID(), j);

    wh_start = true;
}

std::optional<std::string> MitmProxy::get_application() const {

    auto const* mh = first_left();
    if(not mh) return std::nullopt;

    std::string connection_protocol;
    auto app = mh->engine_ctx.application_data;

    if(app) {
        return app->protocol();
    }

    return std::nullopt;
}

void MitmProxy::webhook_session_stop() const {
    if(not sx::http::webhooks::is_enabled() or wh_stop) return;

    nlohmann::json j;
    auto cl = to_connection_label();

    uint64_t uB = 0L;
    uint64_t dB = 0L;
    std::optional<nlohmann::json> l7;
    std::optional<nlohmann::json> tls;

    auto const* l = first_left();
    if(l) {
        uB = l->meter_read_bytes;
        dB = l->meter_write_bytes;

        if(auto app = l->engine_ctx.application_data; app) {
            l7 =  { { "app", app->protocol() },
                    { "details", app->requests_all() },
                    { "signatures", l->matched_signatures() }
            };
        }
    }
    auto const* r = first_right();
    if(r){

        if(auto* scom = dynamic_cast<SSLCom*>(r->com()); scom) {
            nlohmann::json x;
            x["sni"] = scom->get_sni();
            tls = x;
        }
    }

    j["info"] = { {"session", cl },
                  {"policy", matched_policy() },
                  { "bytes_up", uB },
                  { "bytes_down", dB },
    };

    if(tls.has_value())  j["info"]["tls"] = tls.value();
    if(l7.has_value())  j["info"]["l7"] = l7.value();



    sx::http::webhooks::send_action("connection-stop", to_connection_ID(), j);

    wh_stop = true;
}


std::string MitmProxy::to_string(int verbosity) const {
    std::stringstream r;
    if(verbosity >= INF) r <<  "MitM|";

    r << baseProxy::to_string(verbosity);
    
    if(verbosity >= INF) {
        r << string_format(" policy: %d ", matched_policy());
        
        if(identity_resolved()) {
            r << string_format("identity: %s ",identity_->username().c_str());
        }
        
        if(verbosity > INF) r << "\n    ";

        std::string const sp_str = number_suffixed(stats_.mtr_up.get()*8) + "/" + number_suffixed(stats_.mtr_down.get()*8);
        auto speed_str = (sp_str == "0.0/0.0") ? "up/dw: --" : string_format("up/dw: %s", sp_str.c_str());


        r << speed_str;
        
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

std::optional<std::vector<std::string>> MitmProxy::find_id_groups(baseHostCX const* cx) {

    int af = AF_INET;
    if(cx->com()) {
        af = cx->com()->l3_proto();
    }
    const std::string str_af = SockOps::family_str(af);

    bool found = false;
    std::vector<std::string> group_vec;

    auto from_map = [&group_vec](auto const& map, auto const& host) -> bool {

        auto ip = map.find(host);
        if (ip != map.end()) {
            auto* id_ptr = &(*ip).second;

            if(id_ptr) {
                for (auto const &my_id: id_ptr->groups_vec) {
                    group_vec.emplace_back(my_id);
                }

                return true;
            }
        }
        return false;
    };

    if(af == AF_INET or af == 0) {
        auto lc_ = std::scoped_lock(AuthFactory::get_ip4_lock());
        found = from_map(AuthFactory::get_ip4_map(), cx->host());
    }
    else if(af == AF_INET6) {
        auto lc_ = std::scoped_lock(AuthFactory::get_ip6_lock());
        found = from_map(AuthFactory::get_ip6_map(), cx->host());
    }

    if(found) return group_vec;

    return std::nullopt;
}

std::shared_ptr<ProfileSubAuth> MitmProxy::find_auth_subprofile(std::vector<std::string> const& groups) {

    auto policy = CfgFactory::get()->db_policy_list.at(matched_policy());
    auto auth_policy = policy->profile_auth;
    std::shared_ptr<ProfileSubAuth> to_ret;

    if (auth_policy) {
        for (auto const &sub_prof: auth_policy->sub_policies) {

            _dia("apply_id_policies: checking identity policy for: %s", sub_prof->element_name().c_str());

            for (auto const &my_id: groups) {
                _dia("apply_id_policies: identity in policy: %s, match-test real user group '%s'",
                     sub_prof->element_name().c_str(), my_id.c_str());
                if (sub_prof->element_name() == my_id) {
                    _dia("apply_id_policies: .. matched.");
                    to_ret = sub_prof;
                    break;
                }
            }

            if (to_ret != nullptr) {
                break;
            }
        }
    }

    return to_ret;
};

bool MitmProxy::apply_id_policies(baseHostCX* cx) {

    _dia("apply_id_policies: matched policy: %d", matched_policy());

    auto opt_group_vec = find_id_groups(cx);


    if( not opt_group_vec.has_value() ) {
        _deb("apply_id_policies: %d groups not found");
        return false;
    }

    _deb("apply_id_policies: %d groups found", opt_group_vec.value().size());
    auto final_profile = find_auth_subprofile(opt_group_vec.value());

    if (not final_profile) {
        _deb("apply_id_policies: %d no subprofile found");
        return false;
    }

    const char *pc_name = "none";
    const char *pd_name = "none";
    const char *pt_name = "none";
    std::string algs;

    _dia("apply_id_policies: assigning sub-profile %s", final_profile->element_name().c_str());
    if (final_profile->profile_content != nullptr) {
        if (CfgFactory::get()->prof_content_apply(cx, this, final_profile->profile_content)) {
            pc_name = final_profile->profile_content->element_name().c_str();
            _dia("apply_id_policies: assigning content sub-profile %s",
                 final_profile->profile_content->element_name().c_str());
        }
    }
    if (final_profile->profile_detection != nullptr) {
        if (CfgFactory::get()->prof_detect_apply(cx, this, final_profile->profile_detection)) {
            pd_name = final_profile->profile_detection->element_name().c_str();
            _dia("apply_id_policies: assigning detection sub-profile %s",
                 final_profile->profile_detection->element_name().c_str());
        }
    }
    if (final_profile->profile_tls != nullptr) {
        if (CfgFactory::get()->prof_tls_apply(cx, this, final_profile->profile_tls)) {
            pt_name = final_profile->profile_tls->element_name().c_str();
            _dia("apply_id_policies: assigning tls sub-profile %s",
                 final_profile->profile_tls->element_name().c_str());
        }
    }
    if (final_profile->profile_alg_dns != nullptr) {
        if (CfgFactory::get()->prof_alg_dns_apply(cx, this, final_profile->profile_alg_dns)) {
            algs += final_profile->profile_alg_dns->element_name() + " ";
            _dia("apply_id_policies: assigning tls sub-profile %s",
                 final_profile->profile_tls->element_name().c_str());
        }
    }

    // end of custom sub-profiles
    _inf("Connection %s: identity-based sub-profile: name=%s cont=%s det=%s tls=%s algs=%s",
         cx->full_name('L').c_str(),
         final_profile->element_name().c_str(),
         pc_name, pd_name, pt_name, algs.c_str()
        );

    return true;
}

void MitmProxy::update_neighbors() {
    if(auto fl = first_left(); fl) {
        if(auto lhost = fl->chost(); not lhost.empty()) {
            auto &nbr = NbrHood::instance();

            nbr.update(first_left()->chost());
        }
    }
}

bool MitmProxy::resolve_identity(baseHostCX* cx, bool insert_guest = false) {

    if(not cx) return false;
    
    int af = AF_INET;
    if(cx->com()) {
        af = cx->com()->l3_proto();
    }
    std::string str_af = SockOps::family_str(af);

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
    std::unique_ptr<shm_logon_info_base> id_ptr;

    if(af == AF_INET || af == 0) {

        std::scoped_lock<std::recursive_mutex> l_(AuthFactory::get_ip4_lock());
        AuthFactory::get().shm_ip4_table_refresh();

        _deb("identity check[%s]: table size: %d", str_af.c_str(), AuthFactory::get_ip4_map().size());
        auto ip = AuthFactory::get_ip4_map().find(cx->host());
        if (ip != AuthFactory::get_ip4_map().end()) {
            shm_logon_info& li = ip->second.last_logon_info;
            id_ptr.reset(std::move(li.clone()));
        } else {
            if (insert_guest) {
                id_ptr = std::make_unique<shm_logon_info>(cx->host().c_str(),"guest","guest+guests+guests_ipv4");
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
            id_ptr.reset(std::move(li.clone()));
        } else {
            if (insert_guest) {
                id_ptr = std::make_unique<shm_logon_info6>(cx->host().c_str(),"guest","guest+guests+guests_ipv6");
            }
        }    
    }

    if(id_ptr) {

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
            identity(id_ptr.get());
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
    std::string str_af = SockOps::family_str(af);
    

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
    filters_.emplace_back(name, fp);
}


int MitmProxy::handle_sockets_once(baseCom* xcom) {

    webhook_session_start();

    return baseProxy::handle_sockets_once(xcom);
}


std::string whitelist_make_key_l4(baseHostCX const* cx)  {
    
    std::string key;
    
    if(cx != nullptr && cx->peer() != nullptr) {
        key = cx->host() + ":" + cx->peer()->host() + ":" + cx->peer()->port();
    } else {
        key = "?";
    }
    
    return key;
}

std::string whitelist_make_key_cert(baseHostCX const* cx) {
    if (not cx) return {};

    auto const* scom  = dynamic_cast<SSLCom*>(cx->peercom());
    if(not scom) return {};

    auto fg = SSLFactory::fingerprint(scom->target_cert());
    return fg;
}


bool MitmProxy::handle_authentication(MitmHostCX* mh)
{
    bool redirected = false;
    
    if(auth_opts.authenticate or auth_opts.resolve) {
    
        resolve_identity(mh);
        
        if(!identity_resolved()) {        
            _deb("handle_authentication: identity check: unknown");
            
            if(auth_opts.authenticate) {
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
            if(auth_opts.block_identity) {
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

bool MitmProxy::is_white_listed(MitmHostCX const* mh, SSLCom* peercom) {

    auto const* scom = peercom ? peercom : dynamic_cast<SSLCom*>(mh->peercom());
    auto find_it = [&](auto key) -> bool {

        auto lc_ = std::scoped_lock(whitelist_verify().getlock());

        auto wh_entry = whitelist_verify().get(key);
        _dia("whitelist_verify[%s]: %s", key.c_str(), wh_entry ? "found" : "not found");

        // !!! wh might be already invalid here, unlocked !!!
        if (wh_entry != nullptr) {
            if (scom->opt.cert.failed_check_override_timeout_type == 1) {
                wh_entry->expired_at() = ::time(nullptr) + scom->opt.cert.failed_check_override_timeout;
                _dia("whitelist_verify[%s]: timeout reset to %d", key.c_str(),
                     scom->opt.cert.failed_check_override_timeout);
            }
            return true;
        }

        return false;
    };

    //look for whitelisted entry
    std::string key_l4 = whitelist_make_key_l4(mh);
    if ((not key_l4.empty()) and key_l4 != "?" and find_it(key_l4)) return true;

    std::string key_cert = whitelist_make_key_cert(mh);
    if ((not key_cert.empty()) and key_cert != "?" and find_it(key_cert)) return true;

    return false;
};


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

    if(scom && scom->opt.cert.failed_check_replacement) {

        if(!(
            scom->verify_get() == SSLCom::verify_status_t::VRF_OK
             ||
            scom->verify_get() == ( SSLCom::verify_status_t::VRF_OK | SSLCom::verify_status_t::VRF_CLIENT_CERT_RQ )
            )) {

            if(tlog()) tlog()->write_left("original TLS peer verification failed");

            bool whitelist_found = is_white_listed(mh, scom);

            if(not whitelist_found) {
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
                else if(scom->verify_bitcheck(SSLCom::verify_status_t::VRF_CLIENT_CERT_RQ) && scom->opt.cert.client_cert_action > 0) {

                    _dia(" -> client-cert request:  opt_client_cert_action=%d", scom->opt.cert.client_cert_action);

                    if(scom->opt.cert.client_cert_action == 2) {
                        //we should not block
                        _dia(" -> client-cert request: auto-whitelist");

                        auto l4_key = whitelist_make_key_l4(mh);
                        log.event(INF, "%s connections whitelisted due to client cert bypass option", l4_key.c_str());

                        auto lc_ = std::scoped_lock(whitelist_verify().getlock());
                        
                        whitelist_verify_entry v;
                        whitelist_verify().set(l4_key, new whitelist_verify_entry_t(v, scom->opt.cert.failed_check_override_timeout));
                    } else {
                        _dia(" -> client-cert request: no action taken");
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


void MitmProxy::proxy_dump_packet(side_t sid, buffer& buf) {
    auto const& log = log_dump;

    constexpr size_t chunk_sz = 1024;
    size_t printed = 0;
    bool printed_all = false;
    unsigned int counter =  0;

    do {

        if(printed + chunk_sz >= buf.size()) {
            auto cur_buf = buf.view(printed, buf.size() - printed);

            _dia("mitmproxy::proxy-%c%s: \r\n%s", from_side(sid),
                 counter == 0 ? "" : string_format("/%d", counter).c_str(),
                 hex_dump(cur_buf, 4, arrow_from_side(sid), true, printed).c_str());

            printed_all = true;
            break;
        }  else {
            size_t const actual_chunk_sz = std::min(chunk_sz, buf.size() - printed);
            auto cur_buf = buf.view(printed, actual_chunk_sz);

            _dia("mitmproxy::proxy-%c%s: \r\n%s", from_side(sid),
                 string_format("/%d", counter).c_str(),
                 hex_dump(cur_buf, 4, arrow_from_side(sid), true, printed).c_str());

            printed += chunk_sz;
        }
        counter++;

    } while(printed < 20480);


    if(not printed_all) {
        _dia("mitmproxy::proxy-%c: <truncated>", from_side(sid));
    }
};

static std::string b64_encode(buffer &buffer) {
    return libbase64::encode<std::string, char, unsigned char, true>(buffer.data(), buffer.size());
}

static std::string b64_decode(std::string const& encoded) {
    return libbase64::decode<std::string, char, unsigned char, false>(encoded);
}



void MitmProxy::content_webhook(baseHostCX* cx, side_t side, buffer& buffer) {

    auto& log = log_content;

    if(not sx::http::webhooks::is_enabled()) return;
    if(not cx or buffer.empty()) return;

    if(not writer_opts()->webhook_enable) return;

    nlohmann::json j;
    auto cl = to_connection_label();
    std::string encoded = b64_encode(buffer);
    j["info"] = {
        { "session", cl },
        { "side", string_format("%c", from_side(side)) },
        { "content", encoded }
    };

    sx::http::webhooks::send_action_wait("connection-content", to_connection_ID(), j, [&](sx::http::expected_reply r){
        if(r.has_value()) {
            auto reply = r.value();
            _dia("webhook content-replace: response %d", reply.response.first);

            if(reply.response.first >= 200 and reply.response.first < 300) {
                auto json_obj = nlohmann::json::parse(reply.response.second, nullptr, false);
                if(json_obj.is_discarded()) {
                    _err("MitmProxy::content_webhook: response body is invalid");
                }
                else {
                    if(json_obj.contains("action")) {
                        if(json_obj["action"] == "discard") {
                            // data sent to webhook shall be discarded
                            buffer.size(0);
                        }
                        else {
                            // catch-all code to decode response if present
                            if(json_obj.contains("content")) {
                                std::string body = json_obj["content"];
                                auto decoded = b64_decode(body);

                                _dia("webhook content-replace: received %dB of replacement data", decoded.size());
                                {
                                    auto& log = log_content_dump;
                                    _deb("webhook content-replace: replacement: %s\r\n",
                                         hex_dump((unsigned char*)decoded.data(), decoded.size(), 4, 0, true).c_str());
                                }

                                buffer.assign(decoded.data(), decoded.size());
                            }
                            else {
                                _dia("webhook content-replace: no replacement body received");
                            }
                        }
                    }
                }
            }
        }
    });
}

void MitmProxy::proxy(baseHostCX* from, baseHostCX* to, side_t side, bool redirected) {

    if(not to or not from or from->to_read().empty()) return;

    if (!redirected) {
        if (content_rule() != nullptr) {
            buffer b = content_replace_apply(from->to_read());

            if(writer_opts()->webhook_enable) {

                if(writer_opts()->webhook_lock_traffic) {

                    if(from->com() and from->com()->l4_proto() == SOCK_STREAM) {
                        if(from->com()->so_keepalive(from->socket()) == 0) {
                            _deb("connection 'from' socket set to KEEPALIVE");
                        }
                        else {
                            _err("connection 'from' ERROR socket set to KEEPALIVE");
                        }
                    }
                    if(to->com() and to->com()->l4_proto() == SOCK_STREAM) {
                        if (to->com()->so_keepalive(to->socket()) == 0) {
                            _deb("connection 'to' socket set to KEEPALIVE");
                        }
                        else {
                            _err("connection 'to' ERROR socket set to KEEPALIVE");
                        }
                    }

                    // traffic with applied webhook with enabled locking will block here
                    auto lc_ = std::scoped_lock(writer_opts()->webhook_content_lock);
                    content_webhook(from, side, b);
                }
                else {
                    content_webhook(from, side, b);
                }
            }

            if(*log_dump.level() >= iDIA)
                proxy_dump_packet(side, b);

            write_traffic_log(side, from, &b);
            to->to_write(b);
            _dia("mitmproxy::proxy-%c: original %d bytes replaced with %d bytes", from_side(side), from->to_read().size(),
                 b.size());
        } else {

            if(*log_dump.level() >= iDIA)
                proxy_dump_packet(side, from->to_read());


            if(not filters_.empty()) for(auto const& [ filter_name, filter_proxy ]: filters_) {

                    _deb("MitmProxy::proxy: running filter %s", filter_name.c_str());
                    filter_proxy->proxy(from, to, side, redirected);

                    if(state().dead()) {
                        _deb("MitmProxy::proxy: filter %s: proxy marked dead", filter_name.c_str());

                        // after marking dead, session is not getting on_error anymore
                        webhook_session_stop();
                        shutdown();
                        return;
                    }
            }

            auto sz = from->to_read().size();

            write_traffic_log(side, from);
            to->to_write(from->to_read());
            auto fastlane = sz > 0 and from->to_read().empty();

            _dia("mitmproxy::proxy-%c: %d copied %s", from_side(side), sz, fastlane ? "(fastlane)": "");
        }
    } else {

        // rest of connections should be closed when sending replacement to a client
        to->shutdown();
    }
};


void MitmProxy::write_traffic_log(side_t side, baseHostCX* cx, buffer* custom_buffer) {

    if(writer_opts()->write_payload) {
        if(not cx) return;

        auto* buffer = custom_buffer;
        if(not buffer) {
            buffer = &cx->to_read();
        }

        toggle_tlog();

        if(! cx->comlog().empty()) {
            if(tlog()) tlog()->write(side, cx->comlog());
            cx->comlog().clear();
        }

        if(tlog()) tlog()->write(side, *buffer);
    }
}

void MitmProxy::on_left_bytes(baseHostCX* cx) {

    if(not cx or state().dead()) return;

    bool redirected = handle_requirements(cx);

    //update meters
    total_mtr_up().update(cx->to_read().size());
    if(acct_opts.details) {
        NbrHood::instance().apply(cx->host(), [](Neighbor& nbr) {
            return true;
        });
    }

    // because we have left bytes, let's copy them into all right side sockets!
    std::for_each(
            right_sockets.begin(),
            right_sockets.end(),
            [&](auto* to) {
                if(not state().dead()) {
                    proxy(cx, to, side_t::LEFT, redirected);
                }
            });

    // because we have left bytes, let's copy them into all right side sockets!
    std::for_each(
            right_delayed_accepts.begin(),
            right_delayed_accepts.end(),
            [&](auto* to) {
                if(not state().dead()) {
                    proxy(cx, to, side_t::LEFT, redirected);
                }
            });

}


bool MitmProxy::handle_requirements(baseHostCX* cx) {

    bool redirected = false;

    auto* mh = MitmHostCX::from_baseHostCX(cx);

    if(mh != nullptr) {

        if((cx->meter_read_bytes < 1024 and cx->meter_write_bytes < 1024)
           or
           ((cx->meter_read_count + cx->meter_write_count) % 100 == 0)) {
            // check authentication
            redirected = handle_authentication(mh);
        }

        // check com responses
        redirected = handle_com_response_ssl(mh);

    }

    return redirected;
}

void MitmProxy::on_right_bytes(baseHostCX* cx) {

    if(not cx or state().dead()) return;

    bool redirected = handle_requirements(cx->peer());

    // update total meters
    total_mtr_down().update(cx->to_read().size());

    if(acct_opts.details) {
        if(auto fr = first_left(); fr) {
            NbrHood::instance().apply(fr->host(), [](Neighbor &nbr) {
                return true;
            });
        }
    }

    std::for_each(
            left_sockets.begin(),
            left_sockets.end(),
            [&](auto* to) {
                if(not state().dead()) {
                    proxy(cx, to, side_t::RIGHT, redirected);
                }
            });

    // because we have left bytes, let's copy them into all right side sockets!
    std::for_each(
            left_delayed_accepts.begin(),
            left_delayed_accepts.end(),
            [&](auto* to) {
                if(not state().dead()) {
                    proxy(cx, to, side_t::RIGHT, redirected);
                }
            });

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

    auto* mh = MitmHostCX::from_baseHostCX(cx);

    if(side == 'R' && cx->peer())
        mh = MitmHostCX::from_baseHostCX(cx->peer());

    if (mh != nullptr && mh->inspection_verdict() == Inspector::CACHED) flags+="C";

    std::stringstream detail;

    if(cx->peercom()) {
        auto* sc = dynamic_cast<SSLMitmCom*>(cx->peercom());
        if(sc) {
            detail << string_format("sni=%s ", sc->get_sni().c_str());
        }
    }
    if(mh && mh->engine_ctx.application_data) {

        auto* app = dynamic_cast<sx::engine::http::app_HttpRequest*>(mh->engine_ctx.application_data.get());
        if(app) {
            detail << "app=" << app->http_data.proto << app->http_data.host << " ";
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

    auto _log_closed_on = [&](loglevel const& level, const char* state_str) {

        // don't log already dead connections
        if(state().dead()) return;

        _if_level(level) {
            std::stringstream msg;
            msg << "Connection " << side_label << " " << state_str << "on ";

            if(state().error_on_left_read) msg << "Lr";
            if(state().error_on_left_write) msg << "Lw";
            if(state().error_on_right_read) msg << "Rr";
            if(state().error_on_right_write) msg << "Rw";

            if(cx) {
                msg << ": "
                    << get_connection_details_str(this, cx, side);
            }
            auto str = msg.str();
            log.log(level, log.topic(), "%s", str.c_str());
        }
    };
    auto _log_closed = [&](loglevel const& level) {
        _if_level(level) {

            // don't log already dead connections
            if(state().dead()) return;

            if(not cx) {
                _log_closed_on(ERR, "null cx");
                return;
            }

            std::stringstream msg;
            msg << "Connection from " << cx->full_name(side) << " closed: " << get_connection_details_str(this, cx, side);
            if(! replacement_msg.empty() ) {
                msg << ", replaced: " << replacement_msg;
            }
            auto str = msg.str();
            log.log(level, log.topic(), "%s", str.c_str());
        }
        _if_level(DEB) { _debug_zero_connections(cx); }
    };

    if(cx == nullptr) {
        _log_closed_on(ERR, "null cx");

        state().dead(true);
        return;
    }

    // if not dead (yet), do some cleanup/logging chores
    if( !state().dead()) {

        // don't waste time on low-effort delivery stuff, just get rid of it now.
        if(com()->l4_proto() == SOCK_DGRAM) {
            state().dead(true);
        }
        else {
            // STREAM sockets need a bit of caring if still having a peer
            if(cx->peer()) {
                if(! cx->peer()->writebuf()->empty()) {

                    // do half-closed actions, and mark proxy dead if needed
                    on_half_close(cx);

                    if (state().dead()) {
                        // status dead is new, since we check dead status at the beginning
                        _log_closed_on(INF, "half-closed");

                    } else {
                        // on_half_close did not mark it dead, yet
                        _log_closed_on(DIA, "half-closing");

                        // provoke write to the peer's socket (could be superfluous)
                        com()->set_write_monitor(cx->peer()->socket());
                    }
                } else {

                    // duplicate code to DEAD before calling us

                    _if_level(INF) {
                        std::stringstream msg;
                        msg << "Connection from " << cx->full_name(side)
                            << " closed: "
                            << get_connection_details_str(this, cx, side);

                        if (!replacement_msg.empty()) {
                            msg << ", dropped: "
                                << replacement_msg;

                            _inf("%s", msg.str().c_str()); // log to generic logger
                        }
                        _inf("%s", msg.str().c_str());
                    }
                    state().dead(true);
                }
            } else {
                _log_closed_on(DIA, "half-closing, peer dead");
                state().dead(true);
            }
        }
    } else {
        // DEAD before calling us!
        // maybe even dead or unnecessary code

        if(auth_opts.resolve)
            resolve_identity(cx);

        if(cx->peer() && cx->peer()->writebuf()->empty()) {
            _log_closed(INF);

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

        webhook_session_stop();
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

bool MitmProxy::run_timers() {
    auto ret = baseProxy::run_timers();

    // run timers actually crawled children
    if(ret and state().dead()) {
        if (writer_opts()->write_payload) {
            toggle_tlog();
            if (tlog()) {

                std::stringstream ss;
                ss << "connection timed out\n";
                auto msg = ss.str();

                tlog()->write(to_side('L'), msg);
            }
        }

        webhook_session_stop();
    }

    return ret;
}


void MitmProxy::handle_replacement_auth(MitmHostCX* cx) {
  
    std::string redir_pre("<html><head><script>top.location.href=\"");
    std::string redir_suf("\";</script></head><body></body></html>");  
  
//     std::string redir_pre("HTTP/1.0 301 Moved Permanently\r\nLocation: ");
//     std::string redir_suf("\r\n\r\n");  
  
    
    std::string repl;
    std::string repl_port = AuthFactory::get().options.portal_port_http;
    std::string repl_proto = "http";

    if(cx->engine_ctx.application_data->is_ssl) {
        repl_proto = "https";
        repl_port =AuthFactory::get().options.portal_port_https;
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
            
            if(now - token_ts < AuthFactory::get().options.token_timeout) {
                _inf("MitmProxy::handle_replacement_auth: cached token %s for request: %s",
                                token_tk.c_str(), cx->engine_ctx.application_data->str().c_str());
                
                if(cx->com()) {
                    if(cx->com()->l3_proto() == AF_INET) {
                        repl = redir_pre + repl_proto
                                + "://"+AuthFactory::get().options.portal_address+":"+repl_port+"/cgi-bin/auth.py?token="
                                + token_tk + redir_suf;

                    } else if(cx->com()->l3_proto() == AF_INET6) {
                        repl = redir_pre + repl_proto
                                + "://"+AuthFactory::get().options.portal_address6+":"+repl_port+"/cgi-bin/auth.py?token="
                                + token_tk + redir_suf;
                    } 
                } 
                
                if(repl.empty()) {
                    // default to IPv4 address
                    repl = redir_pre + repl_proto
                            + "://"+AuthFactory::get().options.portal_address+":"+repl_port+"/cgi-bin/auth.py?token="
                            + token_tk + redir_suf;
                }
                
                repl = html()->render_server_response(repl);
                
                cx->to_write(repl);
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
                            + "://"+AuthFactory::get().options.portal_address+":"+repl_port+"/cgi-bin/auth.py?token="
                            + tok.token() + redir_suf;

                } else if(cx->com()->l3_proto() == AF_INET6) {
                    repl = redir_pre + repl_proto
                            + "://"+AuthFactory::get().options.portal_address6+":"+repl_port+"/cgi-bin/auth.py?token="
                            + tok.token() + redir_suf;
                } 
            } 
            
            if(repl.empty()) {
                // default to IPv4 address
                _dia("reply fallback to IPv4");
                repl = redir_pre + repl_proto
                        + "://"+AuthFactory::get().options.portal_address+":"+repl_port+"/cgi-bin/auth.py?token="
                        + tok.token() + redir_suf;
            }
            
            repl = html()->render_server_response(repl);
            
            cx->to_write(repl);
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
        repl = block_pre + repl_proto + "://"+AuthFactory::get().options.portal_address+":"+repl_port + "/cgi-bin/auth.py?a=z" + block_post;
        
        std::string cap  = "Page Blocked";
        std::string meta;
        repl = html()->render_msg_html_page(cap,meta, repl,"700px");
        repl = html()->render_server_response(repl);
        
        cx->to_write(repl);
        cx->close_after_write(true);

        replacement_msg += "(auth: blocked)";

    } else
    if (cx->replacement_flag() == MitmHostCX::REPLACE_NONE) {
        _dia("MitmProxy::handle_replacement_auth: asked to handle NONE. No-op.");
    } 
}

std::string MitmProxy::verify_flag_string(int code) {

    using verify_status_t = SSLCom::verify_status_t;

    switch(code) {
        case verify_status_t::VRF_OK:
            return "Certificate verification successful";
        case verify_status_t::VRF_SELF_SIGNED:
            return "Target certificate is self-signed";
        case verify_status_t::VRF_SELF_SIGNED_CHAIN:
            return "Server certificate's chain contains self-signed, untrusted CA certificate";
        case verify_status_t::VRF_UNKNOWN_ISSUER:
            return "Server certificate is issued by untrusted certificate authority";
        case verify_status_t::VRF_CLIENT_CERT_RQ:
            return "Server is asking client for a certificate";
        case verify_status_t::VRF_REVOKED:
            return "Server's certificate is REVOKED";
        case verify_status_t::VRF_HOSTNAME_FAILED:
            return "Client application asked for SNI server is not offering";
        case verify_status_t::VRF_INVALID:
            return "Certificate is not valid";
        case verify_status_t::VRF_ALLFAILED:
            return "It was not possible to obtain certificate status";
        case verify_status_t::VRF_CT_MISSING:
            return "Certificate Transparency info is missing";
        default:
            return string_format("code 0x04%x", code);
    }
}

std::string MitmProxy::verify_flag_string_extended(int code) {

    using verify_status_t = SSLCom::vrf_other_values_t;

    switch(code) {
        case verify_status_t::VRF_OTHER_SHA1_SIGNATURE:
            return "Issuer certificate is signed using SHA1 (considered insecure).";
        case verify_status_t::VRF_OTHER_CT_INVALID:
            return "Certificate Transparency tag is INVALID.";
        case verify_status_t::VRF_OTHER_CT_FAILED:
            return "Unable to verify Certificate Transparency tag.";
        default:
            return string_format("extended code 0x04%x", code);
    }
}

void MitmProxy::set_replacement_msg_ssl(SSLCom* scom) {

    using verify_status_t = SSLCom::verify_status_t;

    if(scom && scom->verify_get() != verify_status_t::VRF_OK) {

        std::stringstream  ss;

        if(scom->verify_bitcheck(verify_status_t::VRF_SELF_SIGNED)) {
            ss << "(ssl:" << verify_flag_string(verify_status_t::VRF_SELF_SIGNED) << ")";
        }
        if(scom->verify_bitcheck(verify_status_t::VRF_SELF_SIGNED_CHAIN)) {
            ss << "(ssl:" << verify_flag_string(verify_status_t::VRF_SELF_SIGNED_CHAIN) << ")";
        }
        if(scom->verify_bitcheck(verify_status_t::VRF_UNKNOWN_ISSUER)) {
            ss << "(ssl:" << verify_flag_string(verify_status_t::VRF_UNKNOWN_ISSUER) << ")";
        }
        if(scom->verify_bitcheck(verify_status_t::VRF_CLIENT_CERT_RQ)) {
            ss << "(ssl:" << verify_flag_string(verify_status_t::VRF_CLIENT_CERT_RQ) << ")";
        }
        if(scom->verify_bitcheck(verify_status_t::VRF_REVOKED)) {
            ss << "(ssl:" << verify_flag_string(verify_status_t::VRF_REVOKED) << ")";
        }
        if(scom->verify_bitcheck(verify_status_t::VRF_HOSTNAME_FAILED)) {
            ss << "(ssl:" << verify_flag_string(verify_status_t::VRF_HOSTNAME_FAILED) << ")";
        }
        if(scom->verify_bitcheck(verify_status_t::VRF_EXTENDED_INFO)) {

            for(auto const& ei: scom->verify_extended_info()) {
                ss << "(ssl: " << verify_flag_string(ei) << ")";
            }
        }
        replacement_msg += ss.str();
    }
}

std::string MitmProxy::replacement_ssl_verify_detail(SSLCom* scom) {

    using verify_status_t = SSLCom::verify_status_t;

    std::stringstream ss;
    if(scom) {
        if (scom->verify_get() != verify_status_t::VRF_OK) {
            bool is_set = false;
            int reason_count = 1;

            if (scom->verify_bitcheck(verify_status_t::VRF_SELF_SIGNED)) {
                ss << "<p><h3 class=\"fg-red\">Reason " << reason_count << ":</h3> " << verify_flag_string(verify_status_t::VRF_SELF_SIGNED) << ".</p>";
                is_set = true;
                ++reason_count;
            }
            if (scom->verify_bitcheck(verify_status_t::VRF_SELF_SIGNED_CHAIN)) {
                ss << "<p><h3 class=\"fg-red\">Reason " << reason_count << ":</h3> " << verify_flag_string(verify_status_t::VRF_SELF_SIGNED_CHAIN)
                   << ".</p>";
                is_set = true;
                ++reason_count;
            }
            if (scom->verify_bitcheck(verify_status_t::VRF_UNKNOWN_ISSUER)) {
                ss << "<p><h3 class=\"fg-red\">Reason " << reason_count << ":</h3>" << verify_flag_string(verify_status_t::VRF_UNKNOWN_ISSUER) << ".</p>";
                is_set = true;
                ++reason_count;
            }
            if (scom->verify_bitcheck(verify_status_t::VRF_CLIENT_CERT_RQ)) {
                ss << "<p><h3 class=\"fg-red\">Reason " << reason_count << ":</h3>" << verify_flag_string(verify_status_t::VRF_CLIENT_CERT_RQ) << ".<p>";
                is_set = true;
                ++reason_count;
            }
            if (scom->verify_bitcheck(verify_status_t::VRF_REVOKED)) {
                ss << "<p><h3 class=\"fg-red\">Reason " << reason_count << ":</h3>" << verify_flag_string(verify_status_t::VRF_REVOKED) <<
                       ". "
                       "This is a serious issue, it's highly recommended to not continue "
                       "to this page.</p>";
                is_set = true;
                ++reason_count;
            }
            if (scom->verify_bitcheck(verify_status_t::VRF_CT_MISSING)) {
                ss << "<p><h3 class=\"fg-red\">Reason " << reason_count << ":</h3>" << verify_flag_string(verify_status_t::VRF_CT_MISSING) <<
                   ". "
                   "This is a serious issue if your target is a public internet service. In such a case it's highly recommended to not continue."
                   "</p>";
                is_set = true;
                ++reason_count;
            }
            if (scom->verify_bitcheck(verify_status_t::VRF_CT_FAILED)) {
                ss << "<p><h3 class=\"fg-red\">Reason " << reason_count << ":</h3>" << verify_flag_string(verify_status_t::VRF_CT_MISSING) <<
                   ". "
                   "This is a serious issue if your target is a public internet service. Don't continue unless you really know what you are doing. "
                   "</p>";
                is_set = true;
                ++reason_count;
            }

            if (scom->verify_bitcheck(verify_status_t::VRF_INVALID)) {
                ss << "<p><h3 class=\"fg-red\">Reason " << reason_count << ":</h3>" << verify_flag_string(verify_status_t::VRF_INVALID) << ".</p>";
                is_set = true;
                ++reason_count;
            }
            if (scom->verify_bitcheck(verify_status_t::VRF_HOSTNAME_FAILED)) {
                ss << "<p><h3 class=\"fg-red\">Reason " << reason_count << ":</h3>" << verify_flag_string(verify_status_t::VRF_HOSTNAME_FAILED) << ".</p>";
                is_set = true;
                ++reason_count;
            }
            if (scom->verify_bitcheck(verify_status_t::VRF_ALLFAILED)) {
                ss << "<p><h3 class=\"fg-red\">Reason " << reason_count << ":</h3>" << verify_flag_string(verify_status_t::VRF_ALLFAILED) << ".</p>";
                is_set = true;
                ++reason_count;
            }
            if(scom->verify_bitcheck(verify_status_t::VRF_EXTENDED_INFO)) {
                for (auto const &ei: scom->verify_extended_info()) {
                    ss << "<p><h3 class=\"fg-red\">Reason " << reason_count << ":</h3>" << verify_flag_string_extended(ei) << ".</p>";
                    is_set = true;
                    ++reason_count;
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


std::string MitmProxy::replacement_ssl_page(SSLCom* scom, sx::engine::http::app_HttpRequest const* app_request, std::string const& more_info) {
    std::string repl;

    const std::string block_target_info = "<p><h3 class=\"fg-red\">Requested site:</h3>" +
                                                app_request->http_data.proto + app_request->http_data.host + "</p>";

    const std::string block_additinal_info = replacement_ssl_verify_detail(scom) + more_info;

    const std::string cap = "TLS security warning";
    const std::string meta;
    const std::string war_img = html()->render_noargs("html_img_warning");
    const std::string msg = string_format("<h2 class=\"fg-red\">%s TLS security warning</h2>%s",war_img.c_str(),(block_target_info + block_additinal_info).c_str());

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
        
        cx->to_write(error);
        cx->close_after_write(true);
        set_replacement_msg_ssl(scom);

        _err("cannot handle replacement for TLS, com is not SSLCom");
        
        return;
    }


    auto* app_request = dynamic_cast<sx::engine::http::app_HttpRequest*>(cx->engine_ctx.application_data.get());
    if(app_request != nullptr) {
        log.event(INF, "[%s]: HTTP replacement active", socle::com::ssl::connection_name(scom, true).c_str());

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
            std::stringstream block_override;

            if (scom->opt.cert.failed_check_override) {
                block_override << R"(<form action="/SM/IT/HP/RO/XY)";

                const std::string key = whitelist_make_key_l4(cx);
                if (cx->peer()) {
                    block_override << "/override/target=" + key;
                    if (not app_request->http_data.uri.empty()) {
                        block_override << "&orig_url=" << find_orig_uri().value_or("/");
                    }
                }
                block_override << R"("><input type="submit" value="Override" class="btn-red"></form>)";
            }

            return block_override.str();
        };

        if(app_request->request().find("/SM/IT/HP/RO/XY/override") != std::string::npos) {
            
            // PHASE IV.
            // perform override action
                
                        
            if(scom->opt.cert.failed_check_override) {
            
                _dia("ssl_override: ph4 - asked for verify override for %s", whitelist_make_key_l4(cx).c_str());
                
                const std::string orig_url = find_orig_uri().value_or("/");

                std::string override_applied = string_format(
                        R"(<html><head><meta http-equiv="Refresh" content="0; url=%s"></head><body><!-- applied, redirecting back to %s --></body></html>)",
                                                            orig_url.c_str(),orig_url.c_str());

                {
                    auto lc_ = std::scoped_lock(whitelist_verify().getlock());
                    whitelist_verify().set(whitelist_make_key_l4(cx),
                                           new whitelist_verify_entry_t({}, scom->opt.cert.failed_check_override_timeout));
                }
                
                override_applied = html()->render_server_response(override_applied);
                
                cx->to_write(override_applied);
                cx->close_after_write(true);
                set_replacement_msg_ssl(scom);
                replacement_msg += "(ssl: override)";
                
                _war("Connection from %s: SSL override activated for %s", cx->full_name('L').c_str(), app_request->request().c_str());
                
                return;
                
            } else {
                // override is not enabled, but client somehow reached this (attack?)
                std::string error("<html><head></head><body><p>Failed to override</p><p>Action is denied.</p></body></html>");
                error = html()->render_server_response(error);

                cx->to_write(error);
                cx->close_after_write(true);
                set_replacement_msg_ssl(scom);
                replacement_msg += "(ssl: override disabled)";
                
                return;
            }
            
        } else 
        if(app_request->request().find("/SM/IT/HP/RO/XY/warning") != std::string::npos){
            
            // PHASE III.
            // display warning and button which will trigger override
        
            _dia("ssl_override: ph3 - warning replacement for %s", whitelist_make_key_l4(cx).c_str());
            
            const std::string repl = replacement_ssl_page(scom, app_request, generate_block_override());

            cx->to_write(repl);
            set_replacement_msg_ssl(scom);
            cx->close_after_write(true);
        } else 
        if(app_request->http_data.uri == "/"){
            // PHASE II
            // redir to warning message
            
            _dia("ssl_override: ph2 - redir to warning replacement for  %s", whitelist_make_key_l4(cx).c_str());
            
            std::string repl = R"(<html><head><meta http-equiv="Refresh" content="0; url=/SM/IT/HP/RO/XY/warning?q=1"></head><body></body></html>)";
            repl = html()->render_server_response(repl);
            cx->to_write(repl);
            cx->close_after_write(true);
            set_replacement_msg_ssl(scom);
        }   
        else {
            // PHASE I
            // redirecting to / -- for example some subpages would be displayed incorrectly
            
            _dia("ssl_override: ph1 - redir to / for %s", whitelist_make_key_l4(cx).c_str());
            
            const std::string redir_pre(R"(<html><head><script>top.location.href=")");
            const std::string redir_suf(R"(";</script></head><body></body></html>)");

            std::string repl = redir_pre + "/SM/IT/HP/RO/XY/warning?q=1&orig_url=" +app_request->http_data.uri + redir_suf;
            repl = html()->render_server_response(repl);
            
            cx->to_write(repl);
            cx->close_after_write(true);
            set_replacement_msg_ssl(scom);
        }
    }

    else {
        _dia("ssl_override: enforced ph1 - redir to / for %s", whitelist_make_key_l4(cx).c_str());
        _inf("readbuf: \n%s", hex_dump(cx->readbuf(), 4).c_str());

        log.event(INF, "[%s]: enforced HTTP replacement active", socle::com::ssl::connection_name(scom, true).c_str());

        const std::string redir_pre("<html><head><script>top.location.href=\"");
        const std::string redir_suf("\";</script></head><body></body></html>");


        std::string repl = redir_pre + "/" + redir_suf;
        repl = html()->render_server_response(repl);

        cx->to_write(repl);
        cx->close_after_write(true);
        set_replacement_msg_ssl(scom);
        replacement_msg += "(ssl: enforced)";
    }
}

void MitmProxy::init_content_replace() {
    content_rule_ = std::make_unique<std::vector<ProfileContentRule>>();
}

buffer MitmProxy::content_replace_apply(const buffer &ref) {
    const std::string data = ref.str();
    std::string result = data;
    
    int stage = 0;
    for(auto& profile: *content_rule()) {
        
        try {
            const std::regex re_match(profile.match.c_str());
            const std::string repl = profile.replace;
            
            if(profile.replace_each_nth != 0) {

                // unfortunately std::regex_replace doesn't return if it really replaced something
                // ... which is no problem if we don't care. But in case we want to replace only 
                // .... nth occurrence, we have to do extra search to check (requiring one extra regex match).
                std::smatch sm;
                const bool is_there = std::regex_search(result,sm,re_match);

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
    
    _dia("content rewritten: original %d bytes with new %d bytes.", ref.size(), ret_b.size());
    _dum("Replacing bytes (%d):\n%s\n# with bytes(%d):\n%s", data.size(), hex_dump(ref).c_str(),
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

MitmHostCX* MitmProxy::first_left() const {
    MitmHostCX* ret{};
    
    if(! left_sockets.empty()) {
        auto* l = left_sockets.at(0);
          ret = MitmHostCX::from_baseHostCX(l);
    }
    else if(! left_delayed_accepts.empty()) {
        auto* l = left_delayed_accepts.at(0);
        ret = MitmHostCX::from_baseHostCX(l);
    }
        
    return ret;
}

MitmHostCX* MitmProxy::first_right() const {
    MitmHostCX* ret = nullptr;
    
    if(! right_sockets.empty()) {
        auto* r = right_sockets.at(0);
        ret = MitmHostCX::from_baseHostCX(r);
    }
    else if(! right_delayed_accepts.empty()) {
        auto* r = right_delayed_accepts.at(0);
        ret = MitmHostCX::from_baseHostCX(r);
    }

    return ret;
}



bool MitmMasterProxy::detect_ssl_on_plain_socket(int sock) {
    
    int ret = false;
    constexpr unsigned int NEW_CX_PEEK_BUFFER_SZ = 10;
    constexpr int time_increment = 2500; // 2.5ms
    constexpr int time_max = time_increment*25;

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
        auto redir = sx::proxymaker::to_magic(target_port);
        target_host = redir.first;
        target_port = redir.second;

        _dia("Connection from %s redirected from magic IP to %s:%d",
             just_accepted_cx->name().c_str(),
             target_host.c_str(), target_port);
    }


    auto *target_cx = new MitmHostCX(just_accepted_cx->com()->slave(),
                             target_host.c_str(),
                             string_format("%d",target_port).c_str());

    auto new_proxy = sx::proxymaker::make(just_accepted_cx, target_cx);
    auto lcx = logan_context(new_proxy->to_string(iNOT));

    if(not sx::proxymaker::policy(new_proxy, redirected_magic)) {
        return;
    }

    if(not sx::proxymaker::authorize(new_proxy)) {
        if(not sx::proxymaker::is_replaceable(target_port)) {
            return;
        }
    }

    if(not sx::proxymaker::setup_snat(new_proxy, source_host, source_port)) {
        return;
    }

    if(not sx::proxymaker::connect(this, std::move(new_proxy))) {
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

    auto new_proxy = sx::proxymaker::make(just_accepted_cx, target_cx);

    auto lcx = logan_context(new_proxy->to_string(iNOT));

    if(not sx::proxymaker::policy(new_proxy, false)) {
        return;
    }

    if(not sx::proxymaker::authorize(new_proxy)) {
        if(not sx::proxymaker::is_replaceable(target_port)) {
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
        return;
    }

    if(not sx::proxymaker::connect(this, std::move(new_proxy))) {
        return;
    }

    _deb("MitmUDPProxy::on_left_new: finished");
}

baseHostCX* MitmUdpProxy::MitmUdpProxy::new_cx(int s) {
    return new MitmHostCX(com()->slave(),s);
}

