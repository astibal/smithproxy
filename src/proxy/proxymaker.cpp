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

#include <service/cfgapi/cfgapi.hpp>
#include <policy/authfactory.hpp>
#include <proxy/mitmproxy.hpp>

#include <proxy/proxymaker.hpp>

namespace sx::proxymaker {

    namespace log {
        logan_lite& proxy() {
            static auto l_ = logan_lite("proxy");
            return l_;
        }

        logan_lite& routing() {
            static auto l_ = logan_lite("proxy.routing");
            return l_;
        }

        logan_lite& make() {
            static auto l_ = logan_lite("proxy.make");
            return l_;
        }

        logan_lite& policy() {
            static auto l_ = logan_lite("proxy.policy");
            return l_;
        }

        logan_lite& authorize() {
            static auto l_ = logan_lite("proxy.authorize");
            return l_;
        }
        logan_lite& snat() {
            static auto l_ = logan_lite("proxy.snat");
            return l_;
        }

        logan_lite& connect() {
            static auto l_ = logan_lite("proxy.connect");
            return l_;
        }
    }

    MitmProxy *make (baseHostCX *left, baseHostCX *right) {

        if(not left or not right) return nullptr;

        auto *new_proxy = new MitmProxy(left->com()->slave());

        auto const& log = log::make();

        // resolve internal name
        left->name();

        // let's add this just_accepted_cx into new_proxy
        if (left->read_waiting_for_peercom()) {
            _deb("MitmMasterProxy::on_left_new: ldaadd the new waiting_for_peercom cx");
            new_proxy->ldaadd(left);
        } else {
            _deb("MitmMasterProxy::on_left_new: ladd the new cx (unpaused)");
            new_proxy->ladd(left);
        }

        auto entangle = [] (baseHostCX *l, baseHostCX *r) {
            r->com()->l3_proto(l->com()->l3_proto());
            l->peer(r);
            r->peer(l);
        };

        entangle(left, right);

        // almost done, just add this target_cx to right side of new proxy
        new_proxy->radd(right);


        return new_proxy;
    }

    bool policy (MitmProxy *proxy, bool implicit_allow) {

        auto const& log = log::policy();

        auto bypass_cx = [] (baseHostCX const* cx) {
            auto *scom = dynamic_cast<SSLCom *>(cx->com());
            if (scom != nullptr) {
                scom->opt.bypass = true;
                scom->verify_reset(SSLCom::verify_status_t::VRF_OK);
            }
        };

        // apply policy and get result
        int policy_num = -1;

        if (implicit_allow) {
            // bypass ssl com to VIP
            bypass_cx(proxy->first_left());
            bypass_cx(proxy->first_right());
            policy_num = PolicyRule::POLICY_IMPLICIT_PASS;
        } else {
            policy_num = CfgFactory::get()->policy_apply(proxy->first_left(), proxy);
        }

        auto *src_cx = proxy->first_left();
        if (not src_cx) {
            if (auto fl = proxy->first_left(); fl)
                _not("MitmMasterProxy::proxy_enforce: source %s is not MitmHostCX", fl->c_type());
            return false;
        }


        auto *dst_cx = proxy->first_right();
        if (not dst_cx) {
            if (auto fr = proxy->first_right(); fr)
                _not("MitmMasterProxy::proxy_enforce: destination %s is not MitmHostCX", fr->c_type());
            return false;
        }

        // let know CX what policy it matched (it is handy when ie upgrade to TLS)
        src_cx->matched_policy(policy_num);
        dst_cx->matched_policy(policy_num);
        proxy->matched_policy(policy_num);

        // we are done
        if(policy_num < 0) return true;

        if( auto policy = CfgFactory::get()->lookup_policy(policy_num); policy) {

            if(policy->profile_routing and not route(proxy, policy->profile_routing))
                _err("routing failed");
        }

        return true;
    }



    using optional_string = std::optional<std::string>;
    std::pair<optional_string, optional_string> get_dnat_target (std::shared_ptr<ProfileRouting> routing_profile, MitmProxy* proxy) {

        if(not routing_profile) return {std::nullopt, std::nullopt };

        auto const& log = log::routing();

        std::string ip;
        std::string port;


        {
            auto l_ = std::scoped_lock(routing_profile->lb_state.lock_);
            auto candidates = routing_profile->lb_candidates(proxy->com()->l3_proto());
            if(candidates.empty()) return { std::nullopt, std::nullopt };

            size_t index = 0;

            switch(routing_profile->dnat_lb_method) {

                case ProfileRouting::lb_method::LB_RR:
                    index = routing_profile->lb_index_rr(candidates.size());
                    break;
                case ProfileRouting::lb_method::LB_L3:
                    index = routing_profile->lb_index_l3(proxy, candidates.size());
                    break;
                case ProfileRouting::lb_method::LB_L4:
                    index = routing_profile->lb_index_l4(proxy, candidates.size());
                    break;
                default:
                    // act as LB_RR
                    index = routing_profile->lb_index_rr(candidates.size());
            }

            ip = candidates[index]->ip();
        }

        if(not routing_profile->dnat_ports.empty()) {
            // find address object referred in "routing"
            auto prt = CfgFactory::get()->lookup_port(routing_profile->dnat_ports[0].c_str());
            if(prt) {
                if( auto port_obj = std::dynamic_pointer_cast<CfgRange>(prt); port_obj) {
                    // no balancing on ports
                    port = string_format("%d", port_obj->value().first);

                    if(port_obj->value().first != port_obj->value().second) {
                        _not("range set, but only first port number is used");
                    }
                }
            }
        }

        return { ip.empty() ? std::nullopt : std::make_optional(ip),
                 port.empty() ? std::nullopt : std::make_optional(port) };
    }

    bool route(MitmProxy* proxy, std::shared_ptr<ProfileRouting> routing_profile) {

        if(not routing_profile or not proxy) return false;

        auto const& log = log::routing();

        // update rt profile internals
        routing_profile->update();

        auto [ op_ip, op_port ] = get_dnat_target(routing_profile, proxy);
        if(not op_ip and not op_port) return false;


        auto orig_px_name = proxy->to_string(iINF);

        for (auto *cx: proxy->rs()) {
            if (op_ip) {
                cx->host(op_ip.value());
                _dia("%s: routing to IP: %s", orig_px_name.c_str(), op_ip->c_str());
            }

            // safeval covers cases when port is set to zero - which means no changes (ie "all" default port range)

            if (op_port) {

                auto port = safe_val(op_port.value());
                _dia("%s: routing to port: %s", orig_px_name.c_str(), port > 0  ? op_port->c_str() : "<unchanged>");

                if(port > 0) {
                    cx->port(op_port.value());
                }
            }
        }

        return true;
    }

    std::pair<std::string, unsigned short>
    to_magic(std::string const &target_host, unsigned short target_port) {

        std::string redir_host;
        unsigned short redir_port;

        if (target_port == 65000 or target_port == 143) {
            // bend broker magic IP
            redir_port = 65000 + CfgFactory::get()->tenant_index;
        } else if (target_port != 443) {
            // auth portal https magic IP
            redir_port = std::stoi(AuthFactory::get().portal_port_http);
        } else {
            // auth portal plaintext magic IP
            redir_port = std::stoi(AuthFactory::get().portal_port_https);
        }
        redir_host = "127.0.0.1";


        return std::make_pair(redir_host, redir_port);
    }


    bool authorize_is_bad (MitmProxy *proxy) {

        auto *left = proxy->first_left();
        auto const* right = proxy->first_right();
        if (not left or not right) return false;


        auto const policy = CfgFactory::get()->policy_prof_auth(left->matched_policy());
        if(not policy) return false;

        auto const& log = log::authorize();

        bool bad_auth = true;

        // investigate L3 protocol
        int af = AF_INET;
        if (left->com()) {
            af = left->com()->l3_proto();
        }
        std::string str_af = SocketInfo::inet_family_str(af);

        // use common base pointer, so we can use all IdentityInfo types

        std::optional<std::vector<std::string>> maybe_groups;
        if (af == AF_INET or af == 0) {
            maybe_groups = AuthFactory::get().ip4_get_groups(left->host());
        } else if (af == AF_INET6) {
            maybe_groups = AuthFactory::get().ip6_get_groups(left->host());
        }

        if(not maybe_groups) return bad_auth;

        for (auto const &sub_policy: CfgFactory::get()->policy_prof_auth(left->matched_policy())->sub_policies) {
            for (auto const &candidate: maybe_groups.value()) {
                _deb("Connection identities: testing ip identity '%s' against policy '%s'", candidate.c_str(), sub_policy->element_name().c_str());
                if (candidate == sub_policy->element_name()) {
                    _dia("Connection identities: ip identity '%s' matches policy '%s'", candidate.c_str(),
                         sub_policy->element_name().c_str());
                    bad_auth = false;
                    break;
                }
            }

            // don't iterate if we know we are ok
            if (not bad_auth)
                break;
        }

        return bad_auth;
    }


    bool authorize (MitmProxy *proxy) {

        auto const& log = log::authorize();

        // resolve source information - is there an identity info for that IP?
        if (proxy->opt_auth_authenticate) {

            _deb("proxymaker::authorize[%s]: must be authorized", proxy->to_string(iINF).c_str());

            bool res = proxy->resolve_identity();

            if(res) {
                _dia("proxymaker::authorize[%s]: identity resolved: %s/%s", proxy->to_string(iINF).c_str(),
                     proxy->identity()->username().c_str(),
                     proxy->identity()->groups().c_str());

                if (authorize_is_bad(proxy)) {
                    _dia("proxymaker::authorize[%s]: this identity is not authorized", proxy->to_string(iINF).c_str());

                    proxy->auth_block_identity = true;
                    return false;
                }
            }
            else {
                _dia("proxymaker::authorize[%s]: identity not resolved", proxy->to_string(iINF).c_str());

                return false;
            }

        } else if (proxy->opt_auth_resolve) {
            _deb("proxymaker::authorize[%s]: optional identity check", proxy->to_string(iINF).c_str());
            proxy->resolve_identity();
        }

        _deb("proxymaker::authorize[%s]: no identity needed", proxy->to_string(iINF).c_str());
        return true;
    }

    bool is_replaceable (unsigned short port) {
        constexpr std::array<unsigned short, 2> ports = {80, 443};

        return std::find(ports.begin(), ports.end(), port) != ports.end();
    }

    bool setup_snat (MitmProxy *proxy, std::string const &source_host, std::string const &source_port) {

        if (not proxy) return false;

        auto const* source_cx = proxy->first_left();
        auto const* target_cx = proxy->first_right();
        if (not target_cx or not source_cx) return false;

        bool enforce_nat = proxy->matched_policy() == PolicyRule::POLICY_IMPLICIT_PASS;

        auto const& log = log::snat();

        // setup NAT
        if (not enforce_nat) {
            try {
                if (CfgFactory::get()->db_policy_list.at(proxy->matched_policy())->nat == PolicyRule::POLICY_NAT_NONE) {

                    target_cx->com()->nonlocal_src_port() = std::stoi(source_port);
                    target_cx->com()->nonlocal_src_host() = source_host;
                    target_cx->com()->nonlocal_src(true);
                }
            }
            catch (std::invalid_argument const &e) {
                _err("proxy_setup_snat (nonat)[%s]: policy #%d: error %s", proxy->to_string(iINF).c_str(),
                     proxy->matched_policy(), e.what());
                return false;
            }
            catch (std::out_of_range const &e) {
                _err("proxy_setup_snat (nonat)[%s]: policy #%d: error %s", proxy->to_string(iINF).c_str(),
                     proxy->matched_policy(), e.what());
                return false;
            }

        }

        return true;
    }


    bool connect (MasterProxy *owner, MitmProxy *new_proxy) {

        auto const& log = log::connect();

        if (owner and new_proxy) {

            auto const* left = new_proxy->first_left();
            auto* right = new_proxy->first_right();
            auto *oc = owner->com();

            if (left and right and oc) {

                _deb("proxymaker::connect[%s]: connecting", new_proxy->to_string(iINF).c_str());

                // owner com sets new_proxy as the epoll handler for left socket
                // finalize connection acceptance by adding new proxy to proxies and connect

                int right_socket = right->connect();
                oc->set_monitor(right_socket);

                oc->set_poll_handler(left->socket(), new_proxy);
                oc->set_poll_handler(right_socket, new_proxy);

                owner->add_proxy(new_proxy);
                _deb("proxymaker::connect[%s]: added to owner proxy", new_proxy->to_string(iINF).c_str());

                return true;
            }
        }


        _deb("proxymaker::connect[%s]: cannot connect null objects");

        return false;
    }


}