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
#include <proxy/mitmproxy.hpp>

#include <proxy/proxymaker.hpp>
#include <proxy/proxymaker_utils.hpp>

#include <proxy/nbrhood.hpp>

#include <arpa/inet.h>

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

    std::unique_ptr<MitmProxy> make(std::unique_ptr<baseHostCX> left_owner,
                                    std::unique_ptr<baseHostCX> right_owner) {

        auto* left = left_owner.get();
        auto* right = right_owner.get();

        if(not valid_host_pair(left, right)) return nullptr;

        auto new_proxy = std::make_unique<MitmProxy>(left->com()->slave());

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
        left_owner.release();

        auto entangle = [] (baseHostCX *l, baseHostCX *r) {
            r->com()->l3_proto(l->com()->l3_proto());
            l->peer(r);
            r->peer(l);
        };

        entangle(left, right);

        // almost done, just add this target_cx to right side of new proxy
        new_proxy->radd(right);
        right_owner.release();


        return new_proxy;
    }

    bool policy (std::unique_ptr<MitmProxy>& proxy, bool implicit_allow) {

        auto const& log = log::policy();

        if(!valid_proxy_endpoints(proxy.get())) return false;
        auto *src_cx = proxy->first_left();
        auto *dst_cx = proxy->first_right();

        auto bypass_cx = [] (baseHostCX const* cx) {
            auto *scom = dynamic_cast<SSLCom *>(cx->com());
            if (scom != nullptr) {
                scom->opt.bypass = true;
                scom->verify_reset(SSLCom::verify_status_t::VRF_OK);
            }
        };

        // apply policy and get result
        int policy_num = -1;
        std::unique_lock config_lock(CfgFactory::lock(), std::defer_lock);

        if (implicit_allow) {
            // bypass ssl com to VIP
            bypass_cx(proxy->first_left());
            bypass_cx(proxy->first_right());
            policy_num = PolicyRule::POLICY_IMPLICIT_PASS;
        } else {
            // Keep selection, profile application and routing bound to one
            // configuration generation.  A reload must not reuse the numeric
            // slot between authorization and routing.
            config_lock.lock();
            policy_num = CfgFactory::get()->policy_apply(proxy->first_left(), proxy.get());
        }

        // let know CX what policy it matched (it is handy when ie upgrade to TLS)
        src_cx->matched_policy(policy_num);
        dst_cx->matched_policy(policy_num);
        proxy->matched_policy(policy_num);

        // A magic-IP redirect is the only intentional implicit pass. A normal
        // flow without a matching rule is an implicit deny, and a matched deny
        // rule must stop before authorization, SNAT and connect.
        if(policy_num == PolicyRule::POLICY_IMPLICIT_PASS) return true;
        if(policy_num < 0) return false;
        if(CfgFactory::get()->policy_action(policy_num) != PolicyRule::POLICY_ACTION_PASS)
            return false;

        if( auto policy = CfgFactory::get()->lookup_policy(policy_num); policy) {

            if(policy->profile_routing and not route(proxy, policy->profile_routing)) {
                _err("routing failed");
                return false;
            }
        }

        if(proxy and not implicit_allow) {
            proxy->update_neighbors();
        }

        if(config_lock.owns_lock()) config_lock.unlock();

        return true;
    }



    using optional_string = std::optional<std::string>;
    std::pair<optional_string, optional_string>
    get_dnat_target(MitmProxy const* proxy, std::shared_ptr<ProfileRouting> routing_profile) {

        if(not routing_profile || not proxy) return {std::nullopt, std::nullopt };

        auto const& log = log::routing();

        std::string ip;
        std::string port;


        {
            auto family = proxy->com() ? proxy->com()->l3_proto() : AF_INET;
            if(auto const* target = proxy->first_right(); target and target->com()) {
                family = target->com()->l3_proto();
                in6_addr address6 {};
                in_addr address4 {};
                if(inet_pton(AF_INET6, target->host().c_str(), &address6) == 1) {
                    family = AF_INET6;
                }
                else if(inet_pton(AF_INET, target->host().c_str(), &address4) == 1) {
                    family = AF_INET;
                }
            }
            auto candidates = routing_profile->lb_candidates(family);
            if(not candidates.empty()) {
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

                if(index < candidates.size() && candidates[index])
                    ip = candidates[index]->ip();
            }
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

    bool route_existing(MitmProxy*proxy, std::shared_ptr<ProfileRouting> routing_profile) {
        return route(proxy, std::move(routing_profile));
    }

    bool route(std::unique_ptr<MitmProxy> &proxy, std::shared_ptr<ProfileRouting> routing_profile) {

        return route(proxy.get(), std::move(routing_profile));
    }

    bool route(MitmProxy* proxy, std::shared_ptr<ProfileRouting> routing_profile) {

        if(not routing_profile or not valid_proxy_endpoints(proxy)) { return false; }

        auto const& log = log::routing();

        // update rt profile internals
        routing_profile->update();

        auto [ op_ip, op_port ] = get_dnat_target(proxy, routing_profile);
        auto const has_sni_rewrite = not routing_profile->rewrite_sni.empty()
                                     and not routing_profile->rewrite_sni_to.empty();
        if(not op_ip and not op_port and not has_sni_rewrite) { return false; }


        auto orig_px_name = proxy->to_string(iINF);

        for (auto* cx: proxy->rs()) {
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

            cx->configure_sni_rewrite(routing_profile->rewrite_sni, routing_profile->rewrite_sni_to);
        }

        for(auto* cx: proxy->ls()) {
            cx->configure_sni_rewrite(routing_profile->rewrite_sni, routing_profile->rewrite_sni_to);
        }

        return true;
    }


    bool is_replaceable (unsigned short port) {
        constexpr std::array<unsigned short, 2> ports = {80, 443};

        return std::find(ports.begin(), ports.end(), port) != ports.end();
    }

    bool setup_snat (std::unique_ptr<MitmProxy> &proxy, std::string const &source_host, std::string const &source_port) {

        if (not valid_proxy_endpoints(proxy.get())) return false;

        auto const* source_cx = proxy->first_left();
        auto const* target_cx = proxy->first_right();

        bool enforce_nat = proxy->matched_policy() == PolicyRule::POLICY_IMPLICIT_PASS;

        auto const& log = log::snat();

        // setup NAT
        if (not enforce_nat) {
            auto policy = CfgFactory::get()->policy_rule(proxy->matched_policy());
            if(not policy) {
                _err("proxy_setup_snat (nonat)[%s]: policy #%d disappeared",
                     proxy->to_string(iINF).c_str(), proxy->matched_policy());
                return false;
            }
            if(policy->nat == PolicyRule::POLICY_NAT_NONE) {
                const auto parsed_port = parse_source_port(source_port);
                if(!parsed_port) return false;
                target_cx->com()->nonlocal_src_port() = *parsed_port;
                target_cx->com()->nonlocal_src_host() = source_host;
                target_cx->com()->nonlocal_src(true);
            }
        }

        return true;
    }


    bool connect(MasterProxy* owner, std::unique_ptr<MitmProxy> &&new_proxy) {
        auto const& log = log::connect();
        if(new_proxy)
            _deb("proxymaker::connect[%s]: connecting", new_proxy->to_string(iINF).c_str());
        const bool connected = connect_owned_proxy(owner, std::move(new_proxy));
        if(!connected) _deb("proxymaker::connect: cannot connect proxy");
        return connected;
    }


}
