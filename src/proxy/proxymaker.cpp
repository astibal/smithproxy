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
#include <proxy/proxymaker_policy.hpp>
#include <proxy/network_policy.hpp>
#include <proxy/revalidation_result.hpp>
#include <proxy/quic_observer.hpp>
#include <proxy/proxymaker_utils.hpp>
#include <proxy/connection_start.hpp>
#include <proxy/connection_identity.hpp>
#include <staticcontent.hpp>
#include <service/http/webhooks.hpp>
#include <proxy/filters/access_filter.hpp>
#include <udpcom.hpp>


#include <proxy/nbrhood.hpp>

#include <arpa/inet.h>

namespace sx::proxymaker {

    int match_policy(baseProxy* proxy) {
        if(!proxy) return -1;
        std::scoped_lock guard(CfgFactory::lock());
        const auto config = CfgFactory::get();
        auto left = proxy->ls(); left.insert(left.end(), proxy->lda().begin(), proxy->lda().end());
        auto right = proxy->rs(); right.insert(right.end(), proxy->rda().begin(), proxy->rda().end());
        const auto network = sx::net::NetworkCtx::instance().snapshot();
        const bool ready = sx::proxy::prepare_network_policy(config->db_policy_list, left, right, *network);
        const int selected = ready ? PolicyMatcher::select(config->db_policy_list, proxy, network.get()) : -1;
        if(auto* observer = dynamic_cast<MitmProxy*>(proxy); observer &&
           (selected >= 0 || config->policy_fail_open))
            observer->policy_input = sx::proxy::policy_input_t::capture(left, right);
        return selected;
    }

    int match_policy(std::vector<baseHostCX*>& left, std::vector<baseHostCX*>& right, MitmProxy* observer) {
        std::scoped_lock guard(CfgFactory::lock());
        const auto config = CfgFactory::get();
        const auto network = sx::net::NetworkCtx::instance().snapshot();
        const bool ready = sx::proxy::prepare_network_policy(config->db_policy_list, left, right, *network);
        const int selected = ready ? PolicyMatcher::select(config->db_policy_list, left, right, network.get()) : -1;
        if(observer && (selected >= 0 || config->policy_fail_open))
            observer->policy_input = sx::proxy::policy_input_t::capture(left, right);
        return selected;
    }


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

        // CfgFactory prepares NetworkCtx ingress/egress metadata once for this
        // selection; SOCKS and other vector callers use the same path.
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


    namespace {

        // The certificate probe and forwarding socket belong to one session.
        // They share this decision, but never share worker-affine QUIC objects.
        class QuicSessionSetup final : public SessionSetup {
        public:
            QuicSessionSetup(std::string const& source_host, std::string const& source_port) {
                static std::atomic_uint64_t sequence {0};
                id_ = "quic-" + sx::proxy::connection_id(StaticContent::boot_random, ++sequence);
                details_["info"] = {
                    {"phase", "setup"}, {"scope", "transport"},
                    {"transport", "udp"}, {"protocol", "quic"},
                    {"source", {{"host", source_host}, {"port", source_port}}},
                    {"webhook_control", {{"version", 1}, {"mode", "regular"},
                                         {"sequence", 0}, {"rewrite", false}}}
                };
            }

            void ingress_ifindex(unsigned index) override { ingress_ifindex_ = index; }
            std::string connection_id() const override { return id_; }
            sx::proxy::QuicObserver* quic_observer() override { return observer_.get(); }

            std::optional<QuicTlsPolicy> tls_policy(
                std::string const& host, std::string const& port) override {

                // Reuse normal ordered UDP policy matching. These temporary
                // contexts have no sockets and never perform transport I/O.
                auto const& source = details_["info"]["source"];
                auto const source_host = source["host"].get<std::string>();
                auto const source_port = source["port"].get<std::string>();
                baseHostCX left(new UDPCom, source_host.c_str(), source_port.c_str());
                baseHostCX right(new UDPCom, host.c_str(), port.c_str());
                left.com()->ingress_ifindex(ingress_ifindex_);
                left.com()->l3_proto(source_host.find(':') == std::string::npos ? AF_INET : AF_INET6);
                right.com()->l3_proto(host.find(':') == std::string::npos ? AF_INET : AF_INET6);
                std::vector<baseHostCX*> sources {&left};
                std::vector<baseHostCX*> targets {&right};

                // Copy values under one configuration generation. The normal
                // connection-start webhook remains outside this operation.
                std::scoped_lock lock(CfgFactory::lock());
                auto config = CfgFactory::get();
                const int index = match_policy(sources, targets);
                auto rule = config->lookup_policy(index);
                if(!rule || config->policy_action(index) != PolicyRule::POLICY_ACTION_PASS) {
                    log::connect().war("QUIC TLS policy rejected target=%s:%s", host.c_str(), port.c_str());
                    return std::nullopt;
                }

                QuicTlsPolicy result;
                if(auto const& profile = rule->profile_tls) {
                    result.use_pfs = profile->left_use_pfs && profile->right_use_pfs;
                    result.alpn_block = profile->opt_alpn_block;
                    result.disable_reuse = profile->left_disable_reuse;
                }
                return result;
            }

            ~QuicSessionSetup() override {
                if (!notified_) return;

                // Also retire setup when certificate verification fails before
                // the listener can publish a normal forwarding session.
                details_["info"].erase("phase");
                sx::http::webhooks::send_action("connection-stop", id_, details_, control_);
                sx::http::webhooks::send_sift_action("connection-stop", id_, details_);
            }

            bool start(std::string const& host, std::string const& port) override {
                if (started_) {
                    // Do not reuse a script's verdict for a different DNS result.
                    return allowed_ && (!notified_ || (host == host_ && port == port_));
                }

                started_ = true;
                host_ = host;
                port_ = port;
                details_["info"]["destination"] = {{"host", host}, {"port", port}};

                // Keep the display label compatible with existing session filters.
                // The envelope id, not this label, identifies the physical session.
                auto endpoint_label = [](std::string const& address, std::string const& service) {
                    const auto bracketed = address.find(':') == std::string::npos
                        ? address : "[" + address + "]";
                    return "quic_" + bracketed + ":" + service;
                };
                const auto& source = details_["info"]["source"];
                details_["info"]["session"] = endpoint_label(
                    source["host"].get<std::string>(), source["port"].get<std::string>())
                    + "+" + endpoint_label(host, port);

                const bool enabled = sx::http::webhooks::is_enabled();
                notified_ = enabled || sx::http::webhooks::sift_enabled();
                if (!notified_) {
                    allowed_ = true;
                    return true;
                }

                bool valid_reply = false;
                bool denied = false;
                if (enabled) {
                    sx::http::webhooks::send_action_wait("connection-start", id_, details_,
                        [&](sx::http::expected_reply reply) {
                            if (!reply) return;

                            auto result = sx::proxy::parse_setup_reply(
                                reply->response.first, reply->response.second);
                            control_->apply(result.body);
                            const auto& control = result.body.value("control", nlohmann::json::object());
                            if(result.action == sx::proxy::setup_action::accept &&
                               control.value("quic_lifecycle", 0) == 1) {
                                observer_ = std::make_unique<sx::proxy::QuicObserver>(
                                    id_, control_->strict(), control.value("quic_start_server", 0) == 1,
                                    control.value("quic_schema", 0) == 2);
                            }
                            valid_reply = result.action != sx::proxy::setup_action::invalid;
                            denied = result.action == sx::proxy::setup_action::drop;
                            if (result.action == sx::proxy::setup_action::not_interested
                                && control_->strict()) valid_reply = false;
                        });
                }

                if (enabled && !valid_reply) {
                    log::connect().war("QUIC connection-start: invalid setup reply (%s)",
                                       control_->strict() ? "fail-closed" : "fail-open");
                }

                sx::http::webhooks::send_sift_action("connection-start", id_, details_);
                allowed_ = !denied && (!enabled || valid_reply || !control_->strict());
                return allowed_;
            }

        private:
            unsigned ingress_ifindex_ = 0;
            std::string id_;
            std::string host_;
            std::string port_;
            nlohmann::json details_;
            std::shared_ptr<sx::http::webhooks::webhook_control_t> control_ =
                std::make_shared<sx::http::webhooks::webhook_control_t>();
            std::unique_ptr<sx::proxy::QuicObserver> observer_;
            bool started_ = false;
            bool notified_ = false;
            bool allowed_ = false;
        };
    }

    std::shared_ptr<SessionSetup> make_quic_session_setup(
        std::string const& source_host, std::string const& source_port) {
        return std::make_shared<QuicSessionSetup>(source_host, source_port);
    }

    bool connection_start(MitmProxy& proxy) {
        if (not proxy.webhook_session_start()) return false;

        // Access authorization is still selected by policy. Run it here,
        // outside the configuration lock and before opening the upstream.
        for (auto const& [name, filter] : proxy.filters_) {
            if (auto* access = dynamic_cast<AccessFilter*>(filter.get())) {
                access->authorize();
                if (proxy.state().dead()) return false;
            }
        }

        return true;
    }

    int connect(MitmProxy& proxy, MitmHostCX& target) {
        if (not connection_start(proxy)) return -1;

        if(not proxy.hook_server_connect(&target)) return -1;

        const int descriptor = target.connect();
        if(!target.com()->descriptor_valid(descriptor)) {
            proxy.hook_server_end(&target, "Upstream connect failed");
        }
        return descriptor;
    }

    bool connect(MasterProxy* owner, std::unique_ptr<MitmProxy> new_proxy) {
        auto const& log = log::connect();
        if(new_proxy)
            _deb("proxymaker::connect[%s]: connecting", new_proxy->to_string(iINF).c_str());
        if(!new_proxy) return false;

        const bool admitted = owner && valid_proxy_endpoints(new_proxy.get()) &&
            connection_start(*new_proxy) &&
            new_proxy->hook_server_connect(new_proxy->first_right());
        const bool connected = admitted && connect_owned_proxy(owner, new_proxy);

        if(!connected) {
            _deb("proxymaker::connect: cannot connect proxy");
            new_proxy->shutdown();
            new_proxy->finalize();
        }
        return connected;
    }


}

// Keep policy evaluation in proxymaker. The master owns traversal and teardown;
// configuration is held only while selecting and checking a single decision.
namespace sx::proxymaker {
sx::proxy::revalidation_result_t revalidate(MasterProxy& master, const sx::proxy::policy_state_t::generations_t& expected) {
    using State = sx::proxy::policy_state_t;
    sx::proxy::revalidation_result_t result;
    std::scoped_lock workers(master.proxy_lock());
    for(const auto& child : master.proxies()) {
        auto* proxy = dynamic_cast<MitmProxy*>(child.get());
        // Pending handshakes and intentional internal bypasses have no admitted
        // ACL inputs. Their normal admission path still handles new traffic.
        if(!proxy || proxy->state().dead() || proxy->matched_policy() < 0 || !proxy->policy_input) continue;
        bool deny = false;
        {
            std::scoped_lock configuration(CfgFactory::lock());
            if(!(State::current_generations() == expected)) {
                ++result.superseded;
                return result;
            }
            const auto config = CfgFactory::get();
            const auto network = sx::net::NetworkCtx::instance().snapshot();
            auto input = proxy->policy_input->view();
            if(!sx::proxy::prepare_network_policy(config->db_policy_list, input.left, input.right, *network)) {
                ++result.deferred; // unavailable metadata: retry on the next tick
                continue;
            }
            const int selected = PolicyMatcher::select(config->db_policy_list,
                input.left, input.right, network.get(), false);
            deny = config->policy_action(selected) != PolicyRule::POLICY_ACTION_PASS;
            // A decision made across a network change must not kill a session.
            if(!(State::current_generations() == expected)) {
                ++result.superseded;
                return result;
            }
        }
        if(deny) {
            proxy->state().dead(true);
            proxy->shutdown(); // close now; master retires the object normally
            ++result.terminated;
        } else {
            ++result.allowed;
        }
    }
    if(!(State::current_generations() == expected)) ++result.superseded;
    return result;
}
} // namespace sx::proxymaker

bool sx::proxy::policy_state_t::validate(MasterProxy& master) {
    const auto previous = observed;
    const bool was_pending = revalidation_required;
    revalidation_result_t report;
    if(!validate()) {
        const auto result = sx::proxymaker::revalidate(master, observed);
        revalidation_required = !result.complete();
        if(result.report(!was_pending || !(previous == observed))) report = result;
    }

    // One summary per master pass, outside the list and configuration locks.
    // Counts are checks, not unique sessions: recovery can inspect them again.
    if(!report.empty()) {
        Log::get()->events().insert(INF,
            "Policy revalidation checks: allowed=%llu terminated=%llu deferred=%llu superseded_passes=%llu master=%s",
            static_cast<unsigned long long>(report.allowed),
            static_cast<unsigned long long>(report.terminated),
            static_cast<unsigned long long>(report.deferred),
            static_cast<unsigned long long>(report.superseded),
            master.to_string(iNOT).c_str());
    }
    return !revalidation_required;
}
