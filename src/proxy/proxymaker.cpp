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

#include <cfgapi.hpp>
#include <policy/authfactory.hpp>

#include <proxy/mitmproxy.hpp>

namespace sx::proxymaker {

    MitmProxy *make (baseHostCX *left, baseHostCX *right) {

        auto *new_proxy = new MitmProxy(left->com()->slave());
        if (not new_proxy or not left or not right) return nullptr;

        auto log = logan_lite("proxy");

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

    bool policy(MitmMasterProxy *owner, MitmProxy *proxy, bool implicit_allow) {

        auto log = logan_lite("proxy");

        auto bypass_cx = [] (baseHostCX *cx) {
            auto *scom = dynamic_cast<SSLCom *>(cx->com());
            if (scom != nullptr) {
                scom->opt_bypass = true;
                scom->verify_reset(SSLCom::VRF_OK);
            }
        };

        // apply policy and get result
        int policy_num = -1;

        if (implicit_allow) {
            // bypass ssl com to VIP
            bypass_cx(proxy->first_left());
            bypass_cx(proxy->first_right());
            policy_num = POLICY_IMPLICIT_PASS;
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
        auto *right = proxy->first_right();

        if (not left or not right) return false;

        auto log = logan_lite("proxy");

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


        if (maybe_groups) {
            if (CfgFactory::get()->policy_prof_auth(left->matched_policy()) != nullptr) {
                for (auto const &i: CfgFactory::get()->policy_prof_auth(left->matched_policy())->sub_policies) {
                    for (auto const &x: maybe_groups.value()) {
                        _deb("Connection identities: ip identity '%s' against policy '%s'", x.c_str(),
                             i->element_name().c_str());
                        if (x == i->element_name()) {
                            _dia("Connection identities: ip identity '%s' matches policy '%s'", x.c_str(),
                                 i->element_name().c_str());
                            bad_auth = false;
                            break;
                        }
                    }

                    // don't iterate if we know we are ok
                    if (not bad_auth)
                        break;
                }
            }
        }

        return bad_auth;
    }


    bool authorize (MitmProxy *proxy) {

        // resolve source information - is there an identity info for that IP?
        if (proxy->opt_auth_authenticate) {
            bool res = proxy->resolve_identity();

            if (not res) {
                return false;
            } else if (authorize_is_bad(proxy)) {
                proxy->auth_block_identity = true;
                return false;

            }
        } else if (proxy->opt_auth_resolve) {
            proxy->resolve_identity();
        }

        return true;
    }

    bool is_replaceable (unsigned short port) {
        constexpr std::array<unsigned short, 2> ports = {80, 443};

        return std::find(ports.begin(), ports.end(), port) != ports.end();
    }

    bool setup_snat (MitmProxy *proxy, std::string const &source_host, std::string const &source_port) {

        if (not proxy) return false;

        auto *source_cx = proxy->first_left();
        auto *target_cx = proxy->first_right();
        if (not target_cx or not source_cx) return false;

        bool enforce_nat = proxy->matched_policy() == POLICY_IMPLICIT_PASS;

        auto log = logan_lite("proxy");

        // setup NAT
        if (not enforce_nat) {
            try {
                if (CfgFactory::get()->db_policy_list.at(proxy->matched_policy())->nat == POLICY_NAT_NONE) {

                    target_cx->com()->nonlocal_src_port() = std::stoi(source_port);
                    target_cx->com()->nonlocal_src_host() = source_host;
                    target_cx->com()->nonlocal_src(true);
                }
            }
            catch (std::invalid_argument const &e) {
                _err("proxy_setup_snat (nonat): %s, policy #%d: %s", proxy->to_string(iINF).c_str(),
                     proxy->matched_policy(), e.what());
                return false;
            }
            catch (std::out_of_range const &e) {
                _err("proxy_setup_snat (nonat): %s, policy #%d: %s", proxy->to_string(iINF).c_str(),
                     proxy->matched_policy(), e.what());
                return false;
            }

        }

        return true;
    }


    bool connect (MitmMasterProxy *owner, MitmProxy *new_proxy) {

        if (owner and new_proxy) {

            auto *left = new_proxy->first_left();
            auto *right = new_proxy->first_right();
            auto *oc = owner->com();

            if (left and right and oc) {
                // owner com sets new_proxy as the epoll handler for left socket
                // finalize connection acceptance by adding new proxy to proxies and connect

                int right_socket = right->connect();
                oc->set_monitor(right_socket);

                oc->set_poll_handler(left->socket(), new_proxy);
                oc->set_poll_handler(right_socket, new_proxy);

                owner->proxies().emplace_back(new_proxy);

                return true;
            }
        }

        return false;
    }


}