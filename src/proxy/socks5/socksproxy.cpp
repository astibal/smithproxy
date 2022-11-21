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

#include <tcpcom.hpp>

#include <proxy/proxymaker.hpp>
#include <proxy/socks5/sockshostcx.hpp>
#include <proxy/socks5/socksproxy.hpp>
#include <proxy/mitmhost.hpp>
#include <service/cfgapi/cfgapi.hpp>
#include <policy/authfactory.hpp>

#include <vector>


void SocksProxy::on_left_message(baseHostCX* basecx) {

    auto* cx = dynamic_cast<socksServerCX*>(basecx);
    if(cx != nullptr) {
        if(cx->socks_error_ != socks5_request_error_::NONE) {
            if(cx->socks_error_ == socks5_request_error_::MALFORMED_DATA) {
                cx->error(true);
                return;
            }
            else {
                cx->verdict(socks5_policy_::REJECT);
            }
        }
        else if(cx->state_ == socks5_state::WAIT_POLICY) {

            bool verdict = false;

            _dia("SocksProxy::on_left_message: policy check: start");

            if(cx->request_command() == socks5_cmd::CONNECT) {
                std::vector<baseHostCX *> l;
                std::vector<baseHostCX *> r;
                l.emplace_back(cx);
                r.emplace_back(cx->right.get());


                auto lc_ = std::scoped_lock(CfgFactory::lock());

                matched_policy(CfgFactory::get()->policy_match(l, r));
                verdict = CfgFactory::get()->policy_action(matched_policy());

                std::shared_ptr<PolicyRule> p;
                if (matched_policy() >= 0) {
                    p = CfgFactory::get()->db_policy_list.at(matched_policy());
                }

                const char *resp = verdict ? "accept" : "reject";
                _dia("socksProxy::on_left_message: policy check result: policy# %d, verdict %s", matched_policy(),
                     resp);
            }
            else if(cx->request_command() == socks5_cmd::UDP_ASSOCIATE) {
                _dia("socksProxy::on_left_message: policy check: accept udp associate");
                verdict = true;
            }

            socks5_policy s5_verdict = verdict ? socks5_policy::ACCEPT : socks5_policy::REJECT;
            cx->verdict(s5_verdict);

            // Proceed with UDP directly to handoff phase
            if(com()->l4_proto() == SOCK_DGRAM) {
                _dia("SocksProxy::on_left_message: socksHostCX policy+handoff");
                cx->state(socks5_state::ZOMBIE);

                cx->com()->l4_proto() != SOCK_DGRAM ? socks5_handoff(cx) : socks5_handoff_udp(cx);
            }
        }
        else if(cx->state_ == socks5_state::HANDOFF) {
            _dia("SocksProxy::on_left_message: socksHostCX handoff msg received");
            cx->state(socks5_state::ZOMBIE);

            socks5_handoff(cx);
        } else {

            _war("SocksProxy::on_left_message: unknown message");
        }
    }
}

std::string SocksProxy::to_string(int lev) const  {
    std::stringstream  r;
    if(lev >= iINF) {
        r << "Socks|";
    }
    r << MitmProxy::to_string(lev);

    return r.str();
};

void SocksProxy::socks5_handoff(socksServerCX* cx) {

    _deb("SocksProxy::socks5_handoff: start");
    
    if(matched_policy() < 0) {
        _dia("SocksProxy::sock5_handoff: matching policy: %d: dropping.",matched_policy());
        state().dead(true);
        return;
    } 
    else if(matched_policy() >= (signed int)CfgFactory::get()->db_policy_list.size()) {
        _dia("SocksProxy::sock5_handoff: matching policy out of policy index table: %d/%d: dropping.",
                                         matched_policy(),
                                         CfgFactory::get()->db_policy_list.size());
        state().dead(true);
        return;
    }
    
    ////// we matched the policy
    
    int s = cx->socket();
    bool ssl = false;

    baseCom* new_com = nullptr;
    switch(cx->com()->nonlocal_dst_port()) {
        case 443:
        case 465:
        case 636:
        case 993:
        case 995:
            if(com()->l4_proto() != SOCK_DGRAM) {
                new_com = new baseSSLMitmCom<SSLCom>();
                break;
            }
            [[fallthrough]];
        default:
            new_com = (com()->l4_proto() == SOCK_DGRAM) ? (baseCom*) new UDPCom() : (baseCom*) new TCPCom();
    }
    new_com->master(com()->master());

    auto* n_cx = new MitmHostCX(new_com, s);
    n_cx->waiting_for_peercom(true);
    n_cx->com()->nonlocal_dst(true);
    n_cx->com()->nonlocal_dst_host() = cx->com()->nonlocal_dst_host();
    n_cx->com()->nonlocal_dst_port() = cx->com()->nonlocal_dst_port();
    n_cx->com()->nonlocal_dst_resolved(true);

    // get rid of it
    cx->remove_socket();
    if(cx->left) {
        // we are using the socket, so we don't want it to be cleared in cx->left destructor.
        cx->left->remove_socket();
    }

    delete cx;

    left_sockets.clear();
    ldaadd(n_cx);
    n_cx->on_delay_socket(s);


    std::string h;
    std::string p;
    if(n_cx->com()->resolve_socket_src(n_cx->socket(),&h,&p)) {
        n_cx->host() = h;
        n_cx->port() = p;
    }
    else {
        state().dead(true);
        return;
    }

    auto *target_cx = new MitmHostCX(n_cx->com()->slave(), n_cx->com()->nonlocal_dst_host().c_str(),
                                     string_format("%d",n_cx->com()->nonlocal_dst_port()).c_str()
    );

    n_cx->peer(target_cx);
    target_cx->peer(n_cx);



    {
        auto lc_ = std::scoped_lock(CfgFactory::lock());
        if (CfgFactory::get()->db_policy_list.at(matched_policy())->nat == PolicyRule::POLICY_NAT_NONE) {
            target_cx->com()->nonlocal_src(true);
            target_cx->com()->nonlocal_src_host() = h;
            target_cx->com()->nonlocal_src_port() = std::stoi(p);
        }
    }

    n_cx->matched_policy(matched_policy());
    target_cx->matched_policy(matched_policy());

    if(ssl) {
        _deb("SocksProxy::socks5_handoff: this connection is SSL port");
    }
    
    radd(target_cx);

    if( auto policy = CfgFactory::get()->lookup_policy(matched_policy()); policy) {

        if(policy->profile_routing and not sx::proxymaker::route(this, policy->profile_routing))
            _err("SocksProxy::socks5_handoff: routing failed");
    }

    if ((CfgFactory::get()->policy_apply(n_cx, this, matched_policy()) < 0) or
        (CfgFactory::get()->policy_apply(target_cx, this, matched_policy()) < 0)) {

        _inf("SocksProxy::socks5_handoff: session failed policy application on contexts");
        state().dead(true);
    } else {

        // connect with applied properties
        int real_socket = target_cx->connect();
        com()->set_monitor(real_socket);
        com()->set_poll_handler(real_socket,this);

        if(not socks5_handoff_resolve_identity(n_cx)) {
            _deb("deleting proxy %s", c_type());
            state().dead(true);
        }
    }

    _dia("SocksProxy::socks5_handoff: finished");
}


bool SocksProxy::socks5_handoff_resolve_identity(MitmHostCX* cx) {

    bool result = true;

    // resolve source information - is there an identity info for that IP?
    if (opt_auth_authenticate || opt_auth_resolve) {

        _dia("socks5_handoff_udp: authentication required or optionally resolved");

        bool identity_resolved = resolve_identity(cx, false);

        if (!identity_resolved) {
            // identity is unknown!

            if(opt_auth_authenticate) {
                short unsigned int target_port = cx->com()->nonlocal_dst_port();


                if (target_port != 80 && target_port != 443) {
                    result = false;
                    _inf("Connection %s closed: authorization failed (unknown identity)",
                         cx->c_type());
                }
            }
            else {
                _dia("Connection %s: authentication info optional, continuing.",cx->c_type());
            }

        } else if(opt_auth_authenticate) {

            result = socks5_handoff_authenticate(cx);

        }
    } else {
        _dia("Connection %s: authentication info optional, continuing.", cx->c_type());
    }

    return result;
}


bool SocksProxy::socks5_handoff_authenticate(MitmHostCX *cx) {

    bool bad_auth = true;

    // investigate L3 protocol
    int af = AF_INET;
    if (cx->com()) {
        af = cx->com()->l3_proto();
    }
    std::string str_af = SockOps::family_str(af);


    std::optional<std::vector<std::string>> groups_vec;

    if (af == AF_INET || af == 0) {
        groups_vec = AuthFactory::get().ip4_get_groups(cx->host());
    } else if (af == AF_INET6) {
        groups_vec = AuthFactory::get().ip6_get_groups(cx->host());
    }

    if ( groups_vec ) {

        if (CfgFactory::get()->policy_prof_auth(matched_policy()) != nullptr)
            for (auto i: CfgFactory::get()->policy_prof_auth(matched_policy())->sub_policies) {
                for (auto const& x: groups_vec.value()) {
                    _deb("Connection identities: ip identity '%s' against policy '%s'", x.c_str(),
                         i->element_name().c_str());
                    if (x == i->element_name()) {
                        _dia("Connection identities: ip identity '%s' matches policy '%s'", x.c_str(),
                             i->element_name().c_str());
                        bad_auth = false;
                    }
                }
            }
        if (bad_auth) {
            short unsigned int target_port = cx->com()->nonlocal_dst_port();


            if (target_port != 80 && target_port != 443) {
                _inf("Connection %s closed: authorization failed (non-matching identity criteria)",
                     cx->c_type());
            } else {
                _inf("Connection %s closed: authorization failed (non-matching identity criteria)(with replacement)",
                     cx->c_type());
                // set bad_auth true, because despite authentication failed, it could be replaced (we can let user know
                // he is not allowed to proceed
                bad_auth = false;
                auth_block_identity = true;
            }
        }
    }

    return not bad_auth;
}

void SocksProxy::socks5_handoff_udp(socksServerCX* cx) {

    _deb("SocksProxy::socks5_handoff_udp: start");

    if(matched_policy() < 0) {
        _dia("SocksProxy::socks5_handoff_udp: matching policy: %d: dropping.",matched_policy());
        state().dead(true);
        return;
    }
    else if(matched_policy() >= (signed int)CfgFactory::get()->db_policy_list.size()) {
        _dia("SocksProxy::socks5_handoff_udp: matching policy out of policy index table: %d/%d: dropping.",
             matched_policy(),
             CfgFactory::get()->db_policy_list.size());
        state().dead(true);
        return;
    }

    ////// we matched the policy

    auto *target_cx = cx->right.release();

    cx->peer(target_cx);
    target_cx->peer(cx);
    target_cx->writebuf()->append(cx->left->readbuf()->data(), cx->left->readbuf()->size());


    auto const& n_cx = cx->left;

    if(not n_cx) {
        _err("SocksProxy::socks5_handoff_udp: left shadow cx is null");
        state().dead(true);
        return;
    }

    {
        auto lc_ = std::scoped_lock(CfgFactory::lock());
        if (CfgFactory::get()->db_policy_list.at(matched_policy())->nat == PolicyRule::POLICY_NAT_NONE) {
            target_cx->com()->nonlocal_src(true);
        }
    }

    n_cx->matched_policy(matched_policy());
    target_cx->matched_policy(matched_policy());

    radd(target_cx);

    if (CfgFactory::get()->policy_apply(n_cx.get(), this, matched_policy()) < 0) {
        // strange, but it can happen if the sockets is closed between policy match and this profile application
        // mark dead.
        _inf("SocksProxy::socks5_handoff_udp: session failed policy application");
        state().dead(true);
    } else {

        // connect with applied properties
        int real_socket = target_cx->connect();
        com()->set_monitor(real_socket);
        com()->set_poll_handler(real_socket,this);

        // apply policy and get result


        if(not socks5_handoff_resolve_identity(n_cx.get())) {
            _deb("deleting proxy %s", c_type());
            state().dead(true);
        }
    }


    _dia("SocksProxy::socks5_handoff_udp: finished");
}



void SocksProxy::on_left_bytes(baseHostCX* cx) {

    if(left_sockets.empty() or right_sockets.empty()) {
        _dia("waiting for proxy pair, L: %d, R: %d ", left_sockets.size(), right_sockets.size());
        return;
    }
    else {
        MitmProxy::on_left_bytes(cx);
    }
};




baseHostCX* MitmSocksProxy::new_cx(int s) {
    auto r = new socksServerCX(com()->slave(),s);
    return r; 
}

void MitmSocksProxy::on_left_new(baseHostCX* just_accepted_cx) {

    auto* new_proxy = new SocksProxy(com()->slave());
    // let's add this just_accepted_cx into new_proxy
    std::string h;
    std::string p;
    just_accepted_cx->name();
    just_accepted_cx->com()->resolve_socket_src(just_accepted_cx->socket(),&h,&p);

    new_proxy->ladd(just_accepted_cx);
    this->add_proxy(new_proxy);
    _deb("MitmSocksProxy::on_left_new: finished");
}

baseHostCX* MitmSocksUdpProxy::new_cx(int s) {
    auto r = new socksServerCX(com()->slave(),s);
    return r;
}

void MitmSocksUdpProxy::on_left_new(baseHostCX* just_accepted_cx) {

    auto* new_proxy = new SocksProxy(com()->slave());
    // let's add this just_accepted_cx into new_proxy
    std::string h;
    std::string p;
    just_accepted_cx->name();
    just_accepted_cx->com()->resolve_socket_src(just_accepted_cx->socket(),&h,&p);

    new_proxy->ladd(just_accepted_cx);
    this->add_proxy(new_proxy);
    _deb("MitmSocksUdpProxy::on_left_new: finished");
}