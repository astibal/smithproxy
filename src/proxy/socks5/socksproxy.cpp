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
#include <proxy/explicitproxy_io_detail.hpp>
#include <proxy/explicitproxyport.hpp>
#include <proxy/socks5/socks5_protocol.hpp>
#include <proxy/socks5/sockshostcx.hpp>
#include <proxy/socks5/socksproxy.hpp>
#include <proxy/mitmhost.hpp>
#include <service/cfgapi/cfgapi.hpp>

#include <algorithm>
#include <vector>
#include <cerrno>
#include <sys/socket.h>

namespace {

class SocksFramingTCPCom final : public TCPCom {
public:
    baseCom* replicate() override { return new TCPCom(); }

    ssize_t read(int fd, void* destination, std::size_t capacity,
                 int flags) override {
        if(stage_ == stage::done) {
            // Do not let baseHostCX's drain loop consume tunnel payload with
            // the SOCKS parser after the CONNECT request boundary.
            errno = EAGAIN;
            return -1;
        }
        if(capacity == 0 || (flags & MSG_PEEK) != 0)
            return TCPCom::read(fd, destination, capacity, flags);

        std::vector<std::uint8_t> preview(capacity);
        const auto available = TCPCom::peek(fd, preview.data(), preview.size(), flags);
        if(available <= 0)
            return available;
        preview.resize(static_cast<std::size_t>(available));

        std::vector<std::uint8_t> candidate;
        candidate.reserve(frame_.size() + preview.size());
        candidate.insert(candidate.end(), frame_.begin(), frame_.end());
        candidate.insert(candidate.end(), preview.begin(), preview.end());

        const auto frame_size = complete_frame_size(candidate);
        auto consume = preview.size();
        if(frame_size > frame_.size())
            consume = std::min(consume, frame_size - frame_.size());

        const auto received = TCPCom::read(fd, destination, consume, flags);
        if(received <= 0)
            return received;

        auto const* bytes = static_cast<std::uint8_t const*>(destination);
        frame_.insert(frame_.end(), bytes, bytes + received);
        const auto completed = complete_frame_size(frame_);
        if(completed != 0 && frame_.size() >= completed) {
            if(stage_ == stage::greeting && !frame_.empty() && frame_[0] == 5) {
                stage_ = stage::request;
                frame_.clear();
            } else {
                stage_ = stage::done;
            }
        }
        return received;
    }

private:
    enum class stage { greeting, request, done };

    std::size_t complete_frame_size(
            std::vector<std::uint8_t> const& bytes) const noexcept {
        if(bytes.empty()) return 0;
        if(stage_ == stage::greeting && bytes[0] != 4)
            return sx::socks5::initial_frame_size_if_complete(
                bytes.data(), bytes.size());
        // SOCKS4 is selectable only by the first frame.  Once a SOCKS5
        // greeting completed, the request stage cannot renegotiate versions.
        if(stage_ == stage::greeting && bytes[0] == 4) {
            const auto size = sx::socks5::socks4_request_size_if_complete(
                bytes.data(), bytes.size());
            // Stop retaining an unterminated or oversized SOCKS4 identity as
            // soon as the parser has enough bytes to reject it. A complete
            // maximum-sized request remains valid and trailing tunnel bytes
            // are not mistaken for part of the request.
            if(size > sx::socks5::maximum_socks4_request_size)
                return sx::socks5::maximum_socks4_request_size;
            if(size == 0 &&
               bytes.size() >= sx::socks5::maximum_socks4_request_size)
                return sx::socks5::maximum_socks4_request_size;
            return size;
        }
        return sx::socks5::request_size_if_complete(bytes.data(), bytes.size());
    }

    stage stage_ = stage::greeting;
    std::vector<std::uint8_t> frame_;
};

} // namespace


void SocksProxy::on_left_message(baseHostCX* basecx) {

    auto* cx = dynamic_cast<socksServerCX*>(basecx);
    // The UDP_ASSOCIATE control channel is itself TCP.  Dispatching solely by
    // the carrier protocol sends it through the generic CONNECT path, whose
    // policy match expects a prepared right-hand context and can dereference
    // a null entry.  Keep SOCKS-specific commands in the SOCKS state machine.
    if(cx != nullptr && cx->com()->l4_proto() != SOCK_DGRAM &&
       cx->request_command() != socks5_cmd::UDP_ASSOCIATE) {
        handle_explicit_connect(cx);
        return;
    }
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
                if(matched_policy() < 0 and CfgFactory::get()->policy_fail_open) {
                    matched_policy(PolicyRule::POLICY_IMPLICIT_PASS);
                }
                authorized_policy_ = matched_policy() == PolicyRule::POLICY_IMPLICIT_PASS
                    ? std::shared_ptr<PolicyRule>{}
                    : CfgFactory::get()->policy_rule(matched_policy());
                verdict = matched_policy() == PolicyRule::POLICY_IMPLICIT_PASS or
                          CfgFactory::get()->policy_action(matched_policy());

                update_neighbors();

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

                cx->com()->l4_proto() != SOCK_DGRAM ? explicit_handoff(cx) : socks5_handoff_udp(cx);
            }
        }
        else if(cx->state_ == socks5_state::HANDOFF) {
            _dia("SocksProxy::on_left_message: socksHostCX handoff msg received");
            // UDP_ASSOCIATE keeps its TCP control connection only as the
            // lifetime/authorization anchor; there is no stream to hand off.
            if(cx->request_command() == socks5_cmd::UDP_ASSOCIATE) {
                cx->read_waiting_for_peercom(false);
                cx->com()->set_monitor(cx->socket());
            } else if(cx->com()->l4_proto() != SOCK_DGRAM) {
                cx->state(socks5_state::ZOMBIE);
                explicit_handoff(cx);
            }
        } else {

            _war("SocksProxy::on_left_message: unknown message");
        }
    }
}

void ExplicitProxy::handle_explicit_connect(ExplicitProxyCX* cx) {
    if(cx->request_error_ != explicit_request_error::NONE) {
        if(cx->request_error_ == explicit_request_error::MALFORMED_DATA) {
            cx->error(true);
        } else {
            cx->verdict(socks5_policy::REJECT);
        }
        return;
    }

    if(cx->state_ == socks5_state::WAIT_POLICY) {
        std::vector<baseHostCX*> left {cx};
        std::vector<baseHostCX*> right {cx->right.get()};

        bool verdict = false;
        {
            auto lock = std::scoped_lock(CfgFactory::lock());
            matched_policy(CfgFactory::get()->policy_match(left, right));
            if(matched_policy() < 0 and CfgFactory::get()->policy_fail_open) {
                matched_policy(PolicyRule::POLICY_IMPLICIT_PASS);
            }
            authorized_policy_ = matched_policy() == PolicyRule::POLICY_IMPLICIT_PASS
                ? std::shared_ptr<PolicyRule>{}
                : CfgFactory::get()->policy_rule(matched_policy());
            verdict = matched_policy() == PolicyRule::POLICY_IMPLICIT_PASS or
                      CfgFactory::get()->policy_action(matched_policy());
        }
        update_neighbors();
        cx->verdict(verdict ? socks5_policy::ACCEPT : socks5_policy::REJECT);
        return;
    }

    if(cx->state_ == socks5_state::HANDOFF) {
        cx->state(socks5_state::ZOMBIE);
        explicit_handoff(cx);
        return;
    }

    _war("ExplicitProxy::handle_explicit_connect: unexpected frontend state");
}

std::string SocksProxy::to_string(int lev) const  {
    std::stringstream  r;
    if(lev >= iINF) {
        r << "Socks|";
    }
    r << MitmProxy::to_string(lev);

    return r.str();
};

void ExplicitProxy::explicit_handoff(ExplicitProxyCX* cx) {

    _deb("SocksProxy::socks5_handoff: start");
    
    auto const implicit_pass = matched_policy() == PolicyRule::POLICY_IMPLICIT_PASS;
    if(matched_policy() < 0) {
        _dia("SocksProxy::sock5_handoff: matching policy: %d: dropping.",matched_policy());
        state().dead(true);
        return;
    } 
    ////// we matched the policy
    
    int s = cx->socket();
    pending_connect_response_ = cx->upstream_success_response();
    upstream_failure_response_ = cx->upstream_failure_response();
    pending_connect_response_offset_ = 0;
    connect_response_ready_ = false;
    close_after_connect_response_ = false;
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

    std::unique_lock config_lock(CfgFactory::lock());
    auto selected_policy = implicit_pass ? std::shared_ptr<PolicyRule>{}
                                         : CfgFactory::get()->policy_rule(matched_policy());
    if(not sx::policy::implicit_pass_is_current(
            implicit_pass, CfgFactory::get()->policy_fail_open)) {
        _err("ExplicitProxy::explicit_handoff: fail-open authorization was retired");
        state().dead(true);
        return;
    }
    if(not implicit_pass and
       not sx::policy::authorized_snapshot_is_current(authorized_policy_, selected_policy)) {
        _err("ExplicitProxy::explicit_handoff: authorized policy changed before handoff");
        state().dead(true);
        return;
    }

    const bool preserve_source = selected_policy &&
                                 selected_policy->nat == PolicyRule::POLICY_NAT_NONE;

    std::optional<unsigned short> source_port;
    if(preserve_source) {
        source_port = sx::explicit_proxy::parse_source_port(p);
        if(not source_port) {
            _err("ExplicitProxy::explicit_handoff: invalid source endpoint %s:%s",
                 h.c_str(), p.c_str());
            state().dead(true);
            return;
        }
    }

    auto *target_cx = new MitmHostCX(n_cx->com()->slave(), n_cx->com()->nonlocal_dst_host().c_str(),
                                     string_format("%d",n_cx->com()->nonlocal_dst_port()).c_str()
    );

    n_cx->peer(target_cx);
    target_cx->peer(n_cx);



    if(preserve_source) {
        target_cx->com()->nonlocal_src(true);
        target_cx->com()->nonlocal_src_host() = h;
        target_cx->com()->nonlocal_src_port() = *source_port;
    }

    n_cx->matched_policy(matched_policy());
    target_cx->matched_policy(matched_policy());

    if(ssl) {
        _deb("SocksProxy::socks5_handoff: this connection is SSL port");
    }
    
    radd(target_cx);

    if(selected_policy) {
        if(selected_policy->profile_routing and
           not sx::proxymaker::route_existing(this, selected_policy->profile_routing)) {
            _err("SocksProxy::socks5_handoff: routing failed");
            state().dead(true);
            return;
        }
    }

    // policy_apply() configures the client-side inspector and applies the TLS
    // profile to the originator plus every target context.  Applying it again
    // to target_cx would duplicate filters/webhooks and incorrectly enable the
    // client-side detection engine on the server side.
    const bool policy_applied = implicit_pass ||
        CfgFactory::get()->policy_apply(n_cx, this, matched_policy()) >= 0;
    config_lock.unlock();

    if (not policy_applied) {

        _inf("SocksProxy::socks5_handoff: session failed policy application on contexts");
        state().dead(true);
    } else {

        // connect with applied properties
        int real_socket = target_cx->connect();
        if(!target_cx->com()->descriptor_valid(real_socket)) {
            _err("SocksProxy::socks5_handoff: upstream connect returned invalid descriptor %d",
                 real_socket);
            state().dead(true);
            return;
        }
        com()->set_poll_handler(real_socket,this);
        // Non-blocking connect completion is reported as write readiness.
        com()->set_write_monitor(real_socket);

    }

    _dia("SocksProxy::socks5_handoff: finished");
}

bool ExplicitProxy::send_pending_connect_response() {
    if(pending_connect_response_.empty()) {
        return true;
    }

    auto* client = first_left();
    if(client == nullptr || client->socket() <= 0) {
        state().dead(true);
        return false;
    }

    auto const* data = pending_connect_response_.data() + pending_connect_response_offset_;
    auto const remaining = pending_connect_response_.size() - pending_connect_response_offset_;
    auto const written = sx::explicit_proxy::io_detail::retry_on_eintr(
        [&] { return ::send(client->socket(), data, remaining, MSG_NOSIGNAL); });
    if(written < 0) {
        if(sx::explicit_proxy::io_detail::send_would_block(errno)) {
            client->com()->set_write_monitor(client->socket());
            return true;
        }
        state().dead(true);
        return false;
    }

    pending_connect_response_offset_ += static_cast<std::size_t>(written);
    if(pending_connect_response_offset_ != pending_connect_response_.size()) {
        client->com()->set_write_monitor(client->socket());
        return true;
    }

    pending_connect_response_.clear();
    pending_connect_response_offset_ = 0;
    if(close_after_connect_response_) {
        state().dead(true);
    } else if(dynamic_cast<SSLCom*>(client->com()) == nullptr) {
        // Plain explicit tunnels have no TLS peer handshake which could
        // release them later.
        client->waiting_for_peercom(false);
        client->com()->set_monitor(client->socket());
    }
    // Keep TLS clients paused after a successful CONNECT response.  The
    // upstream side must first peek the ClientHello, validate the origin
    // certificate and install the spoofed certificate.  That path releases
    // the client when the certificate is ready; doing it here lets SSL_accept
    // race ahead with the default certificate and an untested verify status.
    return true;
}

bool ExplicitProxy::handle_cx_write(unsigned char side, baseHostCX* cx,
                                    bool cross_direction_retry) {
    if(not pending_connect_response_.empty()) {
        if((side == 'r' || side == 'R') && cx->opening()) {
            // This callback is driven by the upstream socket's write event.
            // Do not call is_connected() here: it performs another zero-time
            // epoll probe which can miss the event that brought us here and
            // turn an in-progress connect into a spurious proxy failure.
            int connect_error = 0;
            socklen_t connect_error_size = sizeof(connect_error);
            auto const* tcp = dynamic_cast<TCPCom const*>(cx->com());
            int status = 0;
            if(tcp != nullptr && tcp->connect_failed()) {
                connect_error = tcp->connect_error();
            } else {
                status = static_cast<int>(
                    sx::explicit_proxy::io_detail::retry_on_eintr([&] {
                        return ::getsockopt(cx->socket(), SOL_SOCKET, SO_ERROR,
                                            &connect_error, &connect_error_size);
                    }));
            }

            if(status == 0 && connect_error == 0) {
                cx->opening(false);
            } else if(status == 0 &&
                      (connect_error == EINPROGRESS || connect_error == EALREADY ||
                       connect_error == EWOULDBLOCK)) {
                // The socket has not completed its non-blocking connect yet.
                cx->com()->set_write_monitor(cx->socket());
                return true;
            } else {
                _dia("ExplicitProxy::handle_cx_write: upstream connect failed: %s",
                     string_error(status == 0 ? connect_error : errno).c_str());
                pending_connect_response_ = upstream_failure_response_;
                pending_connect_response_offset_ = 0;
                close_after_connect_response_ = true;
            }
            connect_response_ready_ = true;
            return send_pending_connect_response();
        }
        if((side == 'l' || side == 'L') && connect_response_ready_) {
            return send_pending_connect_response();
        }
    }
    return MitmProxy::handle_cx_write(side, cx, cross_direction_retry);
}

int ExplicitProxy::handle_sockets_once(baseCom* xcom) {
    if(!pending_connect_response_.empty()) {
        // Let the ordinary event dispatcher resolve the nonblocking connect
        // and flush the explicit-proxy reply before a staged exclusive stream
        // handler (notably SSH MITM) takes ownership of both descriptors.
        // Activating libssh first makes each peer wait for a different banner:
        // the client still waits for SOCKS success while the origin waits for
        // the client's SSH identification.
        webhook_session_start();
        return baseProxy::handle_sockets_once(xcom);
    }
    return MitmProxy::handle_sockets_once(xcom);
}

bool ExplicitProxy::handle_cx_write_once(unsigned char side, baseCom* xcom, baseHostCX* basecx) {
    if(not MitmProxy::handle_cx_write_once(side, xcom, basecx)) {
        return false;
    }

    auto* cx = dynamic_cast<ExplicitProxyCX*>(basecx);
    bool const frontend = side == 'l' || side == 'L' || side == 'x' || side == 'X';
    if(frontend && cx != nullptr && cx->state_ == explicit_state::REQRES_SENT &&
       cx->writebuf()->empty()) {
        // baseHostCX::pre_write() runs before the bytes are removed from the
        // write buffer.  Re-evaluate the explicit protocol state after the
        // flush, otherwise a client waiting for the target banner may leave
        // the frontend stuck in REQRES_SENT with no further socket event.
        cx->pre_write();
        return handle_cx_events(side, cx);
    }

    return true;
}

void SocksProxy::socks5_handoff_udp(socksServerCX* cx) {

    _deb("SocksProxy::socks5_handoff_udp: start");

    // A failed or interrupted target setup must not turn a missing shadow
    // endpoint into a null dereference during the asynchronous handoff.
    if(!sx::socks5::detail::udp_handoff_endpoints_ready(cx)) {
        _err("SocksProxy::socks5_handoff_udp: incomplete UDP handoff endpoints");
        state().dead(true);
        return;
    }

    auto const implicit_pass = matched_policy() == PolicyRule::POLICY_IMPLICIT_PASS;
    if(matched_policy() < 0) {
        _dia("SocksProxy::socks5_handoff_udp: matching policy: %d: dropping.",matched_policy());
        state().dead(true);
        return;
    }
    ////// we matched the policy

    auto *target_cx = cx->right.release();

    cx->peer(target_cx);
    target_cx->peer(cx);
    target_cx->writebuf()->append(cx->left->readbuf()->data(), cx->left->readbuf()->size());

    auto const& n_cx = cx->left;

    std::unique_lock config_lock(CfgFactory::lock());
    auto selected_policy = implicit_pass ? std::shared_ptr<PolicyRule>{}
                                         : CfgFactory::get()->policy_rule(matched_policy());
    if(not sx::policy::implicit_pass_is_current(
            implicit_pass, CfgFactory::get()->policy_fail_open)) {
        _err("SocksProxy::socks5_handoff_udp: fail-open authorization was retired");
        state().dead(true);
        return;
    }
    if(not implicit_pass and
       not sx::policy::authorized_snapshot_is_current(authorized_policy_, selected_policy)) {
        _err("SocksProxy::socks5_handoff_udp: authorized policy changed before handoff");
        state().dead(true);
        return;
    }

    if(selected_policy && selected_policy->nat == PolicyRule::POLICY_NAT_NONE)
        target_cx->com()->nonlocal_src(true);

    n_cx->matched_policy(matched_policy());
    target_cx->matched_policy(matched_policy());

    radd(target_cx);

    if(selected_policy) {
        if(selected_policy->profile_routing and
           not sx::proxymaker::route_existing(this, selected_policy->profile_routing)) {
            _err("SocksProxy::socks5_handoff_udp: routing failed");
            state().dead(true);
            return;
        }
    }

    const bool policy_applied = implicit_pass ||
        CfgFactory::get()->policy_apply(n_cx.get(), this, matched_policy()) >= 0;
    config_lock.unlock();

    if (not policy_applied) {
        // strange, but it can happen if the sockets is closed between policy match and this profile application
        // mark dead.
        _inf("SocksProxy::socks5_handoff_udp: session failed policy application");
        state().dead(true);
    } else {

        // connect with applied properties
        int real_socket = target_cx->connect();
        if(!target_cx->com()->descriptor_valid(real_socket)) {
            _err("SocksProxy::socks5_handoff_udp: upstream connect returned invalid descriptor %d",
                 real_socket);
            state().dead(true);
            return;
        }
        com()->set_poll_handler(real_socket,this);
        // The connected UDP/TCP target must get one writable dispatch to
        // leave the opening state and flush its initial request/datagram.
        com()->set_write_monitor(real_socket);

        // apply policy and get result


    }


    _dia("SocksProxy::socks5_handoff_udp: finished");
}

void SocksProxy::on_left_error(baseHostCX* cx) {
    // baseProxy reports protocol errors through this hook as well. Only a
    // terminal transport condition ends RFC 1928's TCP control channel.
    if(auto* control = dynamic_cast<socksServerCX*>(cx);
       control && (control->read_eof() || control->error()))
        control->retire_udp_association();
    ExplicitProxy::on_left_error(cx);
}

void SocksProxy::on_left_bytes(baseHostCX* cx) {
    auto* socks = dynamic_cast<socksServerCX*>(cx);
    if(socks != nullptr && socks->com()->l4_proto() == SOCK_DGRAM &&
       !socks->udp_association_available()) {
        socks->error(true);
        return;
    }
    if(socks != nullptr && !socks->prepare_udp_handoff_datagram())
        return;
    ExplicitProxy::on_left_bytes(cx);
}

void ExplicitProxy::on_left_bytes(baseHostCX* cx) {

    if(left_sockets.empty() or right_sockets.empty()) {
        _dia("waiting for proxy pair, L: %d, R: %d ", left_sockets.size(), right_sockets.size());
        return;
    }
    else {
        MitmProxy::on_left_bytes(cx);
    }
};




baseHostCX* MitmSocksProxy::new_cx(int s) {
    auto* transport = new SocksFramingTCPCom();
    transport->master(com()->master());
    return new socksServerCX(transport, s);
}

void MitmSocksProxy::on_left_new(std::unique_ptr<baseHostCX> accepted_cx) {

    if(not accepted_cx) return;

    auto new_proxy = std::make_unique<SocksProxy>(com()->slave());
    // let's add this just_accepted_cx into new_proxy
    std::string h;
    std::string p;
    accepted_cx->name();
    accepted_cx->com()->resolve_socket_src(accepted_cx->socket(),&h,&p);

    new_proxy->ladd(accepted_cx.get());
    accepted_cx.release();
    this->add_proxy(std::move(new_proxy));
    _deb("MitmSocksProxy::on_left_new: finished");
}

baseHostCX* MitmSocksUdpProxy::new_cx(int s) {
    // SOCKS UDP datagrams are framed plaintext, not DTLS.  Cloning the
    // listener's SSL-capable transport tried to build a second connected UDP
    // socket before policy could select bypass; that unmonitored socket then
    // captured every packet after the embryonic datagram.
    auto* transport = new UDPCom();
    transport->master(com()->master());
    return new socksServerCX(transport, s);
}

void MitmSocksUdpProxy::on_left_new(std::unique_ptr<baseHostCX> accepted_cx) {

    if(not accepted_cx) return;

    auto new_proxy = std::make_unique<SocksProxy>(com()->slave());
    // let's add this just_accepted_cx into new_proxy
    std::string h;
    std::string p;
    accepted_cx->name();
    accepted_cx->com()->resolve_socket_src(accepted_cx->socket(),&h,&p);

    new_proxy->ladd(accepted_cx.get());
    accepted_cx.release();
    this->add_proxy(std::move(new_proxy));
    _deb("MitmSocksUdpProxy::on_left_new: finished");
}
int MitmSocksProxy::handle_sockets_once(baseCom* c) {
    process_session_lists(*this);
    return ThreadedAcceptorProxy<SocksProxy>::handle_sockets_once(c);
}

int MitmSocksUdpProxy::handle_sockets_once(baseCom* c) {
    process_session_lists(*this);
    return ThreadedReceiverProxy<SocksProxy>::handle_sockets_once(c);
}
