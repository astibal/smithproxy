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
#include <log/logger.hpp>
#include <proxy/socks5/sockshostcx.hpp>
#include <proxy/socks5/socks5_protocol.hpp>
#include <proxy/explicitproxyport.hpp>
#include <inspect/dnsinspector.hpp>

#include <common/numops.hpp>

#include <poll.h>
#include <unistd.h>

bool ExplicitProxyCX::global_async_dns = true;

namespace {
bool udp_control_channel_alive(socksServerCX const* control) noexcept {
    if(control == nullptr ||
       !sx::socks5::pollable_control_socket(control->socket())) return false;

    short requested = POLLIN;
#ifdef POLLRDHUP
    requested |= POLLRDHUP;
#endif
    pollfd descriptor {control->socket(), requested, 0};
    const auto status = ::poll(&descriptor, 1, 0);
    if(status < 0) return errno == EINTR;
    if(status == 0) return true;

    short terminal = POLLERR | POLLHUP | POLLNVAL;
#ifdef POLLRDHUP
    terminal |= POLLRDHUP;
#endif
    if((descriptor.revents & terminal) != 0) return false;
    if((descriptor.revents & POLLIN) == 0) return true;

    unsigned char byte = 0;
    const auto received = ::recv(control->socket(), &byte, sizeof(byte),
                                 MSG_PEEK | MSG_DONTWAIT);
    if(received >= 0) return received != 0;
    return errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR;
}

socksServerCX* claim_udp_association_locked(
        socksServerCX::UDP::associations& associations,
        std::string const& host, std::string const& port) {
    const std::string exact = string_format("%s:%s", host.c_str(), port.c_str());
    if(auto found = associations.clients.find(exact);
       found != associations.clients.end()) {
        if(!udp_control_channel_alive(found->second)) {
            associations.clients.erase(found);
            return nullptr;
        }
        return found->second;
    }

    // RFC 1928 permits UDP_ASSOCIATE with DST.PORT zero when the client does
    // not yet know which UDP source port it will use. Bind that wildcard to
    // the first datagram from the authenticated TCP peer's address.
    const std::string wildcard = string_format("%s:0", host.c_str());
    auto found = associations.clients.find(wildcard);
    if(found == associations.clients.end())
        return nullptr;
    if(!udp_control_channel_alive(found->second)) {
        associations.clients.erase(found);
        return nullptr;
    }

    auto* control = found->second;
    associations.clients.erase(found);
    associations.clients.emplace(exact, control);
    control->get_udp()->my_assoc = exact;
    return control;
}
}

socksServerCX::socksServerCX(baseCom* c, unsigned int s) : ExplicitProxyCX(c,s) {
    // SOCKS greeting and request framing is incremental. A zero process_in()
    // result means "retain until the next read", not "discard on the next
    // read cycle".
    if(c && c->l4_proto() != SOCK_DGRAM)
        auto_finish(false);
}

socksServerCX::~socksServerCX() {
    retire_udp_association();
}

void socksServerCX::retire_udp_association() noexcept {
    if(!udp_ || udp_->my_assoc.empty()) return;

    auto associations = UDP::db();
    auto lock = std::scoped_lock(UDP::lock);
    auto found = associations->clients.find(udp_->my_assoc);
    if(found != associations->clients.end() && found->second == this)
        associations->clients.erase(found);
    udp_->my_assoc.clear();
}

bool socksServerCX::udp_association_available() {
    auto associations = UDP::db();
    auto lock = std::scoped_lock(UDP::lock);
    return claim_udp_association_locked(*associations, host(), port()) != nullptr;
}

bool socksServerCX::prepare_udp_handoff_datagram() {
    if(com()->l4_proto() != SOCK_DGRAM || state_ != socks5_state::ZOMBIE)
        return true;

    auto* datagram = readbuf();
    const auto header = sx::socks5::inspect_udp_header(
        datagram->data(), datagram->size());
    if(header != sx::socks5::udp_header_status::ready) {
        datagram->flush(datagram->size());
        return false;
    }

    socks_error_ = socks5_request_error::NONE;
    const auto saved_state = state_;
    try {
        socks_error_ = socks5_parse_request();
    } catch(std::out_of_range const&) {
        socks_error_ = socks5_request_error::MALFORMED_DATA;
    }
    state_ = saved_state;

    if(socks_error_ != socks5_request_error::NONE ||
       req_hdr_size > datagram->size()) {
        datagram->flush(datagram->size());
        return false;
    }

    datagram->flush(req_hdr_size);
    return true;
}

ExplicitProxyCX::ExplicitProxyCX(baseCom* c, unsigned int s) : MitmHostCX(c,s) {
    state_ = explicit_state::INIT;

    // copy setting from global/static variable - don't allow to change async
    // flag on the background during the object life
    async_dns_ = global_async_dns;
}

void ExplicitProxyCX::wait_policy() {
    state_ = explicit_state::WAIT_POLICY;
    read_waiting_for_peercom(true);
}

std::size_t socksServerCX::process_in() {


    switch(state_) {
        case socks5_state::INIT:
            _dia("process_in: state INIT");
            return process_socks_hello();
        case socks5_state::HELLO_SENT:
            _dia("process_in: state HELLO_SENT");
            return 0; // we sent response to client hello, don't process anything
        case socks5_state::WAIT_REQUEST:
            _dia("process_in: state WAIT_REQUEST");
            return process_socks_request();
        case socks5_state::HANDOFF:
            // UDP_ASSOCIATE keeps this TCP connection solely as the RFC 1928
            // lifetime anchor. Consume any unexpected control-channel bytes
            // so an open client cannot grow the retained stream buffer.
            if(req_cmd == socks5_cmd::UDP_ASSOCIATE) {
                return readbuf()->size();
            }
            break;
        default:
            _dia("process_in: state *");
            break;
    }
    
    return 0;
}

std::size_t socksServerCX::process_socks_udp_request() {
    buffer const *b = readbuf();
    socks_error_ = socks5_request_error::NONE;
    const auto header_status = sx::socks5::inspect_udp_header(b->data(), b->size());
    if(header_status == sx::socks5::udp_header_status::incomplete) {
        // UDP preserves message boundaries: a short datagram can never become
        // complete by retaining it for the next read. Consume/drop it instead
        // of letting a second packet splice bytes onto this request.
        return b->size();
    }
    if(header_status != sx::socks5::udp_header_status::ready) {
        socks_error_ = socks5_request_error::MALFORMED_DATA;
        // UDP is connectionless: an invalid packet must not tear down the
        // authenticated association (or poison its reusable pseudo-flow).
        // Consume just this datagram and let the next one be parsed afresh.
        return b->size();
    }

    req_cmd = socks5_cmd::CONNECT;
    req_atype = static_cast<socks5_atype>( b->get_at<uint8_t>(3));

    try {
        _dia("process_socks_udp_request: request size %d, fragment %d, atype %d",
             b->size(), b->get_at<uint8_t>(2), req_atype);
        auto err = handle5_connect();

        if(err != socks5_request_error::NONE) {
            _dia("process_socks_udp_request: request error %d", err);
            socks_error_ = err;
            if(err != socks5_request_error::UNAUTHORIZED)
                state_ = socks5_state::INIT;
            return b->size();
        }
    }
    catch(std::out_of_range const&) {
        _dia("process_socks_udp_request: error");
        socks_error_ = socks5_request_error::MALFORMED_DATA;
        state_ = socks5_state::INIT;
        return b->size();
    }

    // there is actually no response sent in UDP proxy case

    read_force_eagain();

    return b->size();
}

std::size_t socksServerCX::process_socks_hello_tcp() {

    buffer const* b = readbuf();
    const auto greeting_size = sx::socks5::initial_frame_size_if_complete(
        b->data(), b->size());
    if(greeting_size == 0) return 0;

    version = b->get_at<unsigned char>(0);

    // at this stage we have full client hello received
    if (version == 5) {
        _dia("process_socks_hello_tcp: version %d", version);
        const auto nmethods = b->get_at<unsigned char>(1);

        unsigned char server_hello[2];
        server_hello[0] = 5; // version
        server_hello[1] = sx::socks5::offers_no_authentication(
            b->data() + 2, nmethods) ? 0 : 0xff;

        writebuf()->append(server_hello, 2);
        readbuf()->flush(greeting_size);

        if(server_hello[1] == 0xff) {
            _dia("process_socks_hello_tcp: no supported authentication method");
            state_ = socks5_state::HELLO_SENT;
            close_after_write(true);
            com()->set_write_monitor(socket());
            return 0;
        }

        state_ = socks5_state::WAIT_REQUEST;

        // A client may pipeline its request with the greeting. Parse the
        // retained bytes now; no new socket-read edge is guaranteed.
        if(!readbuf()->empty())
            process_socks_request();
        return 0;
    } else if (version == 4) {
        _dia("process_socks_hello_tcp: version %d", version);
        return process_socks_request();
    } else {
        _dia("process_socks_hello_tcp: unsupported socks version");
        error(true);
    }

    return 0;
}

std::size_t socksServerCX::process_socks_hello() {

    if(com()->l4_proto() != SOCK_DGRAM) {
        return process_socks_hello_tcp();
    }
    else {
        return process_socks_udp_request();
    }
    return 0;
}

bool ExplicitProxyCX::choose_server_ip(std::vector<std::string>& target_ips) {

    target_ips.erase(std::remove_if(
        target_ips.begin(), target_ips.end(),
        [](std::string const& target) {
            return sx::explicit_proxy::is_unspecified_address(target);
        }), target_ips.end());

    if(target_ips.empty()) {
        _dia("choose_server_ip: empty");
        return false;
    }

    uint64_t index = 0;

    if(target_ips.size() > 1) {
        //use some semi-random target
        uint64_t baz = (uint64_t)this * (uint64_t)com() * time(nullptr);
        index = baz % target_ips.size();
    }

    std::string target = target_ips.at(index);

    _dia("choose_server_ip: chosen target: %s (index %d out of size %d)",target.c_str(), index, target_ips.size());
    com()->nonlocal_dst_host() = target;
    com()->nonlocal_dst_resolved(true);

    return true;
}

bool ExplicitProxyCX::process_dns_response(std::shared_ptr<DNS_Response> resp) {

    auto target_ips = sx::explicit_proxy::fresh_dns_addresses(resp);
    bool ret = true;

    if (resp) {
        for (auto const& target : target_ips)
            _dia("process_dns_response: validated target candidate: %s", target.c_str());

        if (! target_ips.empty()) {

            DNS_Inspector di;
            di.store(resp);
        }
    }

    const bool selected = choose_server_ip(target_ips);
    const bool prepared = selected && setup_target();
    if(sx::socks5::target_setup_succeeded(selected, prepared)) {
        _dia("process_dns_response: waiting for policy check");

    } else {
        _dia("process_dns_response: unable to find destination address for the request");
        ret = false;
    }

    return ret;
}




void ExplicitProxyCX::setup_dns_async(std::string const& fqdn, DNS_Record_Type type, AddressInfo const& nameserver) {
    uint16_t request_id = 0;
    int dns_sock = DNSFactory::get().send_dns_request(fqdn, type, nameserver, &request_id);
    if (sx::explicit_proxy::valid_dns_socket(dns_sock)) {
        _dia("setup_dns_async: request sent: %s", fqdn.c_str());

        using std::placeholders::_1;
        async_dns_query_ = std::make_unique<AsyncDnsQuery>(this, request_id, fqdn, type,
                                            std::bind(&ExplicitProxyCX::dns_response_callback, this,
                                                      _1));

        switch (type) {
            case AAAA:
                tested_dns_aaaa = true;
                break;
            case A:
                [[fallthrough]];
            default:
                tested_dns_a = true;
        }

        if(async_dns_query_->tap(dns_sock)) {
            state_ = socks5_state::DNS_QUERY_SENT;
        } else {
            _err("failed to register dns request socket %d", dns_sock);
            ::close(dns_sock);
            async_dns_query_.reset();
            state_ = socks5_state::DNS_RESP_FAILED;
            com()->set_monitor(socket());
            com()->set_write_monitor(socket());
        }
    } else {
        _err("failed to send dns request: %s", fqdn.c_str());
        state_ = socks5_state::DNS_RESP_FAILED;
        com()->set_monitor(socket());
        com()->set_write_monitor(socket());
    }
}

explicit_request_error ExplicitProxyCX::resolve_connect_target() {

    if(req_str_addr.empty()) return socks5_request_error::MALFORMED_DATA;

    com()->nonlocal_dst_port() = req_port;
    com()->nonlocal_src(true);
    _dia("handle5_connect: request (FQDN) for %s -> %s:%d",c_type(),com()->nonlocal_dst_host().c_str(),com()->nonlocal_dst_port());

    std::vector<std::string> target_ips;

    struct sockaddr_storage _ss{};
    com()->resolve_socket_src(socket(), nullptr, nullptr, &_ss);
    auto ipver = com()->l3_proto();

    // Some implementations use atype FQDN, but target is an IP address
    auto* adr_as_fqdn = cidr::cidr_from_str(req_str_addr.c_str());
    if(adr_as_fqdn != nullptr) {
        // hmm, it's an address
        cidr_free(adr_as_fqdn);

        target_ips.push_back(req_str_addr);
    } else {
        // really FQDN.

        auto lc_ = std::scoped_lock(DNS::get_dns_lock());

        auto dns_resp = DNS::get_dns_cache().get(( ipver == AF_INET6 ? "AAAA:" : "A:")+req_str_addr);
        if(dns_resp) {
            target_ips = sx::explicit_proxy::fresh_dns_addresses(dns_resp);
            for (auto const& target : target_ips)
                _dia("handle5_connect_fqdn: cache candidate: %s", target.c_str());
        }
    }


    // cache is not populated - send out query
    if(target_ips.empty()) {
        // no targets, send DNS query
        const auto query_order = sx::explicit_proxy::dns_query_order(
            ipver, prefer_ipv6, mixed_ip_versions);

        if(!async_dns_) {
            const bool resolved = sx::explicit_proxy::resolve_first_available(
                query_order, [&](DNS_Record_Type type) {
                    auto const& nameserver = DNS_Setup::choose_dns_server(
                        type == AAAA ? AF_INET6 : AF_INET);
                    std::shared_ptr<DNS_Response> response(
                        DNSFactory::get().resolve_dns_s(
                            req_str_addr, type, nameserver));
                    return process_dns_response(std::move(response));
                });
            if(!resolved) {
                state_ = socks5_state::DNS_RESP_FAILED;
                error(true);
            }

        } else {
            _dia("handle5_connect:");
            const auto dns_req_type = query_order.front();
            auto const& nameserver = DNS_Setup::choose_dns_server(
                dns_req_type == AAAA ? AF_INET6 : AF_INET);
            setup_dns_async(req_str_addr, dns_req_type, nameserver);
        }
    }
    else {
        const bool selected = !target_ips.empty() && choose_server_ip(target_ips);
        const bool prepared = selected && setup_target();
        if(sx::socks5::target_setup_succeeded(selected, prepared)) {
            return socks5_request_error::NONE;
        } else {
            _err("handle5_connect: unable to find destination address for the request");
            error(true);
            return socks5_request_error::MALFORMED_DATA;
        }
    }

    return socks5_request_error::NONE;
}

socks5_request_error socksServerCX::handle4_connect() {
    _dia("handle4_connect: socks4");

    if(readbuf()->size() < 8) {
        _dia("handle4_connect: socks4 request header too short");
        return socks5_request_error::MALFORMED_DATA;
    }

    state_ = socks5_state::REQ_RECEIVED;
    _dia("process_socks_request: socks4 request received");

    req_port = ntohs(readbuf()->get_at<uint16_t>(2));
    if(!sx::socks5::target_port_is_valid(req_cmd, req_port))
        return socks5_request_error::MALFORMED_DATA;
    if(auto domain = sx::socks5::socks4a_domain(
            readbuf()->data(), req_hdr_size); domain) {
        req_atype = socks5_atype::FQDN;
        return prepare_connect_target(std::string(*domain), req_port);
    }

    req_atype = socks5_atype::IPV4;
    auto dst = readbuf()->get_at<uint32_t>(4);


    req_addr.ss = sockaddr_storage{};
    req_addr.family = AF_INET;
    req_addr.as_v4()->sin_family = AF_INET;
    req_addr.as_v4()->sin_addr.s_addr= dst;
    req_addr.as_v4()->sin_port = sx::socks5::sockaddr_port(req_port);

    req_addr.unpack();

    if(sx::explicit_proxy::is_unspecified_address(req_addr.str_host))
        return socks5_request_error::MALFORMED_DATA;

    com()->nonlocal_dst_host() = req_addr.str_host;
    com()->nonlocal_dst_port() = req_port;
    com()->nonlocal_src(true);
    _dia("process_socks_request: request (SOCKSv4) for %s -> %s:%d",c_type(),com()->nonlocal_dst_host().c_str(),com()->nonlocal_dst_port());

    if(not sx::socks5::target_setup_succeeded(true, setup_target())) {
        _err("handle4_connect: target setup failed");
        return socks5_request_error::MALFORMED_DATA;
    }

    return socks5_request_error::NONE;
}

explicit_request_error ExplicitProxyCX::prepare_connect_target(
        std::string const& target_host, unsigned short target_port) {
    if(target_host.empty() or target_port == 0) {
        return socks5_request_error::MALFORMED_DATA;
    }

    req_str_addr = target_host;
    req_port = target_port;
    state_ = socks5_state::REQ_RECEIVED;

    return resolve_connect_target();
}

socks5_request_error socksServerCX::socks5_parse_request() {

    auto authorize_if_udp = [this](std::string const& server, unsigned short srv_port) -> bool {
        if(com()->l4_proto() == SOCK_DGRAM) {
            auto associations = UDP::db();
            auto lock = std::scoped_lock(UDP::lock);
            auto* control = claim_udp_association_locked(
                *associations, host(), port());
            if(control && control->get_udp()->make_authorized(server, srv_port))
                return true;

            _err("authorize_if_udp: UDP violating original target restrictions");
            error(true);
            if(control) {
                _dia("authorize_if_udp: revoking UDP association control channel");
                auto& association = control->get_udp();
                auto found = associations->clients.find(association->my_assoc);
                if(found != associations->clients.end() && found->second == control)
                    associations->clients.erase(found);
                association->my_assoc.clear();
                if(sx::socks5::pollable_control_socket(control->socket()))
                    ::shutdown(control->socket(), SHUT_RDWR);
            }
            return false;
        }
        return true;
    };


    auto atype   = static_cast<socks5_atype>(readbuf()->get_at<unsigned char>(3));

    if(atype != socks5_atype::IPV4 && atype != socks5_atype::IPV6 && atype != socks5_atype::FQDN) {
        return socks5_request_error::UNSUPPORTED_ATYPE;
    }

    if(atype == socks5_atype::FQDN) {
        req_atype = socks5_atype::FQDN;
        state_ = socks5_state::REQ_RECEIVED;

        auto fqdn_sz = readbuf()->get_at<unsigned char>(4);
        if(fqdn_sz == 0 || static_cast<std::size_t>(fqdn_sz) + 7 > readbuf()->size()) {
            _err("handle5_connect: protocol error: request header out of boundary.");
            return socks5_request_error_::MALFORMED_DATA;
        }
        if(!sx::socks5::is_unambiguous_domain(
                readbuf()->data() + 5, fqdn_sz)) {
            _err("handle5_connect: protocol error: ambiguous FQDN identity");
            return socks5_request_error_::MALFORMED_DATA;
        }

        _dia("handle5_connect: fqdn size: %d",fqdn_sz);
        std::string fqdn((const char*)&readbuf()->data()[5],fqdn_sz);
        _dia("handle5_connect: fqdn requested: %s",fqdn.c_str());
        req_str_addr = fqdn;

        req_port = ntohs(readbuf()->get_at<uint16_t>(5+fqdn_sz));
        _dia("handle5_connect: port requested: %d",req_port);

        if(!sx::socks5::target_port_is_valid(req_cmd, req_port))
            return socks5_request_error::MALFORMED_DATA;

        req_hdr_size = 5 + fqdn_sz + 2;

        if(not authorize_if_udp(fqdn, req_port)) return socks5_request_error::UNAUTHORIZED;

    }
    else if(atype == socks5_atype::IPV4 or atype == socks5_atype::IPV6) {

        req_atype = atype;
        state_ = socks5_state::REQ_RECEIVED;
        _dia("handle5_connect: request received, type %d", atype);

        req_addr.ss = sockaddr_storage {};

        if(atype == socks5_atype::IPV4) {
            auto dst = readbuf()->get_at<uint32_t>(4);
            req_port = ntohs(readbuf()->get_at<uint16_t>(8));
            _dia("handle5_connect: request IPv4 for %s -> %s:%d",c_type(),com()->nonlocal_dst_host().c_str(),com()->nonlocal_dst_port());
            req_hdr_size = 10;

            req_addr.family = AF_INET;
            req_addr.as_v4()->sin_family = AF_INET;
            req_addr.as_v4()->sin_addr.s_addr = dst;
            req_addr.as_v4()->sin_port = sx::socks5::sockaddr_port(req_port);
            req_addr.unpack();

        }
        else if(atype == socks5_atype::IPV6) {

            auto arr6 = readbuf()->copy_from<16>(4);
            req_port = ntohs(readbuf()->get_at<uint16_t>(20));
            _dia("handle5_connect: request IPv6 for %s -> %s:%d",c_type(),com()->nonlocal_dst_host().c_str(),com()->nonlocal_dst_port());
            req_hdr_size = 22;

            req_addr.family = AF_INET6;
            req_addr.as_v6()->sin6_family = AF_INET6;
            std::memcpy(&req_addr.as_v6()->sin6_addr, arr6.data(), 16);
            req_addr.as_v6()->sin6_port = sx::socks5::sockaddr_port(req_port);
            req_addr.unpack();
        }

        if(req_cmd != socks5_cmd::UDP_ASSOCIATE &&
           sx::explicit_proxy::is_unspecified_address(req_addr.str_host))
            return socks5_request_error::MALFORMED_DATA;

        com()->nonlocal_dst_host() = req_addr.str_host;
        com()->nonlocal_dst_port() = req_port;
        com()->nonlocal_src(true);
        _dia("handle5_connect: request for %s -> %s:%d",c_type(),com()->nonlocal_dst_host().c_str(),com()->nonlocal_dst_port());

        if(!sx::socks5::target_port_is_valid(req_cmd, req_port))
            return socks5_request_error::MALFORMED_DATA;
        if(not authorize_if_udp(com()->nonlocal_dst_host(), req_port)) return socks5_request_error::UNAUTHORIZED;



    } else {

        _err("handle5_connect address type %d", atype);
        return socks5_request_error::UNSUPPORTED_ATYPE;
    }

    return socks5_request_error::NONE;
}

socks5_request_error socksServerCX::handle5_connect() {

    auto parse_status = socks5_parse_request();

    // A semantically invalid datagram must be consumed without poisoning its
    // reusable virtual flow. Association lookup is meaningful only after the
    // parser has validated and authorized a complete destination.
    if(parse_status == socks5_request_error::NONE &&
       com()->l4_proto() == SOCK_DGRAM) {

        // check if we are in associated clients
        auto ass = UDP::db();
        auto lc_ = std::scoped_lock(UDP::lock);

        auto key = string_format("%s:%s", host().c_str(), port().c_str());
        if(ass->clients.find(key) == ass->clients.end()) {
            error(true);
            _not("handle5_connect: UDP client not properly associated");
            return socks5_request_error::UNAUTHORIZED;
        }
        else {
            _dia("handle5_connect: UDP client association found");
        }
    }

    if(parse_status == socks5_request_error::NONE) {

        if (req_atype == socks5_atype::FQDN) {
            return handle5_connect_fqdn();

        }
        else if (req_atype == socks5_atype::IPV4 or req_atype == socks5_atype::IPV6) {

            if (not setup_target()) {
                return socks5_request_error::MALFORMED_DATA;
            }
        }
        else {
            _err("handle5_connect address type %d", req_atype);
            return socks5_request_error::UNSUPPORTED_ATYPE;
        }

        return socks5_request_error::NONE;
    }
    else {
        return parse_status;
    }
}


std::size_t socksServerCX::process_socks_request() {

    socks_error_ = socks5_request_error::NONE;
    
    _dia("socksServerCX::process_socks_request");

    try {
        if (state_ == socks5_state::DNS_QUERY_SENT) {
            _dia("process_socks_request: triggered when waiting for DNS response");
            return 0;
        }

        _dum("Request dump:\r\n%s", hex_dump(readbuf()->data(), readbuf()->size(), 4, 0, true).c_str());

        if(readbuf()->size() < 2)
            return 0;

        const auto request_version = readbuf()->get_at<unsigned char>(0);
        // A successful SOCKS5 method negotiation binds the remainder of the
        // control connection to SOCKS5.  Reinterpreting the next frame as a
        // fresh SOCKS4 handshake creates a cross-version state transition
        // which neither protocol permits.
        if(state_ == socks5_state::WAIT_REQUEST &&
           !sx::socks5::request_version_matches_negotiation(
               version, request_version)) {
            version = request_version;
            socks_error_ = socks5_request_error::UNSUPPORTED_VERSION;
            error(true);
            return 0;
        }
        version = request_version;
        req_cmd = readbuf()->get_at<unsigned char>(1);
        //@2 is reserved

        if (version == 5) {
            if(readbuf()->size() < 4)
                return 0;
            if(readbuf()->get_at<unsigned char>(2) != 0) {
                socks_error_ = socks5_request_error::MALFORMED_DATA;
            } else if(sx::socks5::request_size_if_complete(
                          readbuf()->data(), readbuf()->size()) == 0) {
                _dia("process_socks_request: incomplete socks5 request");
                return 0;
            } else if (req_cmd == socks5_cmd::CONNECT) {
                socks_error_ = handle5_connect();
            } else if (req_cmd == socks5_cmd::UDP_ASSOCIATE) {
                // let's just handle the response
                socks_error_ = socks5_parse_request();
                wait_policy();
            } else {
                socks_error_ = socks5_request_error::UNSUPPORTED_METHOD;
            }
        } else if (version == 4) {
            req_hdr_size = sx::socks5::socks4_request_size_if_complete(
                readbuf()->data(), readbuf()->size());
            if(req_hdr_size == 0) {
                if(readbuf()->size() <
                   sx::socks5::maximum_socks4_request_size)
                    return 0;
                socks_error_ = socks5_request_error::MALFORMED_DATA;
                error(true);
                return 0;
            }
            if(req_hdr_size > sx::socks5::maximum_socks4_request_size) {
                socks_error_ = socks5_request_error::MALFORMED_DATA;
            } else if(req_cmd != socks5_cmd::CONNECT) {
                socks_error_ = socks5_request_error::UNSUPPORTED_METHOD;
            } else if(sx::socks5::is_socks4a(
                          readbuf()->data(), req_hdr_size) &&
                      !sx::socks5::socks4a_domain(
                          readbuf()->data(), req_hdr_size)) {
                socks_error_ = socks5_request_error::MALFORMED_DATA;
            } else {
                socks_error_ = handle4_connect();
            }
        } else {
            socks_error_ = socks5_request_error::UNSUPPORTED_VERSION;
        }
    }
    catch(std::out_of_range const&) {
        socks_error_ = socks5_request_error::MALFORMED_DATA;
    }


    if(socks_error_ != socks5_request_error_::NONE) {
        _dia("process_socks_request: error %d", socks_error_);
        const bool replyable_v5_error = version == 5 &&
            (socks_error_ == socks5_request_error::UNSUPPORTED_METHOD ||
             socks_error_ == socks5_request_error::UNSUPPORTED_ATYPE);
        const bool replyable_v4_error = version == 4 &&
            socks_error_ == socks5_request_error::UNSUPPORTED_METHOD;
        if(!replyable_v5_error && !replyable_v4_error)
            error(true);
    }


    // TCP framing is retained explicitly (auto_finish is disabled). The
    // context is handed off or closed after this point, and setup_target()
    // has copied any bytes following the request into the replacement client
    // context. Keeping the original bytes here also covers asynchronous DNS.
    return com()->l4_proto() == SOCK_DGRAM ? readbuf()->size() : 0;
}

bool ExplicitProxyCX::setup_target() {
        // prepare a new CX!

        // Resolve and validate the accepted endpoint before constructing a
        // replacement which would otherwise temporarily own the same socket.
        const auto source = sx::explicit_proxy::resolve_source_endpoint(
            socket(), [this](int descriptor, std::string* host, std::string* port) {
                return com()->resolve_socket_src(descriptor, host, port);
            });
        if(not source) {
            _err("ExplicitProxyCX::setup_target: cannot resolve source endpoint");
            return false;
        }

        // LEFT
        int s = socket();
        
        baseCom* new_com = nullptr;
        switch(com()->nonlocal_dst_port()) {
            case 443:
            case 465:
            case 636:
            case 993:
            case 995:

                if(com()->l4_proto() != SOCK_DGRAM) {
                    is_ssl = true;

                    _dia("setup_target: TLS port");
                    new_com = new baseSSLMitmCom<SSLCom>();
                    break;
                }
                else {
                    _dia("setup_target: UDP on TLS port");
                }
                [[fallthrough]];
            default:
                new_com = (com()->l4_proto() == SOCK_DGRAM) ? (baseCom*) new UDPCom() : (baseCom*) new TCPCom();
        }

        auto* n_cx = new MitmHostCX(new_com, s);
        n_cx->waiting_for_peercom(true);

        n_cx->com()->nonlocal_dst(true);
        n_cx->com()->nonlocal_dst_host() = com()->nonlocal_dst_host();
        n_cx->com()->nonlocal_dst_port() = com()->nonlocal_dst_port();
        n_cx->com()->nonlocal_dst_resolved(true);

        if(com()->l4_proto() == SOCK_DGRAM) {
            _dia("setup_target: UDP");
            // with UDP, we receive data with the request, n_cx must have it
            readbuf()->flush(req_hdr_size);
            n_cx->readbuf()->append(readbuf()->data(), readbuf()->size());
        } else if(req_hdr_size > 0 && readbuf()->size() > req_hdr_size) {
            // Preserve a pipelined TLS ClientHello or application payload
            // which arrived in the same read as any explicit CONNECT
            // frontend request (SOCKS or HTTP CONNECT).
            n_cx->readbuf()->append(readbuf()->data() + req_hdr_size,
                                    readbuf()->size() - req_hdr_size);
        }

        // Use of "left" differs between UDP and TCP.
        // TCP - n_cx ("left") replaces current SocksServerCX on the left side of proxy.
        //       This is desirable, at this point SOCKS protocol is not anymore involved.
        //
        // UDP - n_cx ("left") will NOT replace SocksServerCX on the left side,
        //       because all traffic between client on the left and this proxy still talks SOCKS.
        //       UDP payload is always prepended with SOCKS CONNECT request, and its response
        //       is expected to be received back => it *cannot* be replaced with vanilla proxy.

        // for now, move its ownership!
        left.reset(std::move(n_cx));
        _dia("setup_target: prepared left: %s",left->c_type());

        
        // RIGHT
        auto *target_cx = new MitmHostCX(com()->slave(), com()->nonlocal_dst_host().c_str(),
                                            string_format("%d",com()->nonlocal_dst_port()).c_str()
                                            );
        target_cx->waiting_for_peercom(true);
        

        
        target_cx->com()->nonlocal_src(false);
        target_cx->com()->nonlocal_src_host() = source->host;
        target_cx->com()->nonlocal_src_port() = source->port;



        // move pointer's ownership!
        right.reset(target_cx);
        _dia("setup_target: prepared right: %s",right->c_type());
        
        wait_policy();
        
        return true;
}

bool ExplicitProxyCX::new_message() const {
    if(auto const* socks = dynamic_cast<socksServerCX const*>(this);
       socks != nullptr && socks->com()->l4_proto() != SOCK_DGRAM &&
       request_error_ != explicit_request_error::NONE &&
       state_ != explicit_state::REQRES_SENT &&
       state_ != explicit_state::HANDOFF && state_ != explicit_state::ZOMBIE)
        return true;

    if(state_ == socks5_state::WAIT_POLICY && verdict_ == socks5_policy::PENDING) {
        _dia("new_message: policy pending");
        return true;

    }
    if(state_ == socks5_state::HANDOFF) {
        auto const* socks = dynamic_cast<socksServerCX const*>(this);
        if(socks != nullptr &&
           socks->request_command() == socks5_cmd::UDP_ASSOCIATE)
            return false;
    }
    _dia("new_message: %s", state_ == socks5_state::HANDOFF ? "handoff" : "other");
    return state_ == socks5_state::HANDOFF;
}

void socksServerCX::verdict(socks5_policy p) {
        if(p == socks5_policy::ACCEPT and req_cmd == socks5_cmd::UDP_ASSOCIATE) {
            // create source port associate

            auto ass = UDP::db();

            auto lc_ = std::scoped_lock(UDP::lock);

            auto key = string_format("%s:%d", host().c_str(), req_port);
            auto [entry, inserted] = ass->clients.emplace(key, this);
            if(!inserted && entry->second != this) {
                _err("verdict: conflicting UDP association for %s", key.c_str());
                p = socks5_policy::REJECT;
            } else {
                auto& udp = get_udp();
                udp->my_assoc = key;
            }
        }
        ExplicitProxyCX::verdict(p);
}

void ExplicitProxyCX::verdict(explicit_policy p) {
    verdict_ = p;
    state_ = explicit_state::POLICY_RECEIVED;
    if(verdict_ == explicit_policy::ACCEPT || verdict_ == explicit_policy::REJECT) {
        _dia("verdict: policy received: %d", verdict_);
        process_proxy_reply();
    }
}

std::size_t socksServerCX::process_socks_reply_v5() {

    std::array<uint8_t, sx::socks5::maximum_tcp_reply_size> response {0};

    response[0] = 5;
    response[1] = 2; // denied
    if(verdict_ == socks5_policy::ACCEPT) response[1] = 0; //accept

    response[2] = 0;
    int cur_data_ptr = 3;

    if(verdict_ != socks5_policy::ACCEPT) {
        close_after_write(true);
        switch(socks_error_) {
            case socks5_request_error::UNSUPPORTED_METHOD:
                response[1] = 7;
                break;
            case socks5_request_error::UNSUPPORTED_ATYPE:
                response[1] = 8;
                break;
            case socks5_request_error::MALFORMED_DATA:
            case socks5_request_error::UNSUPPORTED_VERSION:
                response[1] = 1;
                break;
            case socks5_request_error::NONE:
            case socks5_request_error::UNAUTHORIZED:
                break;
        }
        response[3] = static_cast<uint8_t>(socks5_atype::IPV4);
        cur_data_ptr = 10;
        goto reply_ready;
    }

    if(req_cmd == socks5_cmd::CONNECT) {
        response[3] = static_cast<uint8_t>(req_atype);
        ++cur_data_ptr;

        if (req_atype == socks5_atype::IPV4) {
            std::memcpy(&response[cur_data_ptr],
                        &req_addr.as_v4()->sin_addr.s_addr, sizeof(uint32_t));
            cur_data_ptr += sizeof(uint32_t);

            const auto network_port = htons(req_port);
            std::memcpy(&response[cur_data_ptr], &network_port, sizeof(network_port));
            cur_data_ptr += sizeof(uint16_t);

        } else if (req_atype == socks5_atype::IPV6) {
            std::memcpy(&response[cur_data_ptr], &req_addr.as_v6()->sin6_addr, sizeof(in6_addr));
            cur_data_ptr += sizeof(in6_addr);

            const auto network_port = htons(req_port);
            std::memcpy(&response[cur_data_ptr], &network_port, sizeof(network_port));
            cur_data_ptr += sizeof(uint16_t);

        } else if (req_atype == socks5_atype::FQDN) {

            auto const reply_size = sx::socks5::domain_reply_size(req_str_addr.size());
            if(!reply_size || *reply_size > response.size()) {
                _err("process_socks_reply_v5: invalid FQDN reply size");
                response[1] = 1;
                response[3] = static_cast<uint8_t>(socks5_atype::IPV4);
                cur_data_ptr = 10;
                goto reply_ready;
            }

            response[cur_data_ptr] = (unsigned char) req_str_addr.size();
            cur_data_ptr++;

            for (char c: req_str_addr) {
                response[cur_data_ptr] = c;
                cur_data_ptr++;
            }

            const auto network_port = htons(req_port);
            std::memcpy(&response[cur_data_ptr], &network_port, sizeof(network_port));
            cur_data_ptr += sizeof(uint16_t);
        }
    }
    else if(req_cmd == socks5_cmd::UDP_ASSOCIATE) {
        response[3] = 1u;
        ++cur_data_ptr;

        const uint32_t any_address = 0;
        std::memcpy(&response[cur_data_ptr], &any_address, sizeof(any_address));
        cur_data_ptr += sizeof(uint32_t);

        std::string relay_port_text;
        const bool relay_resolved = com()->resolve_socket_dst(
            socket(), nullptr, &relay_port_text);
        const auto relay_port = relay_resolved
            ? sx::explicit_proxy::parse_source_port(relay_port_text)
            : std::nullopt;
        if(!sx::socks5::udp_relay_endpoint_ready(relay_resolved, relay_port)) {
            _err("process_socks_reply_v5: cannot resolve UDP relay port");
            response[1] = 1; // general SOCKS server failure
            // verdict() has already registered this control association. A
            // failure reply must not leave authorization live behind it.
            retire_udp_association();
            close_after_write(true);
        }
        const auto network_port = htons(relay_port.value_or(0));
        std::memcpy(&response[cur_data_ptr], &network_port, sizeof(network_port));
        cur_data_ptr += sizeof(uint16_t);
    }

reply_ready:
    writebuf()->append(response.data(), cur_data_ptr);
    state_ = socks5_state::REQRES_SENT;

    _dum("socksServerCX::process_socks_reply: response dump:\r\n%s",hex_dump(response.data(), cur_data_ptr, 4, 0, true).c_str());

    // response is about to be sent. In most cases client sends data on left,
    // but in case it's waiting ie. for banner, we must trigger proxy code to
    // actually connect the right side.
    // Because now are all data handled, there is no way how we get to proxy code,
    // unless:
    //      * new data appears on left
    //      * some error occurs on left
    //      * other way how socket appears in epoll result.
    //
    // we can achieve that to simply put left socket to write monitor.
    // This will make left socket writable (dummy - we don't have anything to write),
    // but also triggers proxy's on_message().

    com()->set_write_monitor(socket());

    _dia("process_socks_reply_v5: finished");
    return cur_data_ptr;

}

int socksServerCX::process_socks_reply_v4() {
    unsigned char b[8];

    b[0] = 0;
    b[1] = 91; // denied
    if(verdict_ == socks5_policy::ACCEPT) b[1] = 90; //accept
    else close_after_write(true);

    const auto network_port = verdict_ == socks5_policy::ACCEPT
        ? htons(req_port) : uint16_t{0};
    std::memcpy(&b[2], &network_port, sizeof(network_port));
    const auto network_address = verdict_ == socks5_policy::ACCEPT
        ? req_addr.as_v4()->sin_addr.s_addr : uint32_t{0};
    std::memcpy(&b[4], &network_address, sizeof(network_address));

    writebuf()->append(b,8);
    state_ = socks5_state::REQRES_SENT;

    _dia("process_socks_reply_v4: finished");
    return 8;

}

std::size_t socksServerCX::process_proxy_reply() {

    _dia("process_socks_reply: version %d", version);

    if(verdict_ == socks5_policy::ACCEPT && req_cmd == socks5_cmd::CONNECT &&
       (version == 4 || version == 5)) {
        // CONNECT success is meaningful only after the nonblocking upstream
        // connect completes.  Keep the same flush-driven transition so a
        // pipelined SOCKS5 method reply leaves before the frontend handoff;
        // ExplicitProxy will send the final protocol reply afterwards.
        state_ = socks5_state::REQRES_SENT;
        com()->set_write_monitor(socket());
        return 0;
    }

    switch(version) {
        case 4:
            return process_socks_reply_v4();
        case 5:
            return process_socks_reply_v5();
        case 0:
            if(com()->l4_proto() == SOCK_DGRAM) {
                _dia("process_socks_reply: version 0 - ok");
                break;
            }
            [[fallthrough]];

        default:
            _err("process_socks_reply: unknown version");
    }

    return 0;
}

std::string_view socksServerCX::upstream_success_response() const {
    static constexpr char socks5[] = {
        0x05, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    };
    static constexpr char socks4[] = {
        0x00, 0x5a, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    };
    if(version == 5) return {socks5, sizeof(socks5)};
    if(version == 4) return {socks4, sizeof(socks4)};
    return {};
}

std::string_view socksServerCX::upstream_failure_response() const {
    static constexpr char socks5[] = {
        0x05, 0x05, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    };
    static constexpr char socks4[] = {
        0x00, 0x5b, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    };
    if(version == 5) return {socks5, sizeof(socks5)};
    if(version == 4) return {socks4, sizeof(socks4)};
    return {};
}

void ExplicitProxyCX::pre_write() {
    _deb("socksServerCX::pre_write[%s]: writebuf=%d, readbuf=%d",c_type(),writebuf()->size(),readbuf()->size());
    if(state_ == socks5_state::HELLO_SENT) {
        // HELLO_SENT is retained only for the terminal 0xff authentication
        // response. Close after the response has actually left the buffer.
        if(writebuf()->empty())
            error(true);
    }
    else if(state_ == socks5_state::REQRES_SENT ) {
        if(writebuf()->empty()) {
            _dia("socksServerCX::pre_write[%s]: all flushed, state change to HANDOFF: writebuf=%d, readbuf=%d",c_type(),writebuf()->size(),readbuf()->size());
            // A UDP association has no stream peer to wait for. Keep the TCP
            // control channel readable so its EOF terminates the association.
            auto const* socks = dynamic_cast<socksServerCX const*>(this);
            bool const udp_association = socks != nullptr &&
                socks->request_command() == socks5_cmd::UDP_ASSOCIATE;
            waiting_for_peercom(!udp_association);
            state(socks5_state::HANDOFF);
            if(udp_association)
                com()->set_monitor(socket());
        }
    }
    else if(state_ == socks5_state::DNS_RESP_FAILED) {
        auto const retry = sx::explicit_proxy::next_dns_retry(
            mixed_ip_versions, tested_dns_a, tested_dns_aaaa);
        if (!retry) {
            _deb("socksServerCX::pre_write[%s]: dns failed", c_type());
            error(true);
        } else if (*retry == AAAA) {
            _dia("socksServerCX::pre_write[%s]: trying DNS AAAA query", c_type());
            tested_dns_aaaa = true;
            auto const& nameserver = DNS_Setup::choose_dns_server(AF_INET6);
            setup_dns_async(req_str_addr, AAAA, nameserver);
        } else {
            _dia("socksServerCX::pre_write[%s]: trying DNS A query", c_type());
            tested_dns_a = true;
            auto const& nameserver = DNS_Setup::choose_dns_server(AF_INET);
            setup_dns_async(req_str_addr, A, nameserver);
        }
    }
}


void ExplicitProxyCX::dns_response_callback(dns_response_t const& rresp) {

    auto resp = std::shared_ptr<DNS_Response>(rresp.first);
    int red = rresp.second;
    state_ = socks5_state::DNS_RESP_RECV;

    if(red <= 0) {
        _deb("handle_event: socket read returned %d",red);
        state_ = socks5_state::DNS_RESP_FAILED;
    } else {
        _deb("handle_event: OK - socket read returned %d",red);
        if(process_dns_response(resp)) {
            _deb("handle_event: OK, done");
        } else {
            _err("handle_event: processing DNS response failed.");
            state_ = socks5_state::DNS_RESP_FAILED;
        }
    }

    //provoke proxy to act.
    com()->set_monitor(socket());
    com()->set_write_monitor(socket());
}


void ExplicitProxyCX::handle_event (baseCom *xcom) {
}

std::size_t socksServerCX::process_socks_response() {
    state_ = socks5_state::INIT;

    buffer b(writebuf()->size() + 200);

    sx::socks5::store_network_u16(&b.data()[0], 0);
    b.data()[2] = 0;

    b.data()[3] = static_cast<uint8_t>(req_atype);
    b.size(4);

    if(req_atype == socks5_atype::IPV4) {
        sx::socks5::store_network_u32(
            &b.data()[4], req_addr.as_v4()->sin_addr.s_addr);
        sx::socks5::store_network_u16(&b.data()[8], req_port);
        b.size(10);
    }
    if(req_atype == socks5_atype::IPV6) {

        std::memcpy(&b.data()[4], &req_addr.as_v6()->sin6_addr, 16);
        sx::socks5::store_network_u16(&b.data()[20], req_port);
        b.size(22);
    }
    else if(req_atype == socks5_atype::FQDN) {
        b.append<>(raw::down_cast<uint8_t>(req_str_addr.size()).value_or(255));
        b.append(req_str_addr.data(), req_str_addr.size());
        b.append<>(htons(req_port));
    }


    b.append(writebuf()->data(), writebuf()->size());
    writebuf()->swap(b);
    return writebuf()->size();
}


std::size_t socksServerCX::process_out() {

    if(com()->l4_proto() != SOCK_DGRAM) {
        _dia("process_out: SOCKS5 response with %dB of proxied data", writebuf()->size());
        return writebuf()->size();
    }
    else if(state_ > socks5_state::REQ_RECEIVED) {
        _dia("process_out: SOCKS5 UDP response header will prefix %dB of proxied data", writebuf()->size());
        return process_socks_response();
    }
    else {
        _err("process_out: unknown state, defaulting to proxy %dB", writebuf()->size());
        return writebuf()->size();
    }
}
