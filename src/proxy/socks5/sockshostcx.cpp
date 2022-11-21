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
#include <inspect/dnsinspector.hpp>

#include <common/numops.hpp>

bool socksServerCX::global_async_dns = true;

socksServerCX::socksServerCX(baseCom* c, unsigned int s) : MitmHostCX(c,s) {
    state_ = socks5_state::INIT;

    // copy setting from global/static variable - don't allow to change async
    // flag on the background during the object life
    async_dns = global_async_dns;
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
        default:
            _dia("process_in: state *");
            break;
    }
    
    return 0;
}

std::size_t socksServerCX::process_socks_udp_request() {
    buffer const *b = readbuf();
    if (b->size() < 4) {
        // minimal size of "client hello" is 3 bytes
        return 0;
    }

    [[maybe_unused]]    uint16_t reserved = b->get_at<uint8_t>(0);
    [[maybe_unused]]    uint8_t fragment = b->get_at<uint8_t>(2);

    req_cmd = socks5_cmd::CONNECT;
    req_atype = static_cast<socks5_atype>( b->get_at<uint8_t>(3));

    try {
        _dia("process_socks_udp_request: request size %d, fragment %d, atype %d", b->size(), fragment, req_atype);
        auto err = handle5_connect();

        if(err != socks5_request_error::NONE) {
            _dia("process_socks_udp_request: ok");
            return 0;
        }
    }
    catch(std::out_of_range const&) {
        _dia("process_socks_udp_request: error");
        return 0;
    }

    // there is actually no response sent in UDP proxy case

    read_force_eagain();

    return b->size();
}

std::size_t socksServerCX::process_socks_hello_tcp() {

    buffer const* b = readbuf();
    if (b->size() < 3) {
        // minimal size of "client hello" is 3 bytes
        return 0;
    }
    version = b->get_at<unsigned char>(0);
    unsigned char nmethods = b->get_at<unsigned char>(1);

    if (b->size() < (unsigned int) (2 + nmethods)) {
        return 0;
    }

    // at this stage we have full client hello received
    if (version == 5) {
        _dia("process_socks_hello_tcp: version %d", version);

        unsigned char server_hello[2];
        server_hello[0] = 5; // version
        server_hello[1] = 0; // no authentication

        writebuf()->append(server_hello, 2);
        state_ = socks5_state::HELLO_SENT;
        state_ = socks5_state::WAIT_REQUEST;

        // flush all data, assuming
        return b->size();
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

bool socksServerCX::choose_server_ip(std::vector<std::string>& target_ips) {

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

bool socksServerCX::process_dns_response(std::shared_ptr<DNS_Response> resp) {

    std::vector<std::string> target_ips;
    bool ret = true;

    if (resp) {
        for (auto const& a: resp->answers()) {
            std::string a_ip = a.ip(false);
            if (! a_ip.empty()) {
                _dia("process_dns_response: target candidate: %s", a_ip.c_str());
                target_ips.push_back(a_ip);
            }
        }

        if (! target_ips.empty()) {

            DNS_Inspector di;
            di.store(resp);
        }
    }

    if(!target_ips.empty() && choose_server_ip(target_ips)) {
        setup_target();
        _dia("process_dns_response: waiting for policy check");

    } else {
        _dia("process_dns_response: unable to find destination address for the request");
        ret = false;
    }

    return ret;
}




void socksServerCX::setup_dns_async(std::string const& fqdn, DNS_Record_Type type, AddressInfo const& nameserver) {
    int dns_sock = DNSFactory::get().send_dns_request(fqdn, type, nameserver);
    if (dns_sock) {
        _dia("setup_dns_async: request sent: %s", fqdn.c_str());

        using std::placeholders::_1;
        async_dns_query = std::make_unique<AsyncDnsQuery>(this,
                                            std::bind(&socksServerCX::dns_response_callback, this,
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

        async_dns_query->tap(dns_sock);
        state_ = socks5_state::DNS_QUERY_SENT;
    } else {
        _err("failed to send dns request: %s", fqdn.c_str());
        error(true);
    }
}

socks5_request_error socksServerCX::handle5_connect_fqdn() {

    if(req_str_addr.empty()) return socks5_request_error::MALFORMED_DATA;

    auto fill_w_dns_cache = [this](std::shared_ptr<DNS_Response> const& dns_resp, std::vector<std::string> where) {
        if ( ! dns_resp->answers().empty() ) {
            long ttl = (dns_resp->loaded_at + dns_resp->answers().at(0).ttl_) - time(nullptr);
            if(ttl > 0) {
                for( auto const& a: dns_resp->answers() ) {
                    std::string a_ip = a.ip(false);
                    if(! a_ip.empty() ) {
                        _dia("handle5_connect_fqdn: cache candidate: %s",a_ip.c_str());
                        where.push_back(a_ip);
                    }
                }
            }
        }
    };

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
            fill_w_dns_cache(dns_resp, target_ips);
        }
    }


    // cache is not populated - send out query
    if(target_ips.empty()) {
        // no targets, send DNS query

        auto const& nameserver = DNS_Setup::choose_dns_server(ipver);

        if(!async_dns) {

            std::shared_ptr<DNS_Response> resp(DNSFactory::get().resolve_dns_s(req_str_addr, A, nameserver));

            process_dns_response(resp);
            setup_target();

        } else {
            _dia("handle5_connect:");

            auto dns_req_type = DNS_Record_Type::A;



            if(ipver == AF_INET6) {
                _dia("handle5_connect: carrier ipv6");
                dns_req_type = DNS_Record_Type::AAAA;
            }
            else {
                _dia("handle5_connect: carrier default");

                if(prefer_ipv6) {
                    _dia("handle5_connect: DNS override to query AAAA");
                    dns_req_type = DNS_Record_Type::AAAA;
                }
            }

            setup_dns_async(req_str_addr, dns_req_type, nameserver);
        }
    }
    else {
        if(! target_ips.empty() && choose_server_ip(target_ips)) {
            setup_target();
        } else {
            _err("handle5_connect: unable to find destination address for the request");
            error(true);
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

    req_atype = socks5_atype::IPV4;
    state_ = socks5_state::REQ_RECEIVED;
    _dia("process_socks_request: socks4 request received");

    req_port = ntohs(readbuf()->get_at<uint16_t>(2));
    auto dst = readbuf()->get_at<uint32_t>(4);


    req_addr.ss = sockaddr_storage{};
    req_addr.family = AF_INET;
    req_addr.as_v4()->sin_family = AF_INET;
    req_addr.as_v4()->sin_addr.s_addr= dst;
    req_addr.as_v4()->sin_port = req_port;

    req_addr.unpack();

    com()->nonlocal_dst_host() = req_addr.str_host;
    com()->nonlocal_dst_port() = req_port;
    com()->nonlocal_src(true);
    _dia("process_socks_request: request (SOCKSv4) for %s -> %s:%d",c_type(),com()->nonlocal_dst_host().c_str(),com()->nonlocal_dst_port());

    setup_target();

    return socks5_request_error::NONE;
}

socks5_request_error socksServerCX::socks5_parse_request() {

    auto authorize_if_udp = [this](std::string const& server, unsigned short srv_port) -> bool {
        // check specific UDP requirement - with the same clientIP:port should not
        if(com()->l4_proto() == SOCK_DGRAM and not get_udp()->make_authorized(server, srv_port)) {
            _err("authorize_if_udp: UDP violating original target restrictions");
            error(true);

            auto ass = UDP::db();

            auto lc_ = std::scoped_lock(UDP::lock);
            std::string key = string_format("%s:%s", host().c_str(), port().c_str());

            auto it = ass->clients.find(key);
            if(it != ass->clients.end()) {

                auto* cx = it->second;
                if(cx) {
                    _dia("authorize_if_udp: shutting down UDP association connection");
                    cx->error(true);
                }
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
        if((unsigned int)fqdn_sz + 4 + 2 >= readbuf()->size()) {
            _err("handle5_connect: protocol error: request header out of boundary.");
            return socks5_request_error_::MALFORMED_DATA;
        }

        _dia("handle5_connect: fqdn size: %d",fqdn_sz);
        std::string fqdn((const char*)&readbuf()->data()[5],fqdn_sz);
        _dia("handle5_connect: fqdn requested: %s",fqdn.c_str());
        req_str_addr = fqdn;

        req_port = ntohs(readbuf()->get_at<uint16_t>(5+fqdn_sz));
        _dia("handle5_connect: port requested: %d",req_port);

        req_hdr_size = 5 + fqdn_sz + 2;

        if(not authorize_if_udp(fqdn, req_port)) return socks5_request_error::UNAUTHORIZED;

    }
    else if(atype == socks5_atype::IPV4 or atype == socks5_atype::IPV6) {

        req_atype = socks5_atype::IPV4;
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
            req_addr.as_v4()->sin_port = req_port;
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
            req_addr.as_v6()->sin6_port = req_port;
            req_addr.unpack();
        }

        com()->nonlocal_dst_host() = req_addr.str_host;
        com()->nonlocal_dst_port() = req_port;
        com()->nonlocal_src(true);
        _dia("handle5_connect: request for %s -> %s:%d",c_type(),com()->nonlocal_dst_host().c_str(),com()->nonlocal_dst_port());

        if(not authorize_if_udp(com()->nonlocal_dst_host(), req_port)) return socks5_request_error::UNAUTHORIZED;



    } else {

        _err("handle5_connect address type %d", atype);
        return socks5_request_error::UNSUPPORTED_ATYPE;
    }

    return socks5_request_error::NONE;
}

socks5_request_error socksServerCX::handle5_connect() {

    auto parse_status = socks5_parse_request();

    if(com()->l4_proto() == SOCK_DGRAM) {

        // check if we are in associated clients
        auto ass = UDP::db();
        auto lc_ = std::scoped_lock(UDP::lock);

        auto key = string_format("%s:%s", host().c_str(), port().c_str());
        if(ass->clients.find(key) == ass->clients.end()) {
            return socks5_request_error::UNAUTHORIZED;
            error(true);
            _not("handle5_connect: UDP client not properly associated");
        }
        else {
            _dia("handle5_connect: UDP client association found");
        }
    }

    if(parse_status == socks5_request_error::NONE) {

        if (req_atype == socks5_atype::FQDN) {
            return handle5_connect_fqdn();

        }
        else if (req_atype == socks5_atype::IPV4) {

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

        version = readbuf()->get_at<unsigned char>(0);
        req_cmd = readbuf()->get_at<unsigned char>(1);
        //@2 is reserved

        if (version == 5) {

            if (readbuf()->size() < 10) {
                _dia("process_socks_request: socks5 request header too short");
                return -1;
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
            socks_error_ = handle4_connect();
        } else {
            socks_error_ = socks5_request_error::UNSUPPORTED_VERSION;
        }
    }
    catch(std::out_of_range const&) {
        socks_error_ = socks5_request_error::MALFORMED_DATA;
    }


    if(socks_error_ != socks5_request_error_::NONE) {
        _dia("process_socks_request: error %d", socks_error_);
        error(true);
    }


    return readbuf()->size();
}

bool socksServerCX::setup_target() {
        // prepare a new CX!

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

        auto* n_cx = new socksMitmHostCX(new_com, s);
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
        std::string h;
        std::string p;
        com()->resolve_socket_src(socket(),&h,&p);

        auto *target_cx = new MitmHostCX(com()->slave(), com()->nonlocal_dst_host().c_str(),
                                            string_format("%d",com()->nonlocal_dst_port()).c_str()
                                            );
        target_cx->waiting_for_peercom(true);
        

        
        target_cx->com()->nonlocal_src(false);
        target_cx->com()->nonlocal_src_host() = h;
        target_cx->com()->nonlocal_src_port() = raw::down_cast_signed<unsigned short>(std::stoi(p)).value_or(0);



        // move pointer's ownership!
        right.reset(target_cx);
        _dia("setup_target: prepared right: %s",right->c_type());
        
        wait_policy();
        
        return true;
}

bool socksServerCX::new_message() const {
    if(state_ == socks5_state::WAIT_POLICY && verdict_ == socks5_policy::PENDING) {
        _dia("new_message: policy pending");
        return true;

    }
    _dia("new_message: %s", state_ == socks5_state::HANDOFF ? "handoff" : "other");
    return state_ == socks5_state::HANDOFF;
}

void socksServerCX::verdict(socks5_policy p) {
    verdict_ = p;
    state_ = socks5_state::POLICY_RECEIVED;

    if(verdict_ == socks5_policy::ACCEPT || verdict_ == socks5_policy::REJECT) {

        _dia("verdict: policy received: %d", verdict_);

        if(verdict_ == socks5_policy::ACCEPT and req_cmd == socks5_cmd::UDP_ASSOCIATE) {
            // create source port associate

            auto ass = UDP::db();

            auto lc_ = std::scoped_lock(UDP::lock);

            auto key = string_format("%s:%d", host().c_str(), req_port);
            ass->clients.emplace(key, this);

            auto& udp = get_udp();
            udp->my_assoc = key;
        }

        process_socks_reply();
    }
}

std::size_t socksServerCX::process_socks_reply_v5() {

    std::array<uint8_t,128> response {0};

    response[0] = 5;
    response[1] = 2; // denied
    if(verdict_ == socks5_policy::ACCEPT) response[1] = 0; //accept

    response[2] = 0;
    int cur_data_ptr = 3;

    if(req_cmd == socks5_cmd::CONNECT) {
        response[3] = static_cast<uint8_t>(req_atype);
        ++cur_data_ptr;

        if (req_atype == socks5_atype::IPV4) {
            *((uint32_t *) &response[cur_data_ptr]) = req_addr.as_v4()->sin_addr.s_addr;
            cur_data_ptr += sizeof(uint32_t);

            *((uint16_t*)&response[cur_data_ptr]) = htons(req_port);
            cur_data_ptr += sizeof(uint16_t);

        } else if (req_atype == socks5_atype::FQDN) {

            response[cur_data_ptr] = (unsigned char) req_str_addr.size();
            cur_data_ptr++;

            for (char c: req_str_addr) {
                response[cur_data_ptr] = c;
                cur_data_ptr++;
            }

            *((uint16_t*)&response[cur_data_ptr]) = htons(req_port);
            cur_data_ptr += sizeof(uint16_t);
        }
    }
    else if(req_cmd == socks5_cmd::UDP_ASSOCIATE) {
        response[3] = 1u;
        ++cur_data_ptr;

        *((uint32_t*)&response[cur_data_ptr]) = 0U;
        cur_data_ptr += sizeof(uint32_t);

        *((uint16_t*)&response[cur_data_ptr]) = htons(1080);
        cur_data_ptr += sizeof(uint16_t);
    }


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

    *((uint16_t*)&b[2]) = htons(req_port);
    *((uint32_t*)&b[4]) = req_addr.as_v4()->sin_addr.s_addr;

    writebuf()->append(b,8);
    state_ = socks5_state::REQRES_SENT;

    _dia("process_socks_reply_v4: finished");
    return 8;

}

std::size_t socksServerCX::process_socks_reply() {

    _dia("process_socks_reply: version %d", version);

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

void socksServerCX::pre_write() {
    _deb("socksServerCX::pre_write[%s]: writebuf=%d, readbuf=%d",c_type(),writebuf()->size(),readbuf()->size());
    if(state_ == socks5_state::REQRES_SENT ) {
        if(writebuf()->empty()) {
            _dia("socksServerCX::pre_write[%s]: all flushed, state change to HANDOFF: writebuf=%d, readbuf=%d",c_type(),writebuf()->size(),readbuf()->size());
            waiting_for_peercom(true);
            state(socks5_state::HANDOFF);
        }
    }
    else if(state_ == socks5_state::DNS_RESP_FAILED) {

        if(mixed_ip_versions)  {
            if (not tested_dns_aaaa) {
                _dia("socksServerCX::pre_write[%s]: trying DNS AAAA query", c_type());

                tested_dns_aaaa = true;

                auto const& nameserver = DNS_Setup::choose_dns_server(AF_INET6);
                setup_dns_async(req_str_addr, AAAA, nameserver);
            }
            else if(not tested_dns_a) {
                _dia("socksServerCX::pre_write[%s]: trying DNS A query", c_type());

                tested_dns_a = true;

                auto const& nameserver = DNS_Setup::choose_dns_server(AF_INET);
                setup_dns_async(req_str_addr, A, nameserver);
            }

        } else {
            _deb("socksServerCX::pre_write[%s]: dns failed", c_type());
            error(true);
        }
    }
}


void socksServerCX::dns_response_callback(dns_response_t const& rresp) {

    auto resp = std::shared_ptr<DNS_Response>(rresp.first);
    int red = rresp.second;
    state_ = socks5_state::DNS_RESP_RECV;

    if(red <= 0) {
        _deb("handle_event: socket read returned %d",red);
        error(true);
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


void socksServerCX::handle_event (baseCom *xcom) {
}

std::size_t socksServerCX::process_socks_response() {
    state_ = socks5_state::INIT;

    buffer b(writebuf()->size() + 200);

    (*(uint16_t*)&b.data()[0]) = 0;
    b.data()[2] = 0;

    b.data()[3] = static_cast<uint8_t>(req_atype);
    b.size(4);

    if(req_atype == socks5_atype::IPV4) {

        (*(uint32_t *) &b.data()[4]) = req_addr.as_v4()->sin_addr.s_addr;
        (*(uint16_t *) &b.data()[8]) = htons(req_port);
        b.size(10);
    }
    if(req_atype == socks5_atype::IPV6) {

        std::memcpy(&b.data()[4], &req_addr.as_v6()->sin6_addr, 16);
        (*(uint16_t *) &b.data()[20]) = htons(req_port);
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

