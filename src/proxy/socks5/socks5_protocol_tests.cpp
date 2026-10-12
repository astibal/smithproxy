#include <gtest/gtest.h>

#include <array>
#include <thread>
#include <vector>

#include <inspect/dns.hpp>
#include <proxy/explicitproxycx.hpp>
#include <proxy/explicitproxy_io_detail.hpp>
#include <proxy/explicitproxyport.hpp>
#include <proxy/socks5/sockshostcx.hpp>
#include <proxy/socks5/socks5_protocol.hpp>

TEST(ExplicitProxyTargetSetup, ValidatesSourceBeforeReplacementOwnership) {
    bool resolver_called = false;
    const auto failed = sx::explicit_proxy::resolve_source_endpoint(
        42, [&](int descriptor, std::string*, std::string*) {
            resolver_called = true;
            EXPECT_EQ(descriptor, 42);
            return false;
        });
    EXPECT_TRUE(resolver_called);
    EXPECT_FALSE(failed);

    const auto invalid_port = sx::explicit_proxy::resolve_source_endpoint(
        43, [](int, std::string* host, std::string* port) {
            *host = "192.0.2.10";
            *port = "443junk";
            return true;
        });
    EXPECT_FALSE(invalid_port);

    const auto valid = sx::explicit_proxy::resolve_source_endpoint(
        44, [](int, std::string* host, std::string* port) {
            *host = "192.0.2.10";
            *port = "443";
            return true;
        });
    ASSERT_TRUE(valid);
    EXPECT_EQ(valid->host, "192.0.2.10");
    EXPECT_EQ(valid->port, 443);
}

TEST(ExplicitProxySocketIo, RetriesSignalsAndClassifiesTransientPressure) {
    int attempts = 0;
    EXPECT_EQ(sx::explicit_proxy::io_detail::retry_on_eintr(
        [&]() -> ssize_t {
            ++attempts;
            if(attempts == 1) {
                errno = EINTR;
                return -1;
            }
            return 9;
        }), 9);
    EXPECT_EQ(attempts, 2);

    EXPECT_TRUE(sx::explicit_proxy::io_detail::send_would_block(EAGAIN));
    EXPECT_TRUE(sx::explicit_proxy::io_detail::send_would_block(EWOULDBLOCK));
    EXPECT_TRUE(sx::explicit_proxy::io_detail::send_would_block(ENOBUFS));
    EXPECT_FALSE(sx::explicit_proxy::io_detail::send_would_block(EPIPE));
}

TEST(ExplicitProxySocketIo, RetriesInterruptedConnectCompletionProbe) {
    int attempts = 0;
    int connect_error = EINPROGRESS;
    EXPECT_EQ(sx::explicit_proxy::io_detail::retry_on_eintr(
        [&]() -> ssize_t {
            ++attempts;
            if(attempts < 3) {
                errno = EINTR;
                return -1;
            }
            connect_error = 0;
            return 0;
        }), 0);
    EXPECT_EQ(attempts, 3);
    EXPECT_EQ(connect_error, 0);
}

TEST(Socks5UdpHeader, WaitsForCompleteFixedHeader) {
    const std::array<std::uint8_t, 4> header {0, 0, 0, 1};
    EXPECT_EQ(sx::socks5::inspect_udp_header(nullptr, 0),
              sx::socks5::udp_header_status::incomplete);
    for(std::size_t size = 0; size < header.size(); ++size) {
        EXPECT_EQ(sx::socks5::inspect_udp_header(header.data(), size),
                  sx::socks5::udp_header_status::incomplete);
    }
    EXPECT_EQ(sx::socks5::inspect_udp_header(header.data(), header.size()),
              sx::socks5::udp_header_status::ready);
}

TEST(Socks5UdpHeader, RejectsNonzeroReservedBytes) {
    for(const auto header : {
            std::array<std::uint8_t, 4>{1, 0, 0, 1},
            std::array<std::uint8_t, 4>{0, 1, 0, 1},
            std::array<std::uint8_t, 4>{0xff, 0xff, 0, 1}}) {
        EXPECT_EQ(sx::socks5::inspect_udp_header(header.data(), header.size()),
                  sx::socks5::udp_header_status::invalid_reserved);
    }
}

TEST(Socks5UdpHeader, RejectsUnsupportedFragments) {
    for(const std::uint8_t fragment : {std::uint8_t{1}, std::uint8_t{127},
                                       std::uint8_t{255}}) {
        const std::array<std::uint8_t, 4> header {0, 0, fragment, 1};
        EXPECT_EQ(sx::socks5::inspect_udp_header(header.data(), header.size()),
                  sx::socks5::udp_header_status::fragmented);
    }
}

TEST(Socks5TcpFraming, SelectsOnlyAnActuallyOfferedNoAuthMethod) {
    const std::array<std::uint8_t, 3> supported {2, 0, 2};
    const std::array<std::uint8_t, 2> unsupported {1, 2};
    EXPECT_TRUE(sx::socks5::offers_no_authentication(
        supported.data(), supported.size()));
    EXPECT_FALSE(sx::socks5::offers_no_authentication(
        unsupported.data(), unsupported.size()));
    EXPECT_FALSE(sx::socks5::offers_no_authentication(nullptr, 1));
}

TEST(Socks5TcpFraming, ZeroMethodGreetingIsCompleteAndRejectable) {
    const std::array<std::uint8_t, 2> no_methods {5, 0};
    EXPECT_EQ(sx::socks5::greeting_size_if_complete(nullptr, 0), 0u);
    EXPECT_EQ(sx::socks5::greeting_size_if_complete(
                  no_methods.data(), 1), 0u);
    EXPECT_EQ(sx::socks5::greeting_size_if_complete(
                  no_methods.data(), no_methods.size()), no_methods.size());

    const std::array<std::uint8_t, 4> two_methods {5, 2, 0, 2};
    EXPECT_EQ(sx::socks5::greeting_size_if_complete(
                  two_methods.data(), 3), 0u);
    EXPECT_EQ(sx::socks5::greeting_size_if_complete(
                  two_methods.data(), two_methods.size()), two_methods.size());
}

TEST(Socks5TcpFraming, UnknownVersionIsImmediatelyRejectable) {
    const std::array<std::uint8_t, 1> unknown {6};
    EXPECT_EQ(sx::socks5::initial_frame_size_if_complete(
                  unknown.data(), unknown.size()), 1u);

    const std::array<std::uint8_t, 2> deceptive_length {6, 255};
    EXPECT_EQ(sx::socks5::initial_frame_size_if_complete(
                  deceptive_length.data(), deceptive_length.size()), 1u);

    const std::array<std::uint8_t, 3> greeting {5, 1, 0};
    EXPECT_EQ(sx::socks5::initial_frame_size_if_complete(
                  greeting.data(), greeting.size()), greeting.size());
}

TEST(Socks5TcpFraming, DistinguishesIncompleteAndCompleteRequestForms) {
    const std::array<std::uint8_t, 10> ipv4 {5, 1, 0, 1, 127, 0, 0, 1, 0, 80};
    for(std::size_t size = 0; size < ipv4.size(); ++size)
        EXPECT_EQ(sx::socks5::request_size_if_complete(ipv4.data(), size), 0u);
    EXPECT_EQ(sx::socks5::request_size_if_complete(ipv4.data(), ipv4.size()), 10u);

    const std::array<std::uint8_t, 22> ipv6 {
        5, 1, 0, 4, 0,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,1, 1,187};
    EXPECT_EQ(sx::socks5::request_size_if_complete(ipv6.data(), 21), 0u);
    EXPECT_EQ(sx::socks5::request_size_if_complete(ipv6.data(), ipv6.size()), 22u);

    const std::array<std::uint8_t, 8> domain {5, 1, 0, 3, 1, 'x', 0, 53};
    EXPECT_EQ(sx::socks5::request_size_if_complete(domain.data(), 7), 0u);
    EXPECT_EQ(sx::socks5::request_size_if_complete(domain.data(), domain.size()), 8u);

    const std::array<std::uint8_t, 7> empty_domain {5, 1, 0, 3, 0, 0, 53};
    EXPECT_EQ(sx::socks5::request_size_if_complete(
        empty_domain.data(), empty_domain.size()), empty_domain.size());

    const std::array<std::uint8_t, 12> ambiguous_domain {
        5, 1, 0, 3, 5, 'a', 0, 'b', '.', 'c', 0, 80};
    EXPECT_EQ(sx::socks5::request_size_if_complete(
                  ambiguous_domain.data(), ambiguous_domain.size()),
              ambiguous_domain.size());
    EXPECT_FALSE(sx::socks5::is_unambiguous_domain(
        ambiguous_domain.data() + 5, ambiguous_domain[4]));
    EXPECT_TRUE(sx::socks5::is_unambiguous_domain(
        domain.data() + 5, domain[4]));

    for(std::uint16_t control = 0; control <= 0x20U; ++control) {
        const std::array<std::uint8_t, 3> unsafe {
            'a', static_cast<std::uint8_t>(control), 'b'};
        EXPECT_FALSE(sx::socks5::is_unambiguous_domain(
            unsafe.data(), unsafe.size())) << control;
    }
    const std::array<std::uint8_t, 3> del {'a', 0x7f, 'b'};
    EXPECT_FALSE(sx::socks5::is_unambiguous_domain(del.data(), del.size()));
    const std::array<std::uint8_t, 3> visible {'a', 0x80, 'b'};
    EXPECT_TRUE(sx::socks5::is_unambiguous_domain(
        visible.data(), visible.size()));
}

TEST(Socks5TcpFraming, NegotiatedVersionCannotSwitchForTheRequest) {
    EXPECT_TRUE(sx::socks5::request_version_matches_negotiation(5, 5));
    EXPECT_FALSE(sx::socks5::request_version_matches_negotiation(5, 4));
    EXPECT_FALSE(sx::socks5::request_version_matches_negotiation(5, 6));

    // SOCKS4 has no preceding method negotiation, so its initial request is
    // still selected directly by its own version byte.
    EXPECT_TRUE(sx::socks5::request_version_matches_negotiation(4, 4));
}

TEST(Socks4TcpFraming, IncludesSocks4aDomainAndRejectsEmptyIdentity) {
    const std::array<std::uint8_t, 9> socks4 {
        4, 1, 0, 80, 127, 0, 0, 1, 0};
    EXPECT_EQ(sx::socks5::socks4_request_size_if_complete(
                  socks4.data(), socks4.size()), socks4.size());
    EXPECT_FALSE(sx::socks5::is_socks4a(socks4.data(), socks4.size()));

    const std::array<std::uint8_t, 22> socks4a {
        4, 1, 1, 187, 0, 0, 0, 1,
        'u', 0,
        't','a','r','g','e','t','.','t','e','s','t',0};
    for(std::size_t size = 0; size < socks4a.size(); ++size)
        EXPECT_EQ(sx::socks5::socks4_request_size_if_complete(
                      socks4a.data(), size), 0u);
    EXPECT_EQ(sx::socks5::socks4_request_size_if_complete(
                  socks4a.data(), socks4a.size()), socks4a.size());
    ASSERT_TRUE(sx::socks5::socks4a_domain(
        socks4a.data(), socks4a.size()).has_value());
    EXPECT_EQ(*sx::socks5::socks4a_domain(socks4a.data(), socks4a.size()),
              "target.test");

    const std::array<std::uint8_t, 10> empty_domain {
        4, 1, 0, 80, 0, 0, 0, 1, 0, 0};
    EXPECT_EQ(sx::socks5::socks4_request_size_if_complete(
                  empty_domain.data(), empty_domain.size()), empty_domain.size());
    EXPECT_FALSE(sx::socks5::socks4a_domain(
        empty_domain.data(), empty_domain.size()).has_value());

    auto unsafe_domain = socks4a;
    unsafe_domain[12] = '\n';
    EXPECT_FALSE(sx::socks5::socks4a_domain(
        unsafe_domain.data(), unsafe_domain.size()).has_value());
}

TEST(Socks4TcpFraming, RequestIdentityHasAnExplicitUpperBound) {
    std::vector<std::uint8_t> maximum(
        sx::socks5::maximum_socks4_request_size, 'u');
    maximum[0] = 4;
    maximum[1] = 1;
    maximum[2] = 0;
    maximum[3] = 80;
    maximum[4] = 127;
    maximum[5] = 0;
    maximum[6] = 0;
    maximum[7] = 1;
    maximum.back() = 0;
    EXPECT_EQ(sx::socks5::socks4_request_size_if_complete(
                  maximum.data(), maximum.size()),
              sx::socks5::maximum_socks4_request_size);

    maximum.insert(maximum.end() - 1, 'u');
    EXPECT_GT(sx::socks5::socks4_request_size_if_complete(
                  maximum.data(), maximum.size()),
              sx::socks5::maximum_socks4_request_size);

    maximum.back() = 'u';
    maximum.resize(sx::socks5::maximum_socks4_request_size);
    EXPECT_EQ(sx::socks5::initial_frame_size_if_complete(
                  maximum.data(), maximum.size()),
              sx::socks5::maximum_socks4_request_size);
}

TEST(Socks5TcpFraming, ReplyCapacityCoversTheMaximumDomain) {
    EXPECT_FALSE(sx::socks5::domain_reply_size(0).has_value());
    EXPECT_FALSE(sx::socks5::domain_reply_size(256).has_value());
    ASSERT_TRUE(sx::socks5::domain_reply_size(255).has_value());
    EXPECT_EQ(*sx::socks5::domain_reply_size(255),
              sx::socks5::maximum_tcp_reply_size);
}

TEST(Socks5DnsCache, UsesFreshCachedAnswerWithoutStartingAnotherQuery) {
    const unsigned char response_bytes[] = {
        0x12, 0x34, 0x81, 0x80, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00,
        0x06, 'c', 'a', 'c', 'h', 'e', 'd', 0x04, 't', 'e', 's', 't', 0x00,
        0x00, 0x01, 0x00, 0x01,
        0xc0, 0x0c, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x3c, 0x00, 0x04,
        192, 0, 2, 44
    };
    buffer packet(const_cast<unsigned char*>(response_bytes),
                  sizeof(response_bytes), sizeof(response_bytes), false);
    auto response = std::make_shared<DNS_Response>();
    ASSERT_TRUE(response->load(&packet).has_value());
    EXPECT_EQ(sx::explicit_proxy::fresh_dns_addresses(response),
              std::vector<std::string>{"192.0.2.44"});
    EXPECT_TRUE(sx::explicit_proxy::fresh_dns_addresses(
                    response, response->loaded_at + 61).empty());

    auto truncated_bytes = std::vector<unsigned char>(
        std::begin(response_bytes), std::end(response_bytes));
    truncated_bytes[2] |= 0x02; // TC
    buffer truncated_packet(truncated_bytes.data(), truncated_bytes.size(),
                            truncated_bytes.size(), false);
    auto truncated = std::make_shared<DNS_Response>();
    ASSERT_TRUE(truncated->load(&truncated_packet).has_value());
    EXPECT_TRUE(sx::explicit_proxy::fresh_dns_addresses(truncated).empty());

    truncated_bytes[2] &= static_cast<unsigned char>(~0x02U);
    truncated_bytes[3] = static_cast<unsigned char>(
        (truncated_bytes[3] & 0xf0U) | 0x02U); // SERVFAIL
    buffer failed_packet(truncated_bytes.data(), truncated_bytes.size(),
                         truncated_bytes.size(), false);
    auto failed = std::make_shared<DNS_Response>();
    ASSERT_TRUE(failed->load(&failed_packet).has_value());
    EXPECT_TRUE(sx::explicit_proxy::fresh_dns_addresses(failed).empty());
}

TEST(Socks5TargetSetup, RequiresSelectionAndCompleteTargetPreparation) {
    EXPECT_TRUE(sx::socks5::target_setup_succeeded(true, true));
    EXPECT_FALSE(sx::socks5::target_setup_succeeded(false, false));
    EXPECT_FALSE(sx::socks5::target_setup_succeeded(true, false));
    EXPECT_FALSE(sx::socks5::target_setup_succeeded(false, true));
}

TEST(Socks5TargetSetup, ZeroPortIsReservedForUdpAssociateControlRequest) {
    constexpr std::uint8_t connect = 1;
    constexpr std::uint8_t bind = 2;
    constexpr std::uint8_t udp_associate = 3;

    EXPECT_FALSE(sx::socks5::target_port_is_valid(connect, 0));
    EXPECT_FALSE(sx::socks5::target_port_is_valid(bind, 0));
    EXPECT_TRUE(sx::socks5::target_port_is_valid(udp_associate, 0));
    EXPECT_TRUE(sx::socks5::target_port_is_valid(connect, 1));
    EXPECT_TRUE(sx::socks5::target_port_is_valid(connect, 65535));
}

TEST(Socks5TargetSetup, UnspecifiedConnectTargetsAreRecognized) {
    EXPECT_TRUE(sx::explicit_proxy::is_unspecified_address("0.0.0.0"));
    EXPECT_TRUE(sx::explicit_proxy::is_unspecified_address("::"));
    EXPECT_TRUE(sx::explicit_proxy::is_unspecified_address(
        "0:0:0:0:0:0:0:0"));
    EXPECT_FALSE(sx::explicit_proxy::is_unspecified_address("127.0.0.1"));
    EXPECT_FALSE(sx::explicit_proxy::is_unspecified_address("::1"));
    EXPECT_FALSE(sx::explicit_proxy::is_unspecified_address("example.test"));
}

TEST(Socks5UdpFraming, StoresNetworkFieldsWithoutAlignedTypedWrites) {
    std::array<std::uint8_t, 9> storage {};
    auto* const unaligned = storage.data() + 1;

    sx::socks5::store_network_u32(unaligned, htonl(0xc000022cU));
    sx::socks5::store_network_u16(unaligned + 4, 0x1234U);

    EXPECT_EQ(storage[0], 0U);
    EXPECT_EQ(std::vector<std::uint8_t>(unaligned, unaligned + 6),
              (std::vector<std::uint8_t>{0xc0, 0x00, 0x02, 0x2c, 0x12, 0x34}));

    sx::socks5::store_network_u16(nullptr, 1);
    sx::socks5::store_network_u32(nullptr, 1);
}

TEST(Socks5TargetSetup, StoresParsedPortInSockaddrNetworkOrder) {
    constexpr std::uint16_t port = 0x1234U;
    const auto stored = sx::socks5::sockaddr_port(port);

    std::array<std::uint8_t, sizeof(stored)> bytes {};
    std::memcpy(bytes.data(), &stored, sizeof(stored));
    EXPECT_EQ(bytes, (std::array<std::uint8_t, 2>{0x12, 0x34}));
    EXPECT_EQ(ntohs(stored), port);
}

TEST(Socks5UdpAssociation, RelayFailureCannotRetainAnAssociation) {
    EXPECT_TRUE(sx::socks5::udp_relay_endpoint_ready(
        true, std::optional<std::uint16_t>{1080}));
    EXPECT_FALSE(sx::socks5::udp_relay_endpoint_ready(
        false, std::optional<std::uint16_t>{1080}));
    EXPECT_FALSE(sx::socks5::udp_relay_endpoint_ready(true, std::nullopt));
    EXPECT_FALSE(sx::socks5::udp_relay_endpoint_ready(false, std::nullopt));
}

TEST(Socks5UdpAssociation, DescriptorZeroIsARealControlSocket) {
    EXPECT_FALSE(sx::socks5::pollable_control_socket(-1));
    EXPECT_TRUE(sx::socks5::pollable_control_socket(0));
    EXPECT_TRUE(sx::socks5::pollable_control_socket(1));
}

TEST(Socks5UdpAssociation, ConcurrentDatabaseInitializationHasOneIdentity) {
    constexpr std::size_t worker_count = 32;
    std::vector<std::shared_ptr<socksServerCX::UDP::associations>> instances(
        worker_count);
    std::vector<std::thread> workers;
    workers.reserve(worker_count);
    for(std::size_t i = 0; i < worker_count; ++i) {
        workers.emplace_back([&, i] {
            instances[i] = socksServerCX::UDP::db();
        });
    }
    for(auto& worker : workers)
        worker.join();

    ASSERT_NE(instances.front(), nullptr);
    for(auto const& instance : instances)
        EXPECT_EQ(instance.get(), instances.front().get());
}

TEST(Socks5UdpAssociation, DestinationIdentityIsAsciiCaseInsensitive) {
    socksServerCX::UDP association;
    EXPECT_TRUE(association.make_authorized("Dns.Example", 53));
    EXPECT_TRUE(association.make_authorized("dns.example", 53));
    EXPECT_FALSE(association.make_authorized("other.example", 53));
    EXPECT_FALSE(association.make_authorized("DNS.EXAMPLE", 54));
}

TEST(Socks5UdpHandoff, RejectsIncompleteShadowEndpoints) {
    struct frontend {
        int* left = nullptr;
        int* right = nullptr;
    } state;
    int endpoint = 0;

    EXPECT_FALSE(sx::socks5::detail::udp_handoff_endpoints_ready(
        static_cast<frontend const*>(nullptr)));
    EXPECT_FALSE(sx::socks5::detail::udp_handoff_endpoints_ready(&state));
    state.left = &endpoint;
    EXPECT_FALSE(sx::socks5::detail::udp_handoff_endpoints_ready(&state));
    state.right = &endpoint;
    EXPECT_TRUE(sx::socks5::detail::udp_handoff_endpoints_ready(&state));
}
