#include <inspect/dns.hpp>
#include <inspect/dnsinspector.hpp>
#include <gtest/gtest.h>

constexpr const char* host = "smithproxy.org";
AddressInfo nameserver(AF_INET, "1.1.1.1", 53);

class DNSInspectorTestCom final : public baseCom {
public:
    std::vector<unsigned char> written;

    baseCom* replicate() override { return new DNSInspectorTestCom(); }
    int connect(const char*, const char*) override { return -1; }
    int accept(int, struct sockaddr*, socklen_t*) override { return -1; }
    ssize_t read(int, void*, size_t, int) override { return -1; }
    ssize_t peek(int, void*, size_t, int) override { return -1; }
    ssize_t write(int, const void* data, size_t size, int) override {
        auto first = static_cast<const unsigned char*>(data);
        written.assign(first, first + size);
        return static_cast<ssize_t>(size);
    }
    void shutdown(int) override {}
    int bind(unsigned short) override { return -1; }
    int bind(const char*) override { return -1; }
    void cleanup() override {}
    bool is_connected(int) override { return true; }
    std::string to_string(int) const override { return "DNSInspectorTestCom"; }
    std::string shortname() const override { return "dns-test"; }
};

class DNSInspectorTestHost final : public AppHostCX {
public:
    explicit DNSInspectorTestHost(baseCom* com) : AppHostCX(com, 0) {}

protected:
    void inspect(char) override {}
    void on_detect(std::shared_ptr<duplexFlowMatch>, flowMatchState&, vector_range&) override {}
    void on_starttls() override {}
};

static buffer dns_tcp_frame(const buffer& packet) {
    buffer framed;
    const auto length = htons(static_cast<uint16_t>(packet.size()));
    framed.append(&length, sizeof(length));
    framed.append(packet);
    return framed;
}

const unsigned char  dns_response1[] = {
        0xf3, 0x1a, 0x81, 0x80, 0x00, 0x01, 0x00, 0x02, 0x00, 0x02, 0x00, 0x06, 0x04, 0x70, 0x63, 0x64,
        0x6e, 0x05, 0x62, 0x72, 0x61, 0x76, 0x65, 0x03, 0x63, 0x6f, 0x6d, 0x00, 0x00, 0x01, 0x00, 0x01,
        0xc0, 0x0c, 0x00, 0x05, 0x00, 0x01, 0x00, 0x00, 0x01, 0x2c, 0x00, 0x30, 0x20, 0x36, 0x36, 0x38,
        0x66, 0x32, 0x62, 0x39, 0x31, 0x30, 0x35, 0x63, 0x33, 0x34, 0x30, 0x37, 0x62, 0x39, 0x36, 0x61,
        0x63, 0x66, 0x39, 0x38, 0x62, 0x32, 0x30, 0x64, 0x38, 0x65, 0x61, 0x39, 0x35, 0x0c, 0x70, 0x61,
        0x63, 0x6c, 0x6f, 0x75, 0x64, 0x66, 0x6c, 0x61, 0x72, 0x65, 0xc0, 0x17, 0xc0, 0x2c, 0x00, 0x01,
        0x00, 0x01, 0x00, 0x00, 0x01, 0x2c, 0x00, 0x04, 0xac, 0x41, 0x0a, 0xe2, 0xc0, 0x4d, 0x00, 0x02,
        0x00, 0x01, 0x00, 0x00, 0x0c, 0x12, 0x00, 0x14, 0x03, 0x67, 0x75, 0x79, 0x02, 0x6e, 0x73, 0x0a,
        0x63, 0x6c, 0x6f, 0x75, 0x64, 0x66, 0x6c, 0x61, 0x72, 0x65, 0xc0, 0x17, 0xc0, 0x4d, 0x00, 0x02,
        0x00, 0x01, 0x00, 0x00, 0x0c, 0x12, 0x00, 0x09, 0x06, 0x62, 0x72, 0x65, 0x6e, 0x64, 0x61, 0xc0,
        0x7c, 0xc0, 0x78, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x0c, 0x12, 0x00, 0x04, 0xac, 0x40, 0x21,
        0xad, 0xc0, 0x78, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x0c, 0x12, 0x00, 0x04, 0xad, 0xf5, 0x3b,
        0xad, 0xc0, 0x78, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x0c, 0x12, 0x00, 0x04, 0x6c, 0xa2, 0xc1,
        0xad, 0xc0, 0x78, 0x00, 0x1c, 0x00, 0x01, 0x00, 0x00, 0x0c, 0x12, 0x00, 0x10, 0x2a, 0x06, 0x98,
        0xc1, 0x00, 0x50, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xac, 0x40, 0x21, 0xad, 0xc0, 0x78, 0x00,
        0x1c, 0x00, 0x01, 0x00, 0x00, 0x0c, 0x12, 0x00, 0x10, 0x26, 0x06, 0x47, 0x00, 0x00, 0x58, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0xad, 0xf5, 0x3b, 0xad, 0xc0, 0x78, 0x00, 0x1c, 0x00, 0x01, 0x00,
        0x00, 0x0c, 0x12, 0x00, 0x10, 0x28, 0x03, 0xf8, 0x00, 0x00, 0x50, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x6c, 0xa2, 0xc1, 0xad };

const unsigned char qname_parse_fail_far[] = {
        0xC0, 0xff, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42

};

const unsigned char qname_parse_fail_end[] = {
        0xC0, 0x08, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42

};
const unsigned char qname_parse_fail_end1[] = {
        0xC0, 0x07, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42

};


TEST(DNS_tests, resolvesA) {
    auto& df = DNSFactory::get();

    for(auto const& rect: { DNS_Record_Type::A }) {
        auto resp = df.resolve_dns_s(host, rect, nameserver, 4);
        ASSERT_TRUE(resp);
        std::cout << resp->answer_str_list() << "\n";
    }
}

TEST(DNS_tests, resolvesMore) {
    auto& df = DNSFactory::get();

    for(auto const& rect: { DNS_Record_Type::A,
                            DNS_Record_Type::AAAA,
                            DNS_Record_Type::NS,
                            DNS_Record_Type::SOA}) {
        auto resp = df.resolve_dns_s(host, rect, nameserver, 4);
        ASSERT_TRUE(resp);
        std::cout << resp->answer_str_list() << "\n";
    }
}

TEST(DNS_tests, dumpHex) {
    auto& df = DNSFactory::get();

    for(auto const& rect: { DNS_Record_Type::A,
                            DNS_Record_Type::AAAA,
                            DNS_Record_Type::NS,
                            DNS_Record_Type::SOA}) {
        auto resp = df.resolve_dns_s(host, rect, nameserver, 4);
        ASSERT_TRUE(resp);
        std::cout << resp->answer_hex_dump() << "\n";
    }
}

TEST(DNS_Packet, load_request1) {
    const uint8_t data[] = {
            0xf3, 0x1a, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x04, 0x70, 0x63, 0x64,
            0x6e, 0x05, 0x62, 0x72, 0x61, 0x76, 0x65, 0x03,
            0x63, 0x6f, 0x6d, 0x00, 0x00, 0x01, 0x00, 0x01
    };
    buffer b((void*)data, sizeof(data), sizeof(data), false);

    auto dr = std::make_unique<DNS_Request>();
    ASSERT_TRUE(dr);

    auto ret = dr->load(&b);
    ASSERT_TRUE(ret.has_value());
    ASSERT_EQ(*ret, sizeof(data));

    std::cout << dr->question_str_0() << "'\n";
    ASSERT_TRUE(dr->question_str_0() == "A:pcdn.brave.com");

    std::cout << "returned: " << ret.value_or(-1) << ":\n" << dr->to_string(iDEB) << "\n";
}

TEST(DNS_Packet, load_response1) {




    buffer b((void*)dns_response1, sizeof(dns_response1), sizeof(dns_response1), false);

    auto dr = std::make_unique<DNS_Response>();
    ASSERT_TRUE(dr);

    auto ret = dr->load(&b);
    ASSERT_TRUE(ret.has_value());
    ASSERT_EQ(*ret, sizeof(dns_response1));

    std::cout << "returned: " << ret.value_or(-1) << ":\n" << dr->to_string(iDEB) << "\n";
    std::cout << "dump:\n" << dr->answer_hex_dump() << "\n";

    for(auto const& ref: dr->questions()) {
        std::cout << "question: " << ref.rec_str << "\n";
    }
    for(auto const& ref: dr->answers()) {
        std::cout << "answer: " << ref.hr() << "\n";
    }
    for(auto const& ref: dr->authorities()) {
        std::cout << "auth: " << ref.hr() << "\n";
    }
    for(auto const& ref: dr->additionals()) {
        std::cout << "add: " << ref.hr() << "\n";
    }
}

TEST(DNS_Packet, qname_reconstuct1) {


    // find pointers
    //    for(unsigned i = 0; i < sizeof(data); ++i) {
    //        if(data[i] >= 0xC0) {
    //            std::cout << "C0: " << i << "\n";
    //        }
    //    }
    auto qname = DNSFactory::get().construct_qname((unsigned char *) &dns_response1[0x78], (unsigned char *) dns_response1,
                                                   sizeof(dns_response1));
    ASSERT_FALSE(qname.empty());

    std::cout << "QNAME: " << qname << "\n";

}


TEST(DNS_Packet, qname_read_after) {
    auto ret = DNSFactory::get().construct_qname((unsigned char *)&qname_parse_fail_far[0], (unsigned char *) qname_parse_fail_far, sizeof(qname_parse_fail_far));
    ASSERT_TRUE(ret.empty());

    ret = DNSFactory::get().construct_qname((unsigned char *)&qname_parse_fail_end[0], (unsigned char *) qname_parse_fail_end, sizeof(qname_parse_fail_end));
    ASSERT_TRUE(ret.empty());

    ret = DNSFactory::get().construct_qname((unsigned char *)&qname_parse_fail_end1[0], (unsigned char *) qname_parse_fail_end1, sizeof(qname_parse_fail_end1));
    ASSERT_TRUE(ret.empty());

}
TEST(DNS_Packet, qname_read_before) {
    unsigned char padded[sizeof(qname_parse_fail_far) + 1]{};
    std::copy(std::begin(qname_parse_fail_far), std::end(qname_parse_fail_far), padded + 1);
    auto ret = DNSFactory::get().construct_qname(padded, padded + 1, sizeof(qname_parse_fail_far));
    ASSERT_TRUE(ret.empty());
}

TEST(DNS_Packet, qname_rejects_truncation_reserved_labels_and_loops) {
    const unsigned char truncated_pointer[] = {0xc0};
    EXPECT_TRUE(DNSFactory::get().construct_qname(truncated_pointer, truncated_pointer,
                                                  sizeof(truncated_pointer)).empty());

    const unsigned char truncated_label[] = {0x03, 'w', 'w', 0x00};
    EXPECT_TRUE(DNSFactory::get().construct_qname(truncated_label, truncated_label,
                                                  sizeof(truncated_label)).empty());

    const unsigned char reserved_label[] = {0x80, 0x00};
    EXPECT_TRUE(DNSFactory::get().construct_qname(reserved_label, reserved_label,
                                                  sizeof(reserved_label)).empty());

    const unsigned char pointer_loop[] = {0xc0, 0x00};
    EXPECT_TRUE(DNSFactory::get().construct_qname(pointer_loop, pointer_loop,
                                                  sizeof(pointer_loop)).empty());
}

TEST(DNS_Packet, qname_uses_the_full_fourteen_bit_compression_offset) {
    std::vector<unsigned char> packet(0x106, 0);
    packet[0] = 0xc1;
    packet[1] = 0x02;
    packet[0x102] = 0x02;
    packet[0x103] = 'o';
    packet[0x104] = 'k';
    packet[0x105] = 0x00;

    EXPECT_EQ(DNSFactory::get().construct_qname(packet.data(), packet.data(), packet.size()), "ok");
}

TEST(DNS_Packet, skip_qname_validates_labels_and_returns_encoded_size) {
    const unsigned char plain[] = {0x03, 'w', 'w', 'w', 0x02, 'c', 'z', 0x00};
    std::string decoded;
    EXPECT_EQ(DNSFactory::get().skip_qname(plain, sizeof(plain), &decoded), sizeof(plain));
    EXPECT_EQ(decoded, "www.cz");

    const unsigned char pointer[] = {0xc0, 0x0c};
    EXPECT_EQ(DNSFactory::get().skip_qname(pointer, sizeof(pointer)), sizeof(pointer));
    EXPECT_EQ(DNSFactory::get().skip_qname(pointer, 1), 0U);

    const unsigned char no_terminator[] = {0x01, 'x'};
    EXPECT_EQ(DNSFactory::get().skip_qname(no_terminator, sizeof(no_terminator)), 0U);
    EXPECT_EQ(DNSFactory::get().skip_qname(nullptr, 0), 0U);
}

TEST(DNS_Packet, rejects_every_truncated_prefix_of_a_valid_response) {
    for(size_t size = 0; size < sizeof(dns_response1); ++size) {
        buffer prefix(const_cast<unsigned char*>(dns_response1), size, size, false);
        DNS_Response response;
        EXPECT_FALSE(response.load(&prefix).has_value()) << "accepted prefix of " << size << " bytes";
    }
}

TEST(DNS_Packet, loads_an_uncompressed_answer_name) {
    const unsigned char response_bytes[] = {
        0x12, 0x34, 0x81, 0x80, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00,
        0x01, 'x', 0x04, 't', 'e', 's', 't', 0x00, 0x00, 0x01, 0x00, 0x01,
        0x01, 'x', 0x04, 't', 'e', 's', 't', 0x00,
        0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x3c, 0x00, 0x04,
        192, 0, 2, 1
    };
    buffer packet(const_cast<unsigned char*>(response_bytes), sizeof(response_bytes),
                  sizeof(response_bytes), false);
    DNS_Response response;
    ASSERT_EQ(response.load(&packet), std::optional<size_t>(sizeof(response_bytes)));
    ASSERT_EQ(response.answers().size(), 1U);
    EXPECT_EQ(response.answers()[0].qname_, "x.test");
    EXPECT_EQ(response.answers()[0].type_, A);
    EXPECT_EQ(response.answers()[0].ip(false), "192.0.2.1");
}

TEST(DNS_Inspector, stores_address_responses_and_domain_hierarchy) {
    {
        auto lock = std::scoped_lock(DNS::get_dns_lock(), DNS::get_domain_lock());
        DNS::get_dns_cache().clear();
        DNS::get_domain_cache().clear();
    }

    buffer packet(const_cast<unsigned char*>(dns_response1), sizeof(dns_response1),
                  sizeof(dns_response1), false);
    auto response = std::make_shared<DNS_Response>();
    ASSERT_TRUE(response->load(&packet).has_value());

    EXPECT_TRUE(DNS_Inspector::store(response));
    EXPECT_EQ(DNS::get_dns_cache().get("A:pcdn.brave.com"), response);

    auto domain = DNS::get_domain_cache().get("brave.com");
    ASSERT_NE(domain, nullptr);
    EXPECT_NE(domain->get("A:pcdn"), nullptr);

    // Exercise replacement of an existing DNS and subdomain cache entry too.
    EXPECT_TRUE(DNS_Inspector::store(response));

    {
        auto lock = std::scoped_lock(DNS::get_dns_lock(), DNS::get_domain_lock());
        DNS::get_dns_cache().clear();
        DNS::get_domain_cache().clear();
    }
}

TEST(DNS_Inspector, rejects_non_address_response_and_unknown_transaction) {
    buffer packet(const_cast<unsigned char*>(dns_response1), sizeof(dns_response1),
                  sizeof(dns_response1), false);
    auto response = std::make_shared<DNS_Response>();
    ASSERT_TRUE(response->load(&packet).has_value());
    ASSERT_GE(response->answers().size(), 2U);
    response->answers()[1].type_ = CNAME;

    EXPECT_FALSE(DNS_Inspector::store(response));

    DNS_Inspector inspector;
    EXPECT_EQ(inspector.find_request(response->id()), nullptr);
    EXPECT_FALSE(inspector.validate_response(response));
    EXPECT_NE(inspector.to_string(iINF).find("requests: 0 valid responses: 0 stored: 0"),
              std::string::npos);
}

TEST(DNS_Inspector, tracks_request_response_and_serves_cached_udp_reply) {
    {
        auto lock = std::scoped_lock(DNS::get_dns_lock(), DNS::get_domain_lock());
        DNS::get_dns_cache().clear();
        DNS::get_domain_cache().clear();
    }

    auto* com = new DNSInspectorTestCom();
    com->l4_proto(SOCK_DGRAM);
    DNSInspectorTestHost host(com);
    com->nonlocal_dst_port() = 53;
    DNS_Inspector inspector;
    inspector.opt_cached_responses = true;

    buffer first_request;
    DNSFactory::get().generate_dns_request(0xf31a, first_request, "pcdn.brave.com", A);
    host.flow().append('r', first_request);
    EXPECT_TRUE(inspector.interested(&host));
    inspector.update(&host);
    ASSERT_NE(inspector.find_request(0xf31a), nullptr);
    EXPECT_EQ(host.idle_delay(), 30);

    host.flow().append('w', dns_response1, sizeof(dns_response1));
    inspector.update(&host);
    EXPECT_FALSE(host.error());
    EXPECT_NE(DNS::get_dns_cache().get("A:pcdn.brave.com"), nullptr);

    buffer cached_request;
    DNSFactory::get().generate_dns_request(0x1234, cached_request, "pcdn.brave.com", A);
    host.flow().append('r', cached_request);
    inspector.update(&host);
    ASSERT_NE(inspector.verdict_response(), nullptr);

    inspector.apply_verdict(&host);
    ASSERT_EQ(com->written.size(), sizeof(dns_response1));
    EXPECT_EQ(com->written[0], 0x12);
    EXPECT_EQ(com->written[1], 0x34);

    {
        auto lock = std::scoped_lock(DNS::get_dns_lock(), DNS::get_domain_lock());
        DNS::get_dns_cache().clear();
        DNS::get_domain_cache().clear();
    }
}

TEST(DNS_Inspector, rejects_response_without_matching_request) {
    auto* com = new DNSInspectorTestCom();
    com->l4_proto(SOCK_DGRAM);
    DNSInspectorTestHost host(com);
    com->nonlocal_dst_port() = 53;
    host.writebuf()->append("pending", 7);

    DNS_Inspector inspector;
    host.flow().append('w', dns_response1, sizeof(dns_response1));
    inspector.update(&host);

    EXPECT_FALSE(host.error());
    EXPECT_TRUE(host.writebuf()->empty());
}

TEST(DNSFactory, CorrelatesReceivedDatagramsWithRequestTransactionId) {
    int sockets[2] {-1, -1};
    ASSERT_EQ(socketpair(AF_UNIX, SOCK_DGRAM, 0, sockets), 0);

    buffer response;
    DNSFactory::get().generate_dns_request(0x1234, response, "example.test", A);
    response.set_at<uint16_t>(2, htons(0x8180));

    ASSERT_EQ(send(sockets[0], response.data(), response.size(), 0),
              static_cast<ssize_t>(response.size()));
    auto mismatched = DNSFactory::get().recv_dns_response(
        sockets[1], 0, 0x4321, "example.test", A);
    EXPECT_EQ(mismatched.first, nullptr);
    EXPECT_GT(mismatched.second, 0);

    ASSERT_EQ(send(sockets[0], response.data(), response.size(), 0),
              static_cast<ssize_t>(response.size()));
    auto matched = DNSFactory::get().recv_dns_response(
        sockets[1], 0, 0x1234, "EXAMPLE.TEST.", A);
    std::unique_ptr<DNS_Response> parsed(matched.first);
    ASSERT_NE(parsed, nullptr);
    EXPECT_EQ(parsed->id(), 0x1234);

    response.set_at<uint16_t>(2, htons(0x0100));
    ASSERT_EQ(send(sockets[0], response.data(), response.size(), 0),
              static_cast<ssize_t>(response.size()));
    auto not_a_response = DNSFactory::get().recv_dns_response(
        sockets[1], 0, 0x1234, "example.test", A);
    EXPECT_EQ(not_a_response.first, nullptr);
    EXPECT_GT(not_a_response.second, 0);

    response.set_at<uint16_t>(2, htons(0x8180));
    ASSERT_EQ(send(sockets[0], response.data(), response.size(), 0),
              static_cast<ssize_t>(response.size()));
    auto wrong_name = DNSFactory::get().recv_dns_response(
        sockets[1], 0, 0x1234, "other.test", A);
    EXPECT_EQ(wrong_name.first, nullptr);
    EXPECT_GT(wrong_name.second, 0);

    ASSERT_EQ(send(sockets[0], response.data(), response.size(), 0),
              static_cast<ssize_t>(response.size()));
    auto wrong_type = DNSFactory::get().recv_dns_response(
        sockets[1], 0, 0x1234, "example.test", AAAA);
    EXPECT_EQ(wrong_type.first, nullptr);
    EXPECT_GT(wrong_type.second, 0);

    close(sockets[0]);
    close(sockets[1]);
}

TEST(DNSFactory, RequestBuilderEnforcesDnsNameBoundsAndNormalizesRootDot) {
    auto& factory = DNSFactory::get();
    buffer plain;
    buffer rooted;
    ASSERT_GT(factory.generate_dns_request(0x1234, plain, "example.test", A), 0U);
    ASSERT_GT(factory.generate_dns_request(0x1234, rooted, "example.test.", A), 0U);
    EXPECT_EQ(plain, rooted);

    buffer invalid;
    EXPECT_EQ(factory.generate_dns_request(1, invalid, "", A), 0U);
    EXPECT_TRUE(invalid.empty());
    EXPECT_EQ(factory.generate_dns_request(1, invalid, ".example", A), 0U);
    EXPECT_EQ(factory.generate_dns_request(1, invalid, "example..test", A), 0U);
    EXPECT_EQ(factory.generate_dns_request(1, invalid, std::string(64, 'a') + ".test", A), 0U);
    EXPECT_EQ(factory.generate_dns_request(1, invalid, std::string(254, 'a'), A), 0U);

    auto const maximum = std::string(63, 'a') + "." + std::string(63, 'b') + "."
                       + std::string(63, 'c') + "." + std::string(61, 'd');
    EXPECT_EQ(maximum.size(), 253U);
    EXPECT_GT(factory.generate_dns_request(1, invalid, maximum, AAAA), 0U);
}

TEST(DNS_Inspector, waits_for_complete_tcp_frames_and_parses_each_length_prefix) {
    auto* com = new DNSInspectorTestCom();
    com->l4_proto(SOCK_STREAM);
    DNSInspectorTestHost host(com);
    com->nonlocal_dst_port() = 53;
    DNS_Inspector inspector;

    buffer first;
    buffer second;
    DNSFactory::get().generate_dns_request(0x1111, first, "one.example", A);
    DNSFactory::get().generate_dns_request(0x2222, second, "two.example", AAAA);
    auto first_frame = dns_tcp_frame(first);
    auto second_frame = dns_tcp_frame(second);

    // A prefix by itself and a short body must remain pending, without parsing
    // or reading beyond the accumulated stream data.
    host.flow().append('r', first_frame.data(), 2);
    inspector.update(&host);
    EXPECT_EQ(inspector.find_request(0x1111), nullptr);

    host.flow().append('r', first_frame.data() + 2, first.size() - 1);
    inspector.update(&host);
    EXPECT_EQ(inspector.find_request(0x1111), nullptr);

    // Complete the first frame and append another frame in the same TCP flow.
    host.flow().append('r', first_frame.data() + first_frame.size() - 1, 1);
    host.flow().append('r', second_frame);
    inspector.update(&host);

    ASSERT_NE(inspector.find_request(0x1111), nullptr);
    ASSERT_NE(inspector.find_request(0x2222), nullptr);
    EXPECT_NE(inspector.to_string(iINF).find("tcp: 1 requests: 2"), std::string::npos);

    buffer first_response = first;
    first_response.set_at<uint16_t>(2, htons(0x8180));
    buffer second_response = second;
    second_response.set_at<uint16_t>(2, htons(0x8180));
    buffer responses;
    responses.append(dns_tcp_frame(first_response));
    responses.append(dns_tcp_frame(second_response));
    host.flow().append('w', responses);
    inspector.update(&host);

    EXPECT_FALSE(host.error());
    EXPECT_NE(inspector.to_string(iINF).find("valid responses: 2"), std::string::npos);
}

TEST(DNS_Inspector, serves_cached_response_with_tcp_length_prefix) {
    {
        auto lock = std::scoped_lock(DNS::get_dns_lock(), DNS::get_domain_lock());
        DNS::get_dns_cache().clear();
        DNS::get_domain_cache().clear();
    }

    auto* com = new DNSInspectorTestCom();
    com->l4_proto(SOCK_STREAM);
    DNSInspectorTestHost host(com);
    com->nonlocal_dst_port() = 53;
    DNS_Inspector inspector;
    inspector.opt_cached_responses = true;

    buffer first_request;
    DNSFactory::get().generate_dns_request(0xf31a, first_request, "pcdn.brave.com", A);
    host.flow().append('r', dns_tcp_frame(first_request));
    inspector.update(&host);

    buffer response(const_cast<unsigned char*>(dns_response1), sizeof(dns_response1),
                    sizeof(dns_response1), false);
    host.flow().append('w', dns_tcp_frame(response));
    inspector.update(&host);
    ASSERT_FALSE(host.error());

    buffer cached_request;
    DNSFactory::get().generate_dns_request(0x3456, cached_request, "pcdn.brave.com", A);
    host.flow().append('r', dns_tcp_frame(cached_request));
    inspector.update(&host);
    ASSERT_NE(inspector.verdict_response(), nullptr);

    inspector.apply_verdict(&host);
    ASSERT_EQ(com->written.size(), sizeof(dns_response1) + 2);
    uint16_t wire_length = 0;
    std::memcpy(&wire_length, com->written.data(), sizeof(wire_length));
    EXPECT_EQ(ntohs(wire_length), sizeof(dns_response1));
    EXPECT_EQ(com->written[2], 0x34);
    EXPECT_EQ(com->written[3], 0x56);

    {
        auto lock = std::scoped_lock(DNS::get_dns_lock(), DNS::get_domain_lock());
        DNS::get_dns_cache().clear();
        DNS::get_domain_cache().clear();
    }
}

TEST(DNS_Inspector, does_not_reuse_cached_verdict_after_expiry_miss_or_other_type) {
    {
        auto lock = std::scoped_lock(DNS::get_dns_lock(), DNS::get_domain_lock());
        DNS::get_dns_cache().clear();
        DNS::get_domain_cache().clear();
    }

    auto* com = new DNSInspectorTestCom();
    com->l4_proto(SOCK_DGRAM);
    DNSInspectorTestHost host(com);
    com->nonlocal_dst_port() = 53;
    DNS_Inspector inspector;
    inspector.opt_cached_responses = true;

    auto send_request = [&](uint16_t id, DNS_Record_Type type) {
        buffer request;
        DNSFactory::get().generate_dns_request(id, request, "pcdn.brave.com", type);
        host.flow().append('r', request);
        inspector.update(&host);
    };

    send_request(0xf31a, A);
    host.flow().append('w', dns_response1, sizeof(dns_response1));
    inspector.update(&host);

    send_request(0x1001, A);
    ASSERT_EQ(inspector.verdict(), Inspector::CACHED);
    ASSERT_NE(inspector.verdict_response(), nullptr);

    auto cached = DNS::get_dns_cache().get("A:pcdn.brave.com");
    ASSERT_NE(cached, nullptr);
    cached->loaded_at = time(nullptr) - 301;
    send_request(0x1002, A);
    EXPECT_EQ(inspector.verdict(), Inspector::OK);
    EXPECT_EQ(inspector.verdict_response(), nullptr);

    cached->loaded_at = time(nullptr);
    send_request(0x1003, A);
    ASSERT_EQ(inspector.verdict(), Inspector::CACHED);
    ASSERT_NE(inspector.verdict_response(), nullptr);

    DNS::get_dns_cache().clear();
    send_request(0x1004, A);
    EXPECT_EQ(inspector.verdict(), Inspector::OK);
    EXPECT_EQ(inspector.verdict_response(), nullptr);

    DNS::get_dns_cache().set("A:pcdn.brave.com", cached);
    send_request(0x1005, A);
    ASSERT_EQ(inspector.verdict(), Inspector::CACHED);
    send_request(0x1006, NS);
    EXPECT_EQ(inspector.verdict(), Inspector::OK);
    EXPECT_EQ(inspector.verdict_response(), nullptr);

    {
        auto lock = std::scoped_lock(DNS::get_dns_lock(), DNS::get_domain_lock());
        DNS::get_dns_cache().clear();
        DNS::get_domain_cache().clear();
    }
}
