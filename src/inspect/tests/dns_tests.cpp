#include <inspect/dns.hpp>
#include <gtest/gtest.h>

constexpr const char* host = "fixture.test";

class DNSFixture : public ::testing::Test {
protected:
    AddressInfo nameserver;

    void SetUp() override {
        const char* port_env = std::getenv("SMITHPROXY_TEST_DNS_PORT");
        const char* host_env = std::getenv("SMITHPROXY_TEST_DNS_HOST4");
        if (not port_env or not host_env) {
            GTEST_SKIP() << "run through tests/fixtures/dns_server.py";
        }
        nameserver = AddressInfo(AF_INET, host_env, static_cast<unsigned short>(std::stoi(port_env)));
    }
};

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


TEST_F(DNSFixture, resolvesA) {
    auto& df = DNSFactory::get();

    for(auto const& rect: { DNS_Record_Type::A }) {
        auto resp = df.resolve_dns_s(host, rect, nameserver, 4);
        ASSERT_NE(resp, nullptr);
        ASSERT_EQ(resp->answers().size(), 1);
        EXPECT_EQ(resp->answer_str_A(), " ip4: 192.0.2.10");
        std::cout << resp->answer_str_list() << "\n";
        delete resp;
    }
}

TEST_F(DNSFixture, resolvesMore) {
    auto& df = DNSFactory::get();

    for(auto const& rect: { DNS_Record_Type::A,
                            DNS_Record_Type::AAAA,
                            DNS_Record_Type::NS,
                            DNS_Record_Type::SOA}) {
        auto resp = df.resolve_dns_s(host, rect, nameserver, 4);
        ASSERT_NE(resp, nullptr);
        ASSERT_EQ(resp->answers().size(), 1);
        std::cout << resp->answer_str_list() << "\n";
        delete resp;
    }
}

TEST_F(DNSFixture, dumpHex) {
    auto& df = DNSFactory::get();

    for(auto const& rect: { DNS_Record_Type::A,
                            DNS_Record_Type::AAAA,
                            DNS_Record_Type::NS,
                            DNS_Record_Type::SOA}) {
        auto resp = df.resolve_dns_s(host, rect, nameserver, 4);
        ASSERT_NE(resp, nullptr);
        ASSERT_EQ(resp->answers().size(), 1);
        std::cout << resp->answer_hex_dump() << "\n";
        delete resp;
    }
}

TEST_F(DNSFixture, resolvesNXDomain) {
    auto* resp = DNSFactory::get().resolve_dns_s("nxdomain.test", DNS_Record_Type::A, nameserver, 4);
    ASSERT_NE(resp, nullptr);
    EXPECT_EQ(resp->flags() & 0x000f, 3);
    EXPECT_TRUE(resp->answers().empty());
    delete resp;
}

TEST_F(DNSFixture, resolvesAOverIPv6Transport) {
    const char* port_env = std::getenv("SMITHPROXY_TEST_DNS_PORT");
    const char* host_env = std::getenv("SMITHPROXY_TEST_DNS_HOST6");
    ASSERT_NE(port_env, nullptr);
    ASSERT_NE(host_env, nullptr);
    AddressInfo nameserver6(AF_INET6, host_env, static_cast<unsigned short>(std::stoi(port_env)));
    auto* resp = DNSFactory::get().resolve_dns_s(host, DNS_Record_Type::A, nameserver6, 4);
    ASSERT_NE(resp, nullptr);
    ASSERT_EQ(resp->answers().size(), 1);
    EXPECT_EQ(resp->answer_str_A(), " ip4: 192.0.2.10");
    delete resp;
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
