#include <inspect/dns.hpp>

#include <gtest/gtest.h>

constexpr const char* nameserver = "8.8.8.8";
constexpr const char* host = "smithproxy.org";


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

