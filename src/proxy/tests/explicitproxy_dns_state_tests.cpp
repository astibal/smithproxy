#include <gtest/gtest.h>

#include <array>

#include <proxy/explicitproxycx.hpp>

TEST(ExplicitProxyDnsState, RejectsDescriptorsReservedByTheEventLoop) {
    EXPECT_FALSE(sx::explicit_proxy::valid_dns_socket(-3));
    EXPECT_FALSE(sx::explicit_proxy::valid_dns_socket(-2));
    EXPECT_FALSE(sx::explicit_proxy::valid_dns_socket(-1));
    EXPECT_FALSE(sx::explicit_proxy::valid_dns_socket(0));
    EXPECT_TRUE(sx::explicit_proxy::valid_dns_socket(1));
}

TEST(ExplicitProxyDnsState, RetriesOnlyUntestedAddressFamilies) {
    EXPECT_FALSE(sx::explicit_proxy::next_dns_retry(false, false, false));
    EXPECT_EQ(sx::explicit_proxy::next_dns_retry(true, false, false), AAAA);
    EXPECT_EQ(sx::explicit_proxy::next_dns_retry(true, false, true), A);
    EXPECT_EQ(sx::explicit_proxy::next_dns_retry(true, true, false), AAAA);
    EXPECT_FALSE(sx::explicit_proxy::next_dns_retry(true, true, true));
}

TEST(ExplicitProxyDnsState, FiltersCachedAddressesByTheirOwnTtl) {
    auto response = std::make_shared<DNS_Response>();
    response->loaded_at = 100;
    response->questions().push_back({"cache.test", A, 1});

    DNS_Answer long_lived;
    long_lived.qname_ = "cache.test";
    long_lived.type_ = A;
    long_lived.class_ = 1;
    long_lived.ttl_ = 60;
    const unsigned char first[] {192, 0, 2, 10};
    long_lived.data_.assign(first, sizeof(first));
    response->answers().push_back(long_lived);

    DNS_Answer expired;
    expired.qname_ = "cache.test";
    expired.type_ = A;
    expired.class_ = 1;
    expired.ttl_ = 1;
    const unsigned char second[] {192, 0, 2, 20};
    expired.data_.assign(second, sizeof(second));
    response->answers().push_back(expired);

    EXPECT_EQ(sx::explicit_proxy::fresh_dns_addresses(response, 102),
              std::vector<std::string>{"192.0.2.10"});

    response->answers()[0].ttl_ = 1;
    response->answers()[1].ttl_ = 60;
    EXPECT_EQ(sx::explicit_proxy::fresh_dns_addresses(response, 102),
              std::vector<std::string>{"192.0.2.20"});
}

TEST(ExplicitProxyDnsState, UsesOnlyAddressesOnTheQuestionCnameChain) {
    auto response = std::make_shared<DNS_Response>();
    response->loaded_at = 100;
    response->questions().push_back({"allowed.test", A, 1});

    DNS_Answer alias;
    alias.qname_ = "allowed.test";
    alias.rdata_name_ = "target.test";
    alias.type_ = CNAME;
    alias.class_ = 1;
    alias.ttl_ = 60;
    response->answers().push_back(alias);

    auto add_address = [&](std::string name, std::array<unsigned char, 4> ip) {
        DNS_Answer answer;
        answer.qname_ = std::move(name);
        answer.type_ = A;
        answer.class_ = 1;
        answer.ttl_ = 60;
        answer.data_.assign(ip.data(), ip.size());
        response->answers().push_back(std::move(answer));
    };
    add_address("target.test", {192, 0, 2, 30});
    add_address("injected.test", {203, 0, 113, 99});

    EXPECT_EQ(sx::explicit_proxy::fresh_dns_addresses(response, 101),
              std::vector<std::string>{"192.0.2.30"});

    response->answers().front().ttl_ = 0;
    EXPECT_TRUE(sx::explicit_proxy::fresh_dns_addresses(response, 101).empty());
}

TEST(ExplicitProxyDnsState, RejectsNonInternetAndAmbiguousQuestionAuthority) {
    auto response = std::make_shared<DNS_Response>();
    response->questions().push_back(DNS_Question{"target.test", A, 3});
    DNS_Answer answer;
    answer.qname_ = "target.test";
    answer.type_ = A;
    answer.class_ = 1;
    answer.ttl_ = 60;
    const unsigned char address[] {192, 0, 2, 50};
    answer.data_.assign(address, sizeof(address));
    response->answers().push_back(answer);

    EXPECT_TRUE(sx::explicit_proxy::fresh_dns_addresses(response).empty());
    response->questions().front().rec_class = 1;
    response->questions().push_back(DNS_Question{"other.test", A, 1});
    EXPECT_TRUE(sx::explicit_proxy::fresh_dns_addresses(response).empty());
}

TEST(ExplicitProxyDnsState, SynchronousResolutionStopsAtFirstSuccess) {
    EXPECT_EQ(sx::explicit_proxy::dns_query_order(AF_INET, false, false),
              std::vector<DNS_Record_Type>{A});
    EXPECT_EQ(sx::explicit_proxy::dns_query_order(AF_INET, true, true),
              (std::vector<DNS_Record_Type>{AAAA, A}));
    EXPECT_EQ(sx::explicit_proxy::dns_query_order(AF_INET6, false, true),
              (std::vector<DNS_Record_Type>{AAAA, A}));

    std::vector<DNS_Record_Type> attempted;
    EXPECT_TRUE(sx::explicit_proxy::resolve_first_available(
        std::vector<DNS_Record_Type>{AAAA, A}, [&](DNS_Record_Type type) {
            attempted.push_back(type);
            return type == A;
        }));
    EXPECT_EQ(attempted, (std::vector<DNS_Record_Type>{AAAA, A}));

    attempted.clear();
    EXPECT_TRUE(sx::explicit_proxy::resolve_first_available(
        std::vector<DNS_Record_Type>{A, AAAA}, [&](DNS_Record_Type type) {
            attempted.push_back(type);
            return true;
        }));
    EXPECT_EQ(attempted, std::vector<DNS_Record_Type>{A});

    attempted.clear();
    EXPECT_FALSE(sx::explicit_proxy::resolve_first_available(
        std::vector<DNS_Record_Type>{A, AAAA}, [&](DNS_Record_Type type) {
            attempted.push_back(type);
            return false;
        }));
    EXPECT_EQ(attempted, (std::vector<DNS_Record_Type>{A, AAAA}));
}
