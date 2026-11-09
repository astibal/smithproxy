#include <gtest/gtest.h>

#include <proxy/filters/access_filter_decision.hpp>

namespace {

using sx::proxy::access_decision;
using sx::proxy::parse_access_response;

TEST(AccessFilterDecision, AcceptsOnlyExactSupportedDecisions) {
    EXPECT_EQ(parse_access_response(200, R"({"access-response":"accept"})").decision,
              access_decision::accept);
    EXPECT_EQ(parse_access_response(299, R"({"access-response":"reject"})").decision,
              access_decision::reject);

    EXPECT_EQ(parse_access_response(200, R"({"access-response":"Accept"})").decision,
              access_decision::fail_closed_invalid_response);
    EXPECT_EQ(parse_access_response(200, R"({"access-response":true})").decision,
              access_decision::fail_closed_invalid_response);
    EXPECT_EQ(parse_access_response(200, R"({})").decision,
              access_decision::fail_closed_invalid_response);
}

TEST(AccessFilterDecision, MalformedAndNonSuccessRepliesFailClosedByDefault) {
    EXPECT_EQ(parse_access_response(200, "not json").decision,
              access_decision::fail_closed_invalid_response);
    EXPECT_EQ(parse_access_response(200, "[]").decision,
              access_decision::fail_closed_invalid_response);
    EXPECT_EQ(parse_access_response(199, R"({"access-response":"reject"})").decision,
              access_decision::fail_closed_transport);
    EXPECT_EQ(parse_access_response(300, R"({"access-response":"reject"})").decision,
              access_decision::fail_closed_transport);
}

TEST(AccessFilterDecision, LegacyFailOpenMustBeExplicit) {
    EXPECT_EQ(parse_access_response(200, "not json", true).decision,
              access_decision::fail_open_invalid_response);
    EXPECT_EQ(parse_access_response(503, "unavailable", true).decision,
              access_decision::fail_open_transport);
}

TEST(AccessFilterDecision, PreservesValidResponseForDiagnostics) {
    auto result = parse_access_response(200, R"({"access-response":"accept","reason":"ok"})");
    EXPECT_EQ(result.response.at("reason"), "ok");
}

} // namespace
