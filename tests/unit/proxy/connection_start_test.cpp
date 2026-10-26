#include <proxy/connection_start.hpp>
#include <gtest/gtest.h>

namespace {
using sx::proxy::setup_action;

struct Case {
    long status;
    const char* body;
    setup_action expected;
};

class ConnectionStartReply : public ::testing::TestWithParam<Case> {};

TEST_P(ConnectionStartReply, ParsesSetupWithoutConfusingContentActions) {
    const auto& test = GetParam();
    EXPECT_EQ(sx::proxy::parse_setup_reply(test.status, test.body).action, test.expected);
}

INSTANTIATE_TEST_SUITE_P(Contract, ConnectionStartReply, ::testing::Values(
    Case{200, "{}", setup_action::accept},
    Case{202, "{}", setup_action::accept},
    Case{204, "", setup_action::accept},
    Case{200, " \t\r\n", setup_action::accept},
    Case{200, R"({"action":"accept"})", setup_action::accept},
    Case{299, R"({"action":"unchanged"})", setup_action::accept},
    Case{200, R"({"control":{"mode":"strict"}})", setup_action::accept},
    Case{200, R"({"action":"drop"})", setup_action::drop},
    Case{202, R"({"action":"drop","reason":"test"})", setup_action::drop},
    Case{200, R"({"action":"not-interested"})", setup_action::not_interested},
    Case{199, R"({"action":"drop"})", setup_action::invalid},
    Case{300, R"({"action":"accept"})", setup_action::invalid},
    Case{503, R"({"action":"drop"})", setup_action::invalid},
    Case{0, "", setup_action::invalid},
    Case{200, "oops", setup_action::invalid},
    Case{200, "[]", setup_action::invalid},
    Case{200, "null", setup_action::invalid},
    Case{200, R"({"action":null})", setup_action::invalid},
    Case{200, R"({"action":42})", setup_action::invalid},
    Case{200, R"({"action":"discard"})", setup_action::invalid},
    Case{200, R"({"action":"need-more"})", setup_action::invalid},
    Case{200, R"({"action":"replace","content":"QQ=="})", setup_action::invalid},
    Case{200, R"({"action":"unknown"})", setup_action::invalid}
));

TEST(ConnectionStart, RetainsControlWithoutActingOnPayload) {
    const auto result = sx::proxy::parse_setup_reply(200,
        R"({"action":"accept","control":{"mode":"strict"},"content":"QQ=="})");
    EXPECT_EQ(result.action, setup_action::accept);
    EXPECT_EQ(result.body["control"]["mode"], "strict");
}

TEST(ConnectionStart, RewriteIsExplicitAndAcceptOnly) {
    for (const auto* body : {"{}", R"({"control":{"rewrite":false}})",
            R"({"action":"drop","control":{"rewrite":true}})",
            R"({"action":"not-interested","control":{"rewrite":true}})"}) {
        EXPECT_FALSE(sx::proxy::parse_setup_reply(200, body).rewrite) << body;
    }
    for (const auto* body : {R"({"control":{"rewrite":true}})",
            R"({"action":"accept","control":{"rewrite":true}})",
            R"({"action":"unchanged","control":{"rewrite":true,"mode":"strict"}})"}) {
        const auto reply = sx::proxy::parse_setup_reply(200, body);
        EXPECT_EQ(reply.action, setup_action::accept);
        EXPECT_TRUE(reply.rewrite);
    }
    for (const auto* body : {R"({"control":{"rewrite":1}})",
            R"({"control":{"rewrite":"true"}})", R"({"control":{"rewrite":null}})",
            R"({"control":[]})", R"({"control":false})"}) {
        const auto reply = sx::proxy::parse_setup_reply(200, body);
        EXPECT_EQ(reply.action, setup_action::invalid);
        EXPECT_FALSE(reply.rewrite);
    }
    EXPECT_FALSE(sx::proxy::parse_setup_reply(503, R"({"control":{"rewrite":true}})").rewrite);
}
} // namespace
