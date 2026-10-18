#include <gtest/gtest.h>

#include <signature.hpp>

#include <algorithm>
#include <memory>
#include <string>
#include <utility>
#include <vector>

namespace {

struct SigStep {
    char side;
    std::string pattern;
    unsigned offset;
    unsigned bytes;
};

std::shared_ptr<duplexFlowMatch> make_signature(
    std::string name, std::vector<SigStep> const& steps) {
    auto signature = std::make_shared<duplexFlowMatch>();
    signature->name() = std::move(name);
    for(auto const& step : steps) {
        auto pattern = step.pattern;
        signature->add(step.side,
            new regexMatch(pattern, step.offset, step.bytes));
    }
    return signature;
}

std::shared_ptr<duplexFlowMatch> starttls_signature(
    std::string name, std::string request, unsigned request_bytes,
    std::string response, unsigned response_bytes) {
    return make_signature(std::move(name), {
        {'r', std::move(request), 0, request_bytes},
        {'w', std::move(response), 0, response_bytes},
    });
}

bool append_and_update(duplexFlow& flow, flowMatchState& state,
                       std::shared_ptr<duplexFlowMatch> const& signature,
                       char side, std::string const& data) {
    buffer input(data.data(), data.size());
    flow.append(side, input);
    return state.update(&flow, signature);
}

bool append_bytewise(duplexFlow& flow, flowMatchState& state,
                     std::shared_ptr<duplexFlowMatch> const& signature,
                     char side, std::string const& data) {
    bool matched = false;
    for(char byte : data) {
        matched = append_and_update(
            flow, state, signature, side, std::string(1, byte));
    }
    return matched;
}

struct StartTlsCase {
    const char* name;
    const char* request_pattern;
    unsigned request_bytes;
    const char* response_pattern;
    unsigned response_bytes;
    const char* request;
    const char* response;
    const char* rejected_response;
};

class StartTlsFlowMatch : public testing::TestWithParam<StartTlsCase> {};

TEST_P(StartTlsFlowMatch, MatchesCompleteDialog) {
    auto const& test = GetParam();
    auto signature = starttls_signature(
        test.name, test.request_pattern, test.request_bytes,
        test.response_pattern, test.response_bytes);
    duplexFlow flow;
    flowMatchState state;

    EXPECT_FALSE(append_and_update(flow, state, signature, 'r', test.request));
    EXPECT_TRUE(append_and_update(flow, state, signature, 'w', test.response));
    EXPECT_TRUE(state.hit());
}

TEST_P(StartTlsFlowMatch, MatchesBytewiseFragmentedDialog) {
    auto const& test = GetParam();
    auto signature = starttls_signature(
        test.name, test.request_pattern, test.request_bytes,
        test.response_pattern, test.response_bytes);
    duplexFlow flow;
    flowMatchState state;

    EXPECT_FALSE(append_bytewise(flow, state, signature, 'r', test.request));
    EXPECT_TRUE(append_bytewise(flow, state, signature, 'w', test.response));
}

TEST_P(StartTlsFlowMatch, RejectsNegativeResponse) {
    auto const& test = GetParam();
    auto signature = starttls_signature(
        test.name, test.request_pattern, test.request_bytes,
        test.response_pattern, test.response_bytes);
    duplexFlow flow;
    flowMatchState state;

    EXPECT_FALSE(append_and_update(flow, state, signature, 'r', test.request));
    EXPECT_FALSE(append_and_update(
        flow, state, signature, 'w', test.rejected_response));
    EXPECT_FALSE(state.hit());
}

INSTANTIATE_TEST_SUITE_P(ConfiguredSignatures, StartTlsFlowMatch,
    testing::Values(
        StartTlsCase{
            "smtp", "^STARTTLS", 16, "^2[0-5]0 [^\\r\\n]*\\r\\n", 512,
            "STARTTLS\r\n", "220 Ready to start TLS\r\n",
            "454 TLS temporarily unavailable\r\n"},
        StartTlsCase{
            "imap", ". STARTTLS\\r\\n", 16, ". OK[^\\r\\n]*\\r\\n", 512,
            "a STARTTLS\r\n", "a OK Begin TLS negotiation\r\n",
            "a NO STARTTLS unavailable\r\n"},
        StartTlsCase{
            "pop3", "^STLS\\r\\n", 10, "^[+]OK[^\\r\\n]*\\r\\n", 512,
            "STLS\r\n", "+OK Begin TLS negotiation\r\n",
            "-ERR TLS unavailable\r\n"},
        StartTlsCase{
            "ftp", "^AUTH TLS\\r\\n", 10,
            "^[2][0-9][0-9] AUTH[^\\r\\n]*\\r\\n", 512,
            "AUTH TLS\r\n", "234 AUTH TLS successful\r\n",
            "534 AUTH TLS unavailable\r\n"},
        StartTlsCase{
            "xmpp", "^<starttls [^>/]+xmpp-tls[^>/]/>", 64,
            "^<proceed [^>/]+xmpp-tls[^>/]/>", 64,
            "<starttls xmlns='urn:ietf:params:xml:ns:xmpp-tls'/>",
            "<proceed xmlns='urn:ietf:params:xml:ns:xmpp-tls'/>",
            "<failure xmlns='urn:ietf:params:xml:ns:xmpp-tls'/>"},
        StartTlsCase{
            "http-connect", "^CONNECT [^ ]+:443[^\\r]*\\r\\n", 200,
            "^HTTP/1.[01] 2[0-9][0-9][^\\r\\n]*\\r\\n"
            "([^\\r\\n]*\\r\\n)*\\r\\n", 4096,
            "CONNECT origin.invalid:443 HTTP/1.1\r\n"
            "Host: origin.invalid:443\r\n\r\n",
            "HTTP/1.1 200 Connection established\r\n\r\n",
            "HTTP/1.1 407 Proxy Authentication Required\r\n\r\n"}
    ),
    [](testing::TestParamInfo<StartTlsCase> const& info) {
        auto name = std::string(info.param.name);
        std::replace(name.begin(), name.end(), '-', '_');
        return name;
    });

TEST(FlowMatchState, IgnoresEarlierProtocolDialog) {
    auto signature = starttls_signature(
        "smtp", "^STARTTLS", 16, "^2[0-5]0 [^\\r\\n]*\\r\\n", 512);
    duplexFlow flow;
    flowMatchState state;

    EXPECT_FALSE(append_and_update(
        flow, state, signature, 'w', "220 mail.example ESMTP ready\r\n"));
    EXPECT_FALSE(append_and_update(
        flow, state, signature, 'r', "EHLO client.example\r\n"));
    EXPECT_FALSE(append_and_update(
        flow, state, signature, 'w', "250-mail.example\r\n250 STARTTLS\r\n"));
    EXPECT_FALSE(append_and_update(
        flow, state, signature, 'r', "STARTTLS\r\n"));
    EXPECT_TRUE(append_and_update(
        flow, state, signature, 'w', "220 Ready to start TLS\r\n"));
}

TEST(FlowMatchState, DoesNotAdvanceOnWrongDirection) {
    auto signature = starttls_signature(
        "smtp", "^STARTTLS", 16, "^220 [^\\r\\n]*\\r\\n", 512);
    duplexFlow flow;
    flowMatchState state;

    EXPECT_FALSE(append_and_update(
        flow, state, signature, 'w', "STARTTLS\r\n"));
    EXPECT_FALSE(append_and_update(
        flow, state, signature, 'r', "STARTTLS\r\n"));
    EXPECT_FALSE(append_and_update(
        flow, state, signature, 'r', "220 not a response\r\n"));
    EXPECT_TRUE(append_and_update(
        flow, state, signature, 'w', "220 Ready\r\n"));
}

TEST(FlowMatchState, IndependentConnectionsDoNotShareProgress) {
    auto signature = starttls_signature(
        "smtp", "^STARTTLS", 16, "^220 [^\\r\\n]*\\r\\n", 512);
    duplexFlow first_flow;
    duplexFlow second_flow;
    flowMatchState first_state;
    flowMatchState second_state;

    EXPECT_FALSE(append_and_update(
        first_flow, first_state, signature, 'r', "STARTTLS\r\n"));
    EXPECT_FALSE(append_and_update(
        second_flow, second_state, signature, 'w', "220 Ready\r\n"));
    EXPECT_TRUE(append_and_update(
        first_flow, first_state, signature, 'w', "220 Ready\r\n"));
    EXPECT_FALSE(second_state.hit());
}

TEST(FlowMatchState, SurvivesTrimAfterPartialMatch) {
    auto signature = starttls_signature(
        "smtp", "^STARTTLS", 16, "^220 [^\\r\\n]*\\r\\n", 512);
    duplexFlow flow;
    flowMatchState state;

    EXPECT_FALSE(append_and_update(
        flow, state, signature, 'r', "STARTTLS\r\n"));
    flow.pop();
    EXPECT_TRUE(append_and_update(
        flow, state, signature, 'w', "220 Ready\r\n"));
}

TEST(FlowMatchState, SurvivesRepeatedTrimsBetweenMatches) {
    auto signature = make_signature("four-step", {
        {'r', "^ONE$", 0, 16},
        {'w', "^TWO$", 0, 16},
        {'r', "^THREE$", 0, 16},
        {'w', "^FOUR$", 0, 16},
    });
    duplexFlow flow;
    flowMatchState state;

    EXPECT_FALSE(append_and_update(flow, state, signature, 'r', "ONE"));
    flow.pop();
    EXPECT_FALSE(append_and_update(flow, state, signature, 'w', "TWO"));
    flow.pop();
    EXPECT_FALSE(append_and_update(flow, state, signature, 'r', "THREE"));
    flow.pop();
    EXPECT_TRUE(append_and_update(flow, state, signature, 'w', "FOUR"));
}

TEST(FlowMatchState, FindsSignatureAfterUnmatchedEntriesWereTrimmed) {
    auto signature = starttls_signature(
        "smtp", "^STARTTLS", 16, "^220 [^\\r\\n]*\\r\\n", 512);
    duplexFlow flow;
    flowMatchState state;

    EXPECT_FALSE(append_and_update(flow, state, signature, 'r', "EHLO client\r\n"));
    EXPECT_FALSE(append_and_update(flow, state, signature, 'w', "250 server\r\n"));
    flow.pop();
    flow.pop();

    EXPECT_FALSE(append_and_update(flow, state, signature, 'r', "STARTTLS\r\n"));
    EXPECT_TRUE(append_and_update(flow, state, signature, 'w', "220 Ready\r\n"));
}

TEST(FlowMatchState, HonorsConfiguredMatchWindow) {
    auto signature = starttls_signature(
        "bounded", "STARTTLS", 8, "220 Ready", 9);
    duplexFlow flow;
    flowMatchState state;

    EXPECT_FALSE(append_and_update(
        flow, state, signature, 'r', "12345678STARTTLS"));
    EXPECT_FALSE(append_and_update(flow, state, signature, 'w', "220 Ready"));
    EXPECT_FALSE(state.hit());
}

} // namespace
