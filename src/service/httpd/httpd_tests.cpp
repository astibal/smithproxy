#include <gtest/gtest.h>

#include <service/httpd/httpd.hpp>

namespace {

using sx::webserver::HttpSessions;
using sx::webserver::TimedOptional;

class HttpSessionsTest : public ::testing::Test {
protected:
    void SetUp() override {
        auto lock = std::scoped_lock(HttpSessions::lock);
        HttpSessions::access_keys.clear();
        HttpSessions::api_keys.clear();
        HttpSessions::extend_on_access = false;
    }

    void TearDown() override {
        auto lock = std::scoped_lock(HttpSessions::lock);
        HttpSessions::access_keys.clear();
        HttpSessions::api_keys.clear();
        HttpSessions::extend_on_access = true;
    }
};

TEST_F(HttpSessionsTest, ExpiredValuesAreRejectedAndRemoved) {
    {
        auto lock = std::scoped_lock(HttpSessions::lock);
        HttpSessions::access_keys["auth"]["csrf"] = TimedOptional<std::string>("token", 0);
    }

    EXPECT_EQ(HttpSessions::table_value("auth", "csrf"), "");
    HttpSessions::cleanup();

    auto lock = std::scoped_lock(HttpSessions::lock);
    EXPECT_TRUE(HttpSessions::access_keys.empty());
}

TEST_F(HttpSessionsTest, ValidValuesAndApiKeySnapshotsRoundTrip) {
    {
        auto lock = std::scoped_lock(HttpSessions::lock);
        HttpSessions::access_keys["auth"]["csrf_token"] = TimedOptional<std::string>("token", 60);
    }

    EXPECT_EQ(HttpSessions::table_value("auth", "csrf_token"), "token");
    EXPECT_TRUE(HttpSessions::validate_tokens("auth", "token"));

    HttpSessions::replace_api_keys({"one", "two"});
    EXPECT_TRUE(HttpSessions::has_api_keys());
    EXPECT_TRUE(HttpSessions::has_api_key("one"));
    EXPECT_FALSE(HttpSessions::has_api_key("missing"));
    EXPECT_EQ(HttpSessions::api_keys_snapshot(),
              (std::set<std::string>{"one", "two"}));
}

TEST(HttpResponderTest, AccumulatesBinaryPostChunksAndBoundsTheBody) {
    unsigned calls = 0;
    std::string received;
    auto callback = [&](MHD_Connection*, std::string const&, std::string const& body) {
        ++calls;
        received = body;
        sx::webserver::Http_JsonResponseParams result;
        result.response_code = 200;
        result.response = {{"ok", true}};
        return result;
    };
    sx::webserver::Http_Responder responder("POST", "/upload", callback);

    void* state = new lmh::ConnectionState(responder);
    std::stringstream response;
    const char first[] = {'a', '\0', 'b'};
    std::size_t first_size = sizeof(first);
    auto pending = responder.createResponse(nullptr, "/upload", "POST", first,
                                            &first_size, &state, response);
    EXPECT_EQ(pending.response_code, MHD_YES);
    EXPECT_EQ(first_size, 0U);
    EXPECT_EQ(calls, 0U);

    const char second[] = {'c', 'd'};
    std::size_t second_size = sizeof(second);
    responder.createResponse(nullptr, "/upload", "POST", second,
                             &second_size, &state, response);
    EXPECT_EQ(calls, 0U);

    std::size_t complete_size = 0;
    auto complete = responder.createResponse(nullptr, "/upload", "POST", nullptr,
                                             &complete_size, &state, response);
    EXPECT_EQ(complete.response_code, 200);
    EXPECT_EQ(calls, 1U);
    EXPECT_EQ(received, std::string(first, sizeof(first)) + std::string(second, sizeof(second)));
    delete static_cast<lmh::ConnectionState*>(state);

    calls = 0;
    state = new lmh::ConnectionState(responder);
    std::string oversized(8U * 1024U * 1024U + 1U, 'x');
    std::size_t oversized_size = oversized.size();
    responder.createResponse(nullptr, "/upload", "POST", oversized.data(),
                             &oversized_size, &state, response);
    complete_size = 0;
    auto rejected = responder.createResponse(nullptr, "/upload", "POST", nullptr,
                                             &complete_size, &state, response);
    EXPECT_EQ(rejected.response_code, 413);
    EXPECT_EQ(calls, 0U);
    delete static_cast<lmh::ConnectionState*>(state);
}


} // namespace
