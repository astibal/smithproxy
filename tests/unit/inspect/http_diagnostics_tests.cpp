#include <inspect/http_diagnostics.hpp>
#include <inspect/engine/http3.hpp>
#include <gtest/gtest.h>

namespace {
using namespace sx::engine;
namespace http = sx::engine::http;
using E = ProtocolEndpoint;

TEST(HttpDiagnostics, Http1CurrentAndHistoryAreReadOnly) {
    ProtocolViews views;
    auto app = std::make_shared<http::app_HttpRequest>();
    app->version = http::app_HttpRequest::HTTP_VER::HTTP_1;
    app->http_data.host = "example.test";
    app->http_data.uri = "/old";
    app->http_data.method = "GET";
    app->http_data.proto = "https://";
    app->next();
    app->http_data.host = "example.test";
    app->http_data.uri = "/new";
    app->http_data.method = "POST";
    app->http_data.params = "a=1";
    app->http_data.proto = "https://";
    views.context(E::Client).application_data = app;
    auto result = http::diagnostics(views);
    auto const& shared = result["views"]["shared"];
    EXPECT_EQ(shared["current"]["url"], "https://example.test/new?a=1");
    EXPECT_EQ(shared["history"][0]["url"], "https://example.test/old");
    EXPECT_EQ(http::diagnostics(views), result);
    EXPECT_EQ(app->http_data.method, "POST");
    EXPECT_EQ(app->http_history.size(), 1U);
    EXPECT_FALSE(views.split());
}

TEST(HttpDiagnostics, Http2StreamsKeepIdentityAndUnknownLengths) {
    ProtocolViews views;
    http::v2::Http2Connection connection;
    connection.latest_request_stream_id = 3;
    connection.streams[1].request_headers_[":path"] = {"/one"};
    connection.streams[3].request_headers_[":path"] = {"/three"};
    connection.streams[3].response_headers_[":status"] = {"200"};
    connection.streams[3].response_body_bytes_ = 12;
    connection.streams[3].response_content_length_ = 12;
    connection.streams[3].response_ended_ = true;
    views.context(E::Client).state_data = connection;
    auto result = http::diagnostics(views);
    auto const& streams = result["views"]["shared"]["streams"];
    ASSERT_EQ(streams.size(), 2U);
    EXPECT_EQ(streams[0]["id"], 1);
    EXPECT_EQ(streams[1]["id"], 3);
    EXPECT_EQ(streams[0]["request"]["headers"][0][1], "/one");
    EXPECT_EQ(streams[1]["response"]["body_bytes"], 12);
    EXPECT_EQ(streams[1]["response"]["content_length"], 12);
    EXPECT_FALSE(streams[0]["response"].contains("content_length"));
    EXPECT_EQ(http::diagnostics(views), result);
}

TEST(HttpDiagnostics, Http3SnapshotDoesNotSelectAnotherStream) {
    ProtocolViews views;
    http::v3::Http3Connection connection;
    auto& selected = connection.streams[ProtocolStream{4, 0}];
    auto& other = connection.streams[ProtocolStream{8, 0}];
    selected.application->http_data.uri = "/four";
    other.application->http_data.uri = "/eight";
    selected.directions[1].headers = {{{":status", "200"}, {"set-cookie", "a=1"}, {"set-cookie", "b=2"}}, {{"trailer", "yes"}}};
    selected.directions[1].reset_error = 0;
    views.context(E::Client).application_data = other.application;
    views.context(E::Client).state_data = connection;
    auto result = http::diagnostics(views, ProtocolStream{4, 0});
    auto const& shared = result["views"]["shared"];
    EXPECT_EQ(shared["current"]["path"], "/four");
    auto const& response = shared["streams"][0]["response"];
    ASSERT_EQ(response["header_sections"].size(), 2U);
    EXPECT_EQ(response["header_sections"][0].size(), 3U);
    EXPECT_EQ(response["reset_error"], 0);
    EXPECT_EQ(views.context(E::Client).application_data, other.application);
    EXPECT_EQ(http::diagnostics(views, ProtocolStream{4, 0}), result);
}

TEST(HttpDiagnostics, NonUtf8BytesRemainSerializableAndLossless) {
    ProtocolViews views;
    http::v2::Http2Connection connection;
    connection.streams[1].request_headers_["x-test"] = {std::string(1, '\xff')};
    views.context(E::Client).state_data = connection;
    auto result = http::diagnostics(views);
    auto const& value = result["views"]["shared"]["streams"][0]["request"]["headers"][0][1];
    EXPECT_EQ(value["encoding"], "base64");
    EXPECT_EQ(value["data"], "/w==");
    EXPECT_NO_THROW(result.dump());
}

TEST(HttpDiagnostics, UnrecognizedProtocolHasNoHttpSnapshot) {
    ProtocolViews views;
    EXPECT_TRUE(http::diagnostics(views).empty());
}
} // namespace
