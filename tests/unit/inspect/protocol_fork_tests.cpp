#include <inspect/engine/http.hpp>
#include <gtest/gtest.h>

namespace {
using sx::engine::EngineCtx;
namespace h2 = sx::engine::http::v2;

buffer bytes(std::string const& text) {
    buffer result;
    result.assign(text.data(), text.size());
    return result;
}

TEST(ProtocolFork, RejectsUnsupportedState) {
    EngineCtx source;
    EXPECT_THROW((void)source.protocol_fork(), std::logic_error);
    source.state_data = std::string("not an adapted protocol");
    EXPECT_THROW((void)source.protocol_fork(), std::logic_error);
}

TEST(ProtocolFork, DetachesBorrowedBodyAndCompressionBuffers) {
    EngineCtx source;
    source.state_data = h2::Http2Connection();
    auto& original = std::any_cast<h2::Http2Connection&>(source.state_data);
    auto storage = bytes("borrowed bytes");
    auto& stream = original.streams[1];
    stream.doh_response_body_ = storage.view();
    stream.gzip.emplace().in = storage.view();

    auto target = source.protocol_fork();
    auto& cloned = std::any_cast<h2::Http2Connection&>(target->state_data).streams.at(1);
    EXPECT_NE(cloned.doh_response_body_.data(), storage.data());
    EXPECT_NE(cloned.gzip->in.data(), storage.data());

    storage.data()[0] = 'X';
    EXPECT_EQ(cloned.doh_response_body_.string_view(), "borrowed bytes");
    EXPECT_EQ(cloned.gzip->in.string_view(), "borrowed bytes");
    cloned.gzip->in.clear();
    EXPECT_EQ(stream.gzip->in.size(), storage.size());
}

TEST(ProtocolFork, PendingInputAndSettingsHaveIndependentLifetimes) {
    EngineCtx source;
    source.state_data = h2::Http2Connection();
    auto& original = std::any_cast<h2::Http2Connection&>(source.state_data);
    original.request_headers_pending.bytes.assign(17, 'h');
    original.left_settings_awaiting_ack = 2;
    original.client_connection_window = 1234;

    auto target = source.protocol_fork();
    auto& cloned = std::any_cast<h2::Http2Connection&>(target->state_data);
    EXPECT_EQ(cloned.request_headers_pending.bytes.size(), 17U);
    EXPECT_EQ(cloned.left_settings_awaiting_ack, 2U);
    EXPECT_EQ(cloned.client_connection_window, 1234);
    cloned.request_headers_pending.bytes.clear();
    cloned.left_settings_awaiting_ack = 0;
    cloned.client_connection_window = 4321;

    EXPECT_EQ(original.request_headers_pending.bytes.size(), 17U);
    EXPECT_EQ(original.left_settings_awaiting_ack, 2U);
    EXPECT_EQ(original.client_connection_window, 1234);
}

TEST(ProtocolFork, CopiesHttpMetadataButNotUnrelatedInspectorState) {
    EngineCtx source;
    source.state_data = h2::Http2Connection();
    auto app = std::make_shared<sx::engine::http::app_HttpRequest>();
    app->properties()["endpoint"] = "source";
    source.application_data = app;

    auto target = source.protocol_fork();
    ASSERT_NE(target->application_data, app);
    EXPECT_EQ(target->application_data->properties().at("endpoint"), "source");
    target->application_data->properties()["endpoint"] = "target";
    EXPECT_EQ(app->properties().at("endpoint"), "source");

    source.application_data = std::make_shared<sx::engine::CustomApplicationData>("external");
    EXPECT_EQ(source.protocol_fork()->application_data, nullptr);
}

#ifdef USE_HPACK
TEST(ProtocolFork, DetachesBothHpackDecoders) {
    EngineCtx source;
    source.state_data = h2::Http2Connection();
    auto& original = std::any_cast<h2::Http2Connection&>(source.state_data);
    original.request_decoder = std::make_shared<HPACK::decoder_t>();
    original.response_decoder = std::make_shared<HPACK::decoder_t>();
    auto target = source.protocol_fork();
    auto& cloned = std::any_cast<h2::Http2Connection&>(target->state_data);
    ASSERT_TRUE(cloned.request_decoder);
    ASSERT_TRUE(cloned.response_decoder);
    EXPECT_NE(cloned.request_decoder, original.request_decoder);
    EXPECT_NE(cloned.response_decoder, original.response_decoder);
}
#endif

TEST(ProtocolFlowStorage, AppendAndEvictPreservePositionWithoutJournal) {
    duplexFlow flow;
    flow.append('r', bytes("first"));
    flow.append('r', bytes(" tail"));
    flow.append('w', bytes("reply"));
    EXPECT_EQ(flow.size(), 2U);
    EXPECT_EQ(flow.exchanges, 1U);
    EXPECT_EQ(flow.flow_queue().front().counter(), 2U);
    EXPECT_EQ(flow.flow_queue().front().data()->string_view(), "first tail");

    flow.pop();
    EXPECT_EQ(flow.pop_count(), 1U);
    EXPECT_EQ(flow.pos_size(), 2U);
    EXPECT_EQ(flow.flow_queue().front().data()->string_view(), "reply");
    flow.pop();
    flow.pop();
    EXPECT_EQ(flow.size(), 0U);
    EXPECT_EQ(flow.pop_count(), 2U);
    flow.append('r', bytes("next"));
    EXPECT_EQ(flow.pos_size(), 3U);
}

TEST(ProtocolFlowStorage, DatagramBoundariesSurviveSameDirectionAndEviction) {
    duplexFlow flow;
    flow.domain(SOCK_DGRAM);
    flow.append('r', bytes("first"));
    flow.append('r', bytes("second"));
    EXPECT_EQ(flow.size(), 2U);
    flow.pop();
    EXPECT_EQ(flow.flow_queue().front().data()->string_view(), "second");
    EXPECT_EQ(flow.flow_queue().front().counter(), 1U);
    EXPECT_EQ(flow.domain(), SOCK_DGRAM);
}
} // namespace
