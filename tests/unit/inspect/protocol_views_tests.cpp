#include <inspect/protocol_views.hpp>
#include <inspect/engine/http.hpp>
#include <gtest/gtest.h>
#include <random>
#include <future>

namespace {
using sx::engine::ProtocolViews;
using sx::engine::EngineCtx;
using E = ProtocolViews::Endpoint;
using P = ProtocolViews::Phase;
namespace h2 = sx::engine::http::v2;

std::string integer(std::uint32_t n) {
    std::string bytes(4, '\0');
    for (int i = 3; i >= 0; --i) { bytes[i] = char(n & 255); n >>= 8; }
    return bytes;
}

std::string frame(unsigned type, unsigned flags, unsigned stream, std::string payload = {}) {
    return integer(payload.size()).substr(1) + char(type) + char(flags) + integer(stream) + payload;
}

std::string setting(unsigned id, unsigned value) {
    return frame(4, 0, 0, integer(id).substr(2) + integer(value));
}

std::string request() {
    return std::string("\x83\x87\x84\x01\x0c", 5) + "example.test";
}

buffer bytes(std::string const& value) {
    buffer result;
    result.assign(value.data(), value.size());
    return result;
}

auto& state(ProtocolViews& views, E endpoint) {
    return std::any_cast<h2::Http2Connection&>(views.context(endpoint).state_data);
}

void exchange(ProtocolViews& views, E sender, std::string const& input,
              std::string const& output) {
    const auto token = views.begin(sender, bytes(input), input.size());
    views.finish(token, bytes(output));
}

void pass(ProtocolViews& views, E sender, std::string const& data) {
    exchange(views, sender, data, data);
}

void initialize(ProtocolViews& views) {
    views.context(E::Client).state_data = h2::Http2Connection();
    pass(views, E::Client, "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n" + frame(4, 0, 0));
    pass(views, E::Server, frame(4, 0, 0));
    pass(views, E::Client, frame(4, 1, 0));
    pass(views, E::Server, frame(4, 1, 0));
    pass(views, E::Client, frame(1, 4, 1, request()));
    pass(views, E::Server, frame(1, 4, 1, std::string(1, '\x88')));
    ASSERT_FALSE(state(views, E::Client).connection_invalid);
    ASSERT_FALSE(state(views, E::Server).connection_invalid);
}

TEST(ProtocolViews, RequestRewriteResponseAndNextRequest) {
    ProtocolViews views(ProtocolViews::Mode::Rewrite);
    initialize(views);
    const auto original = frame(1, 4, 3, request()); // POST
    auto changed_headers = request();
    changed_headers[0] = '\x82'; // GET
    const auto token = views.begin(E::Client, bytes(original), 123);

    ASSERT_EQ(state(views, E::Client).streams.at(3).request_header(":method"), "POST");
    views.finish(token, bytes(frame(1, 4, 3, changed_headers)));
    ASSERT_TRUE(views.split());
    auto* client = &views.context(E::Client);
    auto* server = &views.context(E::Server);
    ASSERT_NE(client, server);
    EXPECT_EQ(state(views, E::Client).streams.at(3).request_header(":method"), "POST");
    EXPECT_EQ(state(views, E::Server).streams.at(3).request_header(":method"), "GET");

    // A server response is first interpreted against GET. The client then
    // sees that same response against POST; the webhook is not called again.
    pass(views, E::Server, frame(1, 4, 3, std::string(1, '\x88')));
    pass(views, E::Client, frame(1, 4, 5, request()));
    EXPECT_EQ(&views.context(E::Client), client);
    EXPECT_EQ(&views.context(E::Server), server);

    for (auto endpoint : {E::Client, E::Server}) {
        EXPECT_EQ(state(views, endpoint).streams.at(3).response_header(":status"), "200");
        EXPECT_EQ(state(views, endpoint).streams.at(5).request_header(":method"), "POST");
        EXPECT_FALSE(state(views, endpoint).connection_invalid);
    }
}

class ProtocolViewsDirection : public ::testing::TestWithParam<E> {};

TEST_P(ProtocolViewsDirection, UnchangedInputIsProcessedOncePerEndpoint) {
    ProtocolViews views(ProtocolViews::Mode::Rewrite);
    initialize(views);
    pass(views, GetParam(), setting(4, 70000));
    EXPECT_TRUE(views.split());
    EXPECT_NE(&views.context(E::Client), &views.context(E::Server));

    for (auto endpoint : {E::Client, E::Server}) {
        auto& ctx = state(views, endpoint);
        EXPECT_EQ(GetParam() == E::Client ? ctx.left_settings_awaiting_ack
                                         : ctx.right_settings_awaiting_ack, 1U);
    }
}

TEST_P(ProtocolViewsDirection, FirstSettingsRewriteAndAckUseCorrectEndpoint) {
    ProtocolViews views(ProtocolViews::Mode::Rewrite);
    initialize(views);
    const auto sender = GetParam();
    const auto receiver = sender == E::Client ? E::Server : E::Client;
    exchange(views, sender, setting(4, 100), setting(4, 200));
    ASSERT_TRUE(views.split());
    EXPECT_EQ(&views.context(sender, P::Output), &views.context(receiver));
    EXPECT_EQ(&views.context(receiver, P::Output), &views.context(sender));

    pass(views, receiver, frame(4, 1, 0));
    pass(views, receiver, frame(0, 0, 1, "12345"));

    for (auto endpoint : {sender, receiver}) {
        auto& ctx = state(views, endpoint);
        const auto& stream = ctx.streams.at(1);
        const auto remaining = receiver == E::Client ? stream.request_flow_window_
                                                     : stream.response_flow_window_;
        EXPECT_EQ(remaining, endpoint == sender ? 95 : 195);
        EXPECT_EQ(sender == E::Client ? ctx.left_settings_awaiting_ack
                                     : ctx.right_settings_awaiting_ack, 0U);
        EXPECT_FALSE(ctx.connection_invalid);
    }
}

TEST_P(ProtocolViewsDirection, HoldThenReleaseAdvancesReceiverOnlyOnRelease) {
    ProtocolViews views(ProtocolViews::Mode::Rewrite);
    initialize(views);
    const auto sender = GetParam();
    const auto receiver = sender == E::Client ? E::Server : E::Client;
    const auto data = frame(0, 0, 1, "hello");
    exchange(views, sender, data.substr(0, 11), "");
    ASSERT_TRUE(views.split());
    EXPECT_NE(&views.context(sender), &views.context(receiver));
    exchange(views, sender, data.substr(11), frame(0, 0, 1, "rewritten"));

    for (auto endpoint : {sender, receiver}) {
        auto& ctx = state(views, endpoint);
        const auto& stream = ctx.streams.at(1);
        EXPECT_EQ(sender == E::Client ? stream.request_body_bytes_ : stream.response_body_bytes_,
                  endpoint == sender ? 5U : 9U);
        EXPECT_TRUE(ctx.left_frame_pending.empty());
        EXPECT_TRUE(ctx.right_frame_pending.empty());
        EXPECT_FALSE(ctx.connection_invalid);
    }
    pass(views, E::Client, frame(6, 0, 0, "12345678"));
    pass(views, E::Server, frame(6, 1, 0, "12345678"));
    EXPECT_TRUE(state(views, receiver).client_pings_pending.empty());
}

TEST_P(ProtocolViewsDirection, RepeatedSameLengthRewritesDoNotCreateMoreViews) {
    ProtocolViews views(ProtocolViews::Mode::Rewrite);
    initialize(views);
    auto sender = GetParam();
    exchange(views, sender, setting(4, 100), setting(4, 200));
    auto* client = &views.context(E::Client);
    auto* server = &views.context(E::Server);

    for (unsigned i = 0; i < 30; ++i) {
        sender = sender == E::Client ? E::Server : E::Client;
        exchange(views, sender, setting(4, 1000 + i), setting(4, 2000 + i));
        EXPECT_EQ(&views.context(E::Client), client);
        EXPECT_EQ(&views.context(E::Server), server);
    }
}

TEST_P(ProtocolViewsDirection, InvalidOutputDoesNotPoisonTheInputParser) {
    ProtocolViews views(ProtocolViews::Mode::Rewrite);
    initialize(views);
    const auto sender = GetParam();
    const auto receiver = sender == E::Client ? E::Server : E::Client;
    // SETTINGS must have stream id zero. Research/rewrite may intentionally
    // send this invalid output; observation must not silently repair it.
    exchange(views, sender, frame(4, 0, 0), frame(4, 0, 1));
    EXPECT_TRUE(state(views, receiver).connection_invalid);
    EXPECT_FALSE(state(views, sender).connection_invalid);
    pass(views, sender, frame(0, 0, 1, "valid input"));
    EXPECT_FALSE(state(views, sender).connection_invalid);
}

TEST_P(ProtocolViewsDirection, EveryDataFrameSplitKeepsIndependentBoundaries) {
    const auto data = frame(0, 0, 1, "fragmented body");
    for (std::size_t cut = 1; cut < data.size(); ++cut) {
        SCOPED_TRACE(cut);
        ProtocolViews views(ProtocolViews::Mode::Rewrite);
        initialize(views);
        const auto sender = GetParam();
        const auto receiver = sender == E::Client ? E::Server : E::Client;
        exchange(views, sender, data.substr(0, cut), "");
        exchange(views, sender, data.substr(cut), frame(0, 0, 1, "replacement"));
        pass(views, sender, frame(0, 0, 1, "next"));
        for (auto endpoint : {sender, receiver}) {
            EXPECT_TRUE(state(views, endpoint).left_frame_pending.empty());
            EXPECT_TRUE(state(views, endpoint).right_frame_pending.empty());
            EXPECT_FALSE(state(views, endpoint).connection_invalid);
        }
    }
}

TEST(ProtocolViews, InputHpackHistorySurvivesOutputRewrite) {
#ifdef USE_HPACK
    ProtocolViews views(ProtocolViews::Mode::Rewrite);
    initialize(views);
    const auto literal = std::string("\x40\x06", 2) + "x-test";
    exchange(views, E::Client,
             frame(1, 4, 3, request() + literal + "\x03one"),
             frame(1, 4, 3, request() + literal + "\x03two"));

    // The next client's index still denotes one. In rewrite mode the server
    // may interpret the same index as two: observe this, do not secretly fix it.
    pass(views, E::Client, frame(1, 4, 5, request() + std::string(1, char(0xbe))));
    EXPECT_EQ(state(views, E::Client).streams.at(5).request_header("x-test"), "one");
    EXPECT_EQ(state(views, E::Server).streams.at(5).request_header("x-test"), "two");
#else
    GTEST_SKIP() << "requires HPACK";
#endif
}

TEST(ProtocolViews, OutputDoesNotOverwriteInputAnnotationsOrOrigin) {
    ProtocolViews views(ProtocolViews::Mode::Rewrite);
    initialize(views);
    const auto input = frame(0, 0, 1, "abc");
    auto token = views.begin(E::Client, bytes(input), 456);
    auto app = std::dynamic_pointer_cast<sx::engine::http::app_HttpRequest>(
        views.context(E::Client).application_data);
    const auto annotations = app->payload_annotations;
    views.finish(token, bytes(frame(0, 0, 1, "much longer")));
    EXPECT_TRUE(app->l7_payload_matches(input, 456));
    EXPECT_EQ(app->payload_annotations, annotations);
    EXPECT_NE(views.context(E::Client).application_data,
              views.context(E::Server).application_data);
    EXPECT_FALSE(views.context(E::Server).protocol_only);
}

TEST(ProtocolViews, RejectsNestedOrStaleCallbacksWithoutChangingState) {
    ProtocolViews views(ProtocolViews::Mode::Rewrite);
    initialize(views);
    const auto input = bytes(frame(0, 0, 1, "abc"));
    const auto token = views.begin(E::Client, input, 0);
    EXPECT_THROW(views.begin(E::Server, input, 0), std::logic_error);
    EXPECT_THROW(views.finish(token + 1, input), std::logic_error);
    views.finish(token, input);
    EXPECT_THROW(views.finish(token, input), std::logic_error);
    EXPECT_TRUE(views.split());
    EXPECT_EQ(state(views, E::Client).streams.at(1).request_body_bytes_, 3U);
}

TEST(ProtocolViews, AbandonedInputIsNotDeliveredToReceiver) {
    ProtocolViews views(ProtocolViews::Mode::Rewrite);
    initialize(views);
    const auto token = views.begin(E::Client, bytes(frame(0, 0, 1, "abc")), 0);
    views.abandon(token);
    EXPECT_TRUE(views.split());
    EXPECT_EQ(state(views, E::Client).streams.at(1).request_body_bytes_, 3U);
    EXPECT_EQ(state(views, E::Server).streams.at(1).request_body_bytes_, 0U);
}

TEST(ProtocolViews, PreservesUnrelatedInputInspectorMetadata) {
    ProtocolViews views(ProtocolViews::Mode::Rewrite);
    initialize(views);
    auto metadata = std::make_shared<sx::engine::CustomApplicationData>("external-inspector");
    metadata->properties()["observation"] = "keep";
    views.context(E::Client).application_data = metadata;
    exchange(views, E::Client, frame(0, 0, 1, "abc"), frame(0, 0, 1, "xyz"));
    EXPECT_EQ(views.context(E::Client).application_data, metadata);
    EXPECT_EQ(metadata->properties().at("observation"), "keep");
    EXPECT_NE(views.context(E::Server).application_data, metadata);
}

TEST(ProtocolViews, FragmentedPrefaceAndSeededHistory) {
    ProtocolViews views(ProtocolViews::Mode::Rewrite);
    views.context(E::Client).state_data = h2::Http2Connection();
    const std::string preface = "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";
    views.seed(E::Client, bytes(preface.substr(0, 7)));
    exchange(views, E::Client, preface.substr(7) + setting(4, 100),
             preface.substr(7) + setting(4, 200));
    pass(views, E::Server, frame(4, 0, 0));
    pass(views, E::Server, frame(4, 1, 0));

    for (auto endpoint : {E::Client, E::Server}) {
        EXPECT_TRUE(state(views, endpoint).client_preface_complete);
        EXPECT_FALSE(state(views, endpoint).connection_invalid);
        EXPECT_EQ(state(views, endpoint).left_settings_awaiting_ack, 0U);
    }
    EXPECT_THROW(views.seed(E::Client, bytes(preface)), std::logic_error);
}

TEST_P(ProtocolViewsDirection, HeldDirectionDoesNotBlockOppositeDirection) {
    ProtocolViews views(ProtocolViews::Mode::Rewrite);
    initialize(views);
    const auto sender = GetParam();
    const auto receiver = sender == E::Client ? E::Server : E::Client;
    const auto held = frame(0, 0, 1, "first");

    exchange(views, sender, held.substr(0, 7), "");
    pass(views, receiver, frame(0, 0, 1, "opposite"));
    exchange(views, sender, held.substr(7), frame(0, 0, 1, "replacement"));

    for (auto endpoint : {sender, receiver}) {
        const auto& stream = state(views, endpoint).streams.at(1);
        EXPECT_EQ(sender == E::Client ? stream.request_body_bytes_ : stream.response_body_bytes_,
                  endpoint == sender ? 5U : 11U);
        EXPECT_EQ(sender == E::Client ? stream.response_body_bytes_ : stream.request_body_bytes_, 8U);
        EXPECT_FALSE(state(views, endpoint).connection_invalid);
    }
}

TEST_P(ProtocolViewsDirection, PaddingIsAccountedIndependentlyAfterResize) {
    ProtocolViews views(ProtocolViews::Mode::Rewrite);
    initialize(views);
    const auto sender = GetParam();
    const auto receiver = sender == E::Client ? E::Server : E::Client;
    exchange(views, sender, frame(0, 8, 1, std::string("\3abc\0\0\0", 7)),
             frame(0, 8, 1, std::string("\0longer", 7)));
    pass(views, sender, frame(0, 0, 1, "next"));

    for (auto endpoint : {sender, receiver}) {
        const auto& stream = state(views, endpoint).streams.at(1);
        EXPECT_EQ(sender == E::Client ? stream.request_body_bytes_ : stream.response_body_bytes_,
                  endpoint == sender ? 7U : 10U);
        EXPECT_FALSE(state(views, endpoint).connection_invalid);
    }
}

TEST(ProtocolViews, FirstRewriteDuringContinuationPreservesBothHeaderBlocks) {
#ifdef USE_HPACK
    const auto prefix = request() + std::string("\x40\x06", 2) + "x-test" + "\x03";

    for (std::size_t cut = 1; cut <= prefix.size(); ++cut) {
        SCOPED_TRACE(cut);
        ProtocolViews views(ProtocolViews::Mode::Rewrite);
        initialize(views);
        pass(views, E::Client, frame(1, 0, 3, prefix.substr(0, cut)));
        exchange(views, E::Client,
                 frame(9, 4, 3, prefix.substr(cut) + "one"),
                 frame(9, 4, 3, prefix.substr(cut) + "two"));
        pass(views, E::Server, frame(1, 4, 3, std::string(1, '\x88')));
        pass(views, E::Client, frame(1, 4, 5, request() + std::string(1, char(0xbe))));

        EXPECT_EQ(state(views, E::Client).streams.at(5).request_header("x-test"), "one");
        EXPECT_EQ(state(views, E::Server).streams.at(5).request_header("x-test"), "two");

        for (auto endpoint : {E::Client, E::Server}) {
            EXPECT_FALSE(state(views, endpoint).request_headers_pending.active());
            EXPECT_FALSE(state(views, endpoint).connection_invalid);
        }
    }
#else
    GTEST_SKIP() << "requires HPACK";
#endif
}

TEST(ProtocolViews, DeterministicMixedTrafficMatchesEndpointByteLedger) {
    // A small independent oracle: what each endpoint sent/received, counted
    // from the test's logical DATA payloads, not read back from parser state.
    for (unsigned seed = 0; seed < 16; ++seed) {
        SCOPED_TRACE(seed);
        std::mt19937 rng(seed);
        ProtocolViews views(ProtocolViews::Mode::Rewrite);
        initialize(views);
        std::uint64_t expected[2][2] = {};
        std::string held[2];
        std::uint64_t held_size[2] = {};
        auto* client = &views.context(E::Client);
        sx::engine::EngineCtx* split_client = nullptr;
        sx::engine::EngineCtx* split_server = nullptr;

        for (unsigned step = 0; step < 100; ++step) {
            SCOPED_TRACE(step);
            const unsigned side = rng() % 2;
            const unsigned other = 1 - side;
            const auto sender = side == 0 ? E::Client : E::Server;
            const auto size = rng() % 32;
            const auto input = frame(0, 0, 1, std::string(size, 'a'));
            expected[side][side] += size;

            std::string output;

            if (rng() % 4 == 0) {
                held[side] += input;
                held_size[side] += size;
            } else {
                const auto changed_size = rng() % 3 == 0 ? rng() % 48 : size;
                output = held[side] + frame(0, 0, 1, std::string(changed_size, 'a'));
                expected[other][side] += held_size[side] + changed_size;
                held[side].clear();
                held_size[side] = 0;
            }

            exchange(views, sender, input, output);

            if (views.split() && !split_client) {
                split_client = &views.context(E::Client);
                split_server = &views.context(E::Server);
                EXPECT_NE(split_client, split_server);
            }

            if (split_client) {
                EXPECT_EQ(&views.context(E::Client), split_client);
                EXPECT_EQ(&views.context(E::Server), split_server);
            } else {
                EXPECT_EQ(&views.context(E::Client), client);
                EXPECT_EQ(&views.context(E::Server), client);
            }

            for (unsigned view = 0; view < 2; ++view) {
                auto& connection = state(views, view == 0 ? E::Client : E::Server);
                const auto& stream = connection.streams.at(1);
                ASSERT_EQ(stream.request_body_bytes_, expected[view][0]);
                ASSERT_EQ(stream.response_body_bytes_, expected[view][1]);
                ASSERT_FALSE(connection.connection_invalid);
                ASSERT_TRUE(connection.left_frame_pending.empty());
                ASSERT_TRUE(connection.right_frame_pending.empty());
            }
        }
    }
}

// Deliberately not HTTP: routing, holds and forks must work without H2 state,
// magic bytes or frame-specific branches in the endpoint-view coordinator.
struct LedgerState {
    std::string client_bytes;
    std::string server_bytes;
};

class LedgerAdapter final : public sx::engine::ProtocolAdapter {
public:
    mutable unsigned forks = 0;
    mutable unsigned inputs = 0;
    mutable unsigned outputs = 0;

    bool owns(EngineCtx const& ctx) const override {
        return ctx.state_data.type() == typeid(LedgerState);
    }

    Preparation prepare(EngineCtx& ctx, bool, buffer const&) const override {
        return owns(ctx) ? Preparation::Ready : Preparation::Unavailable;
    }

    void observe(EngineCtx& ctx, bool from_client, buffer const& data,
                 std::uint64_t) const override {
        auto& state = std::any_cast<LedgerState&>(ctx.state_data);
        (from_client ? state.client_bytes : state.server_bytes).append(data.string_view());

        if (ctx.protocol_only) {
            ++outputs;
            EXPECT_EQ(ctx.origin, nullptr);
        } else {
            ++inputs;
        }
    }

    std::unique_ptr<EngineCtx> fork(EngineCtx const& ctx) const override {
        ++forks;
        return std::make_unique<EngineCtx>(ctx);
    }
};

TEST(ProtocolViews, NonHttpAdapterRoutesBothDirectionsWithOneSetupFork) {
    LedgerAdapter adapter;
    ProtocolViews views(adapter, ProtocolViews::Mode::Rewrite);
    views.context(E::Client).state_data = LedgerState{};
    pass(views, E::Client, "original");
    EXPECT_TRUE(views.split());
    EXPECT_EQ(adapter.outputs, 1U);

    exchange(views, E::Client, "request", "rewritten");
    ASSERT_TRUE(views.split());
    exchange(views, E::Server, "reply", "translated");
    pass(views, E::Client, "next");

    const auto& client = std::any_cast<LedgerState const&>(views.context(E::Client).state_data);
    const auto& server = std::any_cast<LedgerState const&>(views.context(E::Server).state_data);
    EXPECT_EQ(client.client_bytes, "originalrequestnext");
    EXPECT_EQ(server.client_bytes, "originalrewrittennext");
    EXPECT_EQ(client.server_bytes, "translated");
    EXPECT_EQ(server.server_bytes, "reply");
    EXPECT_EQ(adapter.forks, 1U);
    EXPECT_EQ(adapter.inputs, 4U);
    EXPECT_EQ(adapter.outputs, 4U);
    EXPECT_FALSE(views.context(E::Client).protocol_only);
    EXPECT_FALSE(views.context(E::Server).protocol_only);
}

TEST(ProtocolViews, ObserveNeverCopiesOrParsesOutput) {
    LedgerAdapter adapter;
    ProtocolViews views(adapter);
    views.context(E::Client).state_data = LedgerState{};

    for (unsigned i = 0; i < 100; ++i) {
        pass(views, i % 2 ? E::Server : E::Client, "unchanged");
    }

    EXPECT_FALSE(views.split());
    EXPECT_EQ(adapter.forks, 0U);
    EXPECT_EQ(adapter.inputs, 100U);
    EXPECT_EQ(adapter.outputs, 0U);
    EXPECT_THROW(views.set_mode(ProtocolViews::Mode::Rewrite), std::logic_error);
    EXPECT_NO_THROW(views.set_mode(ProtocolViews::Mode::Observe));
}

TEST(ProtocolViews, UnreservedSameSizeEditsKeepOnlyTheInputHistory) {
    LedgerAdapter adapter;
    ProtocolViews views(adapter);
    views.context(E::Client).state_data = LedgerState{};

    for (unsigned i = 0; i < 100; ++i) {
        exchange(views, i % 2 ? E::Server : E::Client, "x", "y");
    }

    const auto& input = std::any_cast<LedgerState const&>(views.context(E::Client).state_data);
    EXPECT_EQ(input.client_bytes, std::string(50, 'x'));
    EXPECT_EQ(input.server_bytes, std::string(50, 'x'));
    EXPECT_EQ(&views.context(E::Client), &views.context(E::Server));
    EXPECT_FALSE(views.split());
    EXPECT_EQ(adapter.forks, 0U);
    EXPECT_EQ(adapter.inputs, 100U);
    EXPECT_EQ(adapter.outputs, 0U);
}

TEST(ProtocolViews, UnreservedHeaderEditDoesNotRepairProtocolState) {
    ProtocolViews views;
    initialize(views);
    auto changed = request();
    changed[0] = '\x82'; // POST -> GET, same HPACK size.
    exchange(views, E::Client, frame(1, 4, 3, request()), frame(1, 4, 3, changed));

    // This mismatch is the advertised low-level contract, not an implicit fork.
    EXPECT_FALSE(views.split());
    EXPECT_EQ(state(views, E::Server).streams.at(3).request_header(":method"), "POST");
    pass(views, E::Client, frame(1, 4, 5, request()));
    EXPECT_EQ(state(views, E::Client).streams.at(5).request_header(":method"), "POST");
    EXPECT_FALSE(state(views, E::Client).connection_invalid);
}

TEST(ProtocolViews, SetupRewriteForksOnceAndKeepsEndpointHistories) {
    for (const auto first : {E::Client, E::Server}) {
        LedgerAdapter adapter;
        ProtocolViews views(adapter);
        views.context(E::Client).state_data = LedgerState{};
        views.set_mode(ProtocolViews::Mode::Rewrite);

        // No payload has been parsed when the output context is initialized.
        exchange(views, first, "source", "changed");
        const auto second = first == E::Client ? E::Server : E::Client;
        const auto token = views.begin(second, bytes("hold"), 4);
        views.abandon(token);
        exchange(views, second, "tail", "holdtail");

        for (unsigned i = 0; i < 100; ++i) pass(views, first, "x");

        const auto& source = std::any_cast<LedgerState const&>(views.context(first).state_data);
        const auto& destination = std::any_cast<LedgerState const&>(views.context(second).state_data);
        EXPECT_EQ(first == E::Client ? source.client_bytes : source.server_bytes,
                  "source" + std::string(100, 'x'));
        EXPECT_EQ(first == E::Client ? destination.client_bytes : destination.server_bytes,
                  "changed" + std::string(100, 'x'));
        EXPECT_EQ(second == E::Client ? source.client_bytes : source.server_bytes, "holdtail");
        EXPECT_EQ(second == E::Client ? destination.client_bytes : destination.server_bytes, "holdtail");
        EXPECT_EQ(adapter.forks, 1U);
        EXPECT_EQ(adapter.inputs, 103U);
        EXPECT_EQ(adapter.outputs, 102U); // Holding emitted nothing.
        EXPECT_THROW(views.set_mode(ProtocolViews::Mode::Observe), std::logic_error);
    }
}

TEST(ProtocolViews, SetupRewriteUsesBothViewsFromFirstPreface) {
    ProtocolViews views(ProtocolViews::Mode::Rewrite);
    duplexFlow history;
    const auto preface = std::string("PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n");
    auto initial = bytes(preface + frame(4, 0, 0));
    ASSERT_TRUE(views.prepare(E::Client, initial, history, false));
    auto token = views.begin(E::Client, initial, initial.size());
    views.finish(token, initial);
    pass(views, E::Server, frame(4, 0, 0));
    auto changed = request();
    changed[0] = '\x82';
    exchange(views, E::Client, frame(1, 4, 1, request()), frame(1, 4, 1, changed));
    EXPECT_EQ(state(views, E::Client).streams.at(1).request_header(":method"), "POST");
    EXPECT_EQ(state(views, E::Server).streams.at(1).request_header(":method"), "GET");
    EXPECT_FALSE(state(views, E::Client).connection_invalid);
    EXPECT_FALSE(state(views, E::Server).connection_invalid);
}

TEST(ProtocolViews, SetupRewriteClonesThePartialPrefaceBeforeCurrentRead) {
    ProtocolViews views(ProtocolViews::Mode::Rewrite);
    views.context(E::Client).negotiated_alpn = "h2";
    const std::string preface(h2::txt::magic);
    duplexFlow history;
    history.append('r', bytes(preface.substr(0, 8)));
    const auto current = bytes(preface.substr(8) + frame(4, 0, 0));
    history.append('r', current);

    ASSERT_TRUE(views.prepare(E::Client, current, history, true));
    const auto token = views.begin(E::Client, current, current.size());
    views.finish(token, current);

    ASSERT_TRUE(views.split());
    for (const auto endpoint : {E::Client, E::Server}) {
        EXPECT_FALSE(state(views, endpoint).connection_invalid);
        EXPECT_EQ(state(views, endpoint).left_settings_awaiting_ack, 1U);
    }
}

TEST(ProtocolViews, NonHttpAdapterHoldsWithoutAdvancingReceiver) {
    LedgerAdapter adapter;
    ProtocolViews views(adapter, ProtocolViews::Mode::Rewrite);
    views.context(E::Client).state_data = LedgerState{};
    const auto token = views.begin(E::Client, bytes("held"), 4);
    views.abandon(token);

    ASSERT_TRUE(views.split());
    EXPECT_EQ(adapter.outputs, 0U);
    exchange(views, E::Client, "tail", "heldtail");

    for (auto endpoint : {E::Client, E::Server}) {
        EXPECT_EQ(std::any_cast<LedgerState const&>(views.context(endpoint).state_data)
                      .client_bytes, "heldtail");
    }

    EXPECT_EQ(adapter.forks, 1U);
}

TEST(ProtocolViews, UnsupportedProtocolKeepsLegacyPath) {
    ProtocolViews views(ProtocolViews::Mode::Rewrite);
    duplexFlow history;
    EXPECT_FALSE(views.prepare(E::Client, bytes("opaque"), history, false));
    EXPECT_FALSE(views.active());
    EXPECT_FALSE(views.context(E::Client).state_data.has_value());
    EXPECT_THROW(views.begin(E::Client, bytes("opaque"), 6), std::logic_error);
}

TEST(ProtocolViews, NonHttpAlpnDoesNotActivateHttpAdapter) {
    ProtocolViews views(ProtocolViews::Mode::Rewrite);
    views.context(E::Client).negotiated_alpn = "smtp";
    duplexFlow history;
    EXPECT_FALSE(views.prepare(E::Client, bytes(h2::txt::magic), history, false));
    EXPECT_FALSE(views.active());
}

TEST(ProtocolViews, AdapterBootstrapsOnlyHistoryBeforeCurrentRead) {
    ProtocolViews views(ProtocolViews::Mode::Rewrite);
    views.context(E::Client).negotiated_alpn = "h2";
    const std::string preface(h2::txt::magic);
    duplexFlow history;
    history.append('r', bytes(preface.substr(0, 8)));
    const auto current = bytes(preface.substr(8) + frame(4, 0, 0));
    history.append('r', current);

    ASSERT_TRUE(views.prepare(E::Client, current, history, true));
    const auto token = views.begin(E::Client, current, current.size());
    views.finish(token, current);
    EXPECT_FALSE(state(views, E::Client).connection_invalid);
    EXPECT_EQ(state(views, E::Client).left_settings_awaiting_ack, 1U);
}

TEST(ProtocolViews, ProtocolTransitionDoesNotReplayOuterBytes) {
    ProtocolViews views(ProtocolViews::Mode::Rewrite);
    auto& ctx = views.context(E::Client);
    ctx.state_data = std::string("outer protocol");
    ctx.negotiated_alpn = "h2";
    duplexFlow history;
    history.append('r', bytes("CONNECT example.test:443 HTTP/1.1\r\n\r\n"));
    const auto current = bytes(std::string(h2::txt::magic) + frame(4, 0, 0));
    ASSERT_TRUE(views.prepare(E::Client, current, history, false));
    const auto token = views.begin(E::Client, current, current.size());
    views.finish(token, current);
    EXPECT_FALSE(state(views, E::Client).connection_invalid);
    EXPECT_EQ(state(views, E::Client).left_settings_awaiting_ack, 1U);
}

TEST(ProtocolViews, SharedFingerprintRejectsInPlaceReplacementAndResize) {
    std::string input("a\0b", 3);
    sx::engine::PayloadAnalysis analysis(input);
    const auto original = analysis.fingerprint(input);
    EXPECT_EQ(original, sx::engine::PayloadAnalysis::calculate_fingerprint(input));
    EXPECT_EQ(original, analysis.fingerprint(std::string(input)));

    input[0] = 'z'; // same allocation and length, but different content
    EXPECT_FALSE(analysis.matches(input));
    EXPECT_EQ(analysis.fingerprint(input),
              sx::engine::PayloadAnalysis::calculate_fingerprint(input));
    EXPECT_NE(analysis.fingerprint(input), original);
    input += "tail";
    EXPECT_FALSE(analysis.matches(input));
    EXPECT_EQ(analysis.fingerprint(input),
              sx::engine::PayloadAnalysis::calculate_fingerprint(input));
    EXPECT_EQ(analysis.fingerprint(std::string("a\0b", 3)), original);
    EXPECT_EQ(analysis.fingerprint(""),
              sx::engine::PayloadAnalysis::calculate_fingerprint(""));
}

TEST(ProtocolViews, SharedFingerprintDoesNotShareStatefulL7Results) {
    ProtocolViews client(ProtocolViews::Mode::Rewrite);
    ProtocolViews server(ProtocolViews::Mode::Rewrite);

    for (auto* views : {&client, &server}) {
        views->context(E::Client).state_data = h2::Http2Connection();
        views->seed(E::Client, bytes(std::string(h2::txt::magic) + frame(4, 0, 0) +
                                    frame(1, 4, 1, request())));
        views->seed(E::Server, bytes(frame(4, 0, 0) + frame(1, 4, 1, std::string(1, '\x88'))));
    }

    // These contexts have different header histories. Identical DATA bytes
    // must NOT make the receiver inherit the sender's encoding annotation.
    state(server, E::Client).streams.at(1).content_encoding_ =
        h2::Http2Stream::content_type_t::GZIP;
    const auto data = bytes(frame(0, 0, 1, "abc"));
    sx::engine::PayloadAnalysis analysis(data.string_view());
    client.seed(E::Client, data, &analysis);
    server.seed(E::Client, data, &analysis);
    auto a = std::dynamic_pointer_cast<sx::engine::http::app_HttpRequest>(
        client.context(E::Client).application_data);
    auto b = std::dynamic_pointer_cast<sx::engine::http::app_HttpRequest>(
        server.context(E::Client).application_data);
    ASSERT_TRUE(a);
    ASSERT_TRUE(b);
    EXPECT_EQ(a->l7_payload_observed_fingerprint, b->l7_payload_observed_fingerprint);
    EXPECT_EQ(a->l7_encoding, std::vector<std::string>{""});
    EXPECT_EQ(b->l7_encoding, std::vector<std::string>{"gzip"});
    EXPECT_FALSE(state(client, E::Client).connection_invalid);
    EXPECT_FALSE(state(server, E::Client).connection_invalid);
    EXPECT_EQ(client.context(E::Client).payload_analysis, nullptr);
    EXPECT_EQ(server.context(E::Client).payload_analysis, nullptr);
}

TEST(ProtocolViews, OutputSkipsPublicationIdentityAndNextInputRestoresIt) {
    ProtocolViews views(ProtocolViews::Mode::Rewrite);
    initialize(views);
    const auto input = bytes(frame(0, 0, 1, "aaa"));
    const auto output = bytes(frame(0, 0, 1, "bbb"));
    const auto token = views.begin(E::Client, input, input.size());
    views.finish(token, output);
    ASSERT_TRUE(views.split());

    for (auto endpoint : {E::Client, E::Server}) {
        const auto& ctx = views.context(endpoint);
        auto app = std::dynamic_pointer_cast<sx::engine::http::app_HttpRequest>(ctx.application_data);
        ASSERT_TRUE(app);
        EXPECT_EQ(app->l7_payload_observed, endpoint == E::Client);
        EXPECT_EQ(app->l7_payload_observed_fingerprint, endpoint == E::Client
                  ? sx::engine::PayloadAnalysis::calculate_fingerprint(input.string_view()) : 0);
        EXPECT_EQ(ctx.payload_analysis, nullptr);
    }

    // The server context is now an INPUT context. Suppression must not stick
    // to an endpoint: this fresh observation must be publishable normally.
    const auto response = bytes(frame(4, 1, 0));
    const auto next = views.begin(E::Server, response, 999);
    auto server = std::dynamic_pointer_cast<sx::engine::http::app_HttpRequest>(
        views.context(E::Server).application_data);
    ASSERT_TRUE(server);
    EXPECT_TRUE(server->l7_payload_matches(response.string_view(), 999));
    views.finish(next, response);

    auto client = std::dynamic_pointer_cast<sx::engine::http::app_HttpRequest>(
        views.context(E::Client).application_data);
    ASSERT_TRUE(client);
    EXPECT_FALSE(client->l7_payload_observed);
    EXPECT_EQ(client->l7_payload_observed_fingerprint, 0U);
}

TEST(ProtocolViews, ProtocolOnlyAnalysisMeansAbsentNotZeroOrCacheMiss) {
    auto analysis = sx::engine::PayloadAnalysis::protocol_only();
    EXPECT_FALSE(analysis.publication_fingerprint(""));
    EXPECT_FALSE(analysis.publication_fingerprint("different payload"));

    sx::engine::http::app_HttpRequest app;
    app.observe_l7_payload("old", 10, {{0, 3}});
    ASSERT_TRUE(app.l7_payload_observed);
    app.observe_l7_payload("new", 11, {{1, 3}}, {"gzip"}, {}, &analysis);
    EXPECT_FALSE(app.l7_payload_observed);
    EXPECT_FALSE(app.l7_payload_matches("new", 11));
    EXPECT_EQ(app.l7_payload, sx::engine::http::L7PayloadHints({{1, 3}}));
    EXPECT_EQ(app.l7_encoding, std::vector<std::string>{"gzip"});
}

TEST(ProtocolViews, ForkDoesNotRetainBorrowedAnalysisWorkspace) {
    ProtocolViews views(ProtocolViews::Mode::Rewrite);
    initialize(views);
    sx::engine::PayloadAnalysis analysis("temporary");
    auto& ctx = views.context(E::Client);
    ctx.payload_analysis = &analysis;
    auto fork = ctx.protocol_fork();
    EXPECT_EQ(fork->payload_analysis, nullptr);
    EXPECT_EQ(ctx.payload_analysis, &analysis);
    ctx.payload_analysis = nullptr;
}

#ifdef USE_HPACK
TEST(ProtocolViews, CanonicalHuffmanTreeIsSharedAndConcurrentDecodingIsIndependent) {
    const auto& tree = HPACK::huffman_tree_t::shared();
    const std::string encoded("\xf1\xe3\xc2\xe5\xf2\x3a\x6b\xa0\xab\x90\xf4\xff", 12);
    std::vector<std::future<std::string>> jobs;

    for (unsigned i = 0; i < 8; ++i) {
        jobs.push_back(std::async(std::launch::async, [&tree, &encoded] {
            EXPECT_EQ(&tree, &HPACK::huffman_tree_t::shared());
            std::string result;

            for (unsigned n = 0; n < 100; ++n) result = tree.decode(encoded);

            return result;
        }));
    }

    for (auto& job : jobs) EXPECT_EQ(job.get(), "www.example.com");
}
#endif

INSTANTIATE_TEST_SUITE_P(BothEndpoints, ProtocolViewsDirection,
                        ::testing::Values(E::Client, E::Server));
} // namespace
