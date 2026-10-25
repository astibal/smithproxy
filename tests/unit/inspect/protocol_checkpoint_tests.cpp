#include <inspect/engine/http.hpp>
#include <gtest/gtest.h>

#include <functional>
#include <random>
#include <string>
#include <vector>

#ifdef CHECKPOINT_NGHTTP2
#include <nghttp2/nghttp2.h>
#endif

namespace sx::engine::http::v2 {
void process_directional_bytes(EngineCtx&, socle::side_t, buffer&);
}

namespace {
using sx::engine::EngineCtx;
namespace h2 = sx::engine::http::v2;
using Side = socle::side_t;

std::string integer(std::uint32_t value) {
    std::string bytes(4, '\0');
    for (int i = 3; i >= 0; --i) {
        bytes[i] = static_cast<char>(value & 255);
        value >>= 8;
    }
    return bytes;
}

std::string frame(unsigned type, unsigned flags, unsigned stream,
                  std::string const& payload = {}) {
    return integer(payload.size()).substr(1) + char(type) + char(flags) +
           integer(stream) + payload;
}

std::string setting(unsigned id, unsigned value) {
    return frame(4, 0, 0, integer(id).substr(2) + integer(value));
}

// Static indexes and literal strings make the fixture independent of the SX
// encoder. POST, https, /, :authority=example.test; no dynamic entries.
std::string request() {
    return std::string("\x83\x87\x84\x01\x0c", 5) + "example.test";
}

h2::Http2Connection& state(EngineCtx& ctx) {
    return std::any_cast<h2::Http2Connection&>(ctx.state_data);
}

void feed(EngineCtx& ctx, Side side, std::string const& bytes) {
    buffer input;
    input.assign(bytes.data(), bytes.size());
    h2::process_directional_bytes(ctx, side, input);
}

void initialize(EngineCtx& ctx) {
    ctx.state_data = h2::Http2Connection();
    ctx.application_data =
        std::make_shared<sx::engine::http::app_HttpRequest>();
    feed(ctx, Side::LEFT, frame(4, 0, 0));
    feed(ctx, Side::RIGHT, frame(4, 0, 0));
    feed(ctx, Side::LEFT, frame(4, 1, 0));
    feed(ctx, Side::RIGHT, frame(4, 1, 0));
    for (unsigned id : {1U, 3U}) {
        feed(ctx, Side::LEFT, frame(1, 4, id, request()));
        feed(ctx, Side::RIGHT, frame(1, 4, id, std::string(1, '\x88')));
    }
    ASSERT_FALSE(state(ctx).connection_invalid);
    ASSERT_EQ(state(ctx).streams.size(), 2U);
}

struct Scenario {
    const char* name;
    std::function<void(EngineCtx&)> input;
    std::function<void(EngineCtx&)> continuation;
};

// Each continuation feeds actual protocol bytes and checks their consequence,
// not merely the fields which input() assigned. This is an in-process parser
// harness, NOT a live webhook or an independent peer implementation.
std::vector<Scenario> scenarios() {
    return {
        {"SettingsAck", [](auto& c) {
            feed(c, Side::LEFT, frame(4, 0, 0));
        }, [](auto& c) {
            feed(c, Side::RIGHT, frame(4, 1, 0));
            EXPECT_EQ(state(c).left_settings_awaiting_ack, 0U);
        }},
        {"TableSizeAck", [](auto& c) {
            feed(c, Side::LEFT, setting(1, 0));
        }, [](auto& c) {
            feed(c, Side::RIGHT, frame(4, 1, 0));
            // Required HPACK size update followed by :status=200 on stream 5.
            feed(c, Side::LEFT, frame(1, 4, 5, request()));
            feed(c, Side::RIGHT, frame(1, 4, 5, std::string("\x20\x88", 2)));
            EXPECT_EQ(state(c).streams.at(5).response_header(":status"), "200");
        }},
        {"MaximumFrame", [](auto& c) {
            feed(c, Side::LEFT, setting(5, 32768));
        }, [](auto& c) {
            feed(c, Side::RIGHT, frame(4, 1, 0));
            feed(c, Side::RIGHT, frame(0, 0, 1, std::string(17000, 'a')));
            EXPECT_EQ(state(c).streams.at(1).response_body_bytes_, 17000U);
        }},
        {"InitialWindow", [](auto& c) {
            feed(c, Side::LEFT, setting(4, 100000));
        }, [](auto& c) {
            feed(c, Side::RIGHT, frame(4, 1, 0));
            feed(c, Side::RIGHT, frame(0, 0, 1, "hello"));
            EXPECT_EQ(state(c).streams.at(1).response_flow_window_, 99995);
            EXPECT_EQ(state(c).streams.at(3).response_flow_window_, 100000);
        }},
        {"PushDisabled", [](auto& c) {
            feed(c, Side::LEFT, setting(2, 0));
        }, [](auto& c) {
            feed(c, Side::RIGHT, frame(4, 1, 0));
            feed(c, Side::RIGHT, frame(5, 4, 1, integer(2) + request()));
            EXPECT_TRUE(state(c).connection_invalid);
        }},
        {"ConcurrentStreams", [](auto& c) {
            feed(c, Side::RIGHT, setting(3, 0));
        }, [](auto& c) {
            feed(c, Side::LEFT, frame(4, 1, 0));
            feed(c, Side::LEFT, frame(1, 4, 5, request()));
            EXPECT_EQ(state(c).streams.count(5), 0U);
            EXPECT_EQ(state(c).streams.count(1), 1U);
        }},
        {"SettingsFifo", [](auto& c) {
            feed(c, Side::LEFT, setting(1, 0));
            feed(c, Side::LEFT, setting(1, 4096));
        }, [](auto& c) {
            feed(c, Side::RIGHT, frame(4, 1, 0));
            EXPECT_EQ(state(c).left_settings_awaiting_ack, 1U);
            feed(c, Side::RIGHT, frame(4, 1, 0));
            EXPECT_EQ(state(c).left_settings_awaiting_ack, 0U);
        }},
        {"DataBody", [](auto& c) {
            feed(c, Side::LEFT, frame(0, 0, 1, "hello"));
        }, [](auto& c) {
            feed(c, Side::LEFT, frame(0, 0, 1, "bye"));
            EXPECT_EQ(state(c).streams.at(1).request_body_bytes_, 8U);
            EXPECT_EQ(state(c).client_connection_window, 65527);
        }},
        {"PaddedData", [](auto& c) {
            feed(c, Side::LEFT, frame(0, 8, 1, std::string("\x02hi\0\0", 5)));
        }, [](auto& c) {
            feed(c, Side::LEFT, frame(0, 0, 1, "!"));
            EXPECT_EQ(state(c).streams.at(1).request_body_bytes_, 3U);
            EXPECT_EQ(state(c).client_connection_window, 65529);
        }},
        {"EndStream", [](auto& c) {
            feed(c, Side::LEFT, frame(0, 1, 1, "done"));
        }, [](auto& c) {
            feed(c, Side::RIGHT, frame(0, 1, 1, "reply"));
            EXPECT_EQ(state(c).streams.count(1), 0U);
            EXPECT_EQ(state(c).streams.count(3), 1U);
        }},
        {"PingAck", [](auto& c) {
            feed(c, Side::LEFT, frame(6, 0, 0, "12345678"));
        }, [](auto& c) {
            feed(c, Side::RIGHT, frame(6, 1, 0, "12345678"));
            EXPECT_TRUE(state(c).client_pings_pending.empty());
        }},
        {"Goaway", [](auto& c) {
            feed(c, Side::RIGHT, frame(7, 0, 0, integer(3) + integer(0)));
        }, [](auto& c) {
            feed(c, Side::LEFT, frame(1, 4, 5, request()));
            EXPECT_EQ(state(c).streams.count(5), 0U);
            feed(c, Side::RIGHT, frame(0, 0, 1, "ok"));
            EXPECT_EQ(state(c).streams.at(1).response_body_bytes_, 2U);
        }},
        {"ResetStream", [](auto& c) {
            feed(c, Side::RIGHT, frame(3, 0, 1, integer(8)));
        }, [](auto& c) {
            feed(c, Side::RIGHT, frame(0, 0, 3, "alive"));
            EXPECT_EQ(state(c).streams.count(1), 0U);
            EXPECT_EQ(state(c).streams.at(3).response_body_bytes_, 5U);
        }},
        {"ConnectionCredit", [](auto& c) {
            feed(c, Side::RIGHT, frame(8, 0, 0, integer(100)));
        }, [](auto& c) {
            feed(c, Side::LEFT, frame(0, 0, 1, "abc"));
            EXPECT_EQ(state(c).client_connection_window, 65632);
            EXPECT_EQ(state(c).streams.at(1).request_flow_window_, 65532);
        }},
        {"StreamCredit", [](auto& c) {
            feed(c, Side::RIGHT, frame(8, 0, 1, integer(100)));
        }, [](auto& c) {
            feed(c, Side::LEFT, frame(0, 0, 1, "abc"));
            EXPECT_EQ(state(c).streams.at(1).request_flow_window_, 65632);
            EXPECT_EQ(state(c).streams.at(3).request_flow_window_, 65535);
        }},
        {"SplitFrameHeader", [](auto& c) {
            feed(c, Side::LEFT, frame(0, 0, 1, "hello").substr(0, 4));
        }, [](auto& c) {
            feed(c, Side::LEFT, frame(0, 0, 1, "hello").substr(4));
            EXPECT_EQ(state(c).streams.at(1).request_body_bytes_, 5U);
            EXPECT_TRUE(state(c).left_frame_pending.empty());
        }},
        {"SplitData", [](auto& c) {
            feed(c, Side::LEFT, frame(0, 0, 1, "hello").substr(0, 11));
        }, [](auto& c) {
            feed(c, Side::LEFT, frame(0, 0, 1, "hello").substr(11));
            EXPECT_EQ(state(c).streams.at(1).request_body_bytes_, 5U);
            EXPECT_EQ(state(c).client_connection_window, 65530);
        }},
        {"Continuation", [](auto& c) {
            feed(c, Side::LEFT, frame(1, 0, 5, request().substr(0, 2)));
        }, [](auto& c) {
            feed(c, Side::LEFT, frame(9, 4, 5, request().substr(2)));
            EXPECT_EQ(state(c).streams.at(5).request_header(":authority"), "example.test");
        }},
        {"DynamicIndex", [](auto& c) {
            const auto literal = std::string("\x40\x06", 2) + "x-test" + "\x03one";
            feed(c, Side::LEFT, frame(1, 4, 5, request() + literal));
        }, [](auto& c) {
            feed(c, Side::LEFT, frame(1, 4, 7, request() + char(0xbe)));
            EXPECT_EQ(state(c).streams.at(7).request_header("x-test"), "one");
        }},
        {"InvalidSticky", [](auto& c) {
            feed(c, Side::LEFT, frame(6, 0, 0, "short"));
        }, [](auto& c) {
            feed(c, Side::LEFT, frame(0, 0, 1, "ignored"));
            EXPECT_TRUE(state(c).connection_invalid);
            EXPECT_EQ(state(c).streams.at(1).request_body_bytes_, 0U);
        }},
    };
}

class ProtocolCheckpointScenarios : public testing::TestWithParam<Scenario> {};

TEST_P(ProtocolCheckpointScenarios, UnchangedKeepsAnalysis) {
    EngineCtx ctx;
    initialize(ctx);
    {
        auto checkpoint = ctx.protocol_snapshot();
        GetParam().input(ctx);
        // Unchanged webhook: dropping the checkpoint must have no effect.
    }
    GetParam().continuation(ctx);
    if (std::string(GetParam().name) != "InvalidSticky" &&
        std::string(GetParam().name) != "PushDisabled") {
        EXPECT_FALSE(state(ctx).connection_invalid);
    }
}

TEST_P(ProtocolCheckpointScenarios, RollbackReplaysContinuation) {
    EngineCtx ctx;
    initialize(ctx);
    GetParam().input(ctx);
    ctx.update_seen_block(42, 77);
    ctx.state_info = h2::state_data_t{41, 77};
    auto checkpoint = ctx.protocol_snapshot();

    // Tentative analysis consumes the continuation. A replacement requires
    // rolling it back, including stream deletion, credits, pending bytes and
    // HPACK mutations. Replay is of the SAME input here: reconciliation of
    // DIFFERENT input is a separate, deliberately not yet implemented layer.
    GetParam().continuation(ctx);
    ctx.update_seen_block(99, 999);
    ctx.state_info = h2::state_data_t{98, 999};
    ctx.status = EngineCtx::status_t::ERROR;

    for (int attempt = 0; attempt < 2; ++attempt) {
        checkpoint.restore(ctx);
        ASSERT_TRUE(ctx.flow_seen);
        EXPECT_EQ(ctx.flow_seen->blocks_seen, 42U);
        EXPECT_EQ(ctx.flow_seen->bytes_in_last_block_seen, 77U);
        EXPECT_EQ(std::any_cast<h2::state_data_t>(ctx.state_info),
                  (h2::state_data_t{41, 77}));
        EXPECT_NE(ctx.status, EngineCtx::status_t::ERROR);
        GetParam().continuation(ctx);
        const std::string name = GetParam().name;
        EXPECT_EQ(state(ctx).connection_invalid,
                  name == "InvalidSticky" || name == "PushDisabled");
    }
}

INSTANTIATE_TEST_SUITE_P(H2, ProtocolCheckpointScenarios,
    testing::ValuesIn(scenarios()),
    [](auto const& info) { return info.param.name; });

TEST(ProtocolCheckpoint, RejectsUnsupportedAndForeignState) {
    EngineCtx first, other;
    EXPECT_THROW((void)first.protocol_snapshot(), std::logic_error);
    initialize(first);
    auto checkpoint = first.protocol_snapshot();
    EXPECT_THROW(checkpoint.restore(other), std::invalid_argument);
    first.state_info = std::string("not a protocol cursor");
    EXPECT_THROW((void)first.protocol_snapshot(), std::logic_error);
}

TEST(ProtocolCheckpoint, DoesNotRestoreApplicationMetadata) {
    EngineCtx ctx;
    initialize(ctx);
    auto checkpoint = ctx.protocol_snapshot();
    auto metadata = ctx.application_data;
    metadata->data.properties["external"] = "retained";
    ctx.negotiated_alpn = "external-change";
    checkpoint.restore(ctx);
    EXPECT_EQ(ctx.application_data, metadata);
    EXPECT_EQ(metadata->data.properties.at("external"), "retained");
    EXPECT_EQ(ctx.negotiated_alpn, "external-change");
}

TEST(ProtocolCheckpoint, BothHpackDecodersAgreeWithIndependentOracleAfterRollback) {
#if defined(CHECKPOINT_NGHTTP2) && defined(USE_HPACK)
    // nghttp2 sees only the accepted history, SX additionally sees a discarded
    // speculative header. A shallow snapshot would shift its dynamic index.
    for (auto side : {Side::LEFT, Side::RIGHT}) {
        EngineCtx ctx;
        initialize(ctx);
        auto decoder = [&]() {
            return side == Side::LEFT ? state(ctx).request_decoder
                                      : state(ctx).response_decoder;
        };

        nghttp2_hd_inflater* raw = nullptr;
        ASSERT_EQ(nghttp2_hd_inflate_new(&raw), 0);
        std::unique_ptr<nghttp2_hd_inflater, decltype(&nghttp2_hd_inflate_del)>
            oracle(raw, nghttp2_hd_inflate_del);

        auto independent = [&](std::string const& block) {
            std::vector<std::pair<std::string, std::string>> fields;
            std::size_t offset = 0;
            for (std::size_t steps = 0; steps < block.size() + 16; ++steps) {
                nghttp2_nv field{};
                int flags = 0;
                auto consumed = nghttp2_hd_inflate_hd2(
                    oracle.get(), &field, &flags,
                    reinterpret_cast<uint8_t const*>(block.data()) + offset,
                    block.size() - offset, 1);
                if (consumed < 0) {
                    ADD_FAILURE() << "nghttp2 decode failed: " << consumed;
                    return fields;
                }
                offset += static_cast<std::size_t>(consumed);
                if (flags & NGHTTP2_HD_INFLATE_EMIT) {
                    fields.emplace_back(
                        std::string(reinterpret_cast<char*>(field.name), field.namelen),
                        std::string(reinterpret_cast<char*>(field.value), field.valuelen));
                }
                if (flags & NGHTTP2_HD_INFLATE_FINAL) {
                    EXPECT_EQ(offset, block.size());
                    EXPECT_EQ(nghttp2_hd_inflate_end_headers(oracle.get()), 0);
                    return fields;
                }
            }
            ADD_FAILURE() << "nghttp2 did not finish the header block";
            return fields;
        };

        const auto accepted = std::string("\x40\x06", 2) + "x-test" + "\x03one";
        const auto discarded = std::string("\x40\x06", 2) + "x-test" + "\x03two";
        ASSERT_TRUE(decoder()->decode(accepted));
        independent(accepted);
        auto checkpoint = ctx.protocol_snapshot();

        for (int replay = 0; replay < 3; ++replay) {
            ASSERT_TRUE(decoder()->decode(discarded));
            checkpoint.restore(ctx);
            const std::string indexed(1, char(0xbe));
            const auto fields = independent(indexed);
            ASSERT_EQ(fields.size(), 1U);
            EXPECT_EQ(fields.front().first, "x-test");
            EXPECT_EQ(fields.front().second, "one");
            ASSERT_TRUE(decoder()->decode(indexed));
            EXPECT_EQ(decoder()->headers().at("x-test").front(), fields.front().second);
        }
    }
#else
    GTEST_SKIP() << "Independent HPACK oracle requires nghttp2 development files and USE_HPACK";
#endif
}

TEST(ProtocolCheckpoint, BoundaryTrackerAndPendingBuffersAreIndependent) {
    EngineCtx ctx;
    initialize(ctx);
    const auto data = frame(0, 0, 1, "hello");
    state(ctx).content_directions[0].observe(std::string_view(data).substr(0, 11), false);
    state(ctx).left_frame_pending = {1, 2, 3};
    state(ctx).right_frame_pending = {4, 5};
    auto checkpoint = ctx.protocol_snapshot();

    for (int replay = 0; replay < 3; ++replay) {
        checkpoint.restore(ctx);
        EXPECT_EQ(state(ctx).left_frame_pending, (std::vector<unsigned char>{1, 2, 3}));
        EXPECT_EQ(state(ctx).right_frame_pending, (std::vector<unsigned char>{4, 5}));
        auto ranges = state(ctx).content_directions[0].observe(
            std::string_view(data).substr(11), false);
        EXPECT_EQ(ranges, (sx::engine::http::L7PayloadHints{{0, 3}}));
        state(ctx).left_frame_pending.clear();
        state(ctx).right_frame_pending.push_back(6);
    }
}

TEST(ProtocolCheckpoint, DetachesNonOwningStreamBuffers) {
    EngineCtx ctx;
    initialize(ctx);
    buffer backing;
    backing.assign("original", 8);
    auto& stream = state(ctx).streams.at(1);
    stream.doh_response_body_ = backing.view();
    stream.gzip.emplace();
    stream.gzip->in = backing.view();
    auto checkpoint = ctx.protocol_snapshot();

    backing.assign("modified", 8);
    checkpoint.restore(ctx);
    EXPECT_EQ(state(ctx).streams.at(1).doh_response_body_.string_view(), "original");
    EXPECT_EQ(state(ctx).streams.at(1).gzip->in.string_view(), "original");

    state(ctx).streams.at(1).doh_response_body_.assign("changed", 7);
    state(ctx).streams.at(1).gzip->in.assign("changed", 7);
    checkpoint.restore(ctx);
    EXPECT_EQ(state(ctx).streams.at(1).doh_response_body_.string_view(), "original");
    EXPECT_EQ(state(ctx).streams.at(1).gzip->in.string_view(), "original");
}

TEST(ProtocolCheckpoint, RejectsProtocolSwitchWithoutPartialRestore) {
    EngineCtx ctx;
    initialize(ctx);
    auto checkpoint = ctx.protocol_snapshot();
    ctx.state_data = std::string("another protocol");
    ctx.update_seen_block(99, 123);
    EXPECT_THROW(checkpoint.restore(ctx), std::logic_error);
    EXPECT_EQ(std::any_cast<std::string>(ctx.state_data), "another protocol");
    EXPECT_EQ(ctx.flow_seen->blocks_seen, 99U);
    EXPECT_EQ(ctx.flow_seen->bytes_in_last_block_seen, 123U);
}

TEST(ProtocolCheckpoint, DiscardedInvalidInputDoesNotPoisonAcceptedReplacement) {
    EngineCtx ctx;
    initialize(ctx);
    auto checkpoint = ctx.protocol_snapshot();
    feed(ctx, Side::LEFT, frame(6, 0, 0, "short"));
    ASSERT_TRUE(state(ctx).connection_invalid);

    checkpoint.restore(ctx);
    feed(ctx, Side::LEFT, frame(6, 0, 0, "12345678"));
    feed(ctx, Side::RIGHT, frame(6, 1, 0, "12345678"));
    EXPECT_FALSE(state(ctx).connection_invalid);
    EXPECT_TRUE(state(ctx).client_pings_pending.empty());
    feed(ctx, Side::RIGHT, frame(0, 0, 1, "alive"));
    EXPECT_EQ(state(ctx).streams.at(1).response_body_bytes_, 5U);
}

void append(duplexFlow& flow, char side, std::string const& bytes) {
    buffer data(bytes.data(), bytes.size());
    flow.append(side, data);
}

std::vector<std::pair<char, std::string>> flow_bytes(duplexFlow const& flow) {
    std::vector<std::pair<char, std::string>> blocks;
    for (auto const& entry : flow.flow_queue()) {
        blocks.emplace_back(entry.source(), std::string(entry.data()->string_view()));
    }
    return blocks;
}

TEST(ProtocolCheckpointFlow, RestoresTailAndEvictedBlocksWithoutCopyingTheirBuffers) {
    EngineCtx ctx;
    initialize(ctx);
    duplexFlow flow;
    append(flow, 'r', "request");
    append(flow, 'w', "response");
    append(flow, 'r', "tail");
    const auto expected = flow_bytes(flow);
    const auto* first_buffer = flow.flow_queue().front().data();
    const auto* tail_buffer = flow.flow_queue().back().data();
    auto checkpoint = ctx.protocol_snapshot(flow);

    for (int replay = 0; replay < 3; ++replay) {
        append(flow, 'r', " appended");
        append(flow, 'w', "next block");
        flow.pop();
        flow.pop();
        ctx.update_seen_block(999, 999);
        checkpoint.restore(ctx);
        EXPECT_EQ(flow_bytes(flow), expected);
        EXPECT_EQ(flow.pop_count(), 0U);
        EXPECT_EQ(flow.pos_size(), 3U);
        EXPECT_EQ(flow.exchanges, 2U);
        EXPECT_EQ(flow.flow_queue().back().counter(), 1U);
        EXPECT_EQ(flow.flow_queue().front().data(), first_buffer);
        EXPECT_EQ(flow.flow_queue().back().data(), tail_buffer);
    }
}

TEST(ProtocolCheckpointFlow, RestoresAfterAllOriginalAndNewBlocksWerePopped) {
    EngineCtx ctx;
    initialize(ctx);
    duplexFlow flow;
    append(flow, 'r', "old");
    flow.pop(); // Existing absolute positions must survive rollback as well.
    append(flow, 'w', "retained");
    auto checkpoint = ctx.protocol_snapshot(flow);
    flow.pop();
    append(flow, 'r', "temporary");
    flow.pop();
    checkpoint.restore(ctx);
    EXPECT_EQ(flow_bytes(flow),
              (std::vector<std::pair<char, std::string>>{{'w', "retained"}}));
    EXPECT_EQ(flow.pop_count(), 1U);
    EXPECT_EQ(flow.pos_size(), 2U);
}

TEST(ProtocolCheckpointFlow, EmptyFlowCanBeRestoredRepeatedly) {
    duplexFlow flow;
    auto checkpoint = flow.snapshot();
    for (int replay = 0; replay < 3; ++replay) {
        append(flow, 'r', "temporary");
        append(flow, 'w', "reply");
        flow.pop();
        checkpoint.restore();
        EXPECT_TRUE(flow.flow_queue().empty());
        EXPECT_EQ(flow.pos_size(), 0U);
        EXPECT_EQ(flow.exchanges, 0U);
    }
}

TEST(ProtocolCheckpointFlow, ReleasingCheckpointAcceptsAppendsAndEvictions) {
    duplexFlow flow;
    append(flow, 'r', "old");
    {
        auto checkpoint = flow.snapshot();
        append(flow, 'w', "accepted");
        flow.pop();
    }
    EXPECT_EQ(flow_bytes(flow),
              (std::vector<std::pair<char, std::string>>{{'w', "accepted"}}));
    EXPECT_EQ(flow.pop_count(), 1U);
    EXPECT_EQ(flow.exchanges, 1U);
    EXPECT_NO_THROW((void)flow.snapshot());
}

TEST(ProtocolCheckpointFlow, RejectsNestedSnapshotsAndExpiredOwner) {
    std::optional<duplexFlow::Checkpoint> saved;
    {
        duplexFlow flow;
        saved = flow.snapshot();
        EXPECT_THROW((void)flow.snapshot(), std::logic_error);
    }
    EXPECT_THROW(saved->restore(), std::logic_error);
}

TEST(ProtocolCheckpointFlow, FailedFlowRestoreDoesNotRestoreEngineHalfway) {
    EngineCtx ctx;
    initialize(ctx);
    duplexFlow flow;
    append(flow, 'r', "old");
    auto checkpoint = ctx.protocol_snapshot(flow);
    feed(ctx, Side::RIGHT, frame(8, 0, 0, integer(100)));
    ctx.update_seen_block(123, 456);
    flow.domain(SOCK_DGRAM); // Outside the documented append/pop contract.
    EXPECT_THROW(checkpoint.restore(ctx), std::logic_error);
    EXPECT_EQ(state(ctx).client_connection_window, 65635);
    EXPECT_EQ(ctx.flow_seen->blocks_seen, 123U);
    EXPECT_EQ(ctx.flow_seen->bytes_in_last_block_seen, 456U);
    EXPECT_EQ(flow.flow_queue().back().data()->string_view(), "old");
}

TEST(ProtocolCheckpointFlow, FailedProtocolRestoreDoesNotRewindFlow) {
    EngineCtx ctx;
    initialize(ctx);
    duplexFlow flow;
    append(flow, 'r', "old");
    auto checkpoint = ctx.protocol_snapshot(flow);
    append(flow, 'r', "suffix");
    ctx.state_data = std::string("protocol switched");
    EXPECT_THROW(checkpoint.restore(ctx), std::logic_error);
    EXPECT_EQ(flow.flow_queue().back().data()->string_view(), "oldsuffix");
}

TEST(ProtocolCheckpointFlow, CopiedTokenKeepsSameJournalAlive) {
    duplexFlow flow;
    append(flow, 'r', "old");
    std::optional<duplexFlow::Checkpoint> copied;
    {
        auto original = flow.snapshot();
        copied = original;
        flow.pop();
    }
    EXPECT_THROW((void)flow.snapshot(), std::logic_error);
    copied->restore();
    EXPECT_EQ(flow.flow_queue().back().data()->string_view(), "old");
    copied.reset();
    EXPECT_NO_THROW((void)flow.snapshot());
}

TEST(ProtocolCheckpointFlow, TruncationAndDatagramMetadataAreRestored) {
    duplexFlow flow;
    flow.domain(SOCK_DGRAM);
    append(flow, 'r', "one");
    auto checkpoint = flow.snapshot();
    append(flow, 'r', "two");
    flow.flow_queue().front().validation.validity(
        FlowEntry<char>::validation_t::up_validity::TRUNCATED);
    checkpoint.restore();
    EXPECT_EQ(flow.size(), 1U);
    EXPECT_EQ(flow.flow_queue().front().validation.validity(),
              FlowEntry<char>::validation_t::up_validity::OK);
    EXPECT_EQ(flow.domain(), SOCK_DGRAM);
}

TEST(ProtocolCheckpointFlow, SettingsReplacementAndPeerAckAfterEviction) {
    EngineCtx ctx;
    initialize(ctx);
    duplexFlow flow;
    append(flow, 'r', "prior request");
    append(flow, 'w', "prior response");
    ctx.update_seen_block(2, 14);
    ctx.state_info = h2::state_data_t{1, 14};
    auto checkpoint = ctx.protocol_snapshot(flow);

    const auto original = setting(4, 1);
    append(flow, 'r', original);
    feed(ctx, Side::LEFT, original);
    flow.pop();
    flow.pop();
    EXPECT_EQ(state(ctx).streams.at(1).response_flow_window_, 1);

    // This is explicit protocol/flow rollback and replacement replay. It is
    // deliberately NOT production reconcile(): that must also preserve the
    // original input decoder history when replacing arbitrary HEADERS/DATA.
    checkpoint.restore(ctx);
    const auto replacement = setting(4, 100000);
    append(flow, 'r', replacement);
    feed(ctx, Side::LEFT, replacement);
    EXPECT_EQ(flow.size(), 3U);
    EXPECT_EQ(flow.flow_queue().back().data()->string_view(), replacement);
    EXPECT_EQ(ctx.flow_seen->blocks_seen, 2U);

    feed(ctx, Side::RIGHT, frame(4, 1, 0));
    feed(ctx, Side::RIGHT, frame(0, 0, 1, "reply"));
    EXPECT_EQ(state(ctx).left_settings_awaiting_ack, 0U);
    EXPECT_EQ(state(ctx).streams.at(1).response_flow_window_, 99995);
    EXPECT_EQ(state(ctx).streams.at(3).response_flow_window_, 100000);
    EXPECT_FALSE(state(ctx).connection_invalid);
}

// These are counterexamples to wiring restore + output replay directly into
// FlowCtx::commit. They intentionally demonstrate the WRONG integration:
// a checkpoint can rewind correctly while the next input is decoded wrongly.
TEST(ProtocolCheckpointIntegration, OutputReplayCannotReplaceInputHpackHistory) {
#ifdef USE_HPACK
    EngineCtx incoming;
    EngineCtx replayed;
    initialize(incoming);
    initialize(replayed);
    auto checkpoint = replayed.protocol_snapshot();

    // The sender inserts x-test=one at dynamic index 62. A replacement sends
    // x-test=two instead. Both header blocks are individually well formed.
    const auto literal = std::string("\x40\x06", 2) + "x-test";
    const auto original = frame(1, 4, 5, request() + literal + "\x03one");
    const auto replacement = frame(1, 4, 5, request() + literal + "\x03two");
    feed(incoming, Side::LEFT, original);
    feed(replayed, Side::LEFT, original);
    checkpoint.restore(replayed);
    feed(replayed, Side::LEFT, replacement);

    ASSERT_FALSE(state(incoming).connection_invalid);
    ASSERT_FALSE(state(replayed).connection_invalid);

    // The next native read still uses the SENDER's table. Switching our input
    // parser to output history silently changes its interpretation, not just
    // the bytes forwarded to the peer. No framing error warns us about this.
    const auto next = frame(1, 4, 7, request() + std::string(1, char(0xbe)));
    feed(incoming, Side::LEFT, next);
    feed(replayed, Side::LEFT, next);

    EXPECT_EQ(state(incoming).streams.at(7).request_header("x-test"), "one");
    EXPECT_EQ(state(replayed).streams.at(7).request_header("x-test"), "two");
    EXPECT_FALSE(state(incoming).connection_invalid);
    EXPECT_FALSE(state(replayed).connection_invalid);
#else
    GTEST_SKIP() << "HPACK history counterexample requires USE_HPACK";
#endif
}

TEST(ProtocolCheckpointIntegration, OutputReplayCannotReplacePendingInputFrame) {
    EngineCtx incoming;
    EngineCtx replayed;
    initialize(incoming);
    initialize(replayed);
    auto checkpoint = replayed.protocol_snapshot();

    const auto original = frame(0, 0, 1, "hello");
    const auto prefix = original.substr(0, 11); // frame header and two body bytes
    feed(incoming, Side::LEFT, prefix);
    feed(replayed, Side::LEFT, prefix);
    ASSERT_FALSE(state(incoming).left_frame_pending.empty());

    checkpoint.restore(replayed);
    feed(replayed, Side::LEFT, frame(0, 0, 1, "replacement"));
    ASSERT_TRUE(state(replayed).left_frame_pending.empty());

    // The sender knows nothing about our output replacement: its next read
    // starts with the remaining body, followed by an ordinary PING frame.
    const auto next = original.substr(11) + frame(6, 0, 0, "12345678");
    feed(incoming, Side::LEFT, next);
    feed(replayed, Side::LEFT, next);

    EXPECT_EQ(state(incoming).streams.at(1).request_body_bytes_, 5U);
    EXPECT_TRUE(state(incoming).left_frame_pending.empty());
    ASSERT_EQ(state(incoming).client_pings_pending.size(), 1U);
    feed(incoming, Side::RIGHT, frame(6, 1, 0, "12345678"));
    EXPECT_TRUE(state(incoming).client_pings_pending.empty());
    EXPECT_FALSE(state(incoming).connection_invalid);

    // Output replay has lost the input boundary. It can no longer recognize
    // the PING, even though the sender's continuation is perfectly valid.
    EXPECT_TRUE(state(replayed).client_pings_pending.empty());
    EXPECT_TRUE(state(replayed).connection_invalid ||
                !state(replayed).left_frame_pending.empty());
}

TEST(ProtocolCheckpointFlow, DeterministicAppendPopSequencesRestoreExactly) {
    std::mt19937 random(0x51a7);
    for (unsigned trial = 0; trial < 200; ++trial) {
        SCOPED_TRACE(trial);
        duplexFlow flow;
        if (trial % 2) flow.domain(SOCK_DGRAM);
        for (unsigned i = 0; i < trial % 9; ++i) {
            append(flow, random() % 2 ? 'r' : 'w', "seed" + std::to_string(i));
        }
        if (trial % 3 == 0) flow.pop();

        const auto expected = flow_bytes(flow);
        const auto expected_pops = flow.pop_count();
        const auto expected_exchanges = flow.exchanges;
        auto checkpoint = flow.snapshot();

        for (unsigned replay = 0; replay < 3; ++replay) {
            for (unsigned step = 0; step < 40; ++step) {
                if (random() % 3 == 0) {
                    flow.pop();
                } else {
                    append(flow, random() % 2 ? 'r' : 'w', std::to_string(random()));
                }
            }
            checkpoint.restore();
            EXPECT_EQ(flow_bytes(flow), expected);
            EXPECT_EQ(flow.pop_count(), expected_pops);
            EXPECT_EQ(flow.exchanges, expected_exchanges);
            EXPECT_EQ(flow.pos_size(), expected_pops + expected.size());
        }
    }
}

} // namespace
