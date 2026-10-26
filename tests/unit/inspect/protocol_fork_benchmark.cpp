#include <inspect/protocol_views.hpp>
#include <inspect/engine/http.hpp>
#include <gtest/gtest.h>

#include <algorithm>
#include <chrono>
#include <iomanip>
#include <iostream>
#include <sys/resource.h>
#include <vector>

namespace {
using sx::engine::ProtocolViews;
using E = ProtocolViews::Endpoint;
namespace h2 = sx::engine::http::v2;
using Clock = std::chrono::steady_clock;

std::string integer(std::uint32_t value) {
    std::string result(4, '\0');

    for (int i = 3; i >= 0; --i) {
        result[i] = char(value & 255);
        value >>= 8;
    }
    return result;
}

buffer frame(unsigned type, unsigned flags, unsigned stream, std::string payload = {}) {
    const auto wire = integer(payload.size()).substr(1) + char(type) + char(flags) +
                      integer(stream) + payload;
    buffer result;
    result.assign(wire.data(), wire.size());
    return result;
}

auto& state(ProtocolViews& views) {
    return std::any_cast<h2::Http2Connection&>(views.context(E::Client).state_data);
}

void initialize(ProtocolViews& views, unsigned streams) {
    views.context(E::Client).state_data = h2::Http2Connection();
    const std::string preface = "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";
    buffer initial;
    initial.assign(preface.data(), preface.size());
    views.seed(E::Client, initial);
    views.seed(E::Client, frame(4, 0, 0));

    // Large, explicitly advertised windows keep the DATA workload legal.
    // There are no timed window updates and no parser failure fast-paths.
    views.seed(E::Server, frame(4, 0, 0, std::string("\0\4", 2) + integer(0x7fffffff)));
    views.seed(E::Client, frame(4, 1, 0));
    views.seed(E::Server, frame(4, 1, 0));
    views.seed(E::Server, frame(8, 0, 0, integer(0x7fffffff - 65535)));

    const auto headers = std::string("\x83\x87\x84\x01\x0c", 5) + "example.test";

    for (unsigned i = 0; i < streams; ++i) {
        views.seed(E::Client, frame(1, 4, 2 * i + 1, headers));
        views.seed(E::Server, frame(1, 4, 2 * i + 1, std::string(1, '\x88')));
    }

    ASSERT_EQ(state(views).streams.size(), streams);
    ASSERT_FALSE(state(views).connection_invalid);
}

enum class Path { SingleParser, Observe, TwoFromStart, TwoShared, TwoSelective,
                  AfterSplit, ForkOnly, FirstRewrite };

const char* name(Path path) {
    switch (path) {
        case Path::SingleParser: return "single_parser";
        case Path::Observe: return "observe_no_fork";
        case Path::TwoFromStart: return "two_contexts_from_start";
        case Path::TwoShared: return "two_contexts_shared_analysis";
        case Path::TwoSelective: return "two_contexts_no_output_fingerprint";
        case Path::AfterSplit: return "after_split_two_parsers";
        case Path::ForkOnly: return "fork_only";
        case Path::FirstRewrite: return "setup_rewrite_first_payload";
    }
    return "unknown";
}

double sample(Path path, unsigned streams, unsigned payload, unsigned iterations) {
    const bool rewrite = path == Path::AfterSplit || path == Path::FirstRewrite;
    ProtocolViews views(rewrite ? ProtocolViews::Mode::Rewrite : ProtocolViews::Mode::Observe);
    initialize(views, streams);
    // Benchmark-only eager strategy. Each coordinator stays unsplit and owns
    // one independent engine. Feed BOTH the same setup from the beginning;
    // do not manufacture the second context by copying initialized state.
    std::unique_ptr<ProtocolViews> receiver;

    if (path == Path::TwoFromStart || path == Path::TwoShared || path == Path::TwoSelective) {
        receiver = std::make_unique<ProtocolViews>();
        initialize(*receiver, streams);
        EXPECT_NE(&state(views), &state(*receiver));
#ifdef USE_HPACK
        EXPECT_NE(state(views).request_decoder, state(*receiver).request_decoder);
        EXPECT_NE(state(views).response_decoder, state(*receiver).response_decoder);
#endif
    }

    auto input = frame(0, 0, 1, std::string(payload, 'a'));
    auto replacement = frame(0, 0, 1, std::string(payload, 'b'));

    if (path == Path::AfterSplit) {
        auto token = views.begin(E::Client, input, input.size());
        views.finish(token, replacement);
        EXPECT_TRUE(views.split());
    }

    // Initialization and payload allocation are outside the timed interval.
    // Setup's first rewrite-capable payload includes the one-time context fork.
    if (path == Path::FirstRewrite) iterations = 1;
    const auto start = Clock::now();

    for (unsigned i = 0; i < iterations; ++i) {
        if (path == Path::ForkOnly) {
            auto copy = views.context(E::Client).protocol_fork();
            // Copy construction AND destruction belong to the measured cost.
            if (!copy) std::abort();
        } else if (path == Path::SingleParser || path == Path::TwoFromStart ||
                   path == Path::TwoShared || path == Path::TwoSelective) {
            // Include snapshot allocation, byte copy, equality checks and
            // cache destruction in the timing. Reuse only within this pair.
            std::optional<sx::engine::PayloadAnalysis> analysis;
            sx::engine::PayloadAnalysis uncached;
            auto protocol_only = sx::engine::PayloadAnalysis::protocol_only();

            if (path == Path::TwoShared || path == Path::TwoSelective)
                analysis.emplace(input.string_view());

            auto* shared = analysis ? &*analysis : &uncached;
            // seed() runs the same parser and annotation pass without forking.
            // With no host/DNS payload, its output-only effect guard is inert.
            views.seed(E::Client, input, shared);

            // The receiver observes the actual outgoing bytes in the same
            // wire direction. No fork, rollback, journal or second webhook.
            // seed() suppresses external effects, inert for this DATA fixture.
            // Explicit publication requests keep the historical controls
            // hashing on both passes. Only the new path suppresses output.
            if (receiver) {
                receiver->seed(E::Client, input,
                    path == Path::TwoSelective ? &protocol_only : shared);
            }
        } else {
            auto token = views.begin(E::Client, input, input.size());
            views.finish(token, path == Path::FirstRewrite ? replacement : input);
        }
    }

    const auto elapsed = std::chrono::duration<double, std::micro>(Clock::now() - start).count();
    const auto expected = path == Path::ForkOnly ? 0U :
        (iterations + (path == Path::AfterSplit ? 1U : 0U)) * payload;

    for (auto endpoint : {E::Client, E::Server}) {
        const auto& connection = std::any_cast<h2::Http2Connection const&>(
            views.context(endpoint).state_data);
        EXPECT_FALSE(connection.connection_invalid);
        EXPECT_EQ(connection.streams.at(1).request_body_bytes_, expected);
        EXPECT_FALSE(connection.streams.at(1).request_invalid_);
    }

    if (receiver) {
        const auto& connection = state(*receiver);
        EXPECT_FALSE(connection.connection_invalid);
        EXPECT_EQ(connection.streams.at(1).request_body_bytes_, expected);
        EXPECT_FALSE(connection.streams.at(1).request_invalid_);
        EXPECT_EQ(connection.client_connection_window, state(views).client_connection_window);
        EXPECT_TRUE(connection.left_frame_pending.empty());
        EXPECT_FALSE(receiver->split());
        EXPECT_FALSE(views.split());

        const auto source_app = std::dynamic_pointer_cast<sx::engine::http::app_HttpRequest>(
            views.context(E::Client).application_data);
        const auto target_app = std::dynamic_pointer_cast<sx::engine::http::app_HttpRequest>(
            receiver->context(E::Client).application_data);
        EXPECT_TRUE(source_app && source_app->l7_payload_observed);
        EXPECT_TRUE(target_app);

        if (target_app) {
            EXPECT_EQ(target_app->l7_payload_observed, path != Path::TwoSelective);
        }
    }

    return elapsed / iterations;
}

// Exercise every measurement path in the correctness gate without running a
// benchmark-scale workload or treating Debug timings as performance evidence.
TEST(ProtocolViewsBenchmark, MeasurementPathsPreserveProtocolState) {
    for (auto path : {Path::SingleParser, Path::Observe, Path::TwoFromStart,
                      Path::TwoShared, Path::TwoSelective, Path::AfterSplit,
                      Path::ForkOnly, Path::FirstRewrite}) {
        SCOPED_TRACE(name(path));
        EXPECT_GE(sample(path, 2, 64, 2), 0.0);
    }
}

TEST(ProtocolForkBenchmark, CostByActiveStreamsAndPayload) {
    // Opt-in CTest benchmark, never part of the correctness gate. Use a Release
    // build on an otherwise idle machine; these are per-batch samples, not a
    // distribution of individual request latencies or end-to-end throughput.
    constexpr unsigned repetitions = 7;
    const std::vector<Path> paths = {Path::SingleParser, Path::Observe,
        Path::TwoFromStart, Path::TwoShared, Path::TwoSelective,
        Path::AfterSplit, Path::ForkOnly, Path::FirstRewrite};
    std::cout << "BENCH,streams,payload_bytes,path,iterations,samples,median_us,min_us,max_us\n";
    std::cout << std::fixed << std::setprecision(3);

    for (unsigned streams : {1U, 32U, 256U, 1024U}) {
        for (unsigned payload : {64U, 16384U}) {
            const unsigned iterations = streams >= 256 ? 128 : 1000;
            std::vector<std::vector<double>> timings(paths.size());

            for (auto path : paths) sample(path, streams, payload, 8); // warm up

            for (unsigned repetition = 0; repetition < repetitions; ++repetition) {
                // Rotate path order to reduce systematic warm-cache/order bias.
                for (unsigned j = 0; j < paths.size(); ++j) {
                    const auto index = (j + repetition) % paths.size();
                    timings[index].push_back(sample(paths[index], streams, payload, iterations));
                }
            }

            for (unsigned i = 0; i < paths.size(); ++i) {
                auto& values = timings[i];
                std::sort(values.begin(), values.end());
                std::cout << "BENCH," << streams << ',' << payload << ',' << name(paths[i])
                          << ',' << (paths[i] == Path::FirstRewrite ? 1 : iterations)
                          << ',' << repetitions << ',' << values[repetitions / 2]
                          << ',' << values.front() << ',' << values.back() << '\n';
            }
        }
    }

    rusage usage{};
    ASSERT_EQ(getrusage(RUSAGE_SELF, &usage), 0);
    std::cout << "PROCESS_PEAK_RSS_KIB," << usage.ru_maxrss
              << " (whole benchmark process, not per connection)\n";
}

TEST(ProtocolForkBenchmark, RetainedStorageCost) {
    // Explicit storage stress fixture, NOT a generated complete H2 exchange.
    // Separately measure a pending header block and an owned gzip cache; both
    // are copied by protocol_fork even when the next callback carries no body.
    for (bool compressed : {false, true}) {
        for (unsigned retained : {0U, 16384U, 262144U, 1048576U}) {
            ProtocolViews views(ProtocolViews::Mode::Rewrite);
            initialize(views, 1);
            auto& connection = state(views);

            if (compressed) {
                auto& gzip = connection.streams.at(1).gzip.emplace();
                const std::string content(retained, 'g');
                gzip.in.assign(content.data(), content.size());
            } else {
                connection.request_headers_pending.bytes.assign(retained, 'h');
            }

            std::vector<double> samples;

            for (unsigned repeat = 0; repeat < 8; ++repeat) {
                const auto start = Clock::now();

                for (unsigned i = 0; i < 128; ++i) {
                    auto copy = views.context(E::Client).protocol_fork();
                    if (!copy) std::abort();
                }

                const auto elapsed = std::chrono::duration<double, std::micro>(
                    Clock::now() - start).count() / 128;
                if (repeat) samples.push_back(elapsed); // first batch warms up
            }

            // Prove this measured a detached copy, not a cheap shared pointer.
            auto copy = views.context(E::Client).protocol_fork();
            auto& cloned = std::any_cast<h2::Http2Connection&>(copy->state_data);

            if (compressed) {
                EXPECT_EQ(cloned.streams.at(1).gzip->in.size(), retained);
                if (retained) {
                    EXPECT_NE(cloned.streams.at(1).gzip->in.data(),
                              connection.streams.at(1).gzip->in.data());
                }
            } else {
                EXPECT_EQ(cloned.request_headers_pending.bytes.size(), retained);
                cloned.request_headers_pending.bytes.clear();
                EXPECT_EQ(connection.request_headers_pending.bytes.size(), retained);
            }

            std::sort(samples.begin(), samples.end());
            std::cout << "STORAGE," << (compressed ? "gzip_cache" : "pending_headers")
                      << ',' << retained << ',' << samples[3] << ',' << samples.front()
                      << ',' << samples.back() << '\n';
        }
    }
}

TEST(ProtocolForkBenchmark, ClosedRequestHistoryCost) {
    // A long-lived connection can retain HTTP metadata even after all but one
    // stream have closed. Do not confuse active stream count with fork size.
    for (unsigned requests : {0U, 100U, 1000U, 10000U}) {
        ProtocolViews views(ProtocolViews::Mode::Rewrite);
        initialize(views, 1);
        const auto headers = std::string("\x83\x87\x84\x01\x0c", 5) + "example.test";

        for (unsigned i = 0; i < requests; ++i) {
            views.seed(E::Client, frame(1, 5, 2 * i + 3, headers));
            views.seed(E::Server, frame(1, 5, 2 * i + 3, std::string(1, '\x88')));
        }

        ASSERT_EQ(state(views).streams.size(), 1U);
        ASSERT_FALSE(state(views).connection_invalid);
        auto app = std::dynamic_pointer_cast<sx::engine::http::app_HttpRequest>(
            views.context(E::Client).application_data);
        ASSERT_TRUE(app);
        ASSERT_EQ(app->http_history.size(), requests);
        std::vector<double> samples;

        for (unsigned repeat = 0; repeat < 8; ++repeat) {
            const auto start = Clock::now();

            for (unsigned i = 0; i < 128; ++i) {
                auto copy = views.context(E::Client).protocol_fork();
                if (!copy) std::abort();
            }

            const auto elapsed = std::chrono::duration<double, std::micro>(
                Clock::now() - start).count() / 128;
            if (repeat) samples.push_back(elapsed);
        }

        std::sort(samples.begin(), samples.end());
        std::cout << "HISTORY," << requests << ',' << state(views).streams.size()
                  << ',' << app->http_history.size() << ',' << samples[3]
                  << ',' << samples.front() << ',' << samples.back() << '\n';
    }
}
} // namespace
