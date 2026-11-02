#include "../pap.hpp"

#include <gtest/gtest.h>

#include <atomic>
#include <condition_variable>
#include <future>
#include <mutex>
#include <optional>
#include <stdexcept>
#include <thread>
#include <utility>
#include <vector>

namespace {

using sx::auth::PapBackend;
using sx::auth::PapCredentials;
using sx::auth::PapExchange;
using sx::auth::Result;
using sx::auth::Status;

struct FakeIo {
    void tap() { ++tap_calls; tapped = true; }
    void untap() { ++untap_calls; tapped = false; }

    int tap_calls = 0;
    int untap_calls = 0;
    bool tapped = false;
};

class ImmediateBackend final : public PapBackend {
public:
    std::optional<Result> verify_pap(PapCredentials credentials, completion_type) override {
        observed = std::move(credentials);
        return Result{Status::accepted, observed.username, {}};
    }
    PapCredentials observed;
};

class DeferredBackend final : public PapBackend {
public:
    std::optional<Result> verify_pap(PapCredentials credentials, completion_type completion) override {
        observed = std::move(credentials);
        completion_ = std::move(completion);
        return std::nullopt;
    }

    void complete(Result result) { completion_(std::move(result)); }

    PapCredentials observed;
    completion_type completion_;
};

class ConcurrentDeferredBackend final : public PapBackend {
public:
    std::optional<Result> verify_pap(PapCredentials, completion_type completion) override {
        std::lock_guard lock(mutex_);
        ++calls_;
        completions_.push_back(std::move(completion));
        return std::nullopt;
    }

    completion_type completion(std::size_t index) {
        std::lock_guard lock(mutex_);
        return completions_.at(index);
    }

    int calls() const {
        std::lock_guard lock(mutex_);
        return calls_;
    }

private:
    mutable std::mutex mutex_;
    int calls_ = 0;
    std::vector<completion_type> completions_;
};

struct ConcurrentIo {
    void tap() {
        tap_calls.fetch_add(1, std::memory_order_relaxed);
        balance.fetch_add(1, std::memory_order_relaxed);
    }
    void untap() {
        untap_calls.fetch_add(1, std::memory_order_relaxed);
        balance.fetch_sub(1, std::memory_order_relaxed);
    }

    std::atomic_int tap_calls{0};
    std::atomic_int untap_calls{0};
    std::atomic_int balance{0};
};

PapExchange exchange_for(FakeIo& io) {
    return PapExchange([&] { io.tap(); }, [&] { io.untap(); });
}

TEST(PapExchange, ImmediateBackendUsesSameTapUntapPath) {
    FakeIo io;
    ImmediateBackend backend;
    auto exchange = exchange_for(io);
    std::vector<Result> results;

    EXPECT_TRUE(exchange.verify(backend, "alice", "secret",
                                [&](Result result) { results.push_back(std::move(result)); }));

    EXPECT_EQ(io.tap_calls, 1);
    EXPECT_EQ(io.untap_calls, 1);
    EXPECT_FALSE(io.tapped);
    EXPECT_FALSE(exchange.pending());
    ASSERT_EQ(results.size(), 1U);
    EXPECT_EQ(results[0].status, Status::accepted);
    EXPECT_EQ(results[0].identity, "alice");
    EXPECT_EQ(backend.observed.password, "secret");
}

TEST(PapExchange, DeferredBackendKeepsIoTappedUntilCompletion) {
    FakeIo io;
    DeferredBackend backend;
    auto exchange = exchange_for(io);
    std::vector<Result> results;

    ASSERT_TRUE(exchange.verify(backend, "alice", "secret",
                                [&](Result result) { results.push_back(std::move(result)); }));
    EXPECT_TRUE(exchange.pending());
    EXPECT_TRUE(io.tapped);
    EXPECT_EQ(io.untap_calls, 0);

    backend.complete(Result{Status::rejected, {}, {}});

    EXPECT_FALSE(exchange.pending());
    EXPECT_FALSE(io.tapped);
    EXPECT_EQ(io.untap_calls, 1);
    ASSERT_EQ(results.size(), 1U);
    EXPECT_EQ(results[0].status, Status::rejected);
}

TEST(PapExchange, RejectsSecondRequestWhileOneIsPending) {
    FakeIo io;
    DeferredBackend backend;
    ImmediateBackend second_backend;
    auto exchange = exchange_for(io);

    ASSERT_TRUE(exchange.verify(backend, "alice", "one", [](Result) {}));
    EXPECT_FALSE(exchange.verify(second_backend, "bob", "two", [](Result) {}));
    EXPECT_EQ(io.tap_calls, 1);

    backend.complete(Result{Status::accepted, "alice", {}});
    EXPECT_TRUE(exchange.verify(second_backend, "bob", "two", [](Result) {}));
    EXPECT_EQ(io.tap_calls, 2);
    EXPECT_EQ(io.untap_calls, 2);
}

TEST(PapExchange, DuplicateAndStaleCallbacksCannotUntapAnotherRequest) {
    FakeIo io;
    DeferredBackend first;
    DeferredBackend second;
    auto exchange = exchange_for(io);
    int completions = 0;

    ASSERT_TRUE(exchange.verify(first, "alice", "one", [&](Result) { ++completions; }));
    auto stale_callback = first.completion_;
    first.complete(Result{Status::accepted, "alice", {}});
    ASSERT_TRUE(exchange.verify(second, "bob", "two", [&](Result) { ++completions; }));

    stale_callback(Result{Status::rejected, {}, {}});
    EXPECT_TRUE(exchange.pending());
    EXPECT_TRUE(io.tapped);
    EXPECT_EQ(io.untap_calls, 1);

    second.complete(Result{Status::accepted, "bob", {}});
    EXPECT_EQ(completions, 2);
    EXPECT_EQ(io.untap_calls, 2);
}

TEST(PapExchange, CancelUntapsAndIgnoresLateCompletion) {
    FakeIo io;
    DeferredBackend backend;
    auto exchange = exchange_for(io);
    int completions = 0;

    ASSERT_TRUE(exchange.verify(backend, "alice", "secret", [&](Result) { ++completions; }));
    exchange.cancel();
    EXPECT_FALSE(io.tapped);
    EXPECT_FALSE(exchange.pending());
    EXPECT_EQ(io.untap_calls, 1);

    backend.complete(Result{Status::accepted, "alice", {}});
    EXPECT_EQ(completions, 0);
    EXPECT_EQ(io.untap_calls, 1);
}

TEST(PapExchange, BackendExceptionUntapsAndReportsError) {
    class ThrowingBackend final : public PapBackend {
        std::optional<Result> verify_pap(PapCredentials, completion_type) override {
            throw std::runtime_error("backend failed");
        }
    } backend;

    FakeIo io;
    auto exchange = exchange_for(io);
    std::optional<Result> result;
    ASSERT_TRUE(exchange.verify(backend, "alice", "secret",
                                [&](Result value) { result = std::move(value); }));

    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(result->status, Status::error);
    EXPECT_EQ(result->error, "backend failed");
    EXPECT_FALSE(io.tapped);
    EXPECT_EQ(io.untap_calls, 1);
}

TEST(PapExchange, ParallelVerifyStartsExactlyOneRequest) {
    ConcurrentIo io;
    ConcurrentDeferredBackend backend;
    PapExchange exchange([&] { io.tap(); }, [&] { io.untap(); });
    constexpr int thread_count = 32;
    std::atomic_bool go{false};
    std::atomic_int accepted_starts{0};
    std::vector<std::thread> threads;

    for(int index = 0; index < thread_count; ++index) {
        threads.emplace_back([&] {
            while(not go.load(std::memory_order_acquire)) std::this_thread::yield();
            if(exchange.verify(backend, "alice", "secret", [](Result) {})) {
                accepted_starts.fetch_add(1, std::memory_order_relaxed);
            }
        });
    }
    go.store(true, std::memory_order_release);
    for(auto& thread : threads) thread.join();

    EXPECT_EQ(accepted_starts.load(), 1);
    EXPECT_EQ(backend.calls(), 1);
    EXPECT_EQ(io.tap_calls.load(), 1);
    EXPECT_EQ(io.balance.load(), 1);

    backend.completion(0)(Result{Status::accepted, "alice", {}});
    EXPECT_EQ(io.untap_calls.load(), 1);
    EXPECT_EQ(io.balance.load(), 0);
}

TEST(PapExchange, ParallelCancelAndCompletionResumeExactlyOnce) {
    constexpr int iterations = 500;
    for(int iteration = 0; iteration < iterations; ++iteration) {
        ConcurrentIo io;
        ConcurrentDeferredBackend backend;
        PapExchange exchange([&] { io.tap(); }, [&] { io.untap(); });
        std::atomic_int completions{0};

        ASSERT_TRUE(exchange.verify(backend, "alice", "secret",
                                    [&](Result) { completions.fetch_add(1); }));
        auto callback = backend.completion(0);
        std::thread cancel_thread([&] { exchange.cancel(); });
        std::thread completion_thread([&] {
            callback(Result{Status::accepted, "alice", {}});
        });
        cancel_thread.join();
        completion_thread.join();

        EXPECT_FALSE(exchange.pending());
        EXPECT_EQ(io.tap_calls.load(), 1);
        EXPECT_EQ(io.untap_calls.load(), 1);
        EXPECT_EQ(io.balance.load(), 0);
        EXPECT_LE(completions.load(), 1);
    }
}

TEST(PapExchange, StaleCallbacksCannotCompleteLaterGenerationsUnderLoad) {
    ConcurrentIo io;
    ConcurrentDeferredBackend backend;
    PapExchange exchange([&] { io.tap(); }, [&] { io.untap(); });
    constexpr int iterations = 200;
    std::atomic_int completions{0};
    std::vector<PapBackend::completion_type> stale;

    for(int iteration = 0; iteration < iterations; ++iteration) {
        ASSERT_TRUE(exchange.verify(backend, "user", "password",
                                    [&](Result) { completions.fetch_add(1); }));
        auto current = backend.completion(static_cast<std::size_t>(iteration));
        for(auto const& old : stale) {
            old(Result{Status::rejected, {}, {}});
        }
        EXPECT_TRUE(exchange.pending());
        current(Result{Status::accepted, "user", {}});
        stale.push_back(std::move(current));
    }

    EXPECT_EQ(completions.load(), iterations);
    EXPECT_EQ(io.tap_calls.load(), iterations);
    EXPECT_EQ(io.untap_calls.load(), iterations);
    EXPECT_EQ(io.balance.load(), 0);
}

TEST(PapExchange, CompletionMayReenterAndStartNextRequest) {
    FakeIo io;
    ImmediateBackend backend;
    auto exchange = exchange_for(io);
    int completions = 0;

    ASSERT_TRUE(exchange.verify(backend, "first", "one", [&](Result) {
        ++completions;
        EXPECT_TRUE(exchange.verify(backend, "second", "two",
                                    [&](Result) { ++completions; }));
    }));

    EXPECT_EQ(completions, 2);
    EXPECT_EQ(io.tap_calls, 2);
    EXPECT_EQ(io.untap_calls, 2);
    EXPECT_FALSE(exchange.pending());
}

TEST(PapExchange, LateCompletionAfterDestructionIsIgnored) {
    ConcurrentIo io;
    ConcurrentDeferredBackend backend;
    PapBackend::completion_type callback;
    std::atomic_int completions{0};

    {
        PapExchange exchange([&] { io.tap(); }, [&] { io.untap(); });
        ASSERT_TRUE(exchange.verify(backend, "alice", "secret",
                                    [&](Result) { completions.fetch_add(1); }));
        callback = backend.completion(0);
    }

    EXPECT_EQ(io.balance.load(), 0);
    callback(Result{Status::accepted, "alice", {}});
    EXPECT_EQ(completions.load(), 0);
    EXPECT_EQ(io.tap_calls.load(), 1);
    EXPECT_EQ(io.untap_calls.load(), 1);
}

TEST(PapExchange, NextRequestWaitsForPreviousUntap) {
    ConcurrentDeferredBackend backend;
    std::promise<void> untap_started;
    std::promise<void> release_untap;
    auto release = release_untap.get_future().share();
    std::atomic_int taps{0};
    std::atomic_int untaps{0};
    PapExchange exchange([&] { ++taps; }, [&] {
        if(++untaps == 1) {
            untap_started.set_value();
            release.wait();
        }
    });
    ASSERT_TRUE(exchange.verify(backend, "first", "password", [](Result) {}));
    auto completion = std::async(std::launch::async, [&] {
        backend.completion(0)(Result{Status::accepted, "first", {}});
    });
    untap_started.get_future().wait();
    auto next = std::async(std::launch::async, [&] {
        return exchange.verify(backend, "second", "password", [](Result) {});
    });
    EXPECT_EQ(next.wait_for(std::chrono::milliseconds(30)), std::future_status::timeout);
    EXPECT_EQ(taps.load(), 1);
    release_untap.set_value();
    completion.get();
    EXPECT_TRUE(next.get());
    exchange.cancel();
    EXPECT_EQ(taps.load(), 2);
    EXPECT_EQ(untaps.load(), 2);
}

} // namespace
