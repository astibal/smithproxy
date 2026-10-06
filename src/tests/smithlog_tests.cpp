#include <gtest/gtest.h>

#include <smithlog.hpp>

#include <atomic>
#include <array>
#include <chrono>
#include <sstream>
#include <thread>
#include <sys/socket.h>
#include <unistd.h>

using namespace std::chrono_literals;

namespace {

class CountingQueueLogger : public QueueLogger {
public:
    std::atomic_uint written {0};

    size_t write_disk(loglevel level, std::string& message) override {
        ++written;
        return QueueLogger::write_disk(level, message);
    }
};

} // namespace

TEST(QueueLogger, ConsumerWritesOutsideQueueLockAndTerminates) {
    auto logger = std::make_shared<CountingQueueLogger>();
    std::thread consumer([logger] { QueueLogger::run_queue(logger); });

    std::string message = "coverage queue entry";
    logger->write_log(loglevel(iINF), message);

    auto const deadline = std::chrono::steady_clock::now() + 1s;
    while (logger->written.load() == 0 && std::chrono::steady_clock::now() < deadline)
        std::this_thread::sleep_for(1ms);

    logger->sig_terminate.store(true, std::memory_order_release);
    consumer.join();
    EXPECT_EQ(logger->written.load(), 1U);
}

TEST(QueueLogger, NullConsumerSourceReturnsImmediately) {
    QueueLogger::run_queue(nullptr);
}

TEST(LogMux, LevelsTimersTopicsAndEscapingHaveStableSemantics) {
    EXPECT_EQ(Log::level_name(iINF), "Informat");
    EXPECT_EQ(Log::level_name(99), "loglev-99");
    EXPECT_EQ(ESC_("100% ready"), "100^ ready");
    EXPECT_LT(get_usec(), 1000000UL);
    EXPECT_GE(get_tm(0).tm_year, 69);

    LogMux mux;
    EXPECT_TRUE(mux.periodic_start(0));
    EXPECT_TRUE(mux.periodic_end());
    EXPECT_FALSE(mux.periodic_start(3600));
    EXPECT_FALSE(mux.periodic_end());
    EXPECT_TRUE(mux.click_timer("coverage", 60));
    EXPECT_FALSE(mux.click_timer("coverage", 60));

    loglevel generic_writer(iINF);
    loglevel generic_message(iINF);
    EXPECT_TRUE(mux.should_log_topic(generic_writer, generic_message));

    loglevel topic_writer(iINF, 0x1234);
    EXPECT_FALSE(mux.should_log_topic(topic_writer, generic_message));
    loglevel ordinary_topic(iINF, 0x1234);
    EXPECT_TRUE(mux.should_log_topic(topic_writer, ordinary_topic));

    loglevel exact_match(iINF, 0x1234, &socle::log::level::LOG_EXEXACT);
    loglevel exact_miss(iINF, 0x5678, &socle::log::level::LOG_EXEXACT);
    EXPECT_TRUE(mux.should_log_topic(topic_writer, exact_match));
    EXPECT_FALSE(mux.should_log_topic(topic_writer, exact_miss));

    loglevel exclusive_generic(iINF, 0x1234, &socle::log::level::LOG_EXTOPIC);
    EXPECT_FALSE(mux.should_log_topic(generic_writer, exclusive_generic));
    EXPECT_TRUE(mux.should_log_topic(topic_writer, exclusive_generic));
}

TEST(LogMux, WritesFilteredLocalAndRemoteTargets) {
    LogMux mux;
    mux.dup2_cout(false);

    auto* local = new std::ostringstream;
    mux.targets("memory", local);
    auto local_profile = std::make_unique<logger_profile>();
    local_profile->level_ = socle::log::level::INF;
    mux.target_profiles()[reinterpret_cast<uint64_t>(local)] = std::move(local_profile);

    int pair[2] {-1, -1};
    ASSERT_EQ(::socketpair(AF_UNIX, SOCK_DGRAM, 0, pair), 0);
    mux.remote_targets("remote", pair[0]);
    auto remote_profile = std::make_unique<logger_profile>();
    remote_profile->level_ = socle::log::level::INF;
    remote_profile->logger_type = logger_profile::REMOTE_SYSLOG;
    remote_profile->syslog_settings.facility = 16;
    remote_profile->syslog_settings.severity = 5;
    mux.target_profiles()[static_cast<uint64_t>(pair[0])] = std::move(remote_profile);

    std::string message = "mux coverage";
    EXPECT_EQ(mux.write_log(socle::log::level::INF, message), message.size());
    EXPECT_NE(local->str().find(message), std::string::npos);

    std::array<char, 128> received{};
    const auto count = ::recv(pair[1], received.data(), received.size(), 0);
    ASSERT_GT(count, 0);
    const std::string wire(received.data(), static_cast<std::size_t>(count));
    EXPECT_NE(wire.find("<133>"), std::string::npos);
    EXPECT_NE(wire.find(message), std::string::npos);

    loglevel too_verbose(iDEB);
    EXPECT_EQ(mux.write_log(too_verbose, message), message.size());
    EXPECT_EQ(local->str().find(message, local->str().find(message) + 1), std::string::npos);

    EXPECT_EQ(std::string(mux.target_name(reinterpret_cast<uint64_t>(local))), "memory");
    EXPECT_EQ(std::string(mux.target_name(0xdeadbeef)), "unknown");
    ::close(pair[0]);
    ::close(pair[1]);
}

TEST(LogLevel, ArithmeticComparisonAndMetadataRoundTrip) {
    loglevel value(iINF, 42);
    value.flags(7);
    value.subject("subject");
    value.area("area");
    EXPECT_EQ(value.topic(), 42U);
    EXPECT_EQ(value.flags(), 7U);
    EXPECT_EQ(value.subject(), "subject");
    EXPECT_EQ(value.area(), "area");
    EXPECT_EQ(value.str(), "level:6 topic:42");

    EXPECT_TRUE(value == iINF);
    EXPECT_TRUE(iINF == value);
    EXPECT_TRUE(value >= iNOT);
    EXPECT_TRUE(iINF <= value);
    EXPECT_TRUE(value > iWAR);
    EXPECT_TRUE(iWAR < value);
    EXPECT_TRUE(value != iDEB);
    EXPECT_EQ((value + 2).level(), static_cast<unsigned int>(iDEB));
    EXPECT_EQ((value - 1).level(), static_cast<unsigned int>(iNOT));
    EXPECT_EQ((value - loglevel(2)).level(), 4U);
}
