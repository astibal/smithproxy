#include <gtest/gtest.h>

#include <smithlog.hpp>

#include <atomic>
#include <chrono>
#include <thread>

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
