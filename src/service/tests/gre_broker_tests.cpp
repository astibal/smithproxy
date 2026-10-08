#include <service/gre_broker.hpp>

#include <atomic>
#include <chrono>
#include <filesystem>
#include <string>
#include <thread>

#include <signal.h>
#include <sys/wait.h>
#include <unistd.h>

#include <gtest/gtest.h>

namespace {

pid_t start_broker(const std::string& path) {
    const pid_t child = ::fork();
    if(child == 0) {
        sx::comm::gre::Profile profile{AF_INET, "127.0.0.1", 1, {}};
        ::_exit(sx::comm::gre::run_standalone_broker(path, std::move(profile)) == 0
                   ? EXIT_SUCCESS : EXIT_FAILURE);
    }
    return child;
}

bool wait_for_path(const std::string& path, bool expected) {
    for(unsigned attempt = 0; attempt < 100; ++attempt) {
        if(std::filesystem::exists(path) == expected) return true;
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }
    return false;
}

TEST(GreBrokerTest, ExternalClientConnectsAndBrokerRemovesOwnedSocket) {
    char directory_template[] = "./smithproxy-gre-broker-test-XXXXXX";
    char* directory = ::mkdtemp(directory_template);
    ASSERT_NE(directory, nullptr);
    const std::string path = std::string(directory) + "/gre.sock";

    const pid_t child = start_broker(path);
    ASSERT_GE(child, 0);
    ASSERT_TRUE(wait_for_path(path, true));
    ASSERT_EQ(sx::comm::gre::connect_external_broker(path), 0);
    ASSERT_NE(sx::comm::gre::transport(), nullptr);
    buffer invalid_frame;
    ASSERT_TRUE(sx::comm::gre::transport()->submit(invalid_frame));
    sx::comm::gre::Stats broker_stats;
    ASSERT_EQ(sx::comm::gre::broker_stats(broker_stats), 0);
    EXPECT_EQ(broker_stats.received, 1U);
    EXPECT_EQ(broker_stats.exported, 0U);
    EXPECT_EQ(broker_stats.errors, 1U);
    EXPECT_EQ(sx::comm::gre::stop_local_broker(), 0);

    ASSERT_EQ(::kill(child, SIGTERM), 0);
    int status = 0;
    ASSERT_EQ(::waitpid(child, &status, 0), child);
    EXPECT_TRUE(WIFEXITED(status));
    EXPECT_EQ(WEXITSTATUS(status), EXIT_SUCCESS);
    EXPECT_FALSE(std::filesystem::exists(path));
    EXPECT_EQ(::rmdir(directory), 0);
}

TEST(GreBrokerTest, ExternalTransportReconnectsAfterBrokerRestart) {
    char directory_template[] = "./smithproxy-gre-reconnect-test-XXXXXX";
    char* directory = ::mkdtemp(directory_template);
    ASSERT_NE(directory, nullptr);
    const std::string path = std::string(directory) + "/gre.sock";

    pid_t child = start_broker(path);
    ASSERT_GE(child, 0);
    ASSERT_TRUE(wait_for_path(path, true));
    ASSERT_EQ(sx::comm::gre::connect_external_broker(path), 0);
    EXPECT_TRUE(sx::comm::gre::stats().connected);

    ASSERT_EQ(::kill(child, SIGTERM), 0);
    int status = 0;
    ASSERT_EQ(::waitpid(child, &status, 0), child);
    ASSERT_TRUE(WIFEXITED(status));
    ASSERT_TRUE(wait_for_path(path, false));

    for(unsigned attempt = 0; attempt < 100 && sx::comm::gre::stats().connected; ++attempt) {
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }
    EXPECT_FALSE(sx::comm::gre::stats().connected);

    child = start_broker(path);
    ASSERT_GE(child, 0);
    ASSERT_TRUE(wait_for_path(path, true));
    for(unsigned attempt = 0; attempt < 200 && !sx::comm::gre::stats().connected; ++attempt) {
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }
    const auto reconnected = sx::comm::gre::stats();
    EXPECT_TRUE(reconnected.connected);
    EXPECT_GE(reconnected.reconnects, 1U);
    sx::comm::gre::Stats broker_stats;
    EXPECT_EQ(sx::comm::gre::broker_stats(broker_stats), 0);

    EXPECT_EQ(sx::comm::gre::stop_local_broker(), 0);
    ASSERT_EQ(::kill(child, SIGTERM), 0);
    ASSERT_EQ(::waitpid(child, &status, 0), child);
    EXPECT_EQ(::rmdir(directory), 0);
}

TEST(GreBrokerTest, InternalBrokerFailureInvokesFatalHandler) {
    std::atomic<bool> failed{false};
    sx::comm::gre::set_internal_failure_handler([&failed] { failed.store(true); });
    sx::comm::gre::Profile profile{AF_INET, "127.0.0.1", 1, {}};
    ASSERT_EQ(sx::comm::gre::start_local_broker(std::move(profile)), 0);
    const pid_t child = sx::comm::gre::owned_broker_pid();
    ASSERT_GT(child, 0);
    ASSERT_EQ(::kill(child, SIGKILL), 0);
    for(unsigned attempt = 0; attempt < 100 && !failed.load(); ++attempt) {
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }
    EXPECT_TRUE(failed.load());
    EXPECT_FALSE(sx::comm::gre::stats().connected);
    EXPECT_EQ(sx::comm::gre::stop_local_broker(), -1);
    sx::comm::gre::set_internal_failure_handler({});
}

} // namespace
