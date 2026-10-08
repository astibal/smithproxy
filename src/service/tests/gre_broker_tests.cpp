#include <service/gre_broker.hpp>

#include <chrono>
#include <filesystem>
#include <string>
#include <thread>

#include <signal.h>
#include <sys/wait.h>
#include <unistd.h>

#include <gtest/gtest.h>

namespace {

TEST(GreBrokerTest, ExternalClientConnectsAndBrokerRemovesOwnedSocket) {
    char directory_template[] = "./smithproxy-gre-broker-test-XXXXXX";
    char* directory = ::mkdtemp(directory_template);
    ASSERT_NE(directory, nullptr);
    const std::string path = std::string(directory) + "/gre.sock";

    const pid_t child = ::fork();
    ASSERT_GE(child, 0);
    if(child == 0) {
        sx::comm::gre::Profile profile{AF_INET, "127.0.0.1", 1, {}};
        ::_exit(sx::comm::gre::run_standalone_broker(path, std::move(profile)) == 0
                   ? EXIT_SUCCESS : EXIT_FAILURE);
    }

    bool ready = false;
    for(unsigned attempt = 0; attempt < 100; ++attempt) {
        if(std::filesystem::exists(path)) { ready = true; break; }
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }
    ASSERT_TRUE(ready);
    ASSERT_EQ(sx::comm::gre::connect_external_broker(path), 0);
    ASSERT_NE(sx::comm::gre::transport(), nullptr);
    EXPECT_EQ(sx::comm::gre::stop_local_broker(), 0);

    ASSERT_EQ(::kill(child, SIGTERM), 0);
    int status = 0;
    ASSERT_EQ(::waitpid(child, &status, 0), child);
    EXPECT_TRUE(WIFEXITED(status));
    EXPECT_EQ(WEXITSTATUS(status), EXIT_SUCCESS);
    EXPECT_FALSE(std::filesystem::exists(path));
    EXPECT_EQ(::rmdir(directory), 0);
}

} // namespace
