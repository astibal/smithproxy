#include <gtest/gtest.h>

#include <service/daemon.hpp>

#include <filesystem>
#include <fcntl.h>
#include <fstream>
#include <iterator>
#include <signal.h>
#include <string>
#include <unistd.h>

void writecrash(int fd, const char* msg, size_t len);

namespace {

volatile sig_atomic_t signal_seen = 0;

void record_signal(int value) {
    signal_seen = value;
}

std::string crashlog_path(const volatile char* path) {
    std::string result;
    while(*path != '\0') {
        result.push_back(*path++);
    }
    return result;
}

class DaemonPidfile : public ::testing::Test {
protected:
    void SetUp() override {
        char path[] = "/tmp/smithproxy-daemon-test-XXXXXX";
        const char* created = ::mkdtemp(path);
        ASSERT_NE(created, nullptr);
        directory_ = created;
        pidfile_ = directory_ / "smithproxy.pid";
    }

    void TearDown() override {
        std::error_code ignored;
        std::filesystem::remove_all(directory_, ignored);
    }

    static std::string contents(const std::filesystem::path& path) {
        std::ifstream input(path);
        return {std::istreambuf_iterator<char>(input), std::istreambuf_iterator<char>()};
    }

    std::filesystem::path directory_;
    std::filesystem::path pidfile_;
};

TEST_F(DaemonPidfile, ClaimsPathOnceWithoutOverwritingOwner) {
    DaemonFactory first;
    first.pid_file = pidfile_;
    ASSERT_TRUE(first.write_pidfile());
    EXPECT_TRUE(first.pid_file_owned);
    EXPECT_EQ(contents(pidfile_), std::to_string(::getpid()));

    DaemonFactory second;
    second.pid_file = pidfile_;
    EXPECT_FALSE(second.write_pidfile());
    EXPECT_FALSE(second.pid_file_owned);
    EXPECT_EQ(contents(pidfile_), std::to_string(::getpid()));

    first.unlink_pidfile();
    ASSERT_TRUE(second.write_pidfile());
    EXPECT_TRUE(second.pid_file_owned);
}

TEST_F(DaemonPidfile, RefusesSymlinkWithoutChangingItsTarget) {
    const auto target = directory_ / "target";
    {
        std::ofstream output(target);
        output << "preserve-me";
    }
    ASSERT_EQ(::symlink(target.c_str(), pidfile_.c_str()), 0);

    DaemonFactory daemon;
    daemon.pid_file = pidfile_;
    EXPECT_FALSE(daemon.write_pidfile());
    EXPECT_FALSE(daemon.pid_file_owned);
    EXPECT_EQ(contents(target), "preserve-me");
    EXPECT_TRUE(std::filesystem::is_symlink(pidfile_));
}

TEST_F(DaemonPidfile, FailedClaimNeverAssumesOwnership) {
    DaemonFactory daemon;
    daemon.pid_file = directory_ / "missing" / "smithproxy.pid";
    EXPECT_FALSE(daemon.write_pidfile());
    EXPECT_FALSE(daemon.pid_file_owned);
}

TEST_F(DaemonPidfile, CrashlogConfigurationAcceptsAnExplicitDisable) {
    DaemonFactory daemon;
    daemon.set_crashlog("/tmp/a-crash-log");
    EXPECT_EQ(crashlog_path(daemon.crashlog_file), "/tmp/a-crash-log");
    daemon.set_crashlog(nullptr);
    EXPECT_EQ(crashlog_path(daemon.crashlog_file), "");
}

TEST_F(DaemonPidfile, CrashWriterHandlesCompleteAndEmptyMessages) {
    const auto output_path = directory_ / "crash-output";
    const int fd = ::open(output_path.c_str(), O_CREAT | O_WRONLY | O_TRUNC, 0600);
    ASSERT_GE(fd, 0);

    constexpr char message[] = "complete crash record";
    writecrash(fd, message, sizeof(message) - 1);
    writecrash(fd, nullptr, sizeof(message) - 1);
    writecrash(fd, message, 0);
    ASSERT_EQ(::close(fd), 0);
    EXPECT_EQ(contents(output_path), message);
}

TEST_F(DaemonPidfile, MetadataExistenceAndForcedCleanupAreObservable) {
    DaemonFactory daemon;
    daemon.set_tenant("smithproxy-test", "tenant-7");
    EXPECT_EQ(daemon.pid_file, "/var/run/smithproxy-test.tenant-7.pid");
    EXPECT_EQ(daemon.class_name(), "DaemonFactory");
    EXPECT_NE(daemon.hr().find("smithproxy-test.tenant-7.pid"), std::string::npos);
    EXPECT_GT(daemon.get_limit_fd(), 0U);

    daemon.pid_file = pidfile_;
    EXPECT_FALSE(daemon.exists_pidfile());
    {
        std::ofstream output(pidfile_);
        output << "foreign";
    }
    EXPECT_TRUE(daemon.exists_pidfile());
    daemon.unlink_pidfile();
    EXPECT_TRUE(daemon.exists_pidfile()) << "unowned pid files must be preserved";
    daemon.unlink_pidfile(true);
    EXPECT_FALSE(daemon.exists_pidfile());
    daemon.unlink_pidfile(true);  // missing-path error handling remains harmless
}

TEST_F(DaemonPidfile, SignalInstallationSupportsHandlerAndIgnoreModes) {
    struct sigaction previous {};
    ASSERT_EQ(::sigaction(SIGUSR2, nullptr, &previous), 0);

    signal_seen = 0;
    DaemonFactory::set_signal(SIGUSR2, record_signal);
    ASSERT_EQ(::raise(SIGUSR2), 0);
    EXPECT_EQ(signal_seen, SIGUSR2);

    DaemonFactory::set_signal(SIGUSR2, nullptr);
    struct sigaction ignored {};
    ASSERT_EQ(::sigaction(SIGUSR2, nullptr, &ignored), 0);
    EXPECT_EQ(ignored.sa_handler, SIG_IGN);
    ASSERT_EQ(::sigaction(SIGUSR2, &previous, nullptr), 0);
}

} // namespace
