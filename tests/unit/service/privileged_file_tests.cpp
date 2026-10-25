#include <gtest/gtest.h>

#include <algorithm>
#include <atomic>
#include <cerrno>
#include <filesystem>
#include <fstream>
#include <memory>
#include <stdexcept>
#include <string>
#include <thread>
#include <vector>

#include <fcntl.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <unistd.h>

#include <service/privileged_file.hpp>

namespace {

class TestOperation final: public sx::privsep::files::Operation {
public:
    sx::privsep::files::Reply execute(const sx::privsep::files::Request& request) override {
        ++calls;
        last_opcode = request.opcode;
        return {0, "handled:" + request.payload, -1};
    }

    void shutdown() noexcept override { ++shutdowns; }

    int calls = 0;
    int shutdowns = 0;
    std::uint8_t last_opcode = 0;
};

class ThrowingOperation final: public sx::privsep::files::Operation {
public:
    sx::privsep::files::Reply execute(const sx::privsep::files::Request&) override {
        throw std::runtime_error("test failure");
    }
};

class PrivilegedFileTest : public ::testing::Test {
protected:
    void SetUp() override {
        char pattern[] = "./smithproxy-file-privsep-test-XXXXXX";
        const char* created = ::mkdtemp(pattern);
        ASSERT_NE(created, nullptr);
        root_ = created;
        targets_.config = (root_ / "smithproxy.cfg").string();
        targets_.pid = (root_ / "smithproxy.pid").string();
    }

    void TearDown() override {
        sx::privsep::files::stop_local_helper();
        std::error_code ignored;
        std::filesystem::remove_all(root_, ignored);
    }

    std::filesystem::path root_;
    sx::privsep::files::Targets targets_;
};

TEST_F(PrivilegedFileTest, DirectConfigReadAndAtomicReplacement) {
    ASSERT_EQ(sx::privsep::files::write_file_atomic(targets_.config, "first\n"), 0);
    std::string content;
    ASSERT_EQ(sx::privsep::files::read_file(targets_.config, content), 0);
    EXPECT_EQ(content, "first\n");

    ASSERT_EQ(sx::privsep::files::write_file_atomic(targets_.config, "second\n"), 0);
    ASSERT_EQ(sx::privsep::files::read_file(targets_.config, content), 0);
    EXPECT_EQ(content, "second\n");

    struct stat state{};
    ASSERT_EQ(::stat(targets_.config.c_str(), &state), 0);
    EXPECT_TRUE(S_ISREG(state.st_mode));
    EXPECT_EQ(state.st_mode & 0777, 0640);
}

TEST_F(PrivilegedFileTest, DirectReadRejectsSymlink) {
    const auto actual = root_ / "actual.cfg";
    ASSERT_EQ(sx::privsep::files::write_file_atomic(actual.string(), "secret"), 0);
    ASSERT_EQ(::symlink(actual.c_str(), targets_.config.c_str()), 0);
    std::string content;
    errno = 0;
    EXPECT_EQ(sx::privsep::files::read_file(targets_.config, content), -1);
    EXPECT_EQ(errno, ELOOP);
}

TEST_F(PrivilegedFileTest, DirectReadRejectsNonRegularFilesWithoutBlocking) {
    ASSERT_EQ(::mkfifo(targets_.config.c_str(), 0600), 0);
    std::string content;
    errno = 0;
    EXPECT_EQ(sx::privsep::files::read_file(targets_.config, content), -1);
    EXPECT_EQ(errno, EINVAL);
}

TEST_F(PrivilegedFileTest, AtomicWriteRejectsSymlinkAndDirectoryTargets) {
    const auto actual = root_ / "actual.cfg";
    ASSERT_EQ(sx::privsep::files::write_file_atomic(actual.string(), "original"), 0);
    ASSERT_EQ(::symlink(actual.c_str(), targets_.config.c_str()), 0);
    errno = 0;
    EXPECT_EQ(sx::privsep::files::write_file_atomic(targets_.config, "replacement"), -1);
    EXPECT_EQ(errno, EINVAL);

    ASSERT_EQ(::unlink(targets_.config.c_str()), 0);
    ASSERT_EQ(::mkdir(targets_.config.c_str(), 0750), 0);
    errno = 0;
    EXPECT_EQ(sx::privsep::files::write_file_atomic(targets_.config, "replacement"), -1);
    EXPECT_EQ(errno, EINVAL);

    std::string content;
    ASSERT_EQ(sx::privsep::files::read_file(actual.string(), content), 0);
    EXPECT_EQ(content, "original");
}

TEST_F(PrivilegedFileTest, ConfigSizeIsBounded) {
    const std::string oversized(16U * 1024U * 1024U + 1U, 'x');
    errno = 0;
    EXPECT_EQ(sx::privsep::files::write_file_atomic(targets_.config, oversized), -1);
    EXPECT_EQ(errno, EFBIG);
    EXPECT_FALSE(std::filesystem::exists(targets_.config));
}

TEST_F(PrivilegedFileTest, ConcurrentAtomicReplacementNeverMixesPayloadsOrLeavesTemps) {
    constexpr unsigned writer_count = 8;
    constexpr unsigned writes_per_writer = 10;
    std::vector<std::string> payloads;
    for(unsigned writer = 0; writer < writer_count; ++writer)
        payloads.emplace_back(4096, static_cast<char>('A' + writer));
    std::atomic<unsigned> failures{0};
    std::vector<std::thread> writers;
    for(unsigned writer = 0; writer < writer_count; ++writer) {
        writers.emplace_back([&, writer] {
            for(unsigned iteration = 0; iteration < writes_per_writer; ++iteration) {
                if(sx::privsep::files::write_file_atomic(targets_.config, payloads[writer]) != 0)
                    failures.fetch_add(1);
            }
        });
    }
    for(auto& writer: writers) writer.join();
    EXPECT_EQ(failures.load(), 0U);
    std::string result;
    ASSERT_EQ(sx::privsep::files::read_file(targets_.config, result), 0);
    EXPECT_NE(std::find(payloads.begin(), payloads.end(), result), payloads.end());
    for(const auto& entry: std::filesystem::directory_iterator(root_))
        EXPECT_EQ(entry.path().filename().string().find(".tmp."), std::string::npos);
}

TEST_F(PrivilegedFileTest, BackupSuffixIsRestrictedAndComputedByHelper) {
    EXPECT_EQ(sx::privsep::files::write_backup_atomic(targets_.config, "1.2.3", "backup"), 0);
    std::string content;
    EXPECT_EQ(sx::privsep::files::read_file(targets_.config + ".1.2.3.bak.cfg", content), 0);
    EXPECT_EQ(content, "backup");

    errno = 0;
    EXPECT_EQ(sx::privsep::files::write_backup_atomic(targets_.config, "../../escape", "bad"), -1);
    EXPECT_EQ(errno, EINVAL);
}

TEST_F(PrivilegedFileTest, ServerReadsWritesAndBacksUpOnlyConfiguredTarget) {
    ASSERT_EQ(sx::privsep::files::write_file_atomic(targets_.config, "initial"), 0);
    int channels[2] = {-1, -1};
    ASSERT_EQ(socle::privsep::make_channel_pair(channels), 0);
    sx::privsep::files::Server server(channels[1], targets_);
    std::thread helper([&server] { EXPECT_EQ(server.run(), 0); });
    auto client = std::make_shared<sx::privsep::files::Client>(channels[0], std::chrono::seconds(1));
    ::close(channels[0]);
    ::close(channels[1]);

    std::string content;
    EXPECT_EQ(client->ping(), 0);
    EXPECT_EQ(client->config_read(content), 0);
    EXPECT_EQ(content, "initial");
    EXPECT_EQ(client->config_write("replacement"), 0);
    EXPECT_EQ(client->config_backup("2.0", "saved"), 0);
    client.reset();
    helper.join();

    EXPECT_EQ(sx::privsep::files::read_file(targets_.config, content), 0);
    EXPECT_EQ(content, "replacement");
    EXPECT_EQ(sx::privsep::files::read_file(targets_.config + ".2.0.bak.cfg", content), 0);
    EXPECT_EQ(content, "saved");
}

TEST_F(PrivilegedFileTest, RegisteredVirtualOperationExtendsProtocolWithoutDispatcherChanges) {
    int channels[2] = {-1, -1};
    ASSERT_EQ(socle::privsep::make_channel_pair(channels), 0);
    sx::privsep::files::Server server(channels[1], targets_);
    auto operation = std::make_shared<TestOperation>();
    ASSERT_EQ(server.register_operation(200, operation), 0);
    ASSERT_EQ(server.register_operation(201, operation), 0);
    std::thread helper([&server] { EXPECT_EQ(server.run(), 0); });
    auto client = std::make_unique<sx::privsep::files::Client>(channels[0], std::chrono::seconds(1));
    ::close(channels[0]);
    ::close(channels[1]);

    sx::privsep::files::Reply response;
    EXPECT_EQ(client->request(200, "alpha", -1, response), 0);
    EXPECT_EQ(response.payload, "handled:alpha");
    EXPECT_EQ(client->request(201, "beta", -1, response), 0);
    EXPECT_EQ(response.payload, "handled:beta");

    // Client destruction closes the channel; one shared capability receives
    // one shutdown callback even when it owns several opcodes.
    client.reset();
    helper.join();
    EXPECT_EQ(operation->calls, 2);
    EXPECT_EQ(operation->last_opcode, 201);
    EXPECT_EQ(operation->shutdowns, 1);
}

TEST_F(PrivilegedFileTest, RegistryRejectsInvalidAndDuplicateOpcodes) {
    int channels[2] = {-1, -1};
    ASSERT_EQ(socle::privsep::make_channel_pair(channels), 0);
    sx::privsep::files::Server server(channels[1], targets_);
    auto operation = std::make_shared<TestOperation>();
    EXPECT_EQ(server.register_operation(202, operation), 0);
    errno = 0;
    EXPECT_EQ(server.register_operation(202, operation), -1);
    EXPECT_EQ(errno, EEXIST);
    errno = 0;
    EXPECT_EQ(server.register_operation(0, operation), -1);
    EXPECT_EQ(errno, EINVAL);
    errno = 0;
    EXPECT_EQ(server.register_operation(203, nullptr), -1);
    EXPECT_EQ(errno, EINVAL);
    ::close(channels[0]);
    ::close(channels[1]);
}

TEST_F(PrivilegedFileTest, UnknownAndThrowingOperationsReturnStableErrors) {
    int channels[2] = {-1, -1};
    ASSERT_EQ(socle::privsep::make_channel_pair(channels), 0);
    sx::privsep::files::Server server(channels[1], targets_);
    ASSERT_EQ(server.register_operation(204, std::make_shared<ThrowingOperation>()), 0);
    std::thread helper([&server] { EXPECT_EQ(server.run(), 0); });
    auto client = std::make_unique<sx::privsep::files::Client>(channels[0], std::chrono::seconds(1));
    ::close(channels[0]);
    ::close(channels[1]);

    sx::privsep::files::Reply response;
    errno = 0;
    EXPECT_EQ(client->request(250, {}, -1, response), -1);
    EXPECT_EQ(errno, EOPNOTSUPP);
    errno = 0;
    EXPECT_EQ(client->request(204, {}, -1, response), -1);
    EXPECT_EQ(errno, EIO);
    client.reset();
    helper.join();
}

TEST_F(PrivilegedFileTest, PidLifecycleIsExclusiveAndOwned) {
    int channels[2] = {-1, -1};
    ASSERT_EQ(socle::privsep::make_channel_pair(channels), 0);
    sx::privsep::files::Server server(channels[1], targets_);
    std::thread helper([&server] { EXPECT_EQ(server.run(), 0); });
    auto client = std::make_shared<sx::privsep::files::Client>(channels[0], std::chrono::seconds(1));
    ::close(channels[0]);
    ::close(channels[1]);

    bool exists = true;
    EXPECT_EQ(client->pid_exists(exists), 0);
    EXPECT_FALSE(exists);
    EXPECT_EQ(client->pid_write(12345), 0);
    EXPECT_EQ(client->pid_exists(exists), 0);
    EXPECT_TRUE(exists);
    errno = 0;
    EXPECT_EQ(client->pid_write(12346), -1);
    EXPECT_EQ(errno, EALREADY);
    EXPECT_EQ(client->pid_remove(), 0);
    EXPECT_EQ(client->pid_exists(exists), 0);
    EXPECT_FALSE(exists);
    client.reset();
    helper.join();
}

TEST_F(PrivilegedFileTest, PidIsRemovedWhenOwnerChannelCloses) {
    int channels[2] = {-1, -1};
    ASSERT_EQ(socle::privsep::make_channel_pair(channels), 0);
    sx::privsep::files::Server server(channels[1], targets_);
    std::thread helper([&server] { EXPECT_EQ(server.run(), 0); });
    auto client = std::make_shared<sx::privsep::files::Client>(channels[0], std::chrono::seconds(1));
    ::close(channels[0]);
    ::close(channels[1]);
    ASSERT_EQ(client->pid_write(12345), 0);
    ASSERT_TRUE(std::filesystem::exists(targets_.pid));
    client.reset();
    helper.join();
    EXPECT_FALSE(std::filesystem::exists(targets_.pid));
}

TEST_F(PrivilegedFileTest, PreexistingPidIsNeverClaimedOrRemoved) {
    {
        std::ofstream pid(targets_.pid);
        ASSERT_TRUE(pid.good());
        pid << "777";
    }
    int channels[2] = {-1, -1};
    ASSERT_EQ(socle::privsep::make_channel_pair(channels), 0);
    sx::privsep::files::Server server(channels[1], targets_);
    std::thread helper([&server] { EXPECT_EQ(server.run(), 0); });
    auto client = std::make_shared<sx::privsep::files::Client>(channels[0], std::chrono::seconds(1));
    ::close(channels[0]);
    ::close(channels[1]);

    errno = 0;
    EXPECT_EQ(client->pid_write(12345), -1);
    EXPECT_EQ(errno, EEXIST);
    client.reset();
    helper.join();

    std::ifstream pid(targets_.pid);
    std::string content;
    pid >> content;
    EXPECT_EQ(content, "777");
}

TEST_F(PrivilegedFileTest, RemoveRequiresPidOwnership) {
    int channels[2] = {-1, -1};
    ASSERT_EQ(socle::privsep::make_channel_pair(channels), 0);
    sx::privsep::files::Server server(channels[1], targets_);
    std::thread helper([&server] { EXPECT_EQ(server.run(), 0); });
    auto client = std::make_shared<sx::privsep::files::Client>(channels[0], std::chrono::seconds(1));
    ::close(channels[0]);
    ::close(channels[1]);

    errno = 0;
    EXPECT_EQ(client->pid_remove(), -1);
    EXPECT_EQ(errno, EPERM);
    client.reset();
    helper.join();
}

TEST_F(PrivilegedFileTest, CleanupDoesNotRemoveReplacementAtPidPath) {
    int channels[2] = {-1, -1};
    ASSERT_EQ(socle::privsep::make_channel_pair(channels), 0);
    sx::privsep::files::Server server(channels[1], targets_);
    std::thread helper([&server] { EXPECT_EQ(server.run(), 0); });
    auto client = std::make_shared<sx::privsep::files::Client>(channels[0], std::chrono::seconds(1));
    ::close(channels[0]);
    ::close(channels[1]);

    ASSERT_EQ(client->pid_write(12345), 0);
    ASSERT_EQ(::unlink(targets_.pid.c_str()), 0);
    {
        std::ofstream replacement(targets_.pid);
        ASSERT_TRUE(replacement.good());
        replacement << "replacement";
        replacement.close();
        ASSERT_TRUE(replacement.good());
    }
    client.reset();
    helper.join();

    std::ifstream replacement(targets_.pid);
    std::string content;
    replacement >> content;
    EXPECT_EQ(content, "replacement");
}

TEST_F(PrivilegedFileTest, FacadeRejectsPathsOutsideInstalledAllowlist) {
    ASSERT_EQ(sx::privsep::files::write_file_atomic(targets_.config, "allowed"), 0);
    ASSERT_EQ(sx::privsep::files::start_local_helper(targets_), 0);
    std::string content;
    EXPECT_EQ(sx::privsep::files::config_read(targets_.config, content), 0);
    EXPECT_EQ(content, "allowed");
    errno = 0;
    EXPECT_EQ(sx::privsep::files::config_read((root_ / "other.cfg").string(), content), -1);
    EXPECT_EQ(errno, EACCES);
    EXPECT_EQ(sx::privsep::files::stop_local_helper(), 0);
}

TEST_F(PrivilegedFileTest, MalformedOperationsDoNotPoisonFollowingRequests) {
    ASSERT_EQ(sx::privsep::files::write_file_atomic(targets_.config, "original"), 0);
    int channels[2] = {-1, -1};
    ASSERT_EQ(socle::privsep::make_channel_pair(channels), 0);
    sx::privsep::files::Server server(channels[1], targets_);
    std::thread helper([&server] { EXPECT_EQ(server.run(), 0); });
    {
        sx::privsep::files::Client client(channels[0], std::chrono::seconds(1));
        ::close(channels[0]);
        ::close(channels[1]);
        sx::privsep::files::Reply response;
        errno = 0;
        EXPECT_EQ(client.request(static_cast<std::uint8_t>(sx::privsep::files::Opcode::ConfigWrite),
                                 "unexpected-payload", -1, response), -1);
        EXPECT_EQ(errno, EINVAL);
        errno = 0;
        EXPECT_EQ(client.request(static_cast<std::uint8_t>(sx::privsep::files::Opcode::PidWrite),
                                 std::string("12\0injected", 11), -1, response), -1);
        EXPECT_EQ(errno, EINVAL);
        EXPECT_EQ(client.ping(), 0);
        std::string content;
        EXPECT_EQ(client.config_read(content), 0);
        EXPECT_EQ(content, "original");
    }
    helper.join();
}

TEST_F(PrivilegedFileTest, OversizedDescriptorContentDoesNotReplaceConfig) {
    ASSERT_EQ(sx::privsep::files::write_file_atomic(targets_.config, "original"), 0);
    int channels[2] = {-1, -1};
    ASSERT_EQ(socle::privsep::make_channel_pair(channels), 0);
    sx::privsep::files::Server server(channels[1], targets_);
    std::thread helper([&server] { EXPECT_EQ(server.run(), 0); });
    {
        sx::privsep::files::Client client(channels[0], std::chrono::seconds(2));
        ::close(channels[0]);
        ::close(channels[1]);
        const int content = ::memfd_create("oversized-config", MFD_CLOEXEC);
        ASSERT_GE(content, 0);
        ASSERT_EQ(::ftruncate(content, 16U * 1024U * 1024U + 1U), 0);
        sx::privsep::files::Reply response;
        errno = 0;
        EXPECT_EQ(client.request(static_cast<std::uint8_t>(sx::privsep::files::Opcode::ConfigWrite),
                                 {}, content, response), -1);
        EXPECT_EQ(errno, EFBIG);
        ::close(content);
        EXPECT_EQ(client.ping(), 0);
        std::string current;
        EXPECT_EQ(client.config_read(current), 0);
        EXPECT_EQ(current, "original");
    }
    helper.join();
}

TEST_F(PrivilegedFileTest, NonSeekableDescriptorCannotReplaceConfig) {
    ASSERT_EQ(sx::privsep::files::write_file_atomic(targets_.config, "original"), 0);
    int channels[2] = {-1, -1};
    ASSERT_EQ(socle::privsep::make_channel_pair(channels), 0);
    sx::privsep::files::Server server(channels[1], targets_);
    std::thread helper([&server] { EXPECT_EQ(server.run(), 0); });
    {
        sx::privsep::files::Client client(channels[0], std::chrono::seconds(1));
        ::close(channels[0]);
        ::close(channels[1]);
        int pipefd[2] = {-1, -1};
        ASSERT_EQ(::pipe2(pipefd, O_CLOEXEC), 0);
        sx::privsep::files::Reply response;
        errno = 0;
        EXPECT_EQ(client.request(static_cast<std::uint8_t>(sx::privsep::files::Opcode::ConfigWrite),
                                 {}, pipefd[0], response), -1);
        EXPECT_EQ(errno, ESPIPE);
        ::close(pipefd[0]);
        ::close(pipefd[1]);
        std::string current;
        EXPECT_EQ(client.config_read(current), 0);
        EXPECT_EQ(current, "original");
    }
    helper.join();
}

} // namespace
