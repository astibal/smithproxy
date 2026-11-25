#include <service/auth/runtime_credentials.hpp>

#include <gtest/gtest.h>

#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

#include <chrono>
#include <filesystem>
#include <fstream>
#include <string>
#include <vector>

namespace {

class RuntimeCredentialsTest : public ::testing::Test {
protected:
    void SetUp() override {
        auto pattern = (std::filesystem::temp_directory_path() /
                        "smithproxy-runtime-credentials-XXXXXX").string();
        auto buffer = std::vector<char>(pattern.begin(), pattern.end());
        buffer.push_back('\0');
        const auto* created = ::mkdtemp(buffer.data());
        ASSERT_NE(created, nullptr);
        directory_ = created;
    }

    void TearDown() override {
        std::error_code error;
        std::filesystem::remove_all(directory_, error);
    }

    sx::auth::RuntimeCredentialSpec spec() const {
        return {
            true,
            directory_ / "current.key",
            directory_ / "previous.key",
            std::chrono::minutes(5),
            std::chrono::hours(24),
            std::chrono::hours(1),
        };
    }

    void write(const std::filesystem::path& path, const std::string& value) {
        std::ofstream output(path);
        ASSERT_TRUE(output.good());
        output << value;
        output.close();
        ASSERT_EQ(::chmod(path.c_str(), 0640), 0);
    }

    void set_modified_time(
        const std::filesystem::path& path,
        const std::chrono::system_clock::time_point value) {
        const auto seconds = std::chrono::time_point_cast<std::chrono::seconds>(value);
        const auto nanoseconds = std::chrono::duration_cast<std::chrono::nanoseconds>(
            value - seconds);
        const struct timespec timestamps[2] = {
            {seconds.time_since_epoch().count(), nanoseconds.count()},
            {seconds.time_since_epoch().count(), nanoseconds.count()},
        };
        ASSERT_EQ(::utimensat(AT_FDCWD, path.c_str(), timestamps, 0), 0);
    }

    std::filesystem::path directory_;
};

TEST_F(RuntimeCredentialsTest, AdoptsFreshLauncherSeed) {
    const std::string seed(64U, 'a');
    write(spec().current_path, seed);
    sx::auth::RuntimeCredentialSnapshot published;
    sx::auth::RuntimeCredentialPair pair(
        spec(), [&published](const auto& snapshot) { published = snapshot; });

    ASSERT_TRUE(pair.reconcile());
    ASSERT_TRUE(published.current);
    EXPECT_EQ(*published.current, seed);
    EXPECT_FALSE(published.previous);
}

TEST_F(RuntimeCredentialsTest, RotatesStaleBootSeedIntoBoundedOverlap) {
    const std::string seed(64U, 'b');
    const auto policy = spec();
    write(policy.current_path, seed);
    sx::auth::RuntimeCredentialSnapshot published;
    sx::auth::RuntimeCredentialPair pair(
        policy, [&published](const auto& snapshot) { published = snapshot; });

    const auto now = std::chrono::system_clock::now();
    ASSERT_TRUE(pair.reconcile(now + std::chrono::minutes(10)));
    ASSERT_TRUE(published.current);
    ASSERT_TRUE(published.previous);
    EXPECT_NE(*published.current, seed);
    EXPECT_EQ(*published.previous, seed);
}

TEST_F(RuntimeCredentialsTest, RejectsAncientBootSeedFromOverlap) {
    const std::string seed(64U, 'c');
    const auto policy = spec();
    write(policy.current_path, seed);
    sx::auth::RuntimeCredentialSnapshot published;
    sx::auth::RuntimeCredentialPair pair(
        policy, [&published](const auto& snapshot) { published = snapshot; });

    const auto now = std::chrono::system_clock::now();
    ASSERT_TRUE(pair.reconcile(now + std::chrono::hours(30)));
    ASSERT_TRUE(published.current);
    EXPECT_NE(*published.current, seed);
    EXPECT_FALSE(published.previous);
    EXPECT_FALSE(std::filesystem::exists(policy.previous_path));
}

TEST_F(RuntimeCredentialsTest, RemovesPreviousAfterOverlap) {
    const auto policy = spec();
    write(policy.current_path, std::string(64U, 'd'));
    write(policy.previous_path, std::string(64U, 'e'));
    sx::auth::RuntimeCredentialSnapshot published;
    sx::auth::RuntimeCredentialPair pair(
        policy, [&published](const auto& snapshot) { published = snapshot; });

    ASSERT_TRUE(pair.reconcile(std::chrono::system_clock::now() + std::chrono::hours(2)));
    EXPECT_FALSE(published.previous);
    EXPECT_FALSE(std::filesystem::exists(policy.previous_path));
}

TEST_F(RuntimeCredentialsTest, ChangesCurrentCredentialOnSchedule) {
    const auto policy = spec();
    const std::string seed(64U, 'j');
    write(policy.current_path, seed);
    sx::auth::RuntimeCredentialSnapshot published;
    sx::auth::RuntimeCredentialPair pair(
        policy, [&published](const auto& snapshot) { published = snapshot; });

    const auto initial = std::chrono::system_clock::now();
    ASSERT_TRUE(pair.reconcile(initial));
    ASSERT_TRUE(pair.reconcile(initial + policy.rotation_interval));
    ASSERT_TRUE(published.current);
    EXPECT_NE(*published.current, seed);
}

TEST_F(RuntimeCredentialsTest, RejectsFutureDatedLauncherSeed) {
    const auto policy = spec();
    const std::string seed(64U, 'k');
    const auto now = std::chrono::system_clock::now();
    write(policy.current_path, seed);
    set_modified_time(policy.current_path, now + std::chrono::minutes(2));
    sx::auth::RuntimeCredentialSnapshot published;
    sx::auth::RuntimeCredentialPair pair(
        policy, [&published](const auto& snapshot) { published = snapshot; });

    ASSERT_TRUE(pair.reconcile(now));
    ASSERT_TRUE(published.current);
    EXPECT_NE(*published.current, seed);
}

TEST_F(RuntimeCredentialsTest, ReplacesCredentialWithUnsafePermissions) {
    const auto policy = spec();
    const std::string unsafe(64U, 'l');
    write(policy.current_path, unsafe);
    ASSERT_EQ(::chmod(policy.current_path.c_str(), 0660), 0);
    sx::auth::RuntimeCredentialSnapshot published;
    sx::auth::RuntimeCredentialPair pair(
        policy, [&published](const auto& snapshot) { published = snapshot; });

    ASSERT_TRUE(pair.reconcile());
    ASSERT_TRUE(published.current);
    EXPECT_NE(*published.current, unsafe);

    struct stat metadata {};
    ASSERT_EQ(::stat(policy.current_path.c_str(), &metadata), 0);
    EXPECT_EQ(metadata.st_mode & 0777, 0640);
}

TEST_F(RuntimeCredentialsTest, ReplacesSymlinkWithoutFollowingIt) {
    const auto policy = spec();
    const auto target = directory_ / "outside.key";
    const std::string outside(64U, 'm');
    write(target, outside);
    ASSERT_EQ(::symlink(target.c_str(), policy.current_path.c_str()), 0);
    sx::auth::RuntimeCredentialSnapshot published;
    sx::auth::RuntimeCredentialPair pair(
        policy, [&published](const auto& snapshot) { published = snapshot; });

    ASSERT_TRUE(pair.reconcile());
    ASSERT_TRUE(published.current);
    EXPECT_NE(*published.current, outside);
    EXPECT_FALSE(std::filesystem::is_symlink(policy.current_path));

    std::ifstream preserved(target);
    std::string preserved_value;
    preserved >> preserved_value;
    EXPECT_EQ(preserved_value, outside);
}

TEST_F(RuntimeCredentialsTest, RemovesDuplicatePreviousGeneration) {
    const auto policy = spec();
    const std::string seed(64U, 'n');
    write(policy.current_path, seed);
    write(policy.previous_path, seed);
    sx::auth::RuntimeCredentialSnapshot published;
    sx::auth::RuntimeCredentialPair pair(
        policy, [&published](const auto& snapshot) { published = snapshot; });

    ASSERT_TRUE(pair.reconcile());
    ASSERT_TRUE(published.current);
    EXPECT_FALSE(published.previous);
    EXPECT_FALSE(std::filesystem::exists(policy.previous_path));
}

TEST_F(RuntimeCredentialsTest, IgnoresReplacementAfterCoreAssumesOwnership) {
    const auto policy = spec();
    const std::string seed(64U, 'f');
    const std::string replacement(64U, 'g');
    write(policy.current_path, seed);
    sx::auth::RuntimeCredentialSnapshot published;
    sx::auth::RuntimeCredentialPair pair(
        policy, [&published](const auto& snapshot) { published = snapshot; });

    ASSERT_TRUE(pair.reconcile());
    write(policy.current_path, replacement);
    ASSERT_TRUE(pair.reconcile());
    ASSERT_TRUE(published.current);
    EXPECT_EQ(*published.current, seed);

    std::ifstream current(policy.current_path);
    std::string restored;
    current >> restored;
    EXPECT_EQ(restored, seed);
}

TEST_F(RuntimeCredentialsTest, DisabledCredentialRemovesPublishedGenerations) {
    auto policy = spec();
    write(policy.current_path, std::string(64U, 'h'));
    write(policy.previous_path, std::string(64U, 'i'));
    policy.enabled = false;
    sx::auth::RuntimeCredentialSnapshot published{
        std::string(64U, 'h'), std::string(64U, 'i')};
    sx::auth::RuntimeCredentialPair pair(
        policy, [&published](const auto& snapshot) { published = snapshot; });

    ASSERT_TRUE(pair.reconcile());
    EXPECT_FALSE(published.current);
    EXPECT_FALSE(published.previous);
    EXPECT_FALSE(std::filesystem::exists(policy.current_path));
    EXPECT_FALSE(std::filesystem::exists(policy.previous_path));
}

TEST(RuntimeCredentialConfigTest, ParsesIndependentCredentialPolicies) {
    const auto policy = sx::auth::parse_gui_runtime_credentials(R"(
        gui = {
          smithproxy = {
            credential_enabled = false;
            api_token_file = "/run/custom/api";
            previous_api_token_file = "/run/custom/api.previous";
            credential_rotation_seconds = 7200L;
            administrator_auth_socket_enabled = false;
            administrator_auth_socket = "/run/custom/admin-auth.sock";
          };
          gateway = {
            credential_enabled = true;
            secret_file = "/run/custom/gateway";
            previous_secret_file = "/run/custom/gateway.previous";
            credential_overlap_seconds = 120L;
          };
        };
    )");

    EXPECT_FALSE(policy.management_api.enabled);
    EXPECT_EQ(policy.management_api.current_path, "/run/custom/api");
    EXPECT_EQ(policy.management_api.rotation_interval, std::chrono::hours(2));
    EXPECT_TRUE(policy.gateway.enabled);
    EXPECT_EQ(policy.gateway.previous_path, "/run/custom/gateway.previous");
    EXPECT_EQ(policy.gateway.overlap, std::chrono::minutes(2));
    EXPECT_FALSE(policy.administrator_auth_socket_enabled);
    EXPECT_EQ(policy.administrator_auth_socket, "/run/custom/admin-auth.sock");
}

} // namespace
