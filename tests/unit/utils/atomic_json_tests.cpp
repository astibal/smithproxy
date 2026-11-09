#include <gtest/gtest.h>
#include <utils/atomic_json.hpp>

namespace {
class AtomicJson : public testing::Test {
protected:
    std::filesystem::path directory;
    std::string target;

    void SetUp() override {
        char pattern[] = "/tmp/smithproxy-atomic-json-XXXXXX";
        auto* name = ::mkdtemp(pattern);
        ASSERT_NE(name, nullptr);
        directory = name;
        target = (directory / "neighbors.json").string();
        std::ofstream(target) << "[{\"old\":true}]";
    }
    void TearDown() override {
        if (!directory.empty()) std::filesystem::remove_all(directory);
    }
    std::string contents() const {
        std::ifstream input(target);
        return {std::istreambuf_iterator<char>(input), std::istreambuf_iterator<char>()};
    }
    void expect_original() const {
        EXPECT_EQ(contents(), "[{\"old\":true}]");
        EXPECT_EQ(std::distance(std::filesystem::directory_iterator(directory),
                                std::filesystem::directory_iterator()), 1);
    }
};

TEST_F(AtomicJson, ReplacesCompleteJsonAndPreservesPermissions) {
    ASSERT_EQ(::chmod(target.c_str(), 0640), 0);
    sx::atomic_json::replace(target, [](FILE* file) {
        sx::atomic_json::write(file, "[{\"new\":18446744073709551615}]");
    });
    EXPECT_EQ(nlohmann::json::parse(contents())[0]["new"].get<uint64_t>(), UINT64_MAX);
    struct stat st{};
    ASSERT_EQ(::stat(target.c_str(), &st), 0);
    EXPECT_EQ(st.st_mode & 0777, 0640);
    EXPECT_EQ(std::distance(std::filesystem::directory_iterator(directory),
                            std::filesystem::directory_iterator()), 1);
}

TEST_F(AtomicJson, CreatesFirstSnapshotWithPrivatePermissions) {
    ASSERT_TRUE(std::filesystem::remove(target));
    sx::atomic_json::replace(target, [](FILE* file) { sx::atomic_json::write(file, "[]"); });
    EXPECT_EQ(contents(), "[]");
    struct stat st{};
    ASSERT_EQ(::stat(target.c_str(), &st), 0);
    EXPECT_EQ(st.st_mode & 0777, 0600);
}

TEST_F(AtomicJson, InvalidJsonAndTrailingDataNeverReplaceOriginal) {
    for (std::string const text: {"", "[", "[{\"x\":1}", "[] garbage", "[] []"}) {
        EXPECT_THROW(sx::atomic_json::replace(target, [&](FILE* file) {
            sx::atomic_json::write(file, text);
        }), std::runtime_error);
        expect_original();
    }
}

TEST_F(AtomicJson, WriterExceptionNeverReplacesOriginal) {
    EXPECT_THROW(sx::atomic_json::replace(target, [](FILE* file) {
        sx::atomic_json::write(file, "[");
        throw std::runtime_error("serialization failed");
    }), std::runtime_error);
    expect_original();
}

// /dev/full produces real ENOSPC without filling the machine's filesystem.
// Replacing the temporary stream descriptor exercises both buffered flush
// failure and immediate fwrite failure with the exact production error paths.
TEST_F(AtomicJson, NoSpaceOnWriteOrFlushPreservesOriginalAndRemovesTemporaryFile) {
    for (size_t size: {size_t{2}, size_t{1024 * 1024}}) {
        bool failed = false;
        try {
            sx::atomic_json::replace(target, [size](FILE* file) {
                int full = ::open("/dev/full", O_WRONLY | O_CLOEXEC);
                if (full < 0) throw std::runtime_error("open /dev/full failed");
                int result = ::dup2(full, ::fileno(file));
                ::close(full);
                if (result < 0) throw std::runtime_error("dup2 /dev/full failed");
                sx::atomic_json::write(file, std::string(size, ' '));
            });
        }
        catch (std::system_error const& e) {
            failed = true;
            EXPECT_EQ(e.code().value(), ENOSPC);
        }
        EXPECT_TRUE(failed);
        expect_original();
    }
}

TEST_F(AtomicJson, RejectsSymlinkWithoutTouchingItsTarget) {
    auto link = (directory / "link.json").string();
    ASSERT_EQ(::symlink(target.c_str(), link.c_str()), 0);
    EXPECT_THROW(sx::atomic_json::replace(link, [](FILE* file) {
        sx::atomic_json::write(file, "[]");
    }), std::runtime_error);
    EXPECT_EQ(contents(), "[{\"old\":true}]");
    EXPECT_TRUE(std::filesystem::is_symlink(link));
}

TEST_F(AtomicJson, RenameFailureCleansTemporaryFile) {
    auto blocked = (directory / "blocked.json").string();
    EXPECT_THROW(sx::atomic_json::replace(blocked, [&](FILE* file) {
        sx::atomic_json::write(file, "[]");
        std::filesystem::create_directory(blocked);
    }), std::system_error);
    EXPECT_TRUE(std::filesystem::is_directory(blocked));
    std::filesystem::remove(blocked);
    expect_original();
}
} // namespace
