#include <gtest/gtest.h>
#include <utils/atomic_json.hpp>

namespace {
// Used only by the dedicated linker-wrapped test executable.
int fail_stage = 0;
int sync_calls = 0;
}

extern "C" int __real_fsync(int);
extern "C" int __real_fclose(FILE*);
extern "C" int __real_rename(char const*, char const*);

extern "C" int __wrap_fsync(int fd) {
    ++sync_calls;
    if ((fail_stage == 1 && sync_calls == 1) || (fail_stage == 2 && sync_calls == 2)) {
        errno = ENOSPC;
        return -1;
    }
    return __real_fsync(fd);
}

extern "C" int __wrap_fclose(FILE* file) {
    int result = __real_fclose(file);
    if (fail_stage == 3) {
        fail_stage = 0;
        errno = ENOSPC;
        return EOF;
    }
    return result;
}

extern "C" int __wrap_rename(char const* source, char const* target) {
    if (fail_stage == 4) {
        errno = ENOSPC;
        return -1;
    }
    return __real_rename(source, target);
}

TEST(AtomicJsonFaults, SyncCloseAndRenameFailuresHaveExplicitPublicationBoundary) {
    char pattern[] = "/tmp/smithproxy-atomic-json-faults-XXXXXX";
    auto* directory = ::mkdtemp(pattern);
    ASSERT_NE(directory, nullptr);
    auto target = (std::filesystem::path(directory) / "neighbors.json").string();
    for (int stage: {1, 2, 3, 4}) {
        SCOPED_TRACE(stage); // file fsync, directory fsync, fclose, rename
        std::ofstream(target) << "[\"old\"]";
        sync_calls = 0;
        fail_stage = stage;
        std::string error;
        int code = 0;
        try {
            sx::atomic_json::replace(target, [](FILE* file) {
                sx::atomic_json::write(file, "[\"new\"]");
            });
        }
        catch (std::system_error const& e) {
            error = e.what();
            code = e.code().value();
        }
        fail_stage = 0;
        EXPECT_EQ(code, ENOSPC);
        if (stage == 2) {
            EXPECT_NE(error.find("replaced"), std::string::npos);
        }
        std::ifstream input(target);
        auto saved = nlohmann::json::parse(input);
        // Directory sync is necessarily after rename: publication has already
        // succeeded, so report uncertain durability, not a retained old file.
        EXPECT_EQ(saved[0], stage == 2 ? "new" : "old");
        EXPECT_EQ(std::distance(std::filesystem::directory_iterator(directory),
                                std::filesystem::directory_iterator()), 1);
    }
    std::filesystem::remove_all(directory);
}
