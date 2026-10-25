#include <service/reload/file_reload_service.hpp>

#include <gtest/gtest.h>

#include <atomic>
#include <chrono>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <string>
#include <stdexcept>
#include <thread>
#include <vector>
#include <unistd.h>

namespace {

using namespace std::chrono_literals;
using sx::reload::FileReloadService;
using sx::reload::ParseResult;
using sx::reload::ReloadStatus;
using sx::reload::ReloadableResource;
using sx::reload::WatchedFileOptions;

struct TestSnapshot {
    std::string text;
};

class TemporaryFile {
public:
    TemporaryFile() {
        auto pattern = (std::filesystem::temp_directory_path() / "smithproxy-reload-XXXXXX").string();
        std::vector<char> writable(pattern.begin(), pattern.end());
        writable.push_back('\0');
        auto descriptor = mkstemp(writable.data());
        if(descriptor >= 0) close(descriptor);
        path_ = writable.data();
    }

    ~TemporaryFile() {
        std::error_code ignored;
        std::filesystem::remove(path_, ignored);
    }

    void write(std::string const& text) const {
        std::ofstream output(path_, std::ios::binary | std::ios::trunc);
        output << text;
        output.close();
        ASSERT_TRUE(output);
    }

    void remove() const {
        std::error_code error;
        ASSERT_TRUE(std::filesystem::remove(path_, error));
        ASSERT_FALSE(error);
    }

    std::filesystem::path const& path() const { return path_; }

private:
    std::filesystem::path path_;
};

ParseResult<TestSnapshot> parse_test_snapshot(std::string_view text) {
    if(text.empty()) return ParseResult<TestSnapshot>::failure("empty input");
    if(text == "invalid") return ParseResult<TestSnapshot>::failure("invalid test data");
    return ParseResult<TestSnapshot>::success(TestSnapshot{std::string(text)});
}

std::shared_ptr<ReloadableResource<TestSnapshot>> resource_for(
        TemporaryFile const& file, bool keep_last = true, std::size_t max_size = 1024) {
    return std::make_shared<ReloadableResource<TestSnapshot>>(
        WatchedFileOptions{file.path(), max_size, keep_last}, parse_test_snapshot);
}

template<class Predicate>
bool wait_until(Predicate predicate, std::chrono::milliseconds timeout = 2s) {
    auto const deadline = std::chrono::steady_clock::now() + timeout;
    while(std::chrono::steady_clock::now() < deadline) {
        if(predicate()) return true;
        std::this_thread::sleep_for(2ms);
    }
    return predicate();
}

TEST(ReloadableResource, PublishesImmutableSnapshotAndVersion) {
    TemporaryFile file;
    file.write("first");
    auto resource = resource_for(file);

    auto result = resource->poll();
    ASSERT_EQ(result.status, ReloadStatus::published);
    ASSERT_EQ(result.version, 1U);
    auto snapshot = resource->snapshot();
    ASSERT_NE(snapshot, nullptr);
    EXPECT_EQ(snapshot->metadata.version, 1U);
    EXPECT_EQ(snapshot->metadata.source, file.path());
    EXPECT_EQ(snapshot->metadata.source_size, 5U);
    EXPECT_EQ(snapshot->value->text, "first");
    EXPECT_EQ(resource->successful_reloads(), 1U);
    EXPECT_EQ(resource->failed_reloads(), 0U);
}

TEST(ReloadableResource, UnchangedFileDoesNotPublishAgain) {
    TemporaryFile file;
    file.write("same");
    auto resource = resource_for(file);

    ASSERT_EQ(resource->poll().status, ReloadStatus::published);
    EXPECT_EQ(resource->poll().status, ReloadStatus::unchanged);
    EXPECT_EQ(resource->version(), 1U);
    EXPECT_EQ(resource->successful_reloads(), 1U);
}

TEST(ReloadableResource, ManualReloadPublishesEvenWithSameSignature) {
    TemporaryFile file;
    file.write("same");
    auto resource = resource_for(file);

    ASSERT_EQ(resource->poll().status, ReloadStatus::published);
    EXPECT_EQ(resource->reload_now().status, ReloadStatus::published);
    EXPECT_EQ(resource->version(), 2U);
}

TEST(ReloadableResource, InvalidReplacementKeepsLastValidSnapshot) {
    TemporaryFile file;
    file.write("valid");
    auto resource = resource_for(file);
    ASSERT_EQ(resource->poll().status, ReloadStatus::published);
    auto old_snapshot = resource->snapshot();

    file.write("invalid");
    auto result = resource->poll();
    EXPECT_EQ(result.status, ReloadStatus::failed);
    EXPECT_EQ(resource->version(), 1U);
    EXPECT_EQ(resource->snapshot(), old_snapshot);
    EXPECT_EQ(resource->snapshot()->value->text, "valid");
    EXPECT_EQ(resource->last_error(), "invalid test data");
    EXPECT_EQ(resource->failed_reloads(), 1U);
}

TEST(ReloadableResource, RecoversAfterInvalidReplacementChangesAgain) {
    TemporaryFile file;
    file.write("version-1");
    auto resource = resource_for(file);
    ASSERT_EQ(resource->poll().status, ReloadStatus::published);

    file.write("invalid");
    ASSERT_EQ(resource->poll().status, ReloadStatus::failed);
    EXPECT_EQ(resource->poll().status, ReloadStatus::unchanged);

    file.write("version-number-two");
    ASSERT_EQ(resource->poll().status, ReloadStatus::published);
    EXPECT_EQ(resource->version(), 2U);
    EXPECT_EQ(resource->snapshot()->value->text, "version-number-two");
    EXPECT_TRUE(resource->last_error().empty());
}

TEST(ReloadableResource, ParserExceptionIsReportedAsReloadFailure) {
    TemporaryFile file;
    file.write("throw");
    auto resource = std::make_shared<ReloadableResource<TestSnapshot>>(
        WatchedFileOptions{file.path(), 1024, true},
        [](std::string_view) -> ParseResult<TestSnapshot> {
            throw std::runtime_error("test exception");
        });

    auto result = resource->poll();
    EXPECT_EQ(result.status, ReloadStatus::failed);
    EXPECT_NE(result.error.find("test exception"), std::string::npos);
    EXPECT_EQ(resource->version(), 0U);
}

TEST(ReloadableResource, MissingFileKeepsSnapshotAndRecreationPublishes) {
    TemporaryFile file;
    file.write("before-remove");
    auto resource = resource_for(file);
    ASSERT_EQ(resource->poll().status, ReloadStatus::published);
    auto held = resource->snapshot();

    file.remove();
    EXPECT_EQ(resource->poll().status, ReloadStatus::failed);
    EXPECT_EQ(resource->version(), 1U);
    EXPECT_EQ(resource->snapshot(), held);

    file.write("after-recreation");
    ASSERT_EQ(resource->poll().status, ReloadStatus::published);
    EXPECT_EQ(resource->version(), 2U);
    EXPECT_EQ(resource->snapshot()->value->text, "after-recreation");
}

TEST(ReloadableResource, CanClearSnapshotOnReloadFailure) {
    TemporaryFile file;
    file.write("valid");
    auto resource = resource_for(file, false);
    ASSERT_EQ(resource->poll().status, ReloadStatus::published);

    file.write("invalid");
    auto result = resource->poll();
    EXPECT_EQ(result.status, ReloadStatus::failed);
    EXPECT_EQ(resource->snapshot(), nullptr);
    EXPECT_EQ(result.version, 2U);
    EXPECT_EQ(resource->version(), 2U);

    // The same failed state does not continuously advance the observable version.
    EXPECT_EQ(resource->reload_now().status, ReloadStatus::failed);
    EXPECT_EQ(resource->version(), 2U);
}

TEST(ReloadableResource, RejectsOversizedFileWithoutCallingParser) {
    TemporaryFile file;
    file.write("too large");
    std::atomic_int calls{0};
    auto resource = std::make_shared<ReloadableResource<TestSnapshot>>(
        WatchedFileOptions{file.path(), 3, true},
        [&calls](std::string_view text) {
            ++calls;
            return parse_test_snapshot(text);
        });

    EXPECT_EQ(resource->poll().status, ReloadStatus::failed);
    EXPECT_EQ(calls.load(), 0);
    EXPECT_EQ(resource->snapshot(), nullptr);
}

TEST(ReloadableResource, ConcurrentReadersOnlyObserveCompleteSnapshots) {
    TemporaryFile file;
    file.write("value-0");
    auto resource = resource_for(file);
    ASSERT_EQ(resource->reload_now().status, ReloadStatus::published);

    std::atomic_bool stop{false};
    std::atomic_bool invalid_observation{false};
    std::vector<std::thread> readers;
    for(int index = 0; index < 8; ++index) {
        readers.emplace_back([&] {
            while(not stop.load(std::memory_order_relaxed)) {
                auto snapshot = resource->snapshot();
                if(not snapshot or not snapshot->value or
                   snapshot->metadata.version == 0 or
                   snapshot->value->text.rfind("value-", 0) != 0) {
                    invalid_observation.store(true, std::memory_order_relaxed);
                }
            }
        });
    }

    for(int index = 1; index <= 100; ++index) {
        file.write("value-" + std::to_string(index));
        ASSERT_EQ(resource->reload_now().status, ReloadStatus::published);
    }
    stop.store(true, std::memory_order_relaxed);
    for(auto& reader : readers) reader.join();

    EXPECT_FALSE(invalid_observation.load());
    EXPECT_EQ(resource->version(), 101U);
    EXPECT_EQ(resource->snapshot()->value->text, "value-100");
}

TEST(ReloadableResource, HeldSnapshotSurvivesLaterPublication) {
    TemporaryFile file;
    file.write("old");
    auto resource = resource_for(file);
    ASSERT_EQ(resource->reload_now().status, ReloadStatus::published);
    auto old_snapshot = resource->snapshot();

    file.write("new-version");
    ASSERT_EQ(resource->reload_now().status, ReloadStatus::published);
    ASSERT_EQ(resource->snapshot()->value->text, "new-version");
    EXPECT_EQ(old_snapshot->metadata.version, 1U);
    EXPECT_EQ(old_snapshot->value->text, "old");
}

TEST(FileReloadService, LoadsAndReloadsMultipleResources) {
    TemporaryFile first_file;
    TemporaryFile second_file;
    first_file.write("first-1");
    second_file.write("second-1");
    auto first = resource_for(first_file);
    auto second = resource_for(second_file);

    FileReloadService service;
    auto first_id = service.add(first, 10ms);
    auto second_id = service.add(second, 10ms);
    ASSERT_NE(first_id, 0U);
    ASSERT_NE(second_id, 0U);
    service.start();

    ASSERT_TRUE(wait_until([&] { return first->version() == 1 and second->version() == 1; }));
    first_file.write("first-version-2");
    ASSERT_TRUE(wait_until([&] { return first->version() == 2; }));
    EXPECT_EQ(first->snapshot()->value->text, "first-version-2");
    EXPECT_EQ(second->version(), 1U);

    EXPECT_TRUE(service.request_reload(second_id));
    ASSERT_TRUE(wait_until([&] { return second->version() == 2; }));
    EXPECT_TRUE(service.remove(first_id));
    EXPECT_FALSE(service.request_reload(first_id));
    service.stop();
    EXPECT_FALSE(service.running());
}

TEST(FileReloadService, StopAndDestructorAreIdempotent) {
    FileReloadService service;
    service.start();
    service.start();
    EXPECT_TRUE(service.running());
    service.stop();
    service.stop();
    EXPECT_FALSE(service.running());
}

} // namespace
