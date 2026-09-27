#pragma once

#include <atomic>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <exception>
#include <filesystem>
#include <fstream>
#include <functional>
#include <limits>
#include <memory>
#include <mutex>
#include <optional>
#include <string>
#include <string_view>
#include <system_error>

namespace sx::reload {

using version_type = std::uint64_t;

enum class ReloadStatus {
    unchanged,
    published,
    failed,
};

struct ReloadResult {
    ReloadStatus status = ReloadStatus::unchanged;
    version_type version = 0;
    std::string error;

    explicit operator bool() const noexcept { return status != ReloadStatus::failed; }
};

struct WatchedFileOptions {
    std::filesystem::path path;
    std::size_t max_size = 4U * 1024U * 1024U;
    bool keep_last_on_error = true;
};

struct SnapshotMetadata {
    version_type version = 0;
    std::filesystem::path source;
    std::filesystem::file_time_type modified{};
    std::uintmax_t source_size = 0;
    std::chrono::system_clock::time_point loaded_at{};
};

template<class T>
struct PublishedSnapshot {
    SnapshotMetadata metadata;
    std::shared_ptr<const T> value;
};

template<class T>
struct ParseResult {
    std::shared_ptr<const T> value;
    std::string error;

    static ParseResult success(T parsed) {
        return {std::make_shared<const T>(std::move(parsed)), {}};
    }

    static ParseResult success(std::shared_ptr<const T> parsed) {
        return {std::move(parsed), {}};
    }

    static ParseResult failure(std::string message) {
        return {nullptr, std::move(message)};
    }

    explicit operator bool() const noexcept { return value != nullptr; }
};

class ReloadableResourceBase {
public:
    virtual ~ReloadableResourceBase() = default;
    virtual ReloadResult poll() = 0;
    virtual ReloadResult reload_now() = 0;
};

template<class T>
class ReloadableResource final : public ReloadableResourceBase {
public:
    using snapshot_type = PublishedSnapshot<T>;
    using parser_type = std::function<ParseResult<T>(std::string_view)>;

    ReloadableResource(WatchedFileOptions options, parser_type parser)
        : options_(std::move(options)), parser_(std::move(parser)) {}

    version_type version() const noexcept {
        return version_.load(std::memory_order_acquire);
    }

    std::shared_ptr<const snapshot_type> snapshot() const noexcept {
        return std::atomic_load_explicit(&snapshot_, std::memory_order_acquire);
    }

    std::string last_error() const {
        std::lock_guard lock(state_lock_);
        return last_error_;
    }

    std::uint64_t successful_reloads() const noexcept {
        return successful_reloads_.load(std::memory_order_relaxed);
    }

    std::uint64_t failed_reloads() const noexcept {
        return failed_reloads_.load(std::memory_order_relaxed);
    }

    ReloadResult poll() override { return reload(false); }
    ReloadResult reload_now() override { return reload(true); }

private:
    struct FileSignature {
        std::filesystem::file_time_type modified{};
        std::uintmax_t size = 0;

        bool operator==(FileSignature const& other) const noexcept {
            return modified == other.modified && size == other.size;
        }
    };

    ReloadResult fail(std::string message) {
        failed_reloads_.fetch_add(1, std::memory_order_relaxed);
        {
            std::lock_guard lock(state_lock_);
            last_error_ = std::move(message);
        }
        auto result_version = version();
        if(not options_.keep_last_on_error and snapshot()) {
            std::atomic_store_explicit(
                &snapshot_, std::shared_ptr<const snapshot_type>{}, std::memory_order_release);
            result_version++;
            version_.store(result_version, std::memory_order_release);
        }
        return {ReloadStatus::failed, result_version, last_error()};
    }

    ReloadResult reload(bool force) {
        std::lock_guard reload_guard(reload_lock_);

        std::error_code error;
        auto const size = std::filesystem::file_size(options_.path, error);
        if(error) {
            attempted_signature_.reset();
            return fail("cannot stat '" + options_.path.string() + "': " + error.message());
        }
        auto const modified = std::filesystem::last_write_time(options_.path, error);
        if(error) {
            attempted_signature_.reset();
            return fail("cannot read timestamp for '" + options_.path.string() + "': " + error.message());
        }

        FileSignature const signature{modified, size};
        if(not force and attempted_signature_ and *attempted_signature_ == signature) {
            return {ReloadStatus::unchanged, version(), {}};
        }
        attempted_signature_ = signature;

        if(size > options_.max_size or
           size > static_cast<std::uintmax_t>(std::numeric_limits<std::streamsize>::max())) {
            return fail("file '" + options_.path.string() + "' exceeds configured size limit");
        }

        std::ifstream input(options_.path, std::ios::binary);
        if(not input) {
            return fail("cannot open '" + options_.path.string() + "'");
        }
        std::string text(static_cast<std::size_t>(size), '\0');
        if(not text.empty()) {
            input.read(text.data(), static_cast<std::streamsize>(text.size()));
            if(input.gcount() != static_cast<std::streamsize>(text.size()) or input.bad()) {
                attempted_signature_.reset();
                return fail("file '" + options_.path.string() + "' changed while it was being read");
            }
        }

        auto const size_after_read = std::filesystem::file_size(options_.path, error);
        if(error) {
            return fail("cannot restat '" + options_.path.string() + "': " + error.message());
        }
        auto const modified_after_read = std::filesystem::last_write_time(options_.path, error);
        if(error) {
            return fail("cannot reread timestamp for '" + options_.path.string() + "': " + error.message());
        }
        if(size_after_read != signature.size or modified_after_read != signature.modified) {
            attempted_signature_.reset();
            return fail("file '" + options_.path.string() + "' changed while it was being read");
        }

        ParseResult<T> parsed;
        try {
            parsed = parser_(text);
        } catch(std::exception const& exception) {
            return fail("parser for '" + options_.path.string() + "' threw: " + exception.what());
        } catch(...) {
            return fail("parser for '" + options_.path.string() + "' threw an unknown exception");
        }
        if(not parsed) {
            return fail(parsed.error.empty() ? "parser rejected '" + options_.path.string() + "'"
                                             : std::move(parsed.error));
        }

        auto const next_version = version_.load(std::memory_order_relaxed) + 1;
        auto published = std::make_shared<const snapshot_type>(snapshot_type{
            SnapshotMetadata{next_version, options_.path, modified, size,
                             std::chrono::system_clock::now()},
            std::move(parsed.value)});

        // Publish the immutable object before the flag. A worker which observes
        // next_version with acquire semantics can then load the matching snapshot.
        std::atomic_store_explicit(&snapshot_, std::move(published), std::memory_order_release);
        version_.store(next_version, std::memory_order_release);
        successful_reloads_.fetch_add(1, std::memory_order_relaxed);
        {
            std::lock_guard lock(state_lock_);
            last_error_.clear();
        }
        return {ReloadStatus::published, next_version, {}};
    }

    WatchedFileOptions options_;
    parser_type parser_;
    mutable std::mutex reload_lock_;
    mutable std::mutex state_lock_;
    std::optional<FileSignature> attempted_signature_;
    std::shared_ptr<const snapshot_type> snapshot_;
    std::atomic<version_type> version_{0};
    std::atomic_uint64_t successful_reloads_{0};
    std::atomic_uint64_t failed_reloads_{0};
    std::string last_error_;
};

} // namespace sx::reload
