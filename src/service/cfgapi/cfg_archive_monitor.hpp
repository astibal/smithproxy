#pragma once

#include <service/reload/reloadable_resource.hpp>

#include <atomic>
#include <cstdint>
#include <functional>
#include <mutex>
#include <string>
#include <string_view>
#include <sys/types.h>

namespace sx::cfg {

// Watches the persistent native archive without applying it to runtime. A
// changed, missing, unreadable, or invalid archive only raises restart state;
// an administrator still decides when Smithproxy may consume those bytes.
class CfgArchiveMonitor final : public sx::reload::ReloadableResourceBase {
public:
    using ReadArchive = std::function<int(const std::string&, std::string&)>;

    struct Context {
        // Persistent native archive selected by CfgFactory.
        std::string path;
        // Exact archive generation already accepted by the running process.
        std::string accepted_payload;
        // Optional privileged reader override used by alternate runtimes and
        // deterministic tests. Production defaults to config_read().
        ReadArchive read_archive {};
    };

    // Establish the accepted generation without reporting an initial change.
    explicit CfgArchiveMonitor(Context context);

    // Check metadata and periodically re-hash even an apparently stable inode.
    sx::reload::ReloadResult poll() override;
    // Inspect current bytes even when their filesystem signature appears equal.
    sx::reload::ReloadResult reload_now() override;

    // Advance the expected hash after Smithproxy itself publishes an archive.
    // This also clears a transient observation of that same accepted write.
    void accept(std::string_view payload);

    // Report whether persistent startup bytes differ from the accepted runtime.
    [[nodiscard]] bool change_detected() const noexcept;
    // Return the most recent changed archive hash, or an empty string on failure.
    [[nodiscard]] std::string detected_hash() const;
    // Return the most recent monitoring or archive-validation error.
    [[nodiscard]] std::string last_error() const;

private:
    struct FileSignature {
        dev_t device {0};
        ino_t inode {0};
        std::uint64_t size {0};
        std::int64_t modified_seconds {0};
        std::int64_t modified_nanoseconds {0};

        // Compare the stable identity and content-related metadata of one inode.
        bool operator==(const FileSignature& other) const noexcept;
    };

    // Read one non-symlink regular-file signature without opening its contents.
    FileSignature signature() const;
    // Perform the complete privileged read, hash, and archive validation pass.
    sx::reload::ReloadResult check(bool force);
    // Publish a failed observation and conservatively require a restart.
    sx::reload::ReloadResult fail(std::string detail);

    std::string path_;
    ReadArchive read_archive_;
    mutable std::mutex state_lock_;
    std::string accepted_hash_;
    std::string detected_hash_;
    std::string last_error_;
    FileSignature attempted_signature_;
    bool have_attempted_signature_ {false};
    // Metadata is only a fast path. Periodically consume this allowance and
    // hash the bytes again so an in-place rewrite with restored mtime cannot
    // remain invisible forever.
    unsigned metadata_fast_paths_remaining_ {0};
    std::atomic_bool change_detected_ {false};
    std::atomic<sx::reload::version_type> version_ {0};
};

}  // namespace sx::cfg
