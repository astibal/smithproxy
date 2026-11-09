#pragma once

#include <chrono>
#include <string>

#include "cfg_io.hpp"

namespace sx::cfg {

// Holds the stable sidecar lock shared by the daemon and offline CFtar tools.
// The archive itself is never locked because atomic replacement changes its
// inode; every writer instead locks the persistent "<archive>.lock" file.
class CfgFileLock {
public:
    // Wait up to timeout for exclusive ownership of "<archive>.lock".
    // The returned guard keeps the lock until destruction or move-assignment.
    static CfgFileLock acquire(
        const std::string& archive_path,
        std::chrono::milliseconds timeout = std::chrono::seconds(5));
    // Acquire through an alternate I/O implementation used by deterministic
    // failure tests and platform-specific adapters.
    static CfgFileLock acquire(
        const std::string& archive_path,
        std::chrono::milliseconds timeout,
        CfgIoPtr io);

    // Transfer lock ownership without releasing the underlying descriptor.
    CfgFileLock(CfgFileLock&& other) noexcept;
    // Release any currently held lock, then take ownership from other.
    CfgFileLock& operator=(CfgFileLock&& other) noexcept;
    // A lock has exactly one owner and therefore cannot be copied.
    CfgFileLock(const CfgFileLock&) = delete;
    // Assignment cannot create a second owner of the same lock either.
    CfgFileLock& operator=(const CfgFileLock&) = delete;
    // Release the sidecar lock and close its descriptor.
    ~CfgFileLock();

private:
    // Adopt the locked directory anchor and sidecar returned by acquire().
    explicit CfgFileLock(int directory_fd, int sidecar_fd, CfgIoPtr io) noexcept;
    // Idempotently unlock and close both owned descriptors.
    void release() noexcept;

    int directory_fd_ {-1};
    int sidecar_fd_ {-1};
    CfgIoPtr io_;
};

}  // namespace sx::cfg
