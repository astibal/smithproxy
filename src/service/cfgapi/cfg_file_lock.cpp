#include "cfg_file_lock.hpp"

#include "cfg_tar.hpp"

#include <cerrno>
#include <cstring>
#include <filesystem>
#include <sys/file.h>
#include <thread>
#include <utility>

namespace sx::cfg {

namespace {

void wait_for_lock(
    int fd,
    const std::string& description,
    std::chrono::steady_clock::time_point deadline,
    const CfgIoPtr& io) {
    while(io->lock(fd, LOCK_EX | LOCK_NB) != 0) {
        if(errno != EWOULDBLOCK && errno != EAGAIN) {
            throw CfgTarError(
                "cannot lock " + description + ": " + std::strerror(errno));
        }
        if(std::chrono::steady_clock::now() >= deadline) {
            throw CfgTarError("timed out waiting for " + description);
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(25));
    }
}

}  // namespace

CfgFileLock::CfgFileLock(
    int directory_fd,
    int sidecar_fd,
    CfgIoPtr io) noexcept
    : directory_fd_(directory_fd),
      sidecar_fd_(sidecar_fd),
      io_(std::move(io)) {}

CfgFileLock CfgFileLock::acquire(
    const std::string& archive_path,
    std::chrono::milliseconds timeout) {
    return acquire(archive_path, timeout, std::make_shared<CfgIo>());
}

CfgFileLock CfgFileLock::acquire(
    const std::string& archive_path,
    std::chrono::milliseconds timeout,
    CfgIoPtr io) {
    if(!io) throw CfgTarError("CFtar lock I/O provider is not available");
    const auto lock_path = archive_path + ".lock";
    auto parent_path = std::filesystem::path(archive_path).parent_path();
    if(parent_path.empty()) parent_path = ".";

    // The directory inode remains stable if an administrator removes the
    // visible sidecar. It prevents a replacement sidecar from creating a
    // second, independent lock domain while a publisher is still active.
    const int directory_fd = io->open_directory(parent_path.string());
    if(directory_fd < 0) {
        throw CfgTarError(
            "cannot open CFtar lock directory " + parent_path.string() +
            ": " + std::strerror(errno));
    }

    const auto deadline = std::chrono::steady_clock::now() + timeout;
    try {
        wait_for_lock(
            directory_fd,
            "CFtar lock directory " + parent_path.string(),
            deadline,
            io);
    }
    catch(...) {
        io->close(directory_fd);
        throw;
    }

    const int sidecar_fd = io->open_lock(lock_path);
    if(sidecar_fd < 0) {
        const auto detail = std::strerror(errno);
        io->lock(directory_fd, LOCK_UN);
        io->close(directory_fd);
        throw CfgTarError("cannot open CFtar lock " + lock_path + ": " + detail);
    }

    // Keep the traditional per-archive sidecar as the second lock. Besides
    // preserving compatibility with older tools, it documents the protected
    // archive and avoids relying only on the broader directory anchor.
    try {
        wait_for_lock(sidecar_fd, "CFtar lock " + lock_path, deadline, io);
    }
    catch(...) {
        io->close(sidecar_fd);
        io->lock(directory_fd, LOCK_UN);
        io->close(directory_fd);
        throw;
    }
    return CfgFileLock(directory_fd, sidecar_fd, std::move(io));
}

CfgFileLock::CfgFileLock(CfgFileLock&& other) noexcept
    : directory_fd_(std::exchange(other.directory_fd_, -1)),
      sidecar_fd_(std::exchange(other.sidecar_fd_, -1)),
      io_(std::move(other.io_)) {}

CfgFileLock& CfgFileLock::operator=(CfgFileLock&& other) noexcept {
    if(this == &other) return *this;
    release();
    directory_fd_ = std::exchange(other.directory_fd_, -1);
    sidecar_fd_ = std::exchange(other.sidecar_fd_, -1);
    io_ = std::move(other.io_);
    return *this;
}

CfgFileLock::~CfgFileLock() {
    release();
}

void CfgFileLock::release() noexcept {
    if(sidecar_fd_ >= 0) {
        io_->lock(sidecar_fd_, LOCK_UN);
        io_->close(sidecar_fd_);
        sidecar_fd_ = -1;
    }
    if(directory_fd_ >= 0) {
        io_->lock(directory_fd_, LOCK_UN);
        io_->close(directory_fd_);
        directory_fd_ = -1;
    }
}

}  // namespace sx::cfg
