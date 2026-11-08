#include "cfg_file_lock.hpp"

#include "cfg_tar.hpp"

#include <cerrno>
#include <cstring>
#include <fcntl.h>
#include <sys/file.h>
#include <thread>
#include <unistd.h>
#include <utility>

namespace sx::cfg {

CfgFileLock::CfgFileLock(int fd) noexcept: fd_(fd) {}

CfgFileLock CfgFileLock::acquire(
    const std::string& archive_path,
    std::chrono::milliseconds timeout) {
    const auto lock_path = archive_path + ".lock";
    const int fd = ::open(
        lock_path.c_str(), O_RDWR | O_CREAT | O_CLOEXEC | O_NOFOLLOW, 0600);
    if(fd < 0) {
        throw CfgTarError(
            "cannot open CFtar lock " + lock_path + ": " + std::strerror(errno));
    }

    // flock() follows the sidecar inode rather than the atomically replaced
    // archive inode. Short sleeps keep timeout behavior predictable.
    const auto deadline = std::chrono::steady_clock::now() + timeout;
    while(::flock(fd, LOCK_EX | LOCK_NB) != 0) {
        if(errno != EWOULDBLOCK && errno != EAGAIN) {
            const auto detail = std::strerror(errno);
            ::close(fd);
            throw CfgTarError(
                "cannot lock CFtar " + lock_path + ": " + detail);
        }
        if(std::chrono::steady_clock::now() >= deadline) {
            ::close(fd);
            throw CfgTarError("timed out waiting for CFtar lock " + lock_path);
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(25));
    }
    return CfgFileLock(fd);
}

CfgFileLock::CfgFileLock(CfgFileLock&& other) noexcept
    : fd_(std::exchange(other.fd_, -1)) {}

CfgFileLock& CfgFileLock::operator=(CfgFileLock&& other) noexcept {
    if(this == &other) return *this;
    release();
    fd_ = std::exchange(other.fd_, -1);
    return *this;
}

CfgFileLock::~CfgFileLock() {
    release();
}

void CfgFileLock::release() noexcept {
    if(fd_ < 0) return;
    ::flock(fd_, LOCK_UN);
    ::close(fd_);
    fd_ = -1;
}

}  // namespace sx::cfg
