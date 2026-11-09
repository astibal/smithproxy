#include "cfg_io.hpp"

#include <fcntl.h>
#include <sys/file.h>
#include <unistd.h>

namespace sx::cfg {

int CfgIo::open_read(const std::string& path) const {
    return ::open(path.c_str(), O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
}

int CfgIo::open_lock(const std::string& path) const {
    return ::open(
        path.c_str(), O_RDWR | O_CREAT | O_CLOEXEC | O_NOFOLLOW, 0600);
}

int CfgIo::inspect_open(int fd, struct stat* metadata) const {
    return ::fstat(fd, metadata);
}

ssize_t CfgIo::read(int fd, void* buffer, std::size_t size) const {
    return ::read(fd, buffer, size);
}

int CfgIo::close(int fd) const {
    return ::close(fd);
}

int CfgIo::lock(int fd, int operation) const {
    return ::flock(fd, operation);
}

int CfgIo::inspect_path(const std::string& path, struct stat* metadata) const {
    return ::lstat(path.c_str(), metadata);
}

int CfgIo::create_temp(std::string& pattern) const {
    return ::mkstemp(pattern.data());
}

int CfgIo::create_temp_directory(std::string& pattern) const {
    return ::mkdtemp(pattern.data()) ? 0 : -1;
}

int CfgIo::set_mode(int fd, mode_t mode) const {
    return ::fchmod(fd, mode);
}

int CfgIo::set_owner(int fd, uid_t owner, gid_t group) const {
    return ::fchown(fd, owner, group);
}

ssize_t CfgIo::write(int fd, const void* buffer, std::size_t size) const {
    return ::write(fd, buffer, size);
}

int CfgIo::sync(int fd) const {
    return ::fsync(fd);
}

int CfgIo::replace(const std::string& from, const std::string& to) const {
    return ::rename(from.c_str(), to.c_str());
}

int CfgIo::open_directory(const std::string& path) const {
    return ::open(path.c_str(), O_RDONLY | O_DIRECTORY | O_CLOEXEC);
}

int CfgIo::remove(const std::string& path) const {
    return ::unlink(path.c_str());
}

}  // namespace sx::cfg
