#pragma once

#include <memory>
#include <string>

#include <sys/stat.h>
#include <sys/types.h>

namespace sx::cfg {

// Provides the filesystem operations used while reading and publishing CFtar
// archives. Tests may override individual calls to exercise otherwise rare
// I/O failures without adding test switches to production control flow.
class CfgIo {
public:
    virtual ~CfgIo() = default;

    // Open one existing archive for a read-only, symlink-safe read.
    virtual int open_read(const std::string& path) const;
    // Open or create the stable sidecar file used to serialize publishers.
    virtual int open_lock(const std::string& path) const;
    // Read metadata for an already opened archive descriptor.
    virtual int inspect_open(int fd, struct stat* metadata) const;
    // Read up to size bytes from an archive descriptor.
    virtual ssize_t read(int fd, void* buffer, std::size_t size) const;
    // Close one file or directory descriptor.
    virtual int close(int fd) const;
    // Apply or release a flock(2) operation on a sidecar descriptor.
    virtual int lock(int fd, int operation) const;

    // Inspect an archive path without following a symbolic link.
    virtual int inspect_path(const std::string& path, struct stat* metadata) const;
    // Create a sibling temporary file and replace the XXXXXX suffix in pattern.
    virtual int create_temp(std::string& pattern) const;
    // Create a private temporary directory and resolve the XXXXXX suffix.
    virtual int create_temp_directory(std::string& pattern) const;
    // Apply the final archive permission bits to a temporary file.
    virtual int set_mode(int fd, mode_t mode) const;
    // Preserve the owner of an archive that is being replaced.
    virtual int set_owner(int fd, uid_t owner, gid_t group) const;
    // Write up to size bytes to a temporary archive descriptor.
    virtual ssize_t write(int fd, const void* buffer, std::size_t size) const;
    // Flush file contents or a parent directory entry to stable storage.
    virtual int sync(int fd) const;
    // Atomically publish a completed temporary archive under its final name.
    virtual int replace(const std::string& from, const std::string& to) const;
    // Open a parent directory so its updated entry can be synchronized.
    virtual int open_directory(const std::string& path) const;
    // Remove an unpublished temporary file during error cleanup.
    virtual int remove(const std::string& path) const;
};

using CfgIoPtr = std::shared_ptr<const CfgIo>;

}  // namespace sx::cfg
