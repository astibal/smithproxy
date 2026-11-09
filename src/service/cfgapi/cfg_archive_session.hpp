#pragma once

#include <string>
#include <string_view>
#include <vector>

#include "cfg_io.hpp"
#include "cfg_tar.hpp"

namespace sx::cfg {

struct CfgArchiveChange {
    // Classifies one path by comparing the base and working generations.
    enum class Kind {
        added,
        modified,
        removed,
    };

    Kind kind;
    std::string path;
};

// Represents one offline administrative session over a validated CFtar.
// Changes stay in a private working copy until save() rechecks the original
// hash under the inter-process lock and publishes the archive atomically.
class CfgArchiveSession {
public:
    // Read and validate one archive, then capture its initial content hash.
    static CfgArchiveSession open(std::string archive_path);
    // Open an archive through an alternate I/O implementation. This keeps
    // fault injection and platform adaptation outside session control flow.
    static CfgArchiveSession open(std::string archive_path, CfgIoPtr io);

    // Return the persistent archive path represented by this session.
    const std::string& path() const noexcept { return archive_path_; }
    // Return the hash that must still match when save() obtains the lock.
    const std::string& base_hash() const noexcept { return base_hash_; }
    // Return the current private working copy, including staged changes.
    const CfgTar& archive() const noexcept { return working_; }
    // Report whether the working copy differs from the last saved generation.
    bool dirty() const;

    // Return one entry from the working copy or throw when it is absent.
    const CfgTar::Entry& entry(std::string_view path) const;
    // Add or replace one working-copy entry and validate the resulting archive.
    // The format-owned manifest cannot be changed through this operation.
    void put(std::string path, std::string content, bool executable = false);
    // Remove one resource entry; mandatory control files are never removable.
    void remove(std::string_view path);
    // Reset every staged change to the last opened or saved generation.
    void discard();

    // Validate both the archive namespace and the parseability of the main
    // libconfig document. Runtime-only checks remain the daemon's concern.
    void validate() const;
    // Describe added, modified and removed paths without exposing their bytes.
    std::vector<CfgArchiveChange> changes() const;

    // Save recovery bytes first, then atomically replace the active archive.
    // A changed on-disk hash aborts rather than rebasing implicitly.
    void save();

private:
    // Build a session only from content already read and validated by open().
    CfgArchiveSession(
        std::string archive_path,
        std::string base_hash,
        CfgTar original,
        CfgIoPtr io);

    // Enforce manifest policy and parse the complete main libconfig document.
    static void validate_archive(const CfgTar& archive);

    std::string archive_path_;
    std::string base_hash_;
    CfgTar original_;
    CfgTar working_;
    CfgIoPtr io_;
};

}  // namespace sx::cfg
