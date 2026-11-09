/*
 * Smithproxy native configuration archive.
 *
 * CfgTar deliberately owns the archive policy instead of exposing libarchive
 * objects to callers. This keeps path validation, size limits and extraction
 * rules identical for every configuration consumer.
 */

#pragma once

#include <cstddef>
#include <cstdint>
#include <map>
#include <stdexcept>
#include <string>
#include <string_view>

namespace sx::cfg {

class CfgTarError final : public std::runtime_error {
public:
    using std::runtime_error::runtime_error;
};

class CfgTar {
public:
    // Limits are enforced while data enters the in-memory model. They apply
    // equally to archives loaded from disk and entries added by Smithproxy.
    struct Limits {
        std::size_t max_entries = 4096;
        std::uint64_t max_file_size = 64ULL * 1024ULL * 1024ULL;
        std::uint64_t max_total_size = 256ULL * 1024ULL * 1024ULL;
        std::size_t max_path_size = 1024;
    };

    struct Entry {
        // CfgTar intentionally reduces POSIX permissions to one meaningful
        // bit. Materialized files are always private: 0600 or 0700.
        std::string data;
        bool executable = false;
    };

    using Entries = std::map<std::string, Entry>;

    CfgTar();
    explicit CfgTar(Limits limits);

    // Validate and canonicalize one path under this archive's path policy.
    [[nodiscard]] std::string checked_path(std::string_view path) const {
        return checked_path(path, limits_);
    }

    // Both readers accept uncompressed TAR only. Compression, links, devices,
    // sparse files and unsafe paths are rejected before an entry is accepted.
    static CfgTar read_file(const std::string& path);
    static CfgTar read_file(const std::string& path, Limits limits);
    static CfgTar read(std::string_view bytes);
    static CfgTar read(std::string_view bytes, Limits limits);

    void add(std::string path, std::string data, bool executable = false);

    // Replace one known entry without changing the archive namespace. This is
    // used when a transaction updates content such as the main configuration;
    // missing paths remain an error rather than being created accidentally.
    void replace(std::string_view path, std::string data, bool executable = false);

    // Store one entry regardless of whether it already exists. remove() is
    // explicit and reports absence, which keeps administrative edits honest.
    void upsert(std::string path, std::string data, bool executable = false);
    bool remove(std::string_view path);
    bool contains(std::string_view path) const;
    const Entry& at(std::string_view path) const;
    const Entries& entries() const noexcept;

    // Produce an uncompressed, deterministic POSIX pax archive. Stable entry
    // ordering and metadata make identical configurations byte-identical.
    std::string write() const;

    // Create a new file without following links or replacing existing data.
    // A partial output is removed if writing or fsync fails.
    void write_file(const std::string& path) const;

    // Create a new private directory and materialize every regular file in it.
    // The destination must not exist; existing data is never merged or replaced.
    void materialize(const std::string& destination) const;

private:
    // Paths are logical archive names, never host filesystem paths.
    static std::string checked_path(std::string_view path, const Limits& limits);
    void check_size(std::size_t size) const;

    Limits limits_;
    Entries entries_;
    std::uint64_t total_size_ = 0;
};

} // namespace sx::cfg
