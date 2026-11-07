#include <service/cfgapi/cfg_tar.hpp>

#include <cstddef>
#include <cstdint>
#include <string_view>

namespace {

[[noreturn]] void invariant_failed() {
    __builtin_trap();
}

} // namespace

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t* data, std::size_t size) {
    sx::cfg::CfgTar::Limits limits;
    limits.max_entries = 64;
    limits.max_file_size = 1024 * 1024;
    limits.max_total_size = 2 * 1024 * 1024;
    limits.max_path_size = 1024;

    try {
        const auto input = std::string_view(reinterpret_cast<const char*>(data), size);
        const auto archive = sx::cfg::CfgTar::read(input, limits);

        // Every accepted archive must survive deterministic serialization and
        // produce the same logical entries when parsed for a second time.
        const auto encoded = archive.write();
        const auto repeated = sx::cfg::CfgTar::read(encoded, limits);
        if (archive.entries().size() != repeated.entries().size() ||
            archive.write() != repeated.write()) {
            invariant_failed();
        }
    }
    catch (const sx::cfg::CfgTarError&) {
        // Invalid and hostile inputs are the normal parser result.
    }
    return 0;
}
