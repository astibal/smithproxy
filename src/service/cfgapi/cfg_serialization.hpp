#pragma once

#include <libconfig.h++>

#include <cstdio>
#include <cstdlib>
#include <optional>
#include <string>

namespace cfgapi_detail {

// Serialize through libconfig's public writer. The returned bytes are the
// canonical in-memory representation used by revision hashing and history.
inline std::optional<std::string> serialize_config(libconfig::Config& config) {
    char* serialized = nullptr;
    std::size_t serialized_size = 0;
    FILE* memory = open_memstream(&serialized, &serialized_size);
    if(not memory) return std::nullopt;

    try {
        config.write(memory);
    } catch(...) {
        fclose(memory);
        free(serialized);
        throw;
    }
    if(fclose(memory) != 0) {
        free(serialized);
        return std::nullopt;
    }

    std::string result(serialized, serialized_size);
    free(serialized);
    return result;
}

inline int write_config_crlf(libconfig::Config& config, FILE* destination) {
    if(not destination) return -1;

    auto serialized = serialize_config(config);
    if(not serialized) return -1;

    bool ok = true;
    for(unsigned char const character : *serialized) {
        if(not ok) break;
        if(character == '\n') ok = fputc('\r', destination) != EOF;
        if(ok) ok = fputc(character, destination) != EOF;
    }
    return ok ? 0 : -1;
}

} // namespace cfgapi_detail
