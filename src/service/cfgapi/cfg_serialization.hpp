#pragma once

#include <libconfig.h++>

#include <cstdio>
#include <cstdlib>

namespace cfgapi_detail {

inline int write_config_crlf(libconfig::Config& config, FILE* destination) {
    if(not destination) return -1;

    char* serialized = nullptr;
    std::size_t serialized_size = 0;
    FILE* memory = open_memstream(&serialized, &serialized_size);
    if(not memory) return -1;

    try {
        config.write(memory);
    } catch(...) {
        fclose(memory);
        free(serialized);
        throw;
    }
    if(fclose(memory) != 0) {
        free(serialized);
        return -1;
    }

    bool ok = true;
    for(std::size_t i = 0; i < serialized_size && ok; ++i) {
        if(serialized[i] == '\n') ok = fputc('\r', destination) != EOF;
        if(ok) ok = fputc(static_cast<unsigned char>(serialized[i]), destination) != EOF;
    }
    free(serialized);
    return ok ? 0 : -1;
}

} // namespace cfgapi_detail
