#include <inspect/engine/http.hpp>

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <string_view>

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t* data,
                                      std::size_t size) {
    sx::engine::http::v2::Http2Direction directions[2];
    std::size_t offset = 0;
    while(offset < size) {
        const auto control = data[offset++];
        const auto side = static_cast<std::size_t>((control >> 7U) & 1U);
        const auto length = std::min<std::size_t>(size - offset,
                                                  1U + (control & 0x7fU));
        const auto block = std::string_view(
            reinterpret_cast<const char*>(data + offset), length);
        const auto ranges = directions[side].observe(block, side == 0);
        std::int64_t previous = 0;
        for(const auto [start, end] : ranges) {
            if(start == -1 && end == -1) continue;
            if(start < 0 || end < start || start < previous ||
               static_cast<std::size_t>(end) > block.size())
                std::abort();
            previous = end;
        }
        for(const auto& annotation : directions[side].annotations()) {
            if(annotation.start < 0 || annotation.end < annotation.start ||
               static_cast<std::size_t>(annotation.end) > block.size())
                std::abort();
        }
        offset += length;
    }
    return 0;
}
