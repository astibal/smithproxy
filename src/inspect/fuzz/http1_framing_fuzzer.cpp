#include <inspect/engine/http.hpp>

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <string_view>

namespace {

void check_ranges(std::string_view block,
                  sx::engine::http::L7PayloadHints const& ranges) {
    std::int64_t previous_end = 0;
    for(const auto [start, end] : ranges) {
        if(start == -1 && end == -1) continue;
        if(start < 0 || end < start ||
           static_cast<std::size_t>(end) > block.size() ||
           start < previous_end) {
            std::abort();
        }
        previous_end = end;
    }
}

} // namespace

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t* data,
                                      std::size_t size) {
    if(size == 0) return 0;

    sx::engine::http::v1::Http1Connection connection;
    std::size_t offset = 0;
    while(offset < size) {
        const auto control = data[offset++];
        const bool response_side = (control & 0x80U) != 0;
        const std::size_t direction = response_side ? 1U : 0U;
        const auto available = size - offset;
        const auto length = std::min<std::size_t>(available,
                                                  1U + (control & 0x7fU));
        const auto block = std::string_view(
            reinterpret_cast<const char*>(data + offset), length);
        const auto ranges = connection.observe(direction, block, response_side);
        check_ranges(block, ranges);
        offset += length;
    }
    return 0;
}
