#include "proxy/multiflow/fake.hpp"
#include "proxy/multiflow/mfproxy.hpp"

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <vector>

namespace mf = sx::multiflow;

namespace {

class input_reader {
public:
    input_reader(std::uint8_t const* data, std::size_t size)
        : data_(data), size_(size) {}

    bool empty() const { return offset_ >= size_; }
    std::uint8_t byte() { return empty() ? 0 : data_[offset_++]; }

    std::vector<unsigned char> bytes(std::size_t maximum) {
        auto const count = std::min<std::size_t>(byte() % (maximum + 1), size_ - offset_);
        std::vector<unsigned char> result(data_ + offset_, data_ + offset_ + count);
        offset_ += count;
        return result;
    }

private:
    std::uint8_t const* data_;
    std::size_t size_;
    std::size_t offset_ = 0;
};

mf::flow_handle choose(std::vector<mf::flow_handle> const& flows, std::uint8_t selector) {
    if (flows.empty()) return { selector, static_cast<mf::generation_id>(selector) };
    return flows[selector % flows.size()];
}

[[noreturn]] void invariant_failed() {
    __builtin_trap();
}

} // namespace

extern "C" int LLVMFuzzerTestOneInput(std::uint8_t const* data, std::size_t size) {
    if (!data || size == 0) return 0;
    input_reader input(data, std::min<std::size_t>(size, 4096));
    auto const watermark = std::size_t { 1 } + input.byte() % 128;
    auto left = std::make_shared<mf::fake_connection>(watermark);
    auto right = std::make_shared<mf::fake_connection>(watermark);
    constexpr std::size_t maximum_flows = 8;
    mf::MFProxy proxy(left, right, { maximum_flows, 64 });
    std::vector<mf::flow_handle> left_flows;
    std::vector<mf::flow_handle> right_flows;
    std::size_t opened = 0;

    for (std::size_t operations = 0; !input.empty() && operations < 512; ++operations) {
        auto const opcode = input.byte() % 13;
        bool const use_left = (input.byte() & 1U) != 0;
        auto& connection = use_left ? left : right;
        auto& flows = use_left ? left_flows : right_flows;
        auto const handle = choose(flows, input.byte());
        switch (opcode) {
            case 0:
            case 1: {
                auto const direction = opcode == 0
                    ? mf::direction::bidirectional : mf::direction::send_only;
                auto const created = connection->open_flow(direction);
                flows.push_back(created);
                ++opened;
                break;
            }
            case 2: {
                auto const payload = input.bytes(32);
                connection->inject_receive(handle, payload.data(), payload.size());
                break;
            }
            case 3: connection->inject_peer_fin(handle); break;
            case 4: connection->reset(handle, input.byte()); break;
            case 5: connection->finish(handle); break;
            case 6: connection->block_finish(handle, (input.byte() & 1U) != 0); break;
            case 7: connection->consume_send(handle, input.byte()); break;
            case 8: connection->close(input.byte()); break;
            case 9: proxy.pump_once(std::size_t { 1 } + input.byte() % 64); break;
            case 10: {
                unsigned char buffer[64] {};
                connection->read(handle, buffer, input.byte() % sizeof(buffer));
                break;
            }
            case 11: {
                auto const payload = input.bytes(32);
                connection->write(handle, payload.data(), payload.size());
                break;
            }
            case 12: connection->drain_events(); break;
        }
        proxy.pump_once(std::size_t { 1 } + input.byte() % 64);
        if (proxy.pair_count() > maximum_flows || proxy.limit_rejections() > opened) {
            invariant_failed();
        }
    }
    for (std::size_t i = 0; i < 16; ++i) proxy.pump_once(64);
    if (proxy.pair_count() > maximum_flows) invariant_failed();
    return 0;
}
