#pragma once

#include <chrono>
#include <cstdint>
#include <mutex>
#include <optional>
#include <string_view>
#include <vector>

#include <protocoltracer.hpp>

class CaptureProtocolTracer final : public socle::ProtocolTracer {
public:
    using writer_type = void (*)(void*, std::string_view);
    CaptureProtocolTracer(void* context, writer_type writer,
                          std::optional<std::uint64_t> subject_id = {}) noexcept;
    void trace(socle::protocol_trace_event const& event) noexcept final;

    static std::vector<unsigned char> encode_block(std::string_view csv_row);

private:
    void write(std::string_view csv_row);
    void* writer_context_ = nullptr;
    writer_type writer_ = nullptr;
    std::optional<std::uint64_t> default_subject_;
    std::mutex mutex_;
    uint64_t sequence_ = 0;
    std::chrono::steady_clock::time_point previous_;
    bool has_previous_ = false;
};
