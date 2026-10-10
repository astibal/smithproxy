#pragma once

#include <chrono>
#include <cstdint>
#include <mutex>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

#include <protocoltracer.hpp>

class CaptureProtocolTracer final : public socle::ProtocolTracer {
public:
    struct record {
        std::uint64_t sequence = 0;
        std::string timestamp;
        std::int64_t timestamp_unix_us = 0;
        std::int64_t delta_us = 0;
        socle::trace_side side = socle::trace_side::proxy;
        socle::trace_component component = socle::trace_component::proxy;
        socle::trace_scope scope = socle::trace_scope::session;
        std::optional<std::uint64_t> subject_id;
        socle::trace_event event = socle::trace_event::created;
        socle::trace_status status = socle::trace_status::info;
        std::string detail;
    };
    struct snapshot {
        std::vector<record> records;
        std::uint64_t dropped = 0;
    };

    using writer_type = void (*)(void*, std::string_view);
    CaptureProtocolTracer(void* context, writer_type writer,
                          std::optional<std::uint64_t> subject_id = {}) noexcept;
    void trace(socle::protocol_trace_event const& event) noexcept final;
    [[nodiscard]] snapshot records(
        std::optional<std::uint64_t> subject_id = {}) const;

    static std::vector<unsigned char> encode_block(std::string_view csv_row);

private:
    void write(std::string_view csv_row);
    void* writer_context_ = nullptr;
    writer_type writer_ = nullptr;
    std::optional<std::uint64_t> default_subject_;
    static constexpr std::size_t maximum_webhook_records = 1024;
    mutable std::mutex mutex_;
    uint64_t sequence_ = 0;
    std::chrono::steady_clock::time_point previous_;
    bool has_previous_ = false;
    std::vector<record> records_;
    std::uint64_t dropped_records_ = 0;
};
