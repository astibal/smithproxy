#include <proxy/capture_protocol_tracer.hpp>

#include <buffer.hpp>
#include <traflog/pcapapi.hpp>

#include <array>
#include <ctime>
#include <cstdio>
#include <memory>
#include <sstream>

namespace {

std::string csv_field(std::string_view value) {
    if(value.find_first_of(",\"\r\n") == std::string_view::npos)
        return std::string(value);
    std::string result;
    result.reserve(value.size() + 2);
    result.push_back('"');
    for(char c : value) {
        if(c == '"') result.push_back('"');
        result.push_back(c);
    }
    result.push_back('"');
    return result;
}

std::string utc_timestamp(std::chrono::system_clock::time_point now) {
    auto const seconds = std::chrono::time_point_cast<std::chrono::seconds>(now);
    auto const micros = std::chrono::duration_cast<std::chrono::microseconds>(
        now - seconds).count();
    auto const time = std::chrono::system_clock::to_time_t(seconds);
    std::tm tm{};
    gmtime_r(&time, &tm);
    std::array<char, 32> prefix{};
    std::strftime(prefix.data(), prefix.size(), "%Y-%m-%dT%H:%M:%S", &tm);
    char result[48]{};
    std::snprintf(result, sizeof(result), "%s.%06lldZ", prefix.data(),
                  static_cast<long long>(micros));
    return result;
}

} // namespace

CaptureProtocolTracer::CaptureProtocolTracer(
    void* context, writer_type writer,
    std::optional<std::uint64_t> subject_id) noexcept
    : writer_context_(context), writer_(writer),
      default_subject_(subject_id) {}

std::vector<unsigned char> CaptureProtocolTracer::encode_block(
    std::string_view csv_row) {
    socle::pcapng::pcapng_custom_block block;
    block.pen = 67005U;
    block.name_space = {'S', 'X', 'P', 'P'};
    block.entry_type = 1;
    block.version = 1;
    block.payload = std::make_shared<buffer>(csv_row.data(), csv_row.size());
    buffer serialized;
    block.append(serialized);
    auto const* begin = static_cast<unsigned char const*>(serialized.data());
    return {begin, begin + serialized.size()};
}

void CaptureProtocolTracer::write(std::string_view csv_row) {
    if(writer_) writer_(writer_context_, csv_row);
}

void CaptureProtocolTracer::trace(
    socle::protocol_trace_event const& event) noexcept {
    try {
        std::scoped_lock lock(mutex_);
        auto const wall_now = std::chrono::system_clock::now();
        auto const steady_now = std::chrono::steady_clock::now();
        auto const delta = has_previous_
            ? std::chrono::duration_cast<std::chrono::microseconds>(
                  steady_now - previous_).count()
            : 0;
        previous_ = steady_now;
        has_previous_ = true;

        auto const unix_us = std::chrono::duration_cast<std::chrono::microseconds>(
            wall_now.time_since_epoch()).count();
        record entry;
        entry.sequence = ++sequence_;
        entry.timestamp = utc_timestamp(wall_now);
        entry.timestamp_unix_us = unix_us;
        entry.delta_us = delta;
        entry.side = event.side;
        entry.component = event.component;
        entry.scope = event.scope;
        if(event.has_subject_id) entry.subject_id = event.subject_id;
        else entry.subject_id = default_subject_;
        entry.event = event.event;
        entry.status = event.status;
        entry.detail = event.detail;

        std::ostringstream row;
        row << entry.sequence << ',' << entry.timestamp << ','
            << entry.timestamp_unix_us << ',' << entry.delta_us << ','
            << socle::to_string(entry.side) << ','
            << socle::to_string(entry.component) << ','
            << socle::to_string(entry.scope) << ',';
        if(entry.subject_id) row << *entry.subject_id;
        row << ',' << socle::to_string(entry.event) << ','
            << socle::to_string(entry.status) << ',' << csv_field(entry.detail);
        write(row.str());

        if(records_.size() < maximum_webhook_records)
            records_.push_back(std::move(entry));
        else
            ++dropped_records_;
    } catch(...) {
        // Diagnostics must never affect the proxied connection.
    }
}

CaptureProtocolTracer::snapshot CaptureProtocolTracer::records(
    std::optional<std::uint64_t> subject_id) const {
    std::scoped_lock lock(mutex_);
    snapshot result;
    result.dropped = dropped_records_;
    result.records.reserve(records_.size());
    for(auto const& entry : records_) {
        if(subject_id && entry.subject_id && entry.subject_id != subject_id)
            continue;
        result.records.push_back(entry);
    }
    return result;
}
