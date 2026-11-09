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

void CaptureProtocolTracer::set_identity(
    std::string session_id, std::string proxy_session_key,
    std::optional<std::uint64_t> subject_id) {
    std::scoped_lock lock(mutex_);
    identity value {std::move(session_id), std::move(proxy_session_key)};
    if(subject_id) {
        stream_identities_[*subject_id] = value;
        if(!session_identity_) session_identity_ = value;
    } else {
        session_identity_ = std::move(value);
    }
    auto retained = std::vector<record>{};
    std::size_t retained_bytes = 0;
    for(auto const& entry : pending_capture_records_) {
        if(auto const* found = identity_for(entry); found) write(entry, *found);
        else {
            retained.push_back(entry);
            retained_bytes += entry.detail.size();
        }
    }
    pending_capture_records_ = std::move(retained);
    pending_detail_bytes_ = retained_bytes;
}

std::vector<unsigned char> CaptureProtocolTracer::encode_block(
    std::string_view csv_row) {
    socle::pcapng::pcapng_custom_block block;
    block.pen = 67005U;
    block.name_space = {'S', 'X', 'P', 'P'};
    block.entry_type = 1;
    block.version = 2;
    block.copyable = true;
    block.payload = std::make_shared<buffer>(csv_row.data(), csv_row.size());
    buffer serialized;
    block.append(serialized);
    auto const* begin = static_cast<unsigned char const*>(serialized.data());
    return {begin, begin + serialized.size()};
}

CaptureProtocolTracer::identity const*
CaptureProtocolTracer::identity_for(record const& entry) const {
    if(entry.subject_id) {
        auto const found = stream_identities_.find(*entry.subject_id);
        return found == stream_identities_.end() ? nullptr : &found->second;
    }
    return session_identity_ ? &*session_identity_ : nullptr;
}

void CaptureProtocolTracer::write(record const& entry, identity const& value) {
    if(!writer_) return;
    std::ostringstream row;
    row << entry.timestamp << ',' << entry.timestamp_unix_us << ','
        << entry.delta_us << ',' << csv_field(value.session_id) << ','
        << csv_field(value.proxy_session_key) << ',' << entry.sequence << ','
        << socle::to_string(entry.side) << ','
        << socle::to_string(entry.component) << ','
        << socle::to_string(entry.scope) << ',';
    if(entry.subject_id) row << *entry.subject_id;
    row << ',' << socle::to_string(entry.event) << ','
        << socle::to_string(entry.status) << ',' << csv_field(entry.detail);
    writer_(writer_context_, row.str());
}

void CaptureProtocolTracer::trace(
    socle::protocol_trace_event const& event) noexcept {
    try {
        std::scoped_lock lock(mutex_);
        auto const wall_now = std::chrono::system_clock::now();
        auto const steady_now = std::chrono::steady_clock::now();
        auto const unix_us = std::chrono::duration_cast<std::chrono::microseconds>(
            wall_now.time_since_epoch()).count();
        record entry;
        entry.sequence = ++sequence_;
        entry.timestamp = utc_timestamp(wall_now);
        entry.timestamp_unix_us = unix_us;
        entry.side = event.side;
        entry.component = event.component;
        entry.scope = event.scope;
        if(event.has_subject_id) entry.subject_id = event.subject_id;
        else entry.subject_id = default_subject_;
        std::optional<std::chrono::steady_clock::time_point> previous = previous_session_;
        if(entry.subject_id) {
            auto const found = previous_streams_.find(*entry.subject_id);
            if(found != previous_streams_.end()
               && (!previous || found->second > *previous)) previous = found->second;
            previous_streams_[*entry.subject_id] = steady_now;
        } else {
            previous_session_ = steady_now;
        }
        entry.delta_us = previous
            ? std::chrono::duration_cast<std::chrono::microseconds>(
                  steady_now - *previous).count()
            : 0;
        entry.event = event.event;
        entry.status = event.status;
        entry.detail = event.detail;

        if(auto const* identity = identity_for(entry); identity) write(entry, *identity);
        else if(writer_ && pending_capture_records_.size() < maximum_pending_records
                && entry.detail.size() <= maximum_pending_detail_bytes - pending_detail_bytes_) {
            pending_capture_records_.push_back(entry);
            pending_detail_bytes_ += entry.detail.size();
        } else if(writer_) {
            ++capture_dropped_;
        }

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
    result.capture_dropped = capture_dropped_;
    result.records.reserve(records_.size());
    for(auto const& entry : records_) {
        if(subject_id && entry.subject_id && entry.subject_id != subject_id)
            continue;
        result.records.push_back(entry);
    }
    return result;
}
