#ifndef SMITHPROXY_TRAFFICCAPTURE_HPP
#define SMITHPROXY_TRAFFICCAPTURE_HPP

#include <algorithm>
#include <atomic>
#include <cstddef>
#include <cstdint>
#include <deque>
#include <memory>
#include <mutex>
#include <utility>
#include <vector>

#include <buffer.hpp>
#include <traflog/basetraflog.hpp>

namespace sx {

/**
 * Optional per-session transformation applied to a configured traffic logger.
 *
 * The proxy core owns logger creation and capture policy. Protocol adapters may
 * decorate a compatible logger without exposing transport-specific state to
 * MitmProxy, baseCom, or the packet-capture implementation.
 */
class traffic_log_adapter {
public:
    virtual ~traffic_log_adapter() = default;

    virtual std::unique_ptr<socle::baseTrafficLogger> wrap(
        std::unique_ptr<socle::baseTrafficLogger> output) = 0;
};

/**
 * Bounded session-level bridge into an ordinary traffic logger.
 *
 * Wire packets and secrets can arrive before policy creates a logger for the
 * first logical flow. Until then records are retained in order within a fixed
 * byte budget. Installing a logger atomically emits retained secrets first,
 * replays packets in their original order, and turns subsequent publications
 * into direct, serialized logger calls. Secrets must precede encrypted PCAPNG
 * packets because Wireshark does not retroactively apply a later DSB.
 */
class session_traffic_log final {
public:
    explicit session_traffic_log(std::size_t maximum_pending_bytes)
        : maximum_pending_bytes_(maximum_pending_bytes) {}

    /** Install the first policy-approved logger and replay pending records. */
    bool install(std::shared_ptr<socle::baseTrafficLogger> output) {
        if (!output) return false;

        // Block direct writers while the backlog crosses the attachment point,
        // preserving record order without holding the state lock during I/O.
        std::lock_guard output_lock(output_mutex_);
        std::deque<record> pending;
        {
            std::lock_guard state_lock(state_mutex_);
            if (output_) return false;
            output_ = std::move(output);
            pending.swap(pending_);
            pending_bytes_ = 0;
        }
        for (auto const& item : pending) {
            if (item.type == record_type::secret) dispatch(*output_, item);
        }
        for (auto const& item : pending) {
            if (item.type == record_type::packet) dispatch(*output_, item);
        }
        return true;
    }

    /** Publish one complete L3 packet; side is retained only as capture metadata. */
    void write_packet(socle::side_t side, buffer const& packet) {
        publish(record {record_type::packet, side, {}, copy(packet)});
    }

    /** Publish session decryption material in its declared external encoding. */
    void write_secret(socle::traffic_secret_format format, buffer const& secret) {
        publish(record {record_type::secret, socle::side_t::LEFT, format, copy(secret)});
    }

    [[nodiscard]] std::size_t pending_bytes() const {
        std::lock_guard lock(state_mutex_);
        return pending_bytes_;
    }
    [[nodiscard]] std::uint64_t dropped_records() const {
        return dropped_records_.load(std::memory_order_relaxed);
    }

private:
    enum class record_type { packet, secret };
    struct record {
        record_type type;
        socle::side_t side;
        socle::traffic_secret_format secret_format;
        std::vector<unsigned char> data;
    };

    static std::vector<unsigned char> copy(buffer const& source) {
        if (source.empty()) return {};
        auto const* begin = static_cast<unsigned char const*>(source.data());
        return {begin, begin + source.size()};
    }

    static void dispatch(socle::baseTrafficLogger& output, record const& item) {
        buffer data(item.data.data(), item.data.size());
        if (item.type == record_type::packet) output.write_packet(item.side, data);
        else output.write_secret(item.secret_format, data);
    }

    void publish(record item) {
        if (item.data.empty()) return;

        std::shared_ptr<socle::baseTrafficLogger> output;
        {
            std::lock_guard lock(state_mutex_);
            output = output_;
            if (!output) {
                // Secrets are essential for decrypting every retained packet.
                // Prefer them by evicting older packets if the journal is full.
                if (item.type == record_type::secret) {
                    while (pending_bytes_ + item.data.size() > maximum_pending_bytes_) {
                        auto found = std::find_if(pending_.begin(), pending_.end(),
                            [](record const& value) {
                                return value.type == record_type::packet;
                            });
                        if (found == pending_.end()) break;
                        pending_bytes_ -= found->data.size();
                        pending_.erase(found);
                        dropped_records_.fetch_add(1, std::memory_order_relaxed);
                    }
                }
                if (pending_bytes_ + item.data.size() > maximum_pending_bytes_) {
                    dropped_records_.fetch_add(1, std::memory_order_relaxed);
                    return;
                }
                pending_bytes_ += item.data.size();
                pending_.push_back(std::move(item));
                return;
            }
        }

        std::lock_guard output_lock(output_mutex_);
        dispatch(*output, item);
    }

    std::size_t maximum_pending_bytes_;
    mutable std::mutex state_mutex_;
    std::mutex output_mutex_;
    std::shared_ptr<socle::baseTrafficLogger> output_;
    std::deque<record> pending_;
    std::size_t pending_bytes_ = 0;
    std::atomic_uint64_t dropped_records_ {0};
};

} // namespace sx

#endif // SMITHPROXY_TRAFFICCAPTURE_HPP
